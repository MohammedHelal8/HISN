"""Incremental ingestion worker. Run under an unprivileged systemd service.

One transaction per line ensures checkpoint and event stay in sync. After rotation,
new inode is processed from position zero. An interrupted read of a partial line
is retried once it becomes complete. Unsupported line formats are counted.
"""
import argparse
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import select
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.log_processing_state import LogProcessingState
from app.security_engine.log_parser import parse_access_log
from app.security_engine.pipeline import process_record, apply_pending_actions

log = logging.getLogger('hisn.ingestion')


def ingest_once(path: str, session_factory=SessionLocal) -> dict[str, int]:
    filepath = Path(path)
    stat = filepath.stat()
    if not filepath.is_file():
        raise ValueError('Log source is not a regular file')
    identity = f'{stat.st_dev}:{stat.st_ino}'
    stats = {'read': 0, 'matched': 0, 'invalid': 0}
    with session_factory() as db:
        # PostgreSQL single-worker coordination, avoid concurrent replays.
        state = db.scalar(select(LogProcessingState).where(LogProcessingState.log_source == str(filepath)).with_for_update())
        if state is None:
            state = LogProcessingState(log_source=str(filepath), file_identity=identity, last_position=0)
            db.add(state)
            db.flush()
        if state.file_identity != identity or stat.st_size < state.last_position:
            state.file_identity, state.last_position = identity, 0
        offset = state.last_position
        with open(filepath, 'rb') as handle:
            handle.seek(offset)
            while True:
                start = handle.tell()
                chunk = handle.readline(16385)
                if not chunk:
                    break
                if len(chunk) > 16384 and not chunk.endswith(b'\n'):
                    # Bounded discard of a very long log line; do not stall forever.
                    while chunk and not chunk.endswith(b'\n'):
                        chunk = handle.readline(16385)
                    if not chunk:  # incomplete trailing oversized line
                        break
                    stats['read'] += 1
                    stats['invalid'] += 1
                    state.last_position = handle.tell()
                    state.last_processed_at = datetime.now(timezone.utc)
                    db.commit()
                    continue
                if not chunk.endswith(b'\n'):
                    # Preserve incomplete line for retry once it is terminated.
                    break
                stats['read'] += 1
                try:
                    if len(chunk) > 16384:
                        record = None
                    else:
                        record = parse_access_log(chunk.decode('utf-8', 'replace'))
                    if record is None:
                        stats['invalid'] += 1
                    else:
                        stats['matched'] += process_record(db, record, f'{filepath}:{identity}:{start}')
                    state.last_position = handle.tell()
                    state.last_processed_at = datetime.now(timezone.utc)
                    db.commit()
                except Exception:
                    db.rollback()
                    log.exception('Ingestion error at byte offset %s', start)
                    raise
    with session_factory() as db:
        apply_pending_actions(db)
    return stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--log', default=settings.hisn_e2guardian_log)
    parser.add_argument('--interval', type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.interval <= 3600:
        parser.error('interval must be 1..3600 seconds')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    while True:
        try:
            log.info('Ingestion: %s', ingest_once(args.log))
        except Exception:
            log.exception('Log ingestion failed; next cycle will retry')
            if args.once:
                raise
        if args.once:
            break
        time.sleep(args.interval)

if __name__ == '__main__':
    main()
