"""HISN ThreatFox domain IOC synchronization. Run with: python -m scripts.sync_threatfox --apply

Safe defaults: dry-run, domain only, no policy writer, no secret logging.
"""
import argparse
import fcntl
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from sqlalchemy import select
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.threat_indicator import ThreatIndicator
from app.security_engine.log_parser import normalize_destination

API = "https://threatfox-api.abuse.ch/api/v1/"
SOURCE = "ThreatFox"

def utcnow():
    return datetime.now(timezone.utc)

def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def write_state(path, data):
    dest = Path(path)
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".threatfox-", dir=str(dest.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def confidence(score):
    if isinstance(score, bool) or score is None:
        return None
    try:
        n = int(score)
    except (TypeError, ValueError):
        return None
    if n < 0 or n > 100:
        return None
    return "HIGH" if n >= 80 else "MEDIUM" if n >= 50 else "LOW"

def fetch(key, days):
    body = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    request = Request(API, data=body,
        headers={"Auth-Key": key, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST")
    with urlopen(request, timeout=40) as response:
        if response.status != 200:
            raise RuntimeError(f"Unexpected HTTP {response.status}")
        raw = response.read(100_000_001)
        if len(raw) > 100_000_000:
            raise RuntimeError("ThreatFox response too large")
    return json.loads(raw)

def collect(payload):
    if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
        raise RuntimeError(f"ThreatFox unsuccessful response: {payload.get('query_status', 'unknown')}")
    levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    accepted = {}
    skipped = Counter()
    for item in payload["data"]:
        if not isinstance(item, dict) or item.get("ioc_type") != "domain":
            skipped["unsupported_type"] += 1
            continue
        score = confidence(item.get("confidence_level"))
        if score is None:
            skipped["invalid_confidence"] += 1
            continue
        try:
            domain = normalize_destination(item.get("ioc", ""))
        except (ValueError, TypeError, AttributeError, UnicodeError):
            skipped["invalid_domain"] += 1
            continue
        # Normalize_destination could return an IP for an invalid source record.
        import ipaddress
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            skipped["not_domain"] += 1
            continue
        # Prefer the highest confidence if multiple ThreatFox rows refer to the same domain.
        if domain not in accepted or levels[score] > levels[accepted[domain]]:
            accepted[domain] = score
    return accepted, skipped


def apply_feed_status(row):
    """Respect explicit administrator disables during a successful feed refresh."""
    row.is_active = not row.admin_disabled

def run(args):
    if args.apply and (settings.hisn_auto_enforce or settings.hisn_enforcement_enabled):
        raise RuntimeError("Refusing sync: set HISN_AUTO_ENFORCE=false and HISN_ENFORCEMENT_ENABLED=false")
    key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if not key:
        raise RuntimeError("THREATFOX_AUTH_KEY environment variable is required")
    payload = fetch(key, args.days)
    accepted, skipped = collect(payload)
    if not accepted:
        raise RuntimeError("No valid domains returned; refusing empty sync")
    print(f"Fetched: {len(payload['data'])}; valid unique domains: {len(accepted)}; skipped: {dict(skipped)}")
    if not args.apply:
        print("DRY RUN - no database or state changes")
        return
    now = utcnow()
    # This is a LOCAL freshness timeout, not ThreatFox's official expiration date.
    expires = now + timedelta(days=args.local_ttl_days)
    inserted = updated = 0
    with SessionLocal() as db:
        for domain, level in accepted.items():
            row = db.scalar(select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == "DOMAIN",
                ThreatIndicator.indicator_value == domain,
                ThreatIndicator.source_name == SOURCE))
            if row is None:
                db.add(ThreatIndicator(indicator_type="DOMAIN", indicator_value=domain,
                    source_name=SOURCE, confidence_level=level, expires_at=expires, is_active=True,
                    last_updated_at=now))
                inserted += 1
            else:
                row.confidence_level = level
                row.expires_at = expires
                row.last_updated_at = now
                # Keep feed updates from reversing an administrator's disable.
                apply_feed_status(row)
                updated += 1
        db.commit()
    previous = read_json(args.state_file)
    write_state(args.state_file, {
        **previous,
        "last_attempt_at": now.isoformat(),
        "last_success_at": now.isoformat(),
        "last_status": "ok",
        "last_total_received": len(payload["data"]),
        "last_valid_unique_domains": len(accepted),
        "last_inserted": inserted,
        "last_updated": updated,
        "last_skipped": dict(skipped),
        "query_days": args.days,
        "local_ttl_days": args.local_ttl_days,
    })
    print(f"Sync success: inserted={inserted}, updated={updated}; no blocking applied")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="commit to database (default is dry-run)")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--local-ttl-days", type=int, default=7)
    parser.add_argument("--state-file", default="/var/lib/hisn/threatfox-sync-state.json")
    args = parser.parse_args()
    if not 1 <= args.days <= 7 or not 1 <= args.local_ttl_days <= 30:
        parser.error("--days must be 1..7 and --local-ttl-days 1..30")
    lock_file = os.environ.get("HISN_THREATFOX_LOCK", "/tmp/hisn-threatfox-sync.lock")
    try:
        with open(lock_file, "a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(args)
    except (BlockingIOError, HTTPError, URLError, OSError, ValueError, RuntimeError) as exc:
        # Avoid printing request headers / secrets; HTTPError can include response URL but not key.
        print(f"ThreatFox sync failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        if args.apply:
            try:
                prior = read_json(args.state_file)
                write_state(args.state_file, {**prior, "last_status": "failed",
                    "last_attempt_at": utcnow().isoformat(),
                    "last_error_type": type(exc).__name__})
            except OSError:
                pass
        raise SystemExit(1)

if __name__ == "__main__":
    main()
