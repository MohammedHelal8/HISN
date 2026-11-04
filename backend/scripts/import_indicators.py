"""Offline TI ingestion: validate rows from an administrator-supplied CSV file.

CSV header: indicator_type,indicator_value,source_name,confidence_level,expires_at
Only DOMAIN/IP indicators supported by the existing PostgreSQL schema.
Use a controlled download workflow for external sources; no arbitrary SSRF URLs.
"""
import argparse
import csv
from pathlib import Path
from sqlalchemy import select
from app.core.database import SessionLocal
from app.models.threat_indicator import ThreatIndicator
from app.schemas.threat_indicator import ThreatIndicatorCreate


def import_csv(path: Path, factory=SessionLocal) -> dict[str, int]:
    totals = {'created': 0, 'updated': 0, 'invalid': 0}
    if not path.is_file() or path.stat().st_size > 10_000_000:
        raise ValueError('CSV file missing or exceeds 10 MB')
    with path.open('r', newline='', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        required = {'indicator_type', 'indicator_value', 'source_name', 'confidence_level'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('CSV is missing required column names')
        with factory() as db:
            # Commit per valid row; an invalid feed item does not poison the whole feed.
            for index, row in enumerate(reader):
                if index >= 100_000:
                    raise ValueError('Too many indicators')
                try:
                    if None in row or any(isinstance(v, str) and len(v) > 500 for v in row.values()):
                        raise ValueError('Malformed CSV fields')
                    values = {key: row.get(key, '') for key in required}
                    values['expires_at'] = row.get('expires_at') or None
                    item = ThreatIndicatorCreate.model_validate(values)
                    existing = db.scalar(select(ThreatIndicator).where(
                        ThreatIndicator.indicator_type == item.indicator_type.value,
                        ThreatIndicator.indicator_value == item.indicator_value,
                        ThreatIndicator.source_name == item.source_name))
                    if existing is None:
                        db.add(ThreatIndicator(indicator_type=item.indicator_type.value,
                                              indicator_value=item.indicator_value, source_name=item.source_name,
                                              confidence_level=item.confidence_level.value,
                                              expires_at=item.expires_at, is_active=True))
                        totals['created'] += 1
                    else:
                        existing.confidence_level = item.confidence_level.value
                        existing.expires_at = item.expires_at
                        existing.is_active = True
                        totals['updated'] += 1
                    db.commit()
                except (ValueError, TypeError):
                    totals['invalid'] += 1
                except Exception:
                    db.rollback()
                    raise
    return totals


def main():
    parser = argparse.ArgumentParser(description='Validate and upsert a trusted CSV TI feed')
    parser.add_argument('csv_file', type=Path)
    args = parser.parse_args()
    print(import_csv(args.csv_file))

if __name__ == '__main__':
    main()
