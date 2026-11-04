import argparse
import ipaddress
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.threat_indicator import ThreatIndicator
from app.security_engine.log_parser import normalize_destination


SOURCE = "ThreatFox"


def confidence_label(score):
    if isinstance(score, bool):
        return None
    try:
        value = int(score)
    except (ValueError, TypeError):
        return None

    if not 0 <= value <= 100:
        return None
    if value >= 80:
        return "HIGH"
    if value >= 50:
        return "MEDIUM"
    return "LOW"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file",
        default="/tmp/hisn_threatfox_test.json",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Save validated indicators to PostgreSQL",
    )
    args = parser.parse_args()

    if args.apply and (
        settings.hisn_auto_enforce
        or settings.hisn_enforcement_enabled
    ):
        raise SystemExit(
            "Disable automatic enforcement and policy writing first."
        )

    with open(args.file, encoding="utf-8") as handle:
        payload = json.load(handle)

    if payload.get("query_status") != "ok":
        raise SystemExit("ThreatFox response is not successful")

    records = payload.get("data")
    if not isinstance(records, list):
        raise SystemExit("Invalid ThreatFox data")

    validated = {}
    skipped = 0

    for item in records:
        if not isinstance(item, dict):
            skipped += 1
            continue

        if item.get("ioc_type") != "domain":
            skipped += 1
            continue

        score = confidence_label(item.get("confidence_level"))
        if score is None:
            skipped += 1
            continue

        try:
            domain = normalize_destination(item.get("ioc", ""))
            ipaddress.ip_address(domain)
            skipped += 1
            continue
        except ValueError:
            pass
        except (TypeError, AttributeError):
            skipped += 1
            continue

        validated[domain] = score

    print("Valid unique domains:", len(validated))
    print("Skipped records:", skipped)

    if not args.apply:
        print("DRY RUN: Database was not modified")
        return

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=7)

    inserted = 0
    updated = 0

    with SessionLocal() as db:
        for domain, confidence in validated.items():
            existing = db.scalar(
                select(ThreatIndicator).where(
                    ThreatIndicator.indicator_type == "DOMAIN",
                    ThreatIndicator.indicator_value == domain,
                    ThreatIndicator.source_name == SOURCE,
                )
            )

            if existing:
                existing.confidence_level = confidence
                existing.is_active = True
                existing.expires_at = expires
                existing.last_updated_at = now
                updated += 1
            else:
                db.add(ThreatIndicator(
                    indicator_type="DOMAIN",
                    indicator_value=domain,
                    source_name=SOURCE,
                    confidence_level=confidence,
                    expires_at=expires,
                    is_active=True,
                ))
                inserted += 1

        db.commit()

    print("Inserted:", inserted)
    print("Updated:", updated)
    print("Import completed successfully")


if __name__ == "__main__":
    main()
