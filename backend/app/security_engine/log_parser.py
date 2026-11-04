"""Strict parsing of two documented HISN-supported access-log layouts.

E2Guardian (whitespace-delimited): DATE TIME USER CLIENT_IP URL ACTION HTTP_STATUS ...
Squid (standard): EPOCH_DURATION CLIENT_IP STATUS SIZE METHOD URL ...
Any alternative E2Guardian logging format must have an explicit parser added;
malformed/unrecognized log lines are not guessed into security events.
"""
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from app.core.config import settings


@dataclass(frozen=True)
class AccessRecord:
    activity_at: datetime
    client_ip: str
    destination: str
    action: str
    source: str
    evidence: str


def normalize_destination(url: str) -> str:
    """Normalize host only; never resolve hostnames or guess paths as domains."""
    value = url.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("Empty or invalid destination")
    if '://' not in value:
        if '/' in value or '@' in value or '?' in value:
            raise ValueError("Invalid destination")
        value = 'http://' + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
        raise ValueError("Only HTTP(S) destinations supported")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not accepted")
    host = parsed.hostname.rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode('idna').decode('ascii')
        if len(host) > 253 or not re.fullmatch(r'[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+', host):
            raise ValueError("Invalid domain")
        if any(len(p) > 63 for p in host.split('.')):
            raise ValueError("Invalid domain length")
        return host



def parse_access_log(line: str) -> AccessRecord | None:
    """Parse supported Squid and E2Guardian access-log layouts."""
    parts = line.strip().split()
    if len(parts) < 6:
        return None

    methods = {
        "GET", "POST", "HEAD", "PUT",
        "DELETE", "OPTIONS", "CONNECT", "PATCH",
    }

    try:
        # Epoch timestamp shared by Squid and E2Guardian layouts.
        if re.fullmatch(r"\d{10}(?:\.\d{1,6})?", parts[0]):
            moment = datetime.fromtimestamp(
                float(parts[0]), tz=timezone.utc
            )

            # E2Guardian: EPOCH CLIENT_IP URL METHOD HTTP_STATUS ...
            if (
                len(parts) >= 6
                and parts[3].upper() in methods
                and re.fullmatch(r"\d{3}", parts[4])
            ):
                client = str(ipaddress.ip_address(parts[1]))
                destination = normalize_destination(parts[2])

                return AccessRecord(
                    activity_at=moment,
                    client_ip=client,
                    destination=destination,
                    action=parts[3].upper(),
                    source="e2guardian",
                    evidence=(
                        f"{moment.isoformat()} {client} "
                        f"{destination} method={parts[3].upper()} "
                        f"status={parts[4]} source=e2guardian"
                    ),
                )

            # Squid: EPOCH DURATION CLIENT_IP STATUS SIZE METHOD URL
            if (
                len(parts) >= 7
                and parts[1].isdigit()
                and parts[5].upper() in methods
            ):
                client = str(ipaddress.ip_address(parts[2]))
                destination = normalize_destination(parts[6])

                return AccessRecord(
                    activity_at=moment,
                    client_ip=client,
                    destination=destination,
                    action=parts[3],
                    source="squid",
                    evidence=(
                        f"{moment.isoformat()} {client} "
                        f"{destination} {parts[3]} source=squid"
                    ),
                )

            return None

        # Legacy E2Guardian:
        # DATE TIME USER CLIENT_IP URL ACTION HTTP_STATUS ...
        if not re.fullmatch(r"\d{4}[./-]\d{2}[./-]\d{2}", parts[0]):
            return None

        moment = (
            datetime.fromisoformat(
                parts[0].replace(".", "-") + "T" + parts[1]
            )
            .replace(tzinfo=ZoneInfo(settings.hisn_log_timezone))
            .astimezone(timezone.utc)
        )

        client = str(ipaddress.ip_address(parts[3]))
        destination = normalize_destination(parts[4])

        if parts[5].upper() not in methods:
            return None

        return AccessRecord(
            activity_at=moment,
            client_ip=client,
            destination=destination,
            action=parts[5].upper(),
            source="e2guardian",
            evidence=(
                f"{moment.isoformat()} {client} "
                f"{destination} {parts[5].upper()} source=e2guardian"
            ),
        )

    except (
        ValueError,
        OverflowError,
        UnicodeError,
        IndexError,
        ZoneInfoNotFoundError,
    ):
        return None
