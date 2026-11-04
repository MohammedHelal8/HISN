"""Deterministic TI matching and explainable confidence-based response decisions."""
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from app.security_engine.log_parser import AccessRecord


@dataclass(frozen=True)
class Decision:
    action: str  # ALERT_ONLY, BLOCK_ELIGIBLE, EXCEPTION
    reason: str


def matches_indicator(destination: str, indicator_type: str, indicator_value: str) -> bool:
    try:
        ipaddress.ip_address(destination)
        return indicator_type == 'IP' and destination == str(ipaddress.ip_address(indicator_value))
    except ValueError:
        return indicator_type == 'DOMAIN' and (destination == indicator_value or destination.endswith('.' + indicator_value))


def indicator_usable(indicator, now: datetime | None = None) -> bool:
    current = now or datetime.now(timezone.utc)
    expiry = indicator.expires_at
    if expiry is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return bool(
        indicator.is_active
        and not getattr(indicator, 'admin_disabled', False)
        and (expiry is None or expiry > current)
    )


def exception_matches(destination: str, exceptions) -> bool:
    """Conservative policy: an exception for a parent domain protects its subdomains."""
    return any(matches_indicator(destination, row.target_type, row.target_value) for row in exceptions)


def response_decision(indicator, destination: str, exceptions, *, allowed: bool) -> Decision:
    if not indicator_usable(indicator) or not matches_indicator(destination, indicator.indicator_type, indicator.indicator_value):
        return Decision('ALERT_ONLY', 'Indicator is expired, inactive, or does not match')
    if exception_matches(destination, exceptions):
        return Decision('EXCEPTION', 'Approved allow/exception policy takes precedence')
    if indicator.confidence_level != 'HIGH':
        return Decision('ALERT_ONLY', f'{indicator.confidence_level} confidence requires manual review')
    if not allowed:
        return Decision('ALERT_ONLY', 'Automatic enforcement disabled by configuration')
    return Decision('BLOCK_ELIGIBLE', f'Validated HIGH confidence from {indicator.source_name}')
