
from enum import Enum
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, Field
from enum import Enum



class IndicatorType(str, Enum):
    DOMAIN = "DOMAIN"
    IP = "IP"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class IncidentStatus(str, Enum):
    NEW = "new"
    UNDER_REVIEW = "under_review"
    CLOSED = "closed"


class ServiceStatus(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class NormalizedLogEntry(BaseModel):
    source: str
    activity_at: datetime | None = None
    client_ip: IPv4Address | IPv6Address | None = None
    destination: str | None = None
    filtering_decision: str | None = None
    file_identity: str
    line_offset: int = Field(ge=0)


class DetectionResult(BaseModel):
    detected: bool
    detection_rule: str | None = None
    indicator_id: int | None = None
    evidence: dict = Field(default_factory=dict)
