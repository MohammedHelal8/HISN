import re
from datetime import datetime
from ipaddress import ip_address

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from app.schemas.common import (
    IndicatorType,
    ConfidenceLevel,
)


class ThreatIndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    indicator_value: str = Field(min_length=1, max_length=255)
    source_name: str = Field(min_length=1, max_length=150)
    confidence_level: ConfidenceLevel
    expires_at: datetime | None = None

    @field_validator("indicator_value")
    @classmethod
    def normalize_indicator_value(cls, value: str) -> str:
        value = value.strip().lower()

        if not value:
            raise ValueError("Indicator value cannot be empty")

        return value

    @field_validator("source_name")
    @classmethod
    def normalize_source_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Source name cannot be empty")

        return value

    @field_validator("indicator_value")
    @classmethod
    def validate_ip_format(cls, value: str, info):
        if info.data.get("indicator_type") == IndicatorType.IP:
            try:
                ip_address(value)
            except ValueError:
                raise ValueError("Invalid IP address")

        return value

    
    @field_validator("indicator_value")
    @classmethod
    def validate_domain_format(cls, value: str, info):
        if info.data.get("indicator_type") != IndicatorType.DOMAIN:
            return value

        if len(value) > 253:
            raise ValueError("Domain name is too long")

        labels = value.split(".")

        if len(labels) < 2:
            raise ValueError("Invalid domain format")

        label_pattern = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )

        for label in labels:
            if not label_pattern.fullmatch(label):
                raise ValueError("Invalid domain format")

        return value



class ThreatIndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    indicator_id: int
    indicator_type: IndicatorType
    indicator_value: str
    source_name: str
    confidence_level: ConfidenceLevel
    first_seen_at: datetime
    last_updated_at: datetime
    expires_at: datetime | None
    is_active: bool
