
from datetime import datetime, timezone
from ipaddress import ip_address
from math import isfinite
from typing import Literal
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class SecurityEvent(BaseModel):
    """Validated network security event."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    schema_version: Literal["1.0"] = "1.0"
    event_type: Literal["NETWORK_FLOW"] = "NETWORK_FLOW"

    observed_at: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | int | None = None

    features: dict[str, float] = Field(min_length=1)

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value):
        if value is not None and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc) if value else value

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value):
        if value is not None:
            return str(ip_address(value))
        return value

    @field_validator("features")
    @classmethod
    def validate_features(cls, value):
        if not value:
            raise ValueError("features cannot be empty")

        for name, number in value.items():
            if not name.strip():
                raise ValueError("feature names cannot be empty")
            if not isfinite(number):
                raise ValueError(
                    f"Feature '{name}' must be finite"
                )

        return value


class DatasetTrainingRecord(BaseModel):
    """Offline training record; never use its label as a model feature."""

    model_config = ConfigDict(extra="forbid")

    features: dict[str, float] = Field(min_length=1)
    dataset_label: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_training_record(self):
        SecurityEvent.validate_features(self.features)
        return self


class DetectionResult(BaseModel):
    """Output produced by the detection pipeline."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    predicted_label: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    risk_score: float | None = Field(default=None, ge=0, le=100)
    incident_status: Literal[
        "OPEN", "INVESTIGATING", "RESOLVED"
    ] = "OPEN"
