"""Strict offline interchange contracts. Fields outside these contracts are rejected."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from src.schemas.models import Origin, Record, check_time


class EntityInput(Record):
    id: str = Field(min_length=1, max_length=256)
    entity_type: str
    value: str
    display_name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    _time = field_validator("first_seen", "last_seen")(check_time)


class EvidenceInput(Record):
    id: str = Field(min_length=1, max_length=256)
    evidence_type: Literal[
        "observation", "source_claim", "behavior", "catalog", "analyst", "hypothesis"
    ]
    description: str = Field(min_length=1)
    observation_time: datetime | None = None
    limitations: list[str] = Field(default_factory=list)
    upstream_claim_id: str | None = None
    quality: float | None = Field(default=None, ge=0, le=1)
    _time = field_validator("observation_time")(check_time)


class ClaimInput(Record):
    id: str = Field(min_length=1, max_length=256)
    source: str
    target: str
    relationship_type: str
    evidence_ids: list[str] = Field(min_length=1)
    origin: Origin = "source_reported"
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    confidence_rationale: str | None = None
    rationale: str | None = None
    status: Literal["active", "disputed", "rejected", "superseded"] = "active"
    _time = field_validator("valid_from", "valid_until")(check_time)


class GraphInput(Record):
    format: Literal["graph"]
    nodes: list[EntityInput] = Field(max_length=10000)
    evidence: list[EvidenceInput] = Field(max_length=20000)
    edges: list[ClaimInput] = Field(max_length=20000)


class IOCInput(Record):
    id: str = Field(min_length=1, max_length=256)
    entity_type: Literal["ipv4", "ipv6", "domain", "url", "file_hash"]
    value: str
    description: str = "Source listed this indicator; maliciousness is not established."
    observation_time: datetime | None = None
    report_id: str | None = None
    upstream_claim_id: str | None = None
    quality: float | None = Field(default=None, ge=0, le=1)
    limitations: list[str] = Field(default_factory=list)
    resolves_to: str | None = None
    _time = field_validator("observation_time")(check_time)


class SandboxInput(Record):
    format: Literal["sandbox"]
    report_id: str = Field(min_length=1, max_length=256)
    entities: list[EntityInput] = Field(max_length=10000)
    events: list[ClaimInput] = Field(max_length=20000)
    evidence: list[EvidenceInput] = Field(max_length=20000)
