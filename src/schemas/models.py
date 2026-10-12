from datetime import datetime, timezone
from typing import Any, Literal
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.normalization.entities import ENTITY_TYPES, normalize, stable_id

SCHEMA_VERSION = 1
Origin = Literal[
    "direct_observation",
    "source_reported",
    "deterministically_derived",
    "analyst_confirmed",
    "hypothesis",
]
ALL = frozenset(ENTITY_TYPES)
REPORTS = {"sandbox_report", "intelligence_report"}
INDICATORS = {"ipv4", "ipv6", "domain", "url", "file_hash"}
FILES = {"file", "malware_sample"}
# Each endpoint rule encodes a specific claim; co-occurrence is OBSERVED_IN only.
RELATIONSHIPS = {
    "RESOLVES_TO": ({"domain"}, {"ipv4", "ipv6"}, "Source records a DNS resolution at a time."),
    "CONTAINS": (
        REPORTS | FILES | {"investigation"},
        ALL,
        "Container explicitly includes an entity.",
    ),
    "OBSERVED_IN": (
        ALL - {"source"},
        REPORTS,
        "Entity appears in this report; no causal assertion.",
    ),
    "COMMUNICATED_WITH": (
        {"process", "malware_sample"},
        {"ipv4", "ipv6", "domain", "url"},
        "Observed network communication.",
    ),
    "DROPPED_FILE": ({"process", "malware_sample"}, FILES, "Observed creation of a file."),
    "SPAWNED_PROCESS": ({"process"}, {"process"}, "Observed process parent-child creation."),
    "MODIFIED_REGISTRY": (
        {"process", "malware_sample"},
        {"registry_key"},
        "Observed registry write.",
    ),
    "ASSOCIATED_WITH": (
        ALL,
        ALL,
        "Explicit source association; does not imply causality or attribution.",
    ),
    "MAPPED_TO_TECHNIQUE": (
        {"process", "malware_sample"} | REPORTS,
        {"attack_technique"},
        "Behavioral evidence supports an ATT&CK mapping.",
    ),
    "REPORTED_BY": (ALL - {"source"}, {"source"}, "Source published this entity or claim."),
    "PART_OF_CAMPAIGN": (
        INDICATORS | FILES | REPORTS | {"malware_family"},
        {"campaign"},
        "Explicit, evidenced campaign membership claim.",
    ),
    "ATTRIBUTED_TO": (
        {"campaign", "malware_family", "malware_sample"} | REPORTS,
        {"threat_actor"},
        "Explicit attribution claim, with source rationale.",
    ),
    "SUPPORTS": (REPORTS, ALL, "Report provides supporting information about this entity."),
    "CONTRADICTS": (REPORTS, ALL, "Report provides contrary information about this entity."),
    "TECHNIQUE_OF": (
        {"attack_technique"},
        {"attack_tactic"},
        "Official catalog tactic membership.",
    ),
    "SUBTECHNIQUE_OF": (
        {"attack_technique"},
        {"attack_technique"},
        "Official catalog sub-technique relationship.",
    ),
}


def now() -> datetime:
    return datetime.now(timezone.utc)


def check_time(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        raise ValueError("timestamps require timezone")
    return value


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = SCHEMA_VERSION

    @field_validator("*", mode="after")
    @classmethod
    def safe_values(cls, value: Any) -> Any:
        def check(v: Any, depth: int = 0) -> None:
            if depth > 12:
                raise ValueError("metadata nesting limit exceeded")
            if isinstance(v, dict):
                for key, item in v.items():
                    if re.search(
                        r"(^|_)(password|secret|token|api_key|authorization|credential)($|_)",
                        key,
                        re.I,
                    ):
                        raise ValueError("credential fields must be removed before import")
                    check(item, depth + 1)
            elif isinstance(v, (list, tuple)):
                if len(v) > 10000:
                    raise ValueError("metadata collection too large")
                for item in v:
                    check(item, depth + 1)
            elif isinstance(v, str) and len(v) > 16384:
                raise ValueError("text field too large")

        check(value)
        return value


class Node(Record):
    node_id: str
    entity_type: str
    canonical_value: str
    display_name: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)
    attributes: dict[str, Any] = Field(default_factory=dict)

    _time = field_validator("first_seen", "last_seen", "created_at", "updated_at")(check_time)

    @model_validator(mode="after")
    def identity(self):
        if normalize(self.entity_type, self.canonical_value) != self.canonical_value:
            raise ValueError("node value must be canonical")
        if self.node_id != stable_id("node", self.entity_type, self.canonical_value):
            raise ValueError("node ID does not match canonical identity")
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("invalid seen interval")
        return self

    @classmethod
    def create(cls, entity_type: str, value: str, **kwargs):
        canonical = normalize(entity_type, value)
        return cls(
            node_id=stable_id("node", entity_type, canonical),
            entity_type=entity_type,
            canonical_value=canonical,
            display_name=kwargs.pop("display_name", value),
            **kwargs,
        )


class Evidence(Record):
    evidence_id: str
    evidence_type: Literal[
        "observation", "source_claim", "behavior", "catalog", "analyst", "hypothesis"
    ]
    source_id: str
    source_record_id: str
    observation_time: datetime | None = None
    ingestion_time: datetime = Field(default_factory=now)
    description: str
    raw_reference: str
    integrity_hash: str | None = None
    limitations: list[str] = Field(default_factory=list)
    upstream_claim_id: str | None = None
    quality: float | None = Field(default=None, ge=0, le=1)

    _time = field_validator("observation_time", "ingestion_time")(check_time)

    @model_validator(mode="after")
    def identity(self):
        if self.evidence_id != stable_id("ev", self.source_id, self.source_record_id):
            raise ValueError("evidence identity mismatch")
        if self.integrity_hash and not re.fullmatch(r"[a-f0-9]{64}", self.integrity_hash):
            raise ValueError("integrity hash must be SHA256")
        if not self.source_record_id or not self.description:
            raise ValueError("evidence record and description are required")
        if self.raw_reference.startswith(("/", "file:", "\\")) or ".." in self.raw_reference.split(
            "/"
        ):
            raise ValueError("raw references must be opaque identifiers, not internal paths")
        return self


class Edge(Record):
    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    evidence_ids: list[str] = Field(min_length=1, max_length=1000)
    source_id: str
    relationship_origin: Origin
    confidence: float | None = Field(default=None, ge=0, le=1)
    confidence_rationale: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    created_at: datetime = Field(default_factory=now)
    status: Literal["active", "disputed", "rejected", "superseded"] = "active"
    rationale: str | None = None

    _time = field_validator("valid_from", "valid_until", "created_at")(check_time)

    @model_validator(mode="after")
    def identity(self):
        if self.relationship_type not in RELATIONSHIPS:
            raise ValueError("unsupported relationship")
        if self.valid_from and self.valid_until and self.valid_from > self.valid_until:
            raise ValueError("invalid validity interval")
        if self.confidence is not None and not self.confidence_rationale:
            raise ValueError("confidence needs a rationale")
        if self.relationship_type in {"ATTRIBUTED_TO", "PART_OF_CAMPAIGN"} and not self.rationale:
            raise ValueError("attribution and campaign claims need explicit rationale")
        expected = stable_id(
            "edge",
            self.source_node_id,
            self.target_node_id,
            self.relationship_type,
            self.source_id,
            self.relationship_origin,
            self.valid_from.isoformat() if self.valid_from else None,
            self.valid_until.isoformat() if self.valid_until else None,
            self.status,
        )
        if self.edge_id != expected:
            raise ValueError("edge identity mismatch")
        self.evidence_ids = sorted(set(self.evidence_ids))
        return self

    @classmethod
    def create(
        cls,
        source: str,
        target: str,
        relationship: str,
        source_id: str,
        origin: Origin,
        evidence_ids: list[str],
        **kwargs,
    ):
        fields = dict(
            source_node_id=source,
            target_node_id=target,
            relationship_type=relationship,
            source_id=source_id,
            relationship_origin=origin,
            evidence_ids=evidence_ids,
            **kwargs,
        )
        fields["edge_id"] = stable_id(
            "edge",
            source,
            target,
            relationship,
            source_id,
            origin,
            kwargs.get("valid_from").isoformat() if kwargs.get("valid_from") else None,
            kwargs.get("valid_until").isoformat() if kwargs.get("valid_until") else None,
            kwargs.get("status", "active"),
        )
        return cls(**fields)


def validate_endpoints(edge: Edge, source: Node, target: Node):
    allowed_source, allowed_target, _ = RELATIONSHIPS[edge.relationship_type]
    if source.entity_type not in allowed_source or target.entity_type not in allowed_target:
        raise ValueError("incompatible relationship endpoint types")
