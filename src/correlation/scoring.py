"""Explainable heuristic scores, deliberately not probabilities or IOC risk."""

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from src.storage.sqlite import GraphStore


class ScoreConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_weight: float = Field(default=0.12, ge=0, le=0.3)
    contradiction_penalty: float = Field(default=0.2, ge=0, le=1)
    stale_days: int = Field(default=365, ge=1, le=36500)
    stale_penalty: float = Field(default=0.15, ge=0, le=1)


ORIGIN_WEIGHTS = {
    "direct_observation": 0.65,
    "source_reported": 0.4,
    "deterministically_derived": 0.55,
    "analyst_confirmed": 0.65,
    "hypothesis": 0.15,
}


class Scorer:
    def __init__(self, store: GraphStore, config: ScoreConfig | None = None):
        self.store, self.config = store, config or ScoreConfig()

    def score(self, edge_id: str, at: datetime | None = None):
        at = at or datetime.now(timezone.utc)
        if at.tzinfo is None:
            raise ValueError("scoring time requires timezone")
        selected = self.store.get_edge(edge_id)
        # Group the same semantic relationship, while preserving individual source claims.
        rows = self.store.matching_edges(
            selected.source_node_id, selected.target_node_id, selected.relationship_type, 1001
        )
        if len(rows) > 1000:
            return {
                "relationship_confidence": None,
                "rationale": ["Claim limit exceeded; refine the investigation."],
                "indicator_risk": None,
                "investigation_priority": None,
            }
        claims = rows
        active = [e for e in claims if e.status in {"active", "disputed"}]
        evidence = {ev: self.store.get_evidence(ev) for e in active for ev in e.evidence_ids}
        rationale = []
        # Unidentified upstream independence never earns a source-count bonus.
        upstream = {e.upstream_claim_id for e in evidence.values() if e.upstream_claim_id}
        qualities = [e.quality for e in evidence.values() if e.quality is not None]
        quality = sum(qualities) / len(qualities) if qualities else None
        rationale.append(
            f"Evidence quality: {quality if quality is not None else 'unknown'} (source-supplied rubric, not calibrated)."
        )
        rationale.append(
            f"{len(evidence)} unique evidence records; {len(upstream)} explicitly identified upstream claim groups."
        )
        if selected.status in {"rejected", "superseded"}:
            rationale.append(
                "Selected claim is rejected or superseded; no current confidence assigned."
            )
            score = None
        elif not qualities:
            rationale.append("Evidence quality is not supplied; confidence remains unknown.")
            score = None
        else:
            score = ORIGIN_WEIGHTS[selected.relationship_origin] * quality
            rationale.append(
                f"Origin weight: {selected.relationship_origin}={ORIGIN_WEIGHTS[selected.relationship_origin]}."
            )
            bonus = min(0.24, max(0, len(upstream) - 1) * self.config.source_weight)
            score += bonus
            rationale.append(
                f"Upstream independence bonus={bonus:.2f}; copied or unspecified claims add no bonus."
            )
            times = [e.observation_time for e in evidence.values() if e.observation_time]
            if times and (at - max(times)).days > self.config.stale_days:
                score -= self.config.stale_penalty
                rationale.append(
                    f"Latest known observation is stale; penalty={self.config.stale_penalty}."
                )
            if not times:
                rationale.append("Observation time is unknown; temporal relevance is unassessed.")
            if any(e.limitations for e in evidence.values()):
                score -= 0.1
                rationale.append("Evidence limitations are recorded; conservative penalty=0.10.")
            if selected.valid_until and selected.valid_until < at:
                score -= self.config.stale_penalty
                rationale.append("Selected relationship validity has expired.")
            if any(e.status == "disputed" for e in claims):
                score -= self.config.contradiction_penalty
                rationale.append(
                    "An explicitly disputed claim is preserved; contradiction penalty applied."
                )
            score = round(min(1, max(0, score)), 3)
        contrary = self.store.matching_edges(
            target=selected.target_node_id, kind="CONTRADICTS", limit=100
        )
        contrary = [e for e in contrary if e.status in {"active", "disputed"}]
        if contrary:
            rationale.append(
                "Entity-level contrary evidence exists; inspect it before interpreting this relationship."
            )
            if score is not None:
                score = round(max(0, score - self.config.contradiction_penalty), 3)
        if selected.relationship_origin == "hypothesis":
            rationale.append("Hypothesis remains a hypothesis regardless of heuristic score.")
        if not upstream:
            rationale.append(
                "Source independence is unknown. Supply upstream claim IDs only when known."
            )
        return {
            "edge_id": edge_id,
            "relationship_confidence": score,
            "evidence_quality": quality,
            "indicator_risk": None,
            "investigation_priority": None,
            "rationale": rationale,
            "contrary_edge_ids": [e.edge_id for e in contrary],
            "source_supplied_confidence": selected.confidence,
            "source_confidence_rationale": selected.confidence_rationale,
            "interpretation": "Heuristic confidence is not a calibrated probability or indicator risk.",
        }
