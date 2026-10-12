from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from src.api.app import create_app
from src.analytics.queries import GraphQueries
from src.correlation.scoring import Scorer
from src.ingestion.pipeline import Ingestor, read_input
from src.normalization.entities import stable_id
from src.schemas.models import Edge, Evidence, Node
from src.storage.sqlite import SQLiteStore
from tests.test_ingestion import attack, sandbox


def test_expected_extraction_precision_recall_and_provenance(tmp_path):
    fixture = Path(__file__).resolve().parents[1] / "data/fixtures/sandbox.json"
    document = json.loads(fixture.read_text())
    expected = {(c["source"], c["target"], c["relationship_type"]) for c in document["events"]}
    with SQLiteStore(tmp_path / "db") as db:
        runner = Ingestor(db)
        runner.ingest(attack())
        result = runner.ingest(document)
        assert result["status"] == "complete"
        rows = db.db.execute(
            "SELECT body FROM edges WHERE kind NOT IN ('OBSERVED_IN','REPORTED_BY','TECHNIQUE_OF','SUBTECHNIQUE_OF')"
        ).fetchall()
        edges = [Edge.model_validate_json(r[0]) for r in rows]
        source_id = stable_id("node", "source", document["source_id"])
        aliases = {}
        for item in document["entities"]:
            value = (
                stable_id("scoped", source_id, document["report_id"], item["id"])
                if item["entity_type"] in {"process", "file", "registry_key"}
                else item["value"]
            )
            aliases[stable_id("node", item["entity_type"], value)] = item["id"]
        actual = {
            (aliases[e.source_node_id], aliases[e.target_node_id], e.relationship_type)
            for e in edges
        }
        assert actual == expected
        assert len(actual & expected) / len(actual) == 1.0
        assert len(actual & expected) / len(expected) == 1.0
        assert all(
            e.evidence_ids and all(db.get_evidence(ev) for ev in e.evidence_ids) for e in edges
        )


def test_untrusted_values_never_executed_or_rendered_as_html(tmp_path):
    document = sandbox()
    marker = tmp_path / "should-not-exist"
    document["entities"][0]["value"] = f"<img src=x onerror=alert(1)> $(touch {marker})"
    with SQLiteStore(tmp_path / "db") as db:
        assert Ingestor(db).ingest(document)["status"] == "complete"
        process = db.search(entity_type="process")[0]
        assert "<img" in process.display_name
    assert not marker.exists()
    js = (Path(__file__).resolve().parents[1] / "frontend/app.js").read_text()
    assert "innerHTML" not in js and "textContent" in js


def test_credentials_and_timezone_rejected():
    with pytest.raises(ValueError):
        Node.create("url", "https://example.org/?api_key=do-not-store")
    with pytest.raises(ValidationError):
        Node.create("domain", "example.org", attributes={"nested": {"password": "do-not-store"}})
    with pytest.raises(ValidationError):
        Node.create("domain", "example.org", first_seen=datetime(2025, 1, 1))


def test_unknown_confidence_and_source_copies(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        doc = sandbox()
        Ingestor(db).ingest(doc)
        e = db.db.execute("SELECT id FROM edges WHERE kind='COMMUNICATED_WITH'").fetchone()[0]
        assert Scorer(db).score(e)["relationship_confidence"] is None
        doc["evidence"][0].update(quality=0.8, upstream_claim_id="one-upstream-claim")
        Ingestor(db).ingest(doc)
        before = Scorer(db).score(e)["relationship_confidence"]
        doc["source_id"] = "republication"
        # Shared canonical IOC relationship across source publishers.
        graph = {
            "format": "graph",
            "source_id": "first",
            "nodes": [
                {"id": "a", "entity_type": "domain", "value": "a.example"},
                {"id": "b", "entity_type": "domain", "value": "b.example"},
            ],
            "evidence": [
                {
                    "id": "ev",
                    "evidence_type": "source_claim",
                    "description": "Copied upstream claim",
                    "quality": 0.8,
                    "upstream_claim_id": "upstream-1",
                }
            ],
            "edges": [
                {
                    "id": "claim",
                    "source": "a",
                    "target": "b",
                    "relationship_type": "ASSOCIATED_WITH",
                    "evidence_ids": ["ev"],
                }
            ],
        }
        Ingestor(db).ingest(graph)
        edge = db.db.execute("SELECT id FROM edges WHERE kind='ASSOCIATED_WITH'").fetchone()[0]
        score = Scorer(db).score(edge)["relationship_confidence"]
        graph["source_id"] = "second"
        Ingestor(db).ingest(graph)
        assert Scorer(db).score(edge)["relationship_confidence"] == score
        assert before is not None


def test_source_delimiter_collision_cannot_merge_processes(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        first = sandbox()
        first.update(source_id="a:b", report_id="c")
        second = sandbox()
        second.update(source_id="a", report_id="b:c")
        Ingestor(db).ingest(first)
        Ingestor(db).ingest(second)
        assert len(db.search(entity_type="process")) == 2


def test_temporal_intervals_and_confidence_rationale():
    with pytest.raises(ValidationError):
        Edge.create("a", "b", "ASSOCIATED_WITH", "s", "hypothesis", ["e"], confidence=0.7)
    with pytest.raises(ValidationError):
        Edge.create("a", "b", "ATTRIBUTED_TO", "s", "source_reported", ["e"])
    with pytest.raises(ValidationError):
        Edge.create(
            "a",
            "b",
            "ASSOCIATED_WITH",
            "s",
            "hypothesis",
            ["e"],
            valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )


def test_high_degree_neighborhood_is_bounded(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        source = Node.create("source", "star-fixture")
        root = Node.create("domain", "root.example")
        db.put_node(source)
        db.put_node(root)
        ev = Evidence(
            evidence_id=stable_id("ev", source.node_id, "star"),
            evidence_type="source_claim",
            source_id=source.node_id,
            source_record_id="star",
            description="Synthetic star",
            raw_reference="fixture:star",
        )
        db.put_evidence(ev)
        with db.transaction():
            for i in range(120):
                node = Node.create("domain", f"n{i}.example")
                db.put_node(node)
                db.put_edge(
                    Edge.create(
                        root.node_id,
                        node.node_id,
                        "ASSOCIATED_WITH",
                        source.node_id,
                        "source_reported",
                        [ev.evidence_id],
                    )
                )
        result = GraphQueries(db).neighborhood(root.node_id, 6, limit=25)
        assert len(result["nodes"]) == 25 and result["truncated"]
        assert len(result["edges"]) == 24


def test_file_symlink_rejected_and_error_payload_redacted(tmp_path):
    actual = tmp_path / "doc.json"
    actual.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(actual)
    with pytest.raises(ValueError):
        read_input(link)
    client = TestClient(create_app(str(tmp_path / "db")))
    response = client.get("/api/neighborhood", params={"node": "secret-value-should-not-echo"})
    assert response.status_code == 422 and "secret-value-should-not-echo" not in response.text


def test_older_catalog_metadata_and_evidence_remain_available(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        runner = Ingestor(db)
        doc = attack()
        runner.ingest(doc)
        before = db.stats()["evidence"]
        doc["catalog_version"] = "synthetic-v2"
        doc["objects"][1]["name"] = "Changed catalog name"
        runner.ingest(doc)
        technique = db.get_node(stable_id("node", "attack_technique", "T1059"))
        assert technique.attributes["catalog_versions"] == ["synthetic-v1", "synthetic-v2"]
        assert db.stats()["evidence"] > before
        assert technique.attributes["variations"]["catalog_hash"]


def test_malformed_vendor_records_report_failure_instead_of_crashing(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        result = Ingestor(db).ingest({"info": []}, source_id="broken-report", adapter="cuckoo")
        assert result["status"] == "failed"
        doc = attack()
        doc["objects"][1]["external_references"] = ["invalid"]
        result = Ingestor(db).ingest(doc)
        assert result["status"] == "partial" and result["failed"] >= 1


def test_hypotheses_cannot_be_promoted_without_new_evidence(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        source = Node.create("source", "researcher")
        a, b = Node.create("domain", "a.example"), Node.create("domain", "b.example")
        for n in (source, a, b):
            db.put_node(n)
        ev = Evidence(
            evidence_id=stable_id("ev", source.node_id, "hypothesis"),
            evidence_type="hypothesis",
            source_id=source.node_id,
            source_record_id="hypothesis",
            description="Unconfirmed idea",
            raw_reference="fixture:idea",
        )
        db.put_evidence(ev)
        hypothesis = Edge.create(
            a.node_id, b.node_id, "ASSOCIATED_WITH", source.node_id, "hypothesis", [ev.evidence_id]
        )
        db.put_edge(hypothesis)
        with pytest.raises(ValueError):
            db.put_edge(
                Edge.create(
                    a.node_id,
                    b.node_id,
                    "ASSOCIATED_WITH",
                    source.node_id,
                    "source_reported",
                    [ev.evidence_id],
                )
            )
        with pytest.raises(ValueError):
            db.put_edge(
                Edge.create(
                    a.node_id,
                    b.node_id,
                    "ASSOCIATED_WITH",
                    source.node_id,
                    "analyst_confirmed",
                    [ev.evidence_id],
                )
            )
        assert db.stats()["edges"] == 1 and db.get_evidence(ev.evidence_id)
