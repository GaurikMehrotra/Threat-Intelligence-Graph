import json

from src.ingestion.pipeline import Ingestor
from src.normalization.entities import stable_id
from src.storage.sqlite import SQLiteStore


def iocs():
    return {
        "format": "ioc",
        "source_id": "publisher",
        "records": [
            {
                "id": "1",
                "entity_type": "domain",
                "value": "EXAMPLE.org.",
                "report_id": "report-1",
                "resolves_to": "192.0.2.1",
            },
            {"id": "2", "entity_type": "domain", "value": "example.org", "report_id": "report-2"},
            {"id": "3", "entity_type": "ipv4", "value": "invalid"},
        ],
    }


def test_partial_duplicate_import(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        runner = Ingestor(db)
        result = runner.ingest(iocs())
        assert result["status"] == "partial" and result["accepted"] == 2
        before = db.stats()
        runner.ingest(iocs())
        after = db.stats()
        assert before["evidence"] == after["evidence"] == 2
        assert before["edges"] == after["edges"]
        assert len(db.search("example.org")) == 1
        assert not db.search("invalid")
        assert db.db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_csv_and_json_equivalent(tmp_path):
    csv = tmp_path / "feed.csv"
    csv.write_text("id,entity_type,value\n1,domain,example.org\n2,ipv6,2001:db8::1\n")
    with SQLiteStore(tmp_path / "db") as db:
        assert Ingestor(db).ingest_file(csv, "csv-publisher")["accepted"] == 2
        p = tmp_path / "feed.json"
        p.write_text(json.dumps(iocs()))
        assert Ingestor(db).ingest_file(p)["accepted"] == 2
        assert len(db.search("example.org")) == 1


def sandbox():
    return {
        "format": "sandbox",
        "source_id": "sandbox-a",
        "report_id": "run-1",
        "entities": [
            {"id": "p", "entity_type": "process", "value": "sample.exe"},
            {"id": "ip", "entity_type": "ipv4", "value": "192.0.2.8"},
        ],
        "evidence": [
            {
                "id": "e",
                "evidence_type": "behavior",
                "description": "Network event: PID 10 connected to IP.",
            }
        ],
        "events": [
            {
                "id": "c",
                "source": "p",
                "target": "ip",
                "relationship_type": "COMMUNICATED_WITH",
                "evidence_ids": ["e"],
                "origin": "direct_observation",
            }
        ],
    }


def test_sandbox_extraction_and_scope(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        runner = Ingestor(db)
        assert runner.ingest(sandbox())["status"] == "complete"
        report = sandbox()
        report["report_id"] = "run-2"
        runner.ingest(report)
        assert len(db.search(entity_type="process")) == 2
        edges = db.db.execute(
            "SELECT count(*) FROM edges WHERE kind='COMMUNICATED_WITH'"
        ).fetchone()[0]
        assert edges == 2
        assert (
            db.db.execute("SELECT count(*) FROM edges WHERE kind='ATTRIBUTED_TO'").fetchone()[0]
            == 0
        )


def test_atomic_sandbox_failure_and_no_fabrication(tmp_path):
    doc = sandbox()
    doc["events"][0]["evidence_ids"] = ["absent"]
    with SQLiteStore(tmp_path / "db") as db:
        result = Ingestor(db).ingest(doc)
        assert result["status"] == "failed"
        assert db.stats()["nodes"] == 1  # source and import audit only
        assert db.stats()["evidence"] == 0


def attack():
    return {
        "type": "bundle",
        "catalog_version": "synthetic-v1",
        "source_id": "fixture-catalog",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--1",
                "spec_version": "2.1",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "spec_version": "2.1",
                "name": "Command interpreter",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Deprecated child",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--2",
                "target_ref": "attack-pattern--1",
            },
        ],
    }


def test_attack_catalog_and_supported_mapping(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        assert Ingestor(db).ingest(attack())["status"] == "complete"
        child = db.get_node(stable_id("node", "attack_technique", "T1059.001"))
        assert child.attributes["deprecated"] is True
        report = sandbox()
        report["entities"].append(
            {"id": "tech", "entity_type": "attack_technique", "value": "T1059"}
        )
        report["events"].append(
            {
                "id": "mapping",
                "source": "p",
                "target": "tech",
                "relationship_type": "MAPPED_TO_TECHNIQUE",
                "evidence_ids": ["e"],
            }
        )
        assert Ingestor(db).ingest(report)["status"] == "complete"
        report["evidence"][0]["evidence_type"] = "source_claim"
        report["events"][0]["origin"] = "source_reported"
        assert Ingestor(db).ingest(report)["status"] == "failed"


def test_cuckoo_does_not_infer_process_communications(tmp_path):
    doc = {
        "info": {"id": 1},
        "behavior": {"processes": [{"process_id": 9, "process_name": "x.exe"}]},
        "network": {
            "hosts": ["192.0.2.1"],
            "dns": [{"request": "example.org", "answers": [{"type": "A", "data": "192.0.2.1"}]}],
        },
    }
    with SQLiteStore(tmp_path / "db") as db:
        assert (
            Ingestor(db).ingest(doc, source_id="sandbox", adapter="cuckoo")["status"] == "complete"
        )
        assert (
            db.db.execute("SELECT count(*) FROM edges WHERE kind='COMMUNICATED_WITH'").fetchone()[0]
            == 0
        )
        assert (
            db.db.execute("SELECT count(*) FROM edges WHERE kind='RESOLVES_TO'").fetchone()[0] == 1
        )
