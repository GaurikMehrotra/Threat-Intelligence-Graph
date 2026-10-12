import pytest
from pydantic import ValidationError

from src.schemas.models import Edge, Evidence, Node
from src.normalization.entities import stable_id
from src.storage.sqlite import SQLiteStore


@pytest.fixture
def store(tmp_path):
    with SQLiteStore(tmp_path / "graph.sqlite3") as db:
        yield db


def evidence(db, source="fixture", record="record"):
    s = Node.create("source", source)
    db.put_node(s)
    e = Evidence(
        evidence_id=stable_id("ev", s.node_id, record),
        evidence_type="observation",
        source_id=s.node_id,
        source_record_id=record,
        description="DNS observation",
        raw_reference="fixture:record",
    )
    db.put_evidence(e)
    return s, e


def test_normalization_and_dedup(store):
    one = Node.create("domain", "EXAMPLE.org.")
    two = Node.create("domain", "example.org")
    assert one.node_id == two.node_id
    store.put_node(one)
    store.put_node(two)
    assert store.stats()["nodes"] == 1
    assert Node.create("ipv6", "2001:0db8::1").canonical_value == "2001:db8::1"
    assert Node.create("url", "HTTPS://Example.org:443").canonical_value == "https://example.org/"
    assert (
        Node.create("process", "report1:1").node_id != Node.create("process", "report2:1").node_id
    )


def test_edge_integrity_and_persistence(tmp_path):
    path = tmp_path / "db"
    with SQLiteStore(path) as db:
        s, ev = evidence(db)
        domain, ip = Node.create("domain", "example.org"), Node.create("ipv4", "192.0.2.1")
        db.put_node(domain)
        db.put_node(ip)
        edge = Edge.create(
            domain.node_id,
            ip.node_id,
            "RESOLVES_TO",
            s.node_id,
            "direct_observation",
            [ev.evidence_id],
        )
        db.put_edge(edge)
        db.put_edge(edge)
        assert db.stats()["edges"] == 1
    with SQLiteStore(path) as db:
        assert db.get_edge(edge.edge_id).evidence_ids == [ev.evidence_id]
        assert db.db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_missing_evidence_and_wrong_endpoints(store):
    s, ev = evidence(store)
    a = Node.create("domain", "example.org")
    b = Node.create("ipv4", "192.0.2.1")
    store.put_node(a)
    store.put_node(b)
    with pytest.raises(ValidationError):
        Edge.create(a.node_id, b.node_id, "RESOLVES_TO", s.node_id, "hypothesis", [])
    with pytest.raises(KeyError):
        store.put_edge(
            Edge.create(a.node_id, b.node_id, "RESOLVES_TO", s.node_id, "hypothesis", ["missing"])
        )
    with pytest.raises(ValueError, match="endpoint"):
        store.put_edge(
            Edge.create(
                b.node_id,
                a.node_id,
                "RESOLVES_TO",
                s.node_id,
                "direct_observation",
                [ev.evidence_id],
            )
        )


def test_rollback_and_immutable_evidence(store):
    with pytest.raises(ValueError), store.transaction():
        store.put_node(Node.create("domain", "example.org"))
        raise ValueError("abort")
    assert store.stats()["nodes"] == 0
    _, ev = evidence(store)
    with pytest.raises(ValueError, match="immutable"):
        store.put_evidence(ev.model_copy(update={"description": "changed"}))


def test_future_schema_rejected(tmp_path):
    path = tmp_path / "db"
    with SQLiteStore(path) as db:
        db.db.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="newer"):
        SQLiteStore(path)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ipv4", "999.1.1.1"),
        ("domain", "bad domain"),
        ("url", "https://user:password@example.org"),
        ("file_hash", "xxx"),
        ("unknown", "x"),
    ],
)
def test_invalid_entities(kind, value):
    with pytest.raises(ValueError):
        Node.create(kind, value)


def test_storage_revalidates_unchecked_model_copies(store):
    node = Node.create("domain", "example.org")
    tampered = node.model_copy(update={"canonical_value": "other.example"})
    with pytest.raises(ValidationError):
        store.put_node(tampered)
    assert store.stats()["nodes"] == 0
