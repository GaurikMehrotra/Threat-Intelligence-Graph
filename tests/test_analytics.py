from datetime import datetime, timezone
import pytest

from src.analytics.queries import GraphQueries
from src.correlation.scoring import Scorer
from src.normalization.entities import stable_id
from src.schemas.models import Edge, Evidence, Node
from src.storage.sqlite import SQLiteStore


@pytest.fixture
def graph(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        source = Node.create("source", "publisher")
        db.put_node(source)
        nodes = [Node.create("domain", f"node-{i}.example") for i in range(6)]
        for n in nodes:
            db.put_node(n)
        ev = Evidence(
            evidence_id=stable_id("ev", source.node_id, "observation"),
            evidence_type="source_claim",
            source_id=source.node_id,
            source_record_id="observation",
            description="Explicit associations",
            raw_reference="fixture:association",
            quality=0.8,
        )
        db.put_evidence(ev)
        edges = []
        for a, b in [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4)]:
            edge = Edge.create(
                nodes[a].node_id,
                nodes[b].node_id,
                "ASSOCIATED_WITH",
                source.node_id,
                "source_reported",
                [ev.evidence_id],
            )
            db.put_edge(edge)
            edges.append(edge)
        yield db, nodes, edges


def test_neighborhood_cycles_bounds_and_shortest_path(graph):
    db, n, edges = graph
    q = GraphQueries(db)
    assert len(q.neighborhood(n[0].node_id, 1)["nodes"]) == 3
    assert len(q.neighborhood(n[0].node_id, 2)["nodes"]) == 4
    assert q.neighborhood(n[0].node_id, 3, 2)["truncated"]
    path = q.path(n[0].node_id, n[4].node_id)
    assert path["found"] and len(path["edge_ids"]) == 3
    assert not q.path(n[0].node_id, n[5].node_id)["found"]
    assert not q.path(n[0].node_id, n[4].node_id, depth=2)["found"]
    with pytest.raises(ValueError):
        q.neighborhood(n[0].node_id, depth=7)
    with pytest.raises(ValueError):
        q.neighborhood(n[0].node_id, entity_types=["invalid"])


def test_shared_components_and_degrees(graph):
    db, n, _ = graph
    q = GraphQueries(db)
    common = q.shared_neighbors([n[0].node_id, n[1].node_id])
    assert [x["node_id"] for x in common["nodes"]] == [n[2].node_id]
    summary = q.summary()
    assert sorted(len(c) for c in summary["components"]) == [1, 1, 5]  # isolated source and node
    assert summary["degrees"][n[2].node_id] == 3


def test_scoring_unknown_and_duplicates(graph):
    db, _, edges = graph
    scorer = Scorer(db)
    before = scorer.score(edges[0].edge_id)
    db.put_edge(edges[0])
    assert scorer.score(edges[0].edge_id) == before
    assert before["relationship_confidence"] == 0.32
    assert before["indicator_risk"] is None
    assert "not a calibrated" in before["interpretation"]


def test_temporal_filter_unknown(graph):
    db, n, _ = graph
    q = GraphQueries(db)
    t = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert len(q.neighborhood(n[0].node_id, after=t, include_unknown=False)["nodes"]) == 1
    assert len(q.neighborhood(n[0].node_id, after=t, include_unknown=True)["nodes"]) == 3


def test_contradictory_attribution_is_preserved(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        source = Node.create("source", "reporter")
        campaign = Node.create("campaign", "reporter:campaign-id")
        actor = Node.create("threat_actor", "reporter:actor-id")
        for node in (source, campaign, actor):
            db.put_node(node)
        for status, record in [("active", "claim"), ("disputed", "counterclaim")]:
            ev = Evidence(
                evidence_id=stable_id("ev", source.node_id, record),
                evidence_type="source_claim",
                source_id=source.node_id,
                source_record_id=record,
                description=record,
                raw_reference="fixture:" + record,
                quality=0.8,
            )
            db.put_evidence(ev)
            edge = Edge.create(
                campaign.node_id,
                actor.node_id,
                "ATTRIBUTED_TO",
                source.node_id,
                "source_reported",
                [ev.evidence_id],
                status=status,
                rationale="Explicit source claim.",
            )
            db.put_edge(edge)
        assert db.stats()["edges"] == 2
        assert Scorer(db).score(edge.edge_id)["relationship_confidence"] == 0.12
        assert db.stats()["evidence"] == 2
