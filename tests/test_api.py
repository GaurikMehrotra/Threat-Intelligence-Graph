from fastapi.testclient import TestClient

from src.api.app import BODY_LIMIT, create_app
from src.ingestion.pipeline import Ingestor
from src.normalization.entities import stable_id
from src.storage.sqlite import SQLiteStore
from tests.test_ingestion import iocs


def test_api_queries_limits_and_xss_headers(tmp_path):
    path = str(tmp_path / "db")
    with SQLiteStore(path) as db:
        Ingestor(db).ingest(iocs())
    with TestClient(create_app(path)) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert client.get("/").status_code == 200
        assert "script-src 'self'" in client.get("/").headers["content-security-policy"]
        assert client.get("/static/app.js").status_code == 200
        nodes = client.get("/api/search", params={"value": "example.org"}).json()
        assert len(nodes) == 1
        node = nodes[0]["node_id"]
        graph = client.get("/api/neighborhood", params={"node": node}).json()
        assert graph["edges"]
        edge = client.get("/api/edges/" + graph["edges"][0]["edge_id"]).json()
        assert edge["evidence"] and "rationale" in edge["score"]
        assert (
            client.get("/api/neighborhood", params={"node": node, "depth": 100}).status_code == 422
        )
        assert client.get("/api/search", params={"limit": 100000}).status_code == 422
        assert client.get("/api/nodes/missing").status_code == 404
        assert (
            client.post("/api/ingest", json={"source_id": "x", "document": iocs()}).status_code
            == 403
        )
        assert client.get("/api/search", params={"value": "' OR 1=1 --"}).json() == []


def test_admin_auth_and_investigation_export(tmp_path):
    client = TestClient(create_app(str(tmp_path / "db"), admin_token="test-only-admin"))  # noqa: S106 -- synthetic test credential
    payload = {"source_id": "publisher", "document": iocs()}
    assert client.post("/api/ingest", json=payload).status_code == 401
    headers = {"Authorization": "Bearer test-only-admin"}
    response = client.post("/api/ingest", json=payload, headers=headers)
    assert response.status_code == 207
    seed = stable_id("node", "domain", "example.org")
    response = client.post(
        "/api/investigations",
        json={"identifier": "case", "title": "Example", "seeds": [seed]},
        headers=headers,
    )
    assert response.status_code == 201
    identifier = response.json()["node_id"]
    report = client.get(f"/api/investigations/{identifier}/export").json()
    assert report["evidence"]
    assert client.get(f"/api/investigations/{identifier}/export?format=md").text.startswith(
        "# Example"
    )
    bad = {"source_id": "x", "document": {}, "password": "not-printed"}
    response = client.post("/api/ingest", json=bad, headers=headers)
    assert response.status_code == 422 and "not-printed" not in response.text


def test_request_size_limit(tmp_path):
    client = TestClient(create_app(str(tmp_path / "db")))
    result = client.post(
        "/api/ingest", content=b"x" * (BODY_LIMIT + 1), headers={"Content-Type": "application/json"}
    )
    assert result.status_code == 413


def test_chunked_request_limit_without_content_length(tmp_path):
    client = TestClient(create_app(str(tmp_path / "db")))
    chunks = (b"x" * 1024 * 1024 for _ in range(9))
    response = client.post(
        "/api/ingest", content=chunks, headers={"Content-Type": "application/json"}
    )
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
