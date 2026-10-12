"""Local analyst API. Read endpoints by default; writes require explicit admin token."""

from contextlib import contextmanager
from datetime import datetime
import hmac
import os
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field

from src.analytics.queries import GraphQueries
from src.correlation.scoring import Scorer
from src.ingestion.pipeline import Ingestor
from src.reporting.reports import create_investigation, investigation_report, to_markdown
from src.schemas.models import Record, RELATIONSHIPS
from src.normalization.entities import ENTITY_TYPES
from src.storage.sqlite import SQLiteStore

BODY_LIMIT = 8 * 1024 * 1024
ID = Annotated[str, Query(pattern=r"^node_[a-f0-9]{64}$")]


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            if int(headers.get(b"content-length", b"0")) > BODY_LIMIT:
                await JSONResponse({"detail": "request too large"}, status_code=413)(
                    scope, receive, send
                )
                return
        except ValueError:
            await JSONResponse({"detail": "invalid content length"}, status_code=400)(
                scope, receive, send
            )
            return
        # Buffer at most the limit before downstream JSON parsing, including chunked requests.
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > BODY_LIMIT:
                await JSONResponse({"detail": "request too large"}, status_code=413)(
                    scope, receive, send
                )
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class ImportRequest(Record):
    source_id: str = Field(min_length=1, max_length=256)
    adapter: str | None = None
    catalog_version: str | None = None
    document: dict


class InvestigationRequest(Record):
    identifier: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=256)
    seeds: list[str] = Field(min_length=1, max_length=20)
    depth: int = Field(default=2, ge=0, le=6)


def create_app(database="local/graph.sqlite3", admin_token=None):
    app = FastAPI(title="Threat Intelligence Graph", version="0.1.0")
    app.add_middleware(BodyLimitMiddleware)
    token = admin_token if admin_token is not None else os.environ.get("TIG_ADMIN_TOKEN")
    db_path = Path(database)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with SQLiteStore(database):
        pass

    @contextmanager
    def store():
        with SQLiteStore(database) as db:
            yield db

    def admin(authorization: Annotated[str | None, Header()] = None):
        if not token:
            raise HTTPException(
                403, "Administrative writes are disabled; use CLI or configure TIG_ADMIN_TOKEN."
            )
        expected = "Bearer " + token
        if not authorization or not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(
                401, "Admin authentication required", headers={"WWW-Authenticate": "Bearer"}
            )

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": "invalid input or relationship semantics"}, status_code=422)

    @app.exception_handler(RecursionError)
    async def excessive_nesting(request, exc):
        return JSONResponse({"detail": "input nesting exceeds parser capacity"}, status_code=422)

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": "entity or evidence not found"}, status_code=404)

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def validation(request, exc):
        return JSONResponse(
            {"detail": [{"field": list(e["loc"]), "type": e["type"]} for e in exc.errors()][:20]},
            status_code=422,
        )

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        with store() as db:
            check = db.integrity_check()
            return {"status": "ok" if check else "degraded", "schema_version": 1}

    @app.get("/api/schema")
    def schema():
        return {
            "entity_types": sorted(ENTITY_TYPES),
            "relationships": {
                k: {"sources": sorted(v[0]), "targets": sorted(v[1]), "semantics": v[2]}
                for k, v in RELATIONSHIPS.items()
            },
        }

    @app.get("/api/search")
    def search(
        value: str = Query(default="", max_length=4096),
        entity_type: str | None = None,
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1000000),
    ):
        with store() as db:
            return [n.model_dump(mode="json") for n in db.search(value, entity_type, limit, offset)]

    @app.get("/api/nodes/{node_id}")
    def node(node_id: str):
        with store() as db:
            return db.get_node(node_id).model_dump(mode="json")

    @app.get("/api/neighborhood")
    def neighborhood(
        node: ID,
        depth: int = Query(default=1, ge=0, le=6),
        limit: int = Query(default=100, ge=1, le=1000),
        entity_type: Annotated[list[str] | None, Query()] = None,
        relationship_type: Annotated[list[str] | None, Query()] = None,
        after: datetime | None = None,
        before: datetime | None = None,
        include_unknown: bool = True,
        include_inactive: bool = False,
    ):
        with store() as db:
            return GraphQueries(db).neighborhood(
                node,
                depth,
                limit,
                entity_type,
                relationship_type,
                after,
                before,
                include_unknown,
                include_inactive,
            )

    @app.get("/api/path")
    def path(
        source: ID,
        target: ID,
        depth: int = Query(default=6, ge=0, le=6),
        limit: int = Query(default=1000, ge=1, le=1000),
        directed: bool = False,
    ):
        with store() as db:
            return GraphQueries(db).path(source, target, depth, limit, directed)

    @app.get("/api/shared")
    def shared(
        node: Annotated[list[str], Query(min_length=2, max_length=10)],
        limit: int = Query(default=100, ge=1, le=1000),
    ):
        with store() as db:
            return GraphQueries(db).shared_neighbors(node, limit)

    @app.get("/api/shared-indicators")
    def shared_indicators(limit: int = Query(default=100, ge=1, le=1000)):
        with store() as db:
            return GraphQueries(db).shared_indicators(limit)

    @app.get("/api/techniques")
    def techniques(node: ID, depth: int = Query(default=2, ge=0, le=6)):
        with store() as db:
            return GraphQueries(db).related_techniques(node, depth)

    @app.get("/api/edges/{edge_id}")
    def edge(edge_id: str):
        with store() as db:
            selected = db.get_edge(edge_id)
            return {
                "edge": selected.model_dump(mode="json"),
                "evidence": [
                    db.get_evidence(e).model_dump(mode="json") for e in selected.evidence_ids
                ],
                "score": Scorer(db).score(edge_id),
            }

    @app.get("/api/stats")
    def stats(analytics: bool = False):
        with store() as db:
            return {
                **db.stats(),
                **({"analytics": GraphQueries(db).summary()} if analytics else {}),
            }

    @app.get("/api/investigations")
    def investigations(
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1000000),
    ):
        with store() as db:
            return [
                n.model_dump(mode="json")
                for n in db.search(entity_type="investigation", limit=limit, offset=offset)
            ]

    @app.get("/api/investigations/{node_id}/export")
    def export(
        node_id: str,
        format: str = Query(default="json", pattern="^(json|md)$"),
        limit: int = Query(default=200, ge=1, le=1000),
    ):
        with store() as db:
            report = investigation_report(db, node_id, limit)
            if format == "md":
                return PlainTextResponse(
                    to_markdown(report),
                    headers={"Content-Disposition": 'attachment; filename="investigation.md"'},
                )
            return JSONResponse(
                report, headers={"Content-Disposition": 'attachment; filename="investigation.json"'}
            )

    @app.post("/api/ingest", dependencies=[Depends(admin)])
    def ingest(request: ImportRequest):
        with store() as db:
            result = Ingestor(db).ingest(
                request.document, request.source_id, request.adapter, request.catalog_version
            )
            return JSONResponse(
                result,
                status_code=422
                if result["status"] == "failed"
                else 207
                if result["status"] == "partial"
                else 201,
            )

    @app.post("/api/investigations", dependencies=[Depends(admin)], status_code=201)
    def investigate(request: InvestigationRequest):
        with store() as db:
            return create_investigation(
                db, request.identifier, request.title, request.seeds, request.depth
            ).model_dump(mode="json")

    frontend = Path(__file__).resolve().parents[2] / "frontend"
    app.mount("/static", StaticFiles(directory=frontend), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(frontend / "index.html")

    return app
