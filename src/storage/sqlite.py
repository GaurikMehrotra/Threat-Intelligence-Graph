"""Persistent registry. Storage methods are independent of API and visualization."""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import ContextManager, Protocol

from src.schemas.models import Edge, Evidence, Node, now, validate_endpoints


class GraphStore(Protocol):
    def put_node(self, node: Node) -> None: ...
    def put_evidence(self, evidence: Evidence) -> None: ...
    def put_edge(self, edge: Edge) -> None: ...
    def get_node(self, node_id: str) -> Node: ...
    def get_edge(self, edge_id: str) -> Edge: ...
    def get_evidence(self, evidence_id: str) -> Evidence: ...
    def transaction(self) -> ContextManager: ...
    def search(
        self, value: str = "", entity_type: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[Node]: ...
    def incident(self, node_id: str, limit: int = 1001) -> list[Edge]: ...
    def scan_nodes(self, limit: int) -> list[Node]: ...
    def scan_edges(self, limit: int) -> list[Edge]: ...
    def matching_edges(
        self,
        source: str | None = None,
        target: str | None = None,
        kind: str | None = None,
        limit: int = 1001,
    ) -> list[Edge]: ...
    def shared_indicator_counts(self, limit: int) -> list[tuple[str, int]]: ...
    def begin_import(
        self, source_id: str, adapter: str, parser_version: str, digest: str
    ) -> int: ...
    def finish_import(self, import_id: int, status: str, accepted: int, errors: list) -> None: ...
    def imports(self) -> list[dict]: ...
    def stats(self) -> dict: ...
    def audit(self, object_id: str, limit: int = 100) -> list[dict]: ...
    def integrity_check(self) -> bool: ...


MIGRATIONS = [
    """
CREATE TABLE nodes (
 id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, canonical_value TEXT NOT NULL,
 body TEXT NOT NULL, UNIQUE(entity_type, canonical_value));
CREATE INDEX nodes_type ON nodes(entity_type);
CREATE INDEX nodes_value ON nodes(canonical_value);
CREATE TABLE evidence (
 id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES nodes(id),
 record_id TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(source_id,record_id));
CREATE TABLE edges (
 id TEXT PRIMARY KEY, source TEXT NOT NULL REFERENCES nodes(id),
 target TEXT NOT NULL REFERENCES nodes(id), kind TEXT NOT NULL,
 source_id TEXT NOT NULL REFERENCES nodes(id), body TEXT NOT NULL);
CREATE INDEX edges_source ON edges(source);
CREATE INDEX edges_target ON edges(target);
CREATE INDEX edges_kind ON edges(kind);
CREATE TABLE edge_evidence (
 edge_id TEXT NOT NULL REFERENCES edges(id), evidence_id TEXT NOT NULL REFERENCES evidence(id),
 PRIMARY KEY(edge_id,evidence_id));
CREATE TABLE imports (
 id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, adapter TEXT NOT NULL,
 parser_version TEXT NOT NULL, integrity_hash TEXT NOT NULL, started TEXT NOT NULL,
 finished TEXT, status TEXT NOT NULL, accepted INTEGER NOT NULL DEFAULT 0,
 failed INTEGER NOT NULL DEFAULT 0, errors TEXT NOT NULL DEFAULT '[]');
CREATE TABLE audit (
 id INTEGER PRIMARY KEY, object_id TEXT NOT NULL, action TEXT NOT NULL,
 at TEXT NOT NULL, previous TEXT, current TEXT NOT NULL);
"""
]


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > len(MIGRATIONS):
            self.db.close()
            raise ValueError("database schema is newer than this application")
        for number in range(version, len(MIGRATIONS)):
            self.db.executescript(
                "BEGIN IMMEDIATE;\n"
                + MIGRATIONS[number]
                + f"\nPRAGMA user_version={number + 1};\nCOMMIT;"
            )

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def transaction(self):
        # savepoints permit an atomic import and independent record rollback.
        self.db.execute("SAVEPOINT ingest")
        try:
            yield
            self.db.execute("RELEASE ingest")
        except Exception:
            self.db.execute("ROLLBACK TO ingest")
            self.db.execute("RELEASE ingest")
            raise

    def _audit(self, object_id, action, previous, current):
        self.db.execute(
            "INSERT INTO audit(object_id,action,at,previous,current) VALUES(?,?,?,?,?)",
            (object_id, action, now().isoformat(), previous, current),
        )

    def get_node(self, node_id: str) -> Node:
        row = self.db.execute("SELECT body FROM nodes WHERE id=?", (node_id,)).fetchone()
        if row is None:
            raise KeyError("node not found")
        return Node.model_validate_json(row[0])

    def get_edge(self, edge_id: str) -> Edge:
        row = self.db.execute("SELECT body FROM edges WHERE id=?", (edge_id,)).fetchone()
        if row is None:
            raise KeyError("edge not found")
        return Edge.model_validate_json(row[0])

    def get_evidence(self, evidence_id: str) -> Evidence:
        row = self.db.execute("SELECT body FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError("evidence not found")
        return Evidence.model_validate_json(row[0])

    def put_node(self, node: Node):
        node = Node.model_validate(node.model_dump())
        with self.transaction():
            row = self.db.execute("SELECT body FROM nodes WHERE id=?", (node.node_id,)).fetchone()
            old = row[0] if row else None
            if row:
                existing = Node.model_validate_json(old)
                merged = existing.attributes.copy()
                for key, value in node.attributes.items():
                    if key == "catalog_versions":
                        merged[key] = sorted(set(merged.get(key, []) + value))
                        continue
                    if key == "representations":
                        for record, representation in value.items():
                            previous = merged.setdefault(key, {}).get(record)
                            if previous is not None and previous != representation:
                                changes = merged.setdefault(
                                    "representation_variations", {}
                                ).setdefault(record, [previous])
                                if representation not in changes:
                                    changes.append(representation)
                            else:
                                merged[key][record] = representation
                        continue
                    if key in merged and merged[key] != value:
                        # Preserve source variations rather than silently overwriting facts.
                        variations = merged.setdefault("variations", {})
                        choices = variations.setdefault(key, [merged[key]])
                        if value not in choices:
                            choices.append(value)
                    else:
                        merged[key] = value
                first = [t for t in (existing.first_seen, node.first_seen) if t]
                last = [t for t in (existing.last_seen, node.last_seen) if t]
                node = Node.model_validate(
                    {
                        **existing.model_dump(),
                        "attributes": merged,
                        "first_seen": min(first) if first else None,
                        "last_seen": max(last) if last else None,
                    }
                )
                if node.model_dump() == existing.model_dump():
                    return
                node.updated_at = now()
            body = node.model_dump_json()
            self.db.execute(
                "INSERT INTO nodes VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                (node.node_id, node.entity_type, node.canonical_value, body),
            )
            self._audit(node.node_id, "update" if old else "create", old, body)

    def put_evidence(self, evidence: Evidence):
        evidence = Evidence.model_validate(evidence.model_dump())
        if self.get_node(evidence.source_id).entity_type != "source":
            raise ValueError("evidence source must be a source node")
        with self.transaction():
            row = self.db.execute(
                "SELECT body FROM evidence WHERE id=?", (evidence.evidence_id,)
            ).fetchone()
            body = evidence.model_dump_json()
            if row:
                prior = Evidence.model_validate_json(row[0])
                if prior.model_dump(exclude={"ingestion_time"}) != evidence.model_dump(
                    exclude={"ingestion_time"}
                ):
                    raise ValueError("immutable evidence ID conflicts with prior observation")
                return
            self.db.execute(
                "INSERT INTO evidence VALUES(?,?,?,?)",
                (evidence.evidence_id, evidence.source_id, evidence.source_record_id, body),
            )
            self._audit(evidence.evidence_id, "create", None, body)

    def put_edge(self, edge: Edge):
        edge = Edge.model_validate(edge.model_dump())
        validate_endpoints(
            edge, self.get_node(edge.source_node_id), self.get_node(edge.target_node_id)
        )
        if self.get_node(edge.source_id).entity_type != "source":
            raise ValueError("edge source must be a source node")
        supporting = [self.get_evidence(e) for e in edge.evidence_ids]
        if any(e.source_id != edge.source_id for e in supporting):
            raise ValueError("claim evidence must match its originating source")
        if edge.relationship_origin != "hypothesis" and any(
            e.evidence_type == "hypothesis" for e in supporting
        ):
            raise ValueError("hypothesis evidence cannot confirm an observed or reported claim")
        if edge.relationship_origin == "analyst_confirmed" and any(
            e.evidence_type != "analyst" for e in supporting
        ):
            raise ValueError("analyst confirmation requires an explicit analyst evidence record")
        if edge.relationship_origin == "direct_observation" and any(
            e.evidence_type not in {"observation", "behavior"} for e in supporting
        ):
            raise ValueError("direct observations require observational evidence")
        if edge.relationship_type == "MAPPED_TO_TECHNIQUE":
            technique = self.get_node(edge.target_node_id)
            if not technique.attributes.get("catalog_versions"):
                raise ValueError("mapping needs a catalog-validated technique")
            if not any(e.evidence_type == "behavior" for e in supporting):
                raise ValueError("technique mapping needs behavioral evidence")
        with self.transaction():
            row = self.db.execute("SELECT body FROM edges WHERE id=?", (edge.edge_id,)).fetchone()
            old = row[0] if row else None
            if row:
                prior = Edge.model_validate_json(old)
                if prior.model_dump(exclude={"created_at", "evidence_ids"}) != edge.model_dump(
                    exclude={"created_at", "evidence_ids"}
                ):
                    raise ValueError(
                        "edge claim conflicts; use a separate source, interval, or status"
                    )
                edge = prior.model_copy(
                    update={"evidence_ids": sorted(set(prior.evidence_ids + edge.evidence_ids))}
                )
                if edge.model_dump() == prior.model_dump():
                    return
            body = edge.model_dump_json()
            self.db.execute(
                "INSERT INTO edges VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                (
                    edge.edge_id,
                    edge.source_node_id,
                    edge.target_node_id,
                    edge.relationship_type,
                    edge.source_id,
                    body,
                ),
            )
            for ev in edge.evidence_ids:
                self.db.execute(
                    "INSERT OR IGNORE INTO edge_evidence VALUES(?,?)", (edge.edge_id, ev)
                )
            self._audit(edge.edge_id, "update" if old else "create", old, body)

    def search(
        self, value: str = "", entity_type: str | None = None, limit: int = 100, offset: int = 0
    ):
        if not 1 <= limit <= 500 or not 0 <= offset <= 1000000:
            raise ValueError("invalid pagination")
        if entity_type is not None:
            from src.normalization.entities import ENTITY_TYPES

            if entity_type not in ENTITY_TYPES:
                raise ValueError("unsupported entity type")
        # Literal substring search: '%' and '_' in input are not SQL wildcard instructions.
        rows = self.db.execute(
            "SELECT body FROM nodes WHERE instr(lower(canonical_value),lower(?))>0 "
            "AND (? IS NULL OR entity_type=?) ORDER BY id LIMIT ? OFFSET ?",
            (value, entity_type, entity_type, limit, offset),
        )
        return [Node.model_validate_json(r[0]) for r in rows]

    def incident(self, node_id: str, limit: int = 1001):
        return [
            Edge.model_validate_json(r[0])
            for r in self.db.execute(
                "SELECT body FROM edges WHERE source=? OR target=? ORDER BY id LIMIT ?",
                (node_id, node_id, limit),
            )
        ]

    def stats(self):
        queries = {
            "nodes": "SELECT count(*) FROM nodes",
            "edges": "SELECT count(*) FROM edges",
            "evidence": "SELECT count(*) FROM evidence",
            "imports": "SELECT count(*) FROM imports",
            "audit": "SELECT count(*) FROM audit",
        }
        return {name: self.db.execute(query).fetchone()[0] for name, query in queries.items()}

    def audit(self, object_id: str, limit: int = 100):
        return [
            dict(r)
            for r in self.db.execute(
                "SELECT id,object_id,action,at FROM audit WHERE object_id=? ORDER BY id DESC LIMIT ?",
                (object_id, limit),
            )
        ]

    def scan_nodes(self, limit):
        return [
            Node.model_validate_json(r[0])
            for r in self.db.execute("SELECT body FROM nodes ORDER BY id LIMIT ?", (limit,))
        ]

    def scan_edges(self, limit):
        return [
            Edge.model_validate_json(r[0])
            for r in self.db.execute("SELECT body FROM edges ORDER BY id LIMIT ?", (limit,))
        ]

    def matching_edges(self, source=None, target=None, kind=None, limit=1001):
        return [
            Edge.model_validate_json(r[0])
            for r in self.db.execute(
                "SELECT body FROM edges WHERE (? IS NULL OR source=?) AND (? IS NULL OR target=?) "
                "AND (? IS NULL OR kind=?) ORDER BY id LIMIT ?",
                (source, source, target, target, kind, kind, limit),
            )
        ]

    def shared_indicator_counts(self, limit):
        return [
            (r[0], r[1])
            for r in self.db.execute(
                "SELECT e.source, count(DISTINCT e.target) AS reports FROM edges e "
                "JOIN nodes n ON n.id=e.source JOIN nodes r ON r.id=e.target "
                "WHERE e.kind='OBSERVED_IN' AND n.entity_type IN ('ipv4','ipv6','domain','url','file_hash') "
                "AND r.entity_type IN ('sandbox_report','intelligence_report') "
                "AND json_extract(e.body,'$.status') NOT IN ('rejected','superseded') "
                "GROUP BY e.source HAVING reports>1 ORDER BY reports DESC,e.source LIMIT ?",
                (limit,),
            )
        ]

    def begin_import(self, source_id, adapter, parser_version, digest):
        with self.transaction():
            cursor = self.db.execute(
                "INSERT INTO imports(source_id,adapter,parser_version,integrity_hash,started,status) VALUES(?,?,?,?,?,?)",
                (source_id, adapter, parser_version, digest, now().isoformat(), "running"),
            )
        return cursor.lastrowid

    def finish_import(self, import_id, status, accepted, errors):
        with self.transaction():
            self.db.execute(
                "UPDATE imports SET finished=?,status=?,accepted=?,failed=?,errors=? WHERE id=?",
                (now().isoformat(), status, accepted, len(errors), json.dumps(errors), import_id),
            )

    def imports(self):
        return [
            {**dict(r), "errors": json.loads(r["errors"])}
            for r in self.db.execute("SELECT * FROM imports ORDER BY id DESC LIMIT 100")
        ]

    def integrity_check(self):
        return self.db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
