"""Command line entry point: python -m src.main --help."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

from src.analytics.queries import GraphQueries
from src.correlation.scoring import ScoreConfig, Scorer
from src.ingestion.pipeline import Ingestor
from src.reporting.reports import (
    create_investigation,
    investigation_report,
    to_markdown,
    write_report,
)
from src.storage.sqlite import SQLiteStore


def parser():
    p = argparse.ArgumentParser(description="Evidence-grounded offline threat intelligence graph")
    p.add_argument(
        "--db", default="local/graph.sqlite3", help="SQLite database (default local/graph.sqlite3)"
    )
    sub = p.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser(
        "ingest", help="Import files offline; malformed batch records are reported"
    )
    ingest.add_argument("--file", action="append", required=True)
    ingest.add_argument("--source-id")
    ingest.add_argument("--adapter", choices=["ioc", "sandbox", "cuckoo", "graph", "attack"])
    ingest.add_argument("--catalog-version")
    search = sub.add_parser("search")
    search.add_argument("--value", default="")
    search.add_argument("--entity-type")
    search.add_argument("--limit", type=int, default=100)
    search.add_argument("--offset", type=int, default=0)
    neighbors = sub.add_parser("neighbors")
    neighbors.add_argument("--node", required=True)
    neighbors.add_argument("--depth", type=int, default=1)
    neighbors.add_argument("--limit", type=int, default=100)
    neighbors.add_argument("--entity-type", action="append")
    neighbors.add_argument("--relationship-type", action="append")
    neighbors.add_argument("--after", type=datetime.fromisoformat)
    neighbors.add_argument("--before", type=datetime.fromisoformat)
    neighbors.add_argument("--exclude-unknown-time", action="store_true")
    neighbors.add_argument("--include-inactive", action="store_true")
    path = sub.add_parser("path")
    path.add_argument("--source", required=True)
    path.add_argument("--target", required=True)
    path.add_argument("--depth", type=int, default=6)
    path.add_argument("--limit", type=int, default=1000)
    path.add_argument("--directed", action="store_true")
    shared = sub.add_parser("shared")
    shared.add_argument("--node", action="append", required=True)
    shared.add_argument("--limit", type=int, default=100)
    sub.add_parser("shared-indicators")
    techniques = sub.add_parser("techniques")
    techniques.add_argument("--node", required=True)
    techniques.add_argument("--depth", type=int, default=2)
    for name in ("evidence", "score"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--edge", required=True)
        if name == "score":
            cmd.add_argument("--config", help="JSON scoring configuration")
    audit = sub.add_parser("audit")
    audit.add_argument("--object", required=True)
    investigate = sub.add_parser("investigate")
    investigate.add_argument("--id", required=True)
    investigate.add_argument("--title", required=True)
    investigate.add_argument("--node", action="append", required=True)
    investigate.add_argument("--depth", type=int, default=2)
    export = sub.add_parser("export")
    export.add_argument("--investigation", required=True)
    export.add_argument("--format", choices=["json", "md"], default="json")
    export.add_argument(
        "--output", help="New filename within reports/; existing files are never overwritten"
    )
    export.add_argument("--limit", type=int, default=200)
    stats = sub.add_parser("stats")
    stats.add_argument("--analytics", action="store_true")
    sub.add_parser("imports")
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    return p


def run(args):
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if args.command == "serve":
        if not 1024 <= args.port <= 65535:
            raise ValueError("port must be 1024..65535")
        import uvicorn
        from src.api.app import create_app

        uvicorn.run(create_app(args.db), host="127.0.0.1", port=args.port, access_log=False)
        return None
    with SQLiteStore(args.db) as db:
        q = GraphQueries(db)
        if args.command == "ingest":
            results = []
            for filename in args.file:
                try:
                    results.append(
                        Ingestor(db).ingest_file(
                            filename, args.source_id, args.adapter, args.catalog_version
                        )
                    )
                except (ValueError, OSError) as exc:
                    results.append(
                        {
                            "status": "failed",
                            "error": "input unavailable or invalid",
                            "error_type": type(exc).__name__,
                        }
                    )
            return results
        if args.command == "search":
            return [
                n.model_dump(mode="json")
                for n in db.search(args.value, args.entity_type, args.limit, args.offset)
            ]
        if args.command == "neighbors":
            return q.neighborhood(
                args.node,
                args.depth,
                args.limit,
                args.entity_type,
                args.relationship_type,
                args.after,
                args.before,
                not args.exclude_unknown_time,
                args.include_inactive,
            )
        if args.command == "path":
            return q.path(args.source, args.target, args.depth, args.limit, args.directed)
        if args.command == "shared":
            return q.shared_neighbors(args.node, args.limit)
        if args.command == "shared-indicators":
            return q.shared_indicators()
        if args.command == "techniques":
            return q.related_techniques(args.node, args.depth)
        if args.command == "evidence":
            edge = db.get_edge(args.edge)
            return {
                "edge": edge.model_dump(mode="json"),
                "evidence": [db.get_evidence(e).model_dump(mode="json") for e in edge.evidence_ids],
            }
        if args.command == "score":
            config = (
                ScoreConfig.model_validate_json(Path(args.config).read_text())
                if args.config
                else None
            )
            return Scorer(db, config).score(args.edge)
        if args.command == "audit":
            return db.audit(args.object)
        if args.command == "investigate":
            return create_investigation(db, args.id, args.title, args.node, args.depth).model_dump(
                mode="json"
            )
        if args.command == "export":
            report = investigation_report(db, args.investigation, args.limit)
            if args.output:
                if not args.output.endswith("." + args.format):
                    raise ValueError("output extension must match format")
                return {
                    "saved": write_report(report, args.output),
                    "truncated": report["truncated"],
                }
            return to_markdown(report) if args.format == "md" else report
        if args.command == "stats":
            return {**db.stats(), **({"analytics": q.summary()} if args.analytics else {})}
        if args.command == "imports":
            return db.imports()
        raise ValueError("unknown command")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = run(args)
        if result is not None:
            print(result if isinstance(result, str) else json.dumps(result, indent=2))
        if args.command == "ingest" and any(r["status"] != "complete" for r in result):
            return 2
        return 0
    except (ValueError, KeyError, OSError) as exc:
        # Avoid echoing internal paths or invalid report contents.
        print(
            json.dumps(
                {
                    "error": "operation failed validation or referenced data is unavailable",
                    "type": type(exc).__name__,
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
