"""Measured synthetic performance and extraction; temporary DBs, no network."""

from pathlib import Path
import ipaddress
import json
import platform
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.analytics.queries import GraphQueries
from src.ingestion.pipeline import Ingestor
from src.normalization.entities import stable_id
from src.schemas.models import Edge
from src.storage.sqlite import SQLiteStore


def main():
    root = Path(__file__).resolve().parents[1]
    records = [
        {
            "id": str(i),
            "entity_type": "domain",
            "value": f"ioc-{i}.example",
            "report_id": "synthetic-benchmark",
            "resolves_to": str(ipaddress.ip_address(int(ipaddress.ip_address("198.18.0.1")) + i)),
        }
        for i in range(500)
    ]
    document = {"format": "ioc", "source_id": "benchmark-fixture", "records": records}
    with TemporaryDirectory(prefix="tig-evaluation-") as temp:
        with SQLiteStore(Path(temp) / "benchmark.sqlite3") as db:
            tracemalloc.start()
            started = perf_counter()
            outcome = Ingestor(db).ingest(document)
            ingestion_seconds = perf_counter() - started
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            assert outcome["accepted"] == 500 and outcome["failed"] == 0
            seed = stable_id("node", "domain", "ioc-0.example")
            started = perf_counter()
            graph = GraphQueries(db).neighborhood(seed, depth=3, limit=100)
            traversal_seconds = perf_counter() - started
            before = db.stats()
            started = perf_counter()
            Ingestor(db).ingest(document)
            repeat_seconds = perf_counter() - started
            after = db.stats()
            assert all(before[k] == after[k] for k in ("nodes", "edges", "evidence", "audit"))
            benchmark = {
                "records": 500,
                "graph_counts": {k: before[k] for k in ("nodes", "edges", "evidence")},
                "ingestion_seconds": round(ingestion_seconds, 4),
                "repeat_ingestion_seconds": round(repeat_seconds, 4),
                "peak_python_allocation_mib": round(peak / 1024**2, 3),
                "neighborhood_seconds": round(traversal_seconds, 4),
                "returned_nodes": len(graph["nodes"]),
                "returned_edges": len(graph["edges"]),
                "truncated": graph["truncated"],
                "repeat_import_identity_unchanged": True,
            }
        with SQLiteStore(Path(temp) / "extraction.sqlite3") as db:
            runner = Ingestor(db)
            runner.ingest_file(root / "data/fixtures/attack-synthetic.json")
            outcome = runner.ingest_file(root / "data/fixtures/sandbox.json")
            assert outcome["status"] == "complete"
            report = json.loads((root / "data/fixtures/sandbox.json").read_text())
            expected = {
                (c["source"], c["target"], c["relationship_type"]) for c in report["events"]
            }
            source = stable_id("node", "source", report["source_id"])
            aliases = {}
            for n in report["entities"]:
                value = (
                    stable_id("scoped", source, report["report_id"], n["id"])
                    if n["entity_type"] in {"process", "file", "registry_key"}
                    else n["value"]
                )
                aliases[stable_id("node", n["entity_type"], value)] = n["id"]
            edges = [
                Edge.model_validate_json(r[0])
                for r in db.db.execute(
                    "SELECT body FROM edges WHERE kind IN ('COMMUNICATED_WITH','DROPPED_FILE','SPAWNED_PROCESS','MODIFIED_REGISTRY','MAPPED_TO_TECHNIQUE')"
                )
            ]
            predicted = {
                (aliases[e.source_node_id], aliases[e.target_node_id], e.relationship_type)
                for e in edges
            }
            true_positive = len(predicted & expected)
            completeness = sum(
                bool(e.evidence_ids) and all(db.get_evidence(ev) for ev in e.evidence_ids)
                for e in edges
            ) / len(edges)
            extraction = {
                "expected_relationships": len(expected),
                "predicted_relationships": len(predicted),
                "true_positives": true_positive,
                "false_positives": len(predicted - expected),
                "false_negatives": len(expected - predicted),
                "precision": true_positive / len(predicted),
                "recall": true_positive / len(expected),
                "evidence_reference_completeness": completeness,
            }
    result = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "method": "One synthetic run; perf_counter wall time, tracemalloc Python allocations (not total RSS).",
        "benchmark": benchmark,
        "extraction": extraction,
        "limitations": [
            "Synthetic ground truth only; not real-world malware or intelligence validation.",
            "Single-machine, single-run timings are not performance guarantees.",
            "Explicit-event extraction measured; arbitrary report-language interpretation is unsupported.",
        ],
    }
    target = root / "local/evaluation.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
