"""Repeatable synthetic investigation. Does not contact any external services."""

from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.ingestion.pipeline import Ingestor
from src.normalization.entities import stable_id
from src.reporting.reports import create_investigation, investigation_report, write_report
from src.storage.sqlite import SQLiteStore


def main():
    root = Path(__file__).resolve().parents[1]
    local = root / "local"
    local.mkdir(exist_ok=True)
    with SQLiteStore(local / "demo.sqlite3") as store:
        runner = Ingestor(store)
        for filename in ("attack-synthetic.json", "iocs.json", "sandbox.json", "attribution.json"):
            result = runner.ingest_file(root / "data" / "fixtures" / filename)
            if result["status"] != "complete":
                raise RuntimeError(json.dumps(result))
        result = runner.ingest_file(
            root / "data" / "fixtures" / "iocs.csv", source_id="synthetic-csv"
        )
        if result["status"] != "complete":
            raise RuntimeError(json.dumps(result))
        seed = stable_id("node", "domain", "c2.example")
        investigation = create_investigation(
            store, "synthetic-demo", "Synthetic evidence investigation", [seed], depth=3
        )
        report = investigation_report(store, investigation.node_id)
        exports = local / "exports"
        # Existing reports remain untouched on repeat runs; emit new exclusive filenames.
        run = store.stats()["imports"]
        for ext in ("json", "md"):
            write_report(report, f"demo-{run}.{ext}", exports)
        print(
            json.dumps(
                {
                    "database": "local/demo.sqlite3",
                    "investigation_id": investigation.node_id,
                    "seed_node_id": seed,
                    "stats": store.stats(),
                    "exported_nodes": len(report["nodes"]),
                    "exported_edges": len(report["edges"]),
                    "truncated": report["truncated"],
                    "reports": f"local/exports/demo-{run}.json / .md",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
