import json
import subprocess
import sys

import pytest

from src.ingestion.pipeline import Ingestor
from src.normalization.entities import stable_id
from src.reporting.reports import (
    create_investigation,
    investigation_report,
    to_markdown,
    write_report,
)
from src.storage.sqlite import SQLiteStore
from tests.test_ingestion import iocs


def test_reports_contain_evidence_and_safe_outputs(tmp_path):
    with SQLiteStore(tmp_path / "db") as db:
        Ingestor(db).ingest(iocs())
        seed = stable_id("node", "domain", "example.org")
        inv = create_investigation(db, "case-1", "<script>alert(1)</script>", [seed])
        report = investigation_report(db, inv.node_id)
        assert report["evidence"]
        assert {ev for edge in report["edges"] for ev in edge["evidence_ids"]} <= {
            e["evidence_id"] for e in report["evidence"]
        }
        assert "<script>" not in to_markdown(report)
        output = tmp_path / "exports"
        write_report(report, "case.json", output)
        with pytest.raises(FileExistsError):
            write_report(report, "case.json", output)
        with pytest.raises(ValueError):
            write_report(report, "../../escape.json", output)
        symlink = tmp_path / "linked"
        symlink.symlink_to(output, target_is_directory=True)
        with pytest.raises(ValueError):
            write_report(report, "other.json", symlink)


def test_cli_end_to_end_and_failure_status(tmp_path):
    fixture = tmp_path / "iocs.json"
    fixture.write_text(json.dumps(iocs()))
    command = [sys.executable, "-m", "src.main", "--db", str(tmp_path / "db")]
    result = subprocess.run(  # noqa: S603 -- controlled local CLI test arguments
        [*command, "ingest", "--file", str(fixture)], capture_output=True, text=True, check=False
    )  # noqa: S603
    assert result.returncode == 2
    result = subprocess.run(  # noqa: S603 -- controlled local CLI test arguments
        [*command, "search", "--value", "example.org"], capture_output=True, text=True, check=True
    )  # noqa: S603
    assert len(json.loads(result.stdout)) == 1
    result = subprocess.run([*command, "stats"], capture_output=True, text=True, check=True)  # noqa: S603
    assert json.loads(result.stdout)["evidence"] == 2
    result = subprocess.run(  # noqa: S603 -- controlled local CLI test arguments
        [*command, "neighbors", "--node", "missing"], capture_output=True, text=True, check=False
    )  # noqa: S603
    assert result.returncode == 1 and "node not found" not in result.stderr


def test_documented_cli_subcommands_have_help():
    for cmd in [
        "ingest",
        "search",
        "neighbors",
        "path",
        "shared",
        "shared-indicators",
        "techniques",
        "evidence",
        "score",
        "audit",
        "investigate",
        "export",
        "stats",
        "imports",
        "serve",
    ]:
        result = subprocess.run(  # noqa: S603 -- controlled local CLI test arguments
            [sys.executable, "-m", "src.main", cmd, "--help"], capture_output=True, check=False
        )  # noqa: S603
        assert result.returncode == 0
