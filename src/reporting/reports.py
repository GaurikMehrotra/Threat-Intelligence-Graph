"""Investigation reports contain claims and evidence, not invented conclusions."""

import json
from pathlib import Path
import re

from src.analytics.queries import GraphQueries
from src.correlation.scoring import Scorer
from src.normalization.entities import stable_id
from src.schemas.models import Edge, Evidence, Node, now
from src.storage.sqlite import GraphStore


def create_investigation(store: GraphStore, identifier: str, title: str, seeds: list[str], depth=2):
    GraphQueries._limits(depth, 100)
    if not seeds or len(seeds) > 20:
        raise ValueError("investigations require 1..20 seed entities")
    for seed in seeds:
        store.get_node(seed)
    source = Node.create("source", "local-analyst")
    investigation = Node.create(
        "investigation",
        identifier,
        display_name=title,
        attributes={"seed_node_ids": sorted(set(seeds)), "depth": depth},
    )
    record = stable_id("investigation", identifier, title, sorted(set(seeds)), depth)
    evidence = Evidence(
        evidence_id=stable_id("ev", source.node_id, record),
        evidence_type="analyst",
        source_id=source.node_id,
        source_record_id=record,
        description="Analyst selected investigation seed entities, not an attribution.",
        raw_reference="investigation:" + record,
    )
    with store.transaction():
        store.put_node(source)
        store.put_node(investigation)
        store.put_evidence(evidence)
        for seed in seeds:
            store.put_edge(
                Edge.create(
                    investigation.node_id,
                    seed,
                    "CONTAINS",
                    source.node_id,
                    "analyst_confirmed",
                    [evidence.evidence_id],
                )
            )
    return investigation


def investigation_report(store: GraphStore, investigation_id: str, limit=200):
    investigation = store.get_node(investigation_id)
    if investigation.entity_type != "investigation":
        raise ValueError("export target must be an investigation")
    nodes, edges = {investigation_id: investigation.model_dump(mode="json")}, {}
    truncated = False
    for seed in investigation.attributes["seed_node_ids"]:
        graph = GraphQueries(store).neighborhood(seed, investigation.attributes["depth"], limit)
        truncated |= graph["truncated"]
        for node in graph["nodes"]:
            if node["node_id"] in nodes or len(nodes) < limit:
                nodes[node["node_id"]] = node
            else:
                truncated = True
        for edge in graph["edges"]:
            if edge["source_node_id"] in nodes and edge["target_node_id"] in nodes:
                if len(edges) < 5000:
                    edges[edge["edge_id"]] = edge
                else:
                    truncated = True
    evidence_ids = {e for edge in edges.values() for e in edge["evidence_ids"]}
    evidence = [store.get_evidence(e).model_dump(mode="json") for e in sorted(evidence_ids)]
    return {
        "schema_version": 1,
        "generated_at": now().isoformat(),
        "investigation": investigation.model_dump(mode="json"),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "evidence": evidence,
        "scores": [Scorer(store).score(e) for e in edges],
        "truncated": truncated,
        "limitations": [
            "Recorded relationships are claims, not established facts.",
            "Graph connectivity does not establish actor identity, ownership, or campaign membership.",
            "Heuristic confidence is not a probability; indicator risk is not computed.",
            "Unknown times remain unknown; exports reflect current stored claims.",
        ],
    }


def markdown_text(value: str) -> str:
    # Escape markup and HTML so untrusted values cannot add links, scripts or report sections.
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>\-])", r"\\\1", text).replace("\n", " ").replace("\r", " ")


def to_markdown(report):
    lines = [
        "# " + markdown_text(report["investigation"]["display_name"]),
        "",
        "Generated: " + report["generated_at"],
        "",
        f"Truncated: {report['truncated']}",
        "",
        "## Limitations",
        "",
    ]
    lines.extend("- " + markdown_text(item) for item in report["limitations"])
    lines += ["", "## Entities", "", "| Type | Value | ID |", "| --- | --- | --- |"]
    for n in report["nodes"]:
        lines.append(
            "| "
            + " | ".join(markdown_text(n[k]) for k in ("entity_type", "display_name", "node_id"))
            + " |"
        )
    lines += ["", "## Relationship claims", ""]
    scores = {s["edge_id"]: s for s in report["scores"]}
    for edge in report["edges"]:
        score = scores[edge["edge_id"]]
        lines += [
            "### " + edge["edge_id"],
            "",
            f"{edge['relationship_type']}: {edge['source_node_id']} → {edge['target_node_id']}",
            "",
            f"Origin: {edge['relationship_origin']}; status: {edge['status']}; heuristic confidence: {score['relationship_confidence']}",
            "",
            "Evidence: " + ", ".join(edge["evidence_ids"]),
            "",
            "Source: " + edge["source_id"],
            "",
        ]
        if edge.get("rationale"):
            lines += ["Source rationale: " + markdown_text(edge["rationale"]), ""]
        lines.extend("- " + markdown_text(reason) for reason in score["rationale"])
        lines.append("")
    lines += ["## Evidence registry", ""]
    for ev in report["evidence"]:
        lines += [
            "### " + ev["evidence_id"],
            "",
            markdown_text(ev["description"]),
            "",
            "Source: " + ev["source_id"],
            "",
            "Reference: " + markdown_text(ev["raw_reference"]),
            "",
            "Observation time: " + str(ev["observation_time"]),
            "",
            "Integrity SHA256: " + str(ev["integrity_hash"]),
            "",
        ]
        lines.extend("- Limitation: " + markdown_text(item) for item in ev["limitations"])
    return "\n".join(lines) + "\n"


def write_report(report, filename: str, root: str | Path = "reports"):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(json|md)", filename):
        raise ValueError("output must be a simple .json or .md filename")
    root = Path(root)
    if root.is_symlink():
        raise ValueError("export directory must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    path = root / filename
    # Exclusive create: no following existing symlinks and no overwriting user reports.
    with path.open("x", encoding="utf-8") as stream:
        stream.write(
            to_markdown(report) if filename.endswith(".md") else json.dumps(report, indent=2)
        )
    return filename
