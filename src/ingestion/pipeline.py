"""Offline adapters, transactional batches, immutable content references."""

import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.ingestion.formats import GraphInput, IOCInput, SandboxInput
from src.normalization.entities import SCOPED_TYPES, stable_id
from src.schemas.models import Edge, Evidence, Node, now
from src.storage.sqlite import GraphStore

PARSER_VERSION = "1.0.0"
MAX_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 20000
NAMED_TYPES = {
    "malware_sample",
    "malware_family",
    "campaign",
    "threat_actor",
    "sandbox_report",
    "intelligence_report",
}


def read_input(path: str | Path) -> tuple[Any, str]:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("input must be a regular non-symlink file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds 64 MiB limit")
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8-sig")
    if path.suffix.lower() == ".csv":
        rows = []
        for row in csv.DictReader(io.StringIO(text)):
            if len(rows) >= MAX_RECORDS:
                raise ValueError("CSV exceeds 20000 record limit")
            rows.append(row)
        for row in rows:
            for key in list(row):
                if row[key] == "":
                    del row[key]
        return {"format": "ioc", "records": rows}, digest
    try:
        return json.loads(text), digest
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid JSON document") from exc


class Ingestor:
    def __init__(self, store: GraphStore):
        self.store = store
        self.source: Node | None = None
        self.digest = ""

    def _ev(self, record_id, kind, description, **kwargs):
        ev = Evidence(
            evidence_id=stable_id("ev", self.source.node_id, record_id),
            evidence_type=kind,
            source_id=self.source.node_id,
            source_record_id=record_id,
            description=description,
            raw_reference=f"sha256:{self.digest}#{record_id}",
            integrity_hash=self.digest,
            **kwargs,
        )
        self.store.put_evidence(ev)
        return ev

    def _edge(self, source, target, kind, ev, origin="source_reported", **kwargs):
        edge = Edge.create(
            source, target, kind, self.source.node_id, origin, [e.evidence_id for e in ev], **kwargs
        )
        self.store.put_edge(edge)
        return edge

    def ingest_file(self, path, source_id=None, adapter=None, catalog_version=None):
        document, digest = read_input(path)
        return self.ingest(document, source_id, adapter, catalog_version, digest)

    def ingest(self, document, source_id=None, adapter=None, catalog_version=None, digest=None):
        if isinstance(document, list):
            document = {"format": "ioc", "records": document}
        if not isinstance(document, dict):
            raise ValueError("expected object or IOC array")
        self.digest = (
            digest or hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
        )
        source_name = source_id or document.get("source_id")
        if not isinstance(source_name, str) or not source_name.strip():
            raise ValueError("source_id is required; identify the actual originating publisher")
        self.source = Node.create("source", source_name)
        self.store.put_node(self.source)
        adapter = adapter or (
            "attack" if document.get("type") == "bundle" else document.get("format", "ioc")
        )
        if adapter not in {"ioc", "graph", "sandbox", "cuckoo", "attack"}:
            raise ValueError("unsupported adapter")
        import_id = self.store.begin_import(
            self.source.node_id, adapter, PARSER_VERSION, self.digest
        )
        accepted, errors = 0, []
        try:
            if adapter == "ioc":
                records = document.get("records")
                if not isinstance(records, list) or len(records) > MAX_RECORDS:
                    raise ValueError("records must be an array of at most 20000 items")
                allowed = {"format", "source_id", "records", "schema_version"}
                if set(document) - allowed:
                    raise ValueError("unexpected IOC document fields")
                for index, raw in enumerate(records):
                    try:
                        with self.store.transaction():
                            self._ioc(IOCInput.model_validate(raw))
                        accepted += 1
                    except (ValueError, KeyError, TypeError, AttributeError) as exc:
                        errors.append(self._error(index, exc))
            elif adapter == "attack":
                accepted, errors = self._attack(document, catalog_version)
            else:
                if adapter == "cuckoo":
                    document = self._cuckoo(document)
                clean = {key: value for key, value in document.items() if key != "source_id"}
                with self.store.transaction():
                    if adapter == "graph":
                        self._graph(GraphInput.model_validate(clean))
                    else:
                        self._sandbox(SandboxInput.model_validate(clean))
                accepted = 1
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            errors.append(self._error(None, exc))
        status = "partial" if accepted and errors else "failed" if errors else "complete"
        self.store.finish_import(import_id, status, accepted, errors)
        return {
            "import_id": import_id,
            "adapter": adapter,
            "parser_version": PARSER_VERSION,
            "status": status,
            "accepted": accepted,
            "failed": len(errors),
            "errors": errors,
        }

    @staticmethod
    def _error(index, exc):
        # Do not echo untrusted payloads, source paths, or validation input values into logs.
        if isinstance(exc, ValidationError):
            detail = [
                {"field": ".".join(str(x) for x in e["loc"]), "type": e["type"]}
                for e in exc.errors(include_input=False, include_url=False)
            ][:20]
        elif isinstance(exc, KeyError):
            detail = "referenced entity or evidence not found"
        else:
            detail = "record failed normalization, validation, or relationship semantics"
        return {"record_index": index, "error": detail}

    def _ioc(self, item: IOCInput):
        # The content hash and parser version make changed observations new evidence;
        # an identical file import retains the same identity.
        record = f"ioc:{PARSER_VERSION}:{self.digest}:{item.id}"
        node = Node.create(
            item.entity_type,
            item.value,
            first_seen=item.observation_time,
            last_seen=item.observation_time,
            attributes={"representations": {self.source.node_id + ":" + item.id: item.value}},
        )
        self.store.put_node(node)
        ev = self._ev(
            record,
            "source_claim",
            item.description,
            observation_time=item.observation_time,
            limitations=item.limitations,
            upstream_claim_id=item.upstream_claim_id,
            quality=item.quality,
        )
        self._edge(node.node_id, self.source.node_id, "REPORTED_BY", [ev])
        if item.report_id:
            report = Node.create(
                "intelligence_report",
                stable_id("report", self.source.node_id, item.report_id),
                display_name=item.report_id,
            )
            self.store.put_node(report)
            self._edge(node.node_id, report.node_id, "OBSERVED_IN", [ev])
        if item.resolves_to:
            if item.entity_type != "domain":
                raise ValueError("resolves_to is only valid for domain records")
            ip = ipaddress.ip_address(item.resolves_to)
            target = Node.create("ipv4" if ip.version == 4 else "ipv6", str(ip))
            self.store.put_node(target)
            self._edge(
                node.node_id, target.node_id, "RESOLVES_TO", [ev], valid_from=item.observation_time
            )

    def _entities(self, entities, scope):
        nodes = {}
        for item in entities:
            if item.id in nodes:
                raise ValueError("duplicate local entity ID")
            value = item.value
            if item.entity_type in SCOPED_TYPES:
                value = stable_id("scoped", self.source.node_id, scope, item.id)
            elif item.entity_type in NAMED_TYPES:
                value = stable_id("named", self.source.node_id, item.entity_type, value)
            node = Node.create(
                item.entity_type,
                value,
                display_name=item.display_name or item.value,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                attributes={
                    **item.attributes,
                    "representations": {
                        self.source.node_id + ":" + scope + ":" + item.id: item.value
                    },
                },
            )
            # Generic imports cannot claim catalog verification.
            if "catalog_versions" in item.attributes and item.entity_type.startswith("attack_"):
                raise ValueError("ATT&CK catalog metadata must come from the STIX adapter")
            self.store.put_node(node)
            nodes[item.id] = node.node_id
        return nodes

    def _evidence(self, entries, scope):
        result = {}
        for item in entries:
            if item.id in result:
                raise ValueError("duplicate evidence alias")
            fields = item.model_dump(
                exclude={"id", "schema_version", "evidence_type", "description"}
            )
            ev = self._ev(
                f"{scope}:{PARSER_VERSION}:{self.digest}:{item.id}",
                item.evidence_type,
                item.description,
                **fields,
            )
            result[item.id] = ev
        return result

    def _claims(self, claims, nodes, evidence):
        seen = set()
        for item in claims:
            if item.id in seen:
                raise ValueError("duplicate claim alias")
            seen.add(item.id)
            fields = item.model_dump(
                exclude={
                    "id",
                    "schema_version",
                    "source",
                    "target",
                    "relationship_type",
                    "evidence_ids",
                    "origin",
                }
            )
            self._edge(
                nodes[item.source],
                nodes[item.target],
                item.relationship_type,
                [evidence[e] for e in item.evidence_ids],
                item.origin,
                **fields,
            )

    def _graph(self, graph):
        nodes = self._entities(graph.nodes, "graph")
        evidence = self._evidence(graph.evidence, "graph")
        self._claims(graph.edges, nodes, evidence)

    def _sandbox(self, report):
        report_node = Node.create(
            "sandbox_report",
            stable_id("report", self.source.node_id, report.report_id),
            display_name=report.report_id,
        )
        self.store.put_node(report_node)
        nodes = self._entities(report.entities, report.report_id)
        evidence = self._evidence(report.evidence, report.report_id)
        # Membership provenance is report content, not behavioral causality.
        membership = self._ev(
            f"report:{PARSER_VERSION}:{self.digest}:{report.report_id}",
            "source_claim",
            "Entities explicitly listed in sandbox report.",
        )
        for node in nodes.values():
            self._edge(node, report_node.node_id, "OBSERVED_IN", [membership])
        self._claims(report.events, nodes, evidence)

    @staticmethod
    def _cuckoo(doc):
        """Conservative subset: processes, hosts, dropped files, explicit DNS answers.

        A host list never implies which process communicated. No API-call heuristics.
        """
        entities, events, evidence = [], [], []
        report_id = str(doc.get("info", {}).get("id", ""))
        if not report_id:
            raise ValueError("Cuckoo info.id is required")
        for p in doc.get("behavior", {}).get("processes", []):
            entities.append(
                {
                    "id": "pid:" + str(p["process_id"]),
                    "entity_type": "process",
                    "value": str(p.get("process_name", p["process_id"])),
                }
            )
        for index, host in enumerate(doc.get("network", {}).get("hosts", [])):
            ip = ipaddress.ip_address(host)
            entities.append(
                {
                    "id": f"host:{index}",
                    "entity_type": "ipv4" if ip.version == 4 else "ipv6",
                    "value": str(ip),
                }
            )
        for index, dropped in enumerate(doc.get("dropped", [])):
            if dropped.get("sha256"):
                entities.append(
                    {"id": f"hash:{index}", "entity_type": "file_hash", "value": dropped["sha256"]}
                )
        for index, dns in enumerate(doc.get("network", {}).get("dns", [])):
            domain = f"dns:{index}"
            entities.append({"id": domain, "entity_type": "domain", "value": dns["request"]})
            for j, answer in enumerate(dns.get("answers", [])):
                if answer.get("type") not in {"A", "AAAA"}:
                    continue
                ip = ipaddress.ip_address(answer["data"])
                alias = f"answer:{index}:{j}"
                entities.append(
                    {
                        "id": alias,
                        "entity_type": "ipv4" if ip.version == 4 else "ipv6",
                        "value": str(ip),
                    }
                )
                evidence.append(
                    {
                        "id": alias,
                        "evidence_type": "observation",
                        "description": "Sandbox DNS response.",
                        "limitations": ["No DNS observation timestamp supplied by this adapter."],
                    }
                )
                events.append(
                    {
                        "id": alias,
                        "source": domain,
                        "target": alias,
                        "relationship_type": "RESOLVES_TO",
                        "evidence_ids": [alias],
                        "origin": "direct_observation",
                    }
                )
        return {
            "format": "sandbox",
            "report_id": report_id,
            "entities": entities,
            "events": events,
            "evidence": evidence,
        }

    def _attack(self, document, version):
        if document.get("type") != "bundle" or not isinstance(document.get("objects"), list):
            raise ValueError("expected ATT&CK STIX 2.1 bundle")
        objects = document["objects"]
        if len(objects) > 50000:
            raise ValueError("ATT&CK bundle exceeds 50000 object limit")
        version = version or document.get("catalog_version")
        if not version or not isinstance(version, str):
            raise ValueError("catalog_version is required (use --catalog-version)")
        nodes, tactics, errors, accepted = {}, {}, [], 0
        for index, obj in enumerate(objects):
            if not isinstance(obj, dict):
                errors.append({"record_index": index, "error": "invalid STIX object"})
                continue
            if obj.get("type") not in {"attack-pattern", "x-mitre-tactic"}:
                continue
            try:
                with self.store.transaction():
                    if obj.get("spec_version", "2.1") != "2.1":
                        raise ValueError("STIX 2.1 objects required")
                    refs = [
                        r["external_id"]
                        for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack" and "external_id" in r
                    ]
                    if len(refs) != 1 or not obj.get("id") or not obj.get("name"):
                        raise ValueError("ATT&CK object missing identity")
                    kind = (
                        "attack_technique" if obj["type"] == "attack-pattern" else "attack_tactic"
                    )
                    catalog_time = now().isoformat()
                    try:
                        previous = self.store.get_node(stable_id("node", kind, refs[0]))
                        if previous.attributes.get("catalog_hash") == self.digest:
                            catalog_time = previous.attributes["catalog_import_time"]
                    except KeyError:
                        pass
                    node = Node.create(
                        kind,
                        refs[0],
                        display_name=obj["name"],
                        attributes={
                            "catalog_versions": [version],
                            "stix_id": obj["id"],
                            "revoked": bool(obj.get("revoked", False)),
                            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                            "modified": obj.get("modified"),
                            "catalog_import_time": catalog_time,
                            "catalog_hash": self.digest,
                        },
                    )
                    self.store.put_node(node)
                    ev = self._ev(
                        f"attack:{PARSER_VERSION}:{self.digest}:{obj['id']}",
                        "catalog",
                        f"ATT&CK catalog {version}: {refs[0]}",
                    )
                    self._edge(node.node_id, self.source.node_id, "REPORTED_BY", [ev])
                    nodes[obj["id"]] = (node, ev)
                    if kind == "attack_tactic":
                        tactics[obj.get("x_mitre_shortname", "")] = node
                accepted += 1
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                errors.append(self._error(index, exc))
        for index, obj in enumerate(objects):
            if not isinstance(obj, dict):
                continue
            try:
                with self.store.transaction():
                    if obj.get("type") == "attack-pattern" and obj.get("id") in nodes:
                        node, ev = nodes[obj["id"]]
                        for phase in obj.get("kill_chain_phases", []):
                            if phase.get("kill_chain_name") == "mitre-attack":
                                tactic = tactics.get(phase["phase_name"])
                                if tactic is None:
                                    raise ValueError("catalog tactic reference missing")
                                self._edge(
                                    node.node_id,
                                    tactic.node_id,
                                    "TECHNIQUE_OF",
                                    [ev],
                                    "deterministically_derived",
                                )
                    elif (
                        obj.get("type") == "relationship"
                        and obj.get("relationship_type") == "subtechnique-of"
                    ):
                        child, _ = nodes[obj["source_ref"]]
                        parent, _ = nodes[obj["target_ref"]]
                        ev = self._ev(
                            f"attack:{PARSER_VERSION}:{self.digest}:{obj['id']}",
                            "catalog",
                            "Official sub-technique relationship.",
                        )
                        self._edge(
                            child.node_id,
                            parent.node_id,
                            "SUBTECHNIQUE_OF",
                            [ev],
                            "source_reported",
                        )
                        accepted += 1
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                errors.append(self._error(index, exc))
        return accepted, errors
