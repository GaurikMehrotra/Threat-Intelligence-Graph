# Offline input contracts

Use UTF-8 JSON/CSV, regular non-symlink files, at most 64 MiB. A source identity is mandatory, either in
JSON `source_id` or via CLI `--source-id`. The API accepts documents, never file paths (8 MiB limit).
No URLs/IPs from these records are fetched. Remove credentials and unnecessary sensitive fields before
import. Timestamps use ISO 8601 with timezone. `schema_version` defaults to 1.

## IOCs

```json
{"format":"ioc","source_id":"publisher-1","records":[
  {"id":"dns-1","entity_type":"domain","value":"Example.org.",
   "report_id":"bulletin-1","resolves_to":"192.0.2.1",
   "observation_time":"2025-01-01T12:00:00Z",
   "description":"Source explicitly reported a DNS answer.","quality":0.8}
]}
```

`records` accepts up to 20,000 independent records. `id`, `entity_type`, `value` are required. Entity
choices: ipv4, ipv6, domain, url, file_hash. Optional fields: description, observation_time, report_id,
upstream_claim_id, quality, limitations, resolves_to. `resolves_to` is only valid for a domain and creates
an explicit source-reported DNS claim. Without it, presence creates REPORTED_BY and optional OBSERVED_IN
only. Unknown maliciousness is not filled in. Arrays of IOC records are accepted with CLI source identity.
CSV uses these column names; omit complex list fields and use JSON when they are needed. IDs should be
stable within the originating source. A record with bad values fails independently. Exit status and
import history report partial success; repeated exact files preserve identity and provenance.

## Sandbox

`data/fixtures/sandbox.json` is a complete behavioral demonstration. Top-level fields: format=sandbox,
source_id, report_id, entities, events, evidence. Entity aliases and evidence aliases are local to the
report. Each entity has id, entity_type, value, optional display_name, attributes, first_seen, last_seen.
Evidence has id, evidence_type, description, optional observation_time, quality, limitations,
upstream_claim_id. An event has id, source alias, target alias, relationship_type, nonempty evidence_ids,
origin, and optional validity/confidence/rationale/status fields. Missing references fail the entire
report transaction. Process/file/registry identities are report-scoped. Membership edges are sourced
from report content; they do not establish a behavior. Every behavior requires its explicit event.

For mappings, import the applicable ATT&CK catalog first, list the technique as an entity, and reference
behavior evidence in MAPPED_TO_TECHNIQUE. Mere technique presence produces no mapping.

## Cuckoo subset

Use `--adapter cuckoo --source-id YOUR_SANDBOX`. Supported fields:
`info.id`, `behavior.processes[].process_id/process_name`, `network.hosts[]`,
`network.dns[].request/answers[].type/data`, and `dropped[].sha256`.
Processes, hosts, and dropped hashes are OBSERVED_IN the report. Only explicit A/AAAA DNS answers
produce RESOLVES_TO. Parent-process links, API calls, registry writes, and per-process traffic are not
guessed from this subset. Convert richer vendor observations to the documented sandbox contract to
retain explicit semantics and timestamps. Other vendor fields are not ingested by this adapter;
retain the original report for review.

## Generic graph

`data/fixtures/attribution.json` demonstrates conflicting attribution. Top-level format=graph,
source_id, nodes, evidence, edges. Node entries use the same entity input fields as sandbox entities;
evidence and edge entries use the same evidence/event input fields. Every edge resolves local aliases.
This is one atomic document, not an unchecked bulk database loader. No arbitrary stable IDs, embedded
sources, or fabricated catalog verification are trusted. Explicit technique IDs can refer to already
cataloged techniques. Named entities use source-scoped identifiers; processes/files/registry keys
use source + graph + local alias scope. Keep aliases stable across reprocessing.

## ATT&CK

Use a STIX 2.1 bundle from MITRE Enterprise ATT&CK with CLI `--catalog-version VERSION`. The top-level
bundle also supports `catalog_version` and `source_id` for fixtures. Up to 50,000 objects are accepted;
attack-pattern and x-mitre-tactic objects need one `mitre-attack` external ID, STIX ID and name.
The adapter creates technique/tactic nodes, tactic memberships from mitre-attack kill-chain phases,
and explicit subtechnique-of relationships. Other STIX object/relationship types are outside v1 scope.
Deprecated/revoked nodes remain valid historical references. Unsupported or malformed references are
reported; nothing is invented to repair them. Import version and content hash distinguish catalogs.

## Errors and reprocessing

Import results include adapter, parser_version, status, accepted, failed, and redacted errors with record
index/validation field type. Accepted counts denote IOC records, entire sandbox/graph documents, or
supported ATT&CK objects/sub-technique relationships; unsupported STIX types are unrun, not failed.
Evidence references contain the file digest and record identity. Parser version changes create new
observations while canonical entities remain stable. Independent observations stay separate; analysts
can supply a shared upstream_claim_id only when the same originating claim is known.
