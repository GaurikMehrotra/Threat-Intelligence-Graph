# Graph schema v1

All records require `schema_version=1`. Timestamps, when known, require a timezone. Unknown times and
confidence remain null. Extra fields are rejected; arbitrary safe metadata belongs in `attributes`.

## Nodes

Required: `node_id`, `entity_type`, `canonical_value`, `display_name`, `created_at`, `updated_at`,
`attributes`, `schema_version`; optional `first_seen` and `last_seen` must form a valid interval.
Node IDs are SHA256 over a JSON tuple of type and canonical value, prefixed `node_`.

Types: ipv4, ipv6, domain, url, file_hash, file, malware_sample, malware_family, process, registry_key,
sandbox_report, intelligence_report, attack_technique, attack_tactic, campaign, threat_actor, source,
investigation. Registry keys extend the initial entity list so MODIFIED_REGISTRY has a meaningful target.

Canonical rules: IPv4/IPv6 use `ipaddress`; domains use IDNA, lowercase and trailing-dot removal;
HTTP(S) URLs normalize scheme, host, default port and empty path, while preserving path case/query/
fragment. URL credentials and credential-like query keys are rejected. File hashes accept hex MD5,
SHA1, SHA256 and SHA512 (algorithm implied by length). ATT&CK IDs validate technique/sub-technique/tactic
syntax. Files/processes/registry values are observation-scoped, never identified by a path/name alone.
Named malware/campaign/actor/report entities use source-defined IDs in a source scope. Identical display
names do not merge; equivalent actors across sources need an explicit association claim.

## Evidence

`evidence_id`, `evidence_type`, `source_id`, `source_record_id`, `ingestion_time`, `description`,
`raw_reference`, `limitations`, `schema_version`; optional `observation_time`, `integrity_hash` (SHA256),
`upstream_claim_id`, and `quality` (0..1 source-supplied quality rubric). Types: observation, source_claim,
behavior, catalog, analyst, hypothesis. `ev_` identifiers derive from source and source record.
The source must reference a source node. Evidence is immutable: conflicting reuse of an ID fails.
Content references use `sha256:DIGEST#RECORD` rather than internal filesystem paths. Evidence quality
is not relationship confidence or an assertion of source independence.

## Relationship claims

Required: `edge_id`, `source_node_id`, `target_node_id`, `relationship_type`, nonempty `evidence_ids`,
`source_id`, `relationship_origin`, `created_at`, `schema_version`. Optional: `confidence`,
`confidence_rationale`, `valid_from`, `valid_until`, `rationale`; `status` is active, disputed, rejected,
or superseded. Numeric supplied confidence requires a supplied rationale. Actor attribution and campaign
membership require explicit source rationale. The edge ID hashes endpoints, relationship, source,
origin, interval and status, so different claims are retained. Duplicate evidence IDs are collapsed.

Origins: direct_observation, source_reported, deterministically_derived, analyst_confirmed, hypothesis.
Direct observations require observation/behavior evidence; analyst confirmation requires analyst
records; hypothesis evidence cannot support a non-hypothesis origin. ATT&CK mappings additionally
require behavioral evidence and a locally catalog-validated technique. Ingestion does not generate
attribution or campaign claims from co-occurrence, shared infrastructure, or similar ATT&CK mappings.

| Relationship | Permitted endpoints | Meaning |
| --- | --- | --- |
| RESOLVES_TO | domain → IPv4/IPv6 | Explicit recorded DNS answer; not ownership |
| CONTAINS | report/file/sample/investigation → entity | Explicit containment or selected case membership |
| OBSERVED_IN | entity except source → report | Listed in report; no causality |
| COMMUNICATED_WITH | process/sample → IP/domain/URL | Explicit observed communication |
| DROPPED_FILE | process/sample → file/sample | Explicit file creation |
| SPAWNED_PROCESS | process → process | Explicit process creation |
| MODIFIED_REGISTRY | process/sample → registry_key | Explicit registry write |
| ASSOCIATED_WITH | entity → entity | Explicit association, not attribution or causality |
| MAPPED_TO_TECHNIQUE | process/sample/report → technique | Evidence-backed behavioral mapping |
| REPORTED_BY | entity except source → source | Source published the entity or claim |
| PART_OF_CAMPAIGN | IOC/file/sample/report/family → campaign | Explicit campaign membership with rationale |
| ATTRIBUTED_TO | campaign/family/sample/report → actor | Explicit attribution with rationale, possibly disputed |
| SUPPORTS | report → entity | Report provides supporting information about an entity |
| CONTRADICTS | report → entity | Entity-level contrary information; not automatic negation of every edge |
| TECHNIQUE_OF | technique → tactic | Official ATT&CK membership |
| SUBTECHNIQUE_OF | technique → technique | Official ATT&CK parent relationship |

The exact machine-enforced endpoint sets are available from `/api/schema`. Claims are directed; default
neighborhoods and shortest paths intentionally view connectivity as undirected, with optional directed
path search. Contradictions are represented by separate disputed/rejected claims or report-to-entity
CONTRADICTS edges, not by destructive replacement. Claim-to-claim evidence links are not a v1 entity type.

Future schema revisions must add migrations and compatibility tests. Unknown database/model versions
are rejected rather than interpreted silently.
