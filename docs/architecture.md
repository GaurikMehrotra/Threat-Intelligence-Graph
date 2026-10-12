# Architecture and persistence

## Components and flow

`src/schemas/models.py` validates versioned node/evidence/edge records and relationship endpoint rules.
`src/normalization/entities.py` establishes canonical observable identities without network access.
`src/ingestion/formats.py` defines input contracts; `pipeline.py` identifies sources, registers immutable
content-addressed evidence, extracts explicit claims, validates them, and persists transactions.
`src/analytics/queries.py` implements bounded graph algorithms, while `src/correlation/scoring.py`
explains optional heuristic confidence. `src/reporting/reports.py` creates investigations and exports.
`src/main.py` provides the CLI; `src/api/app.py` serves the API and standalone frontend.

No visualization or API dependency enters the ingestion, scoring or graph algorithms. All database SQL
is in `src/storage/sqlite.py`. `GraphStore` is the business-facing protocol (record operations,
transactions, scans, incident/matching queries, import history, integrity and shared-indicator queries).
Another storage engine must implement this interface, including transaction and immutable-evidence
semantics. This release implements SQLite only; Neo4j is an evaluated future option with service and
migration overhead that the initial single-machine workflow does not justify.

## Database

Migration 1 initializes relational `nodes`, `edges`, `evidence`, `edge_evidence`, `imports`, and `audit`
tables. `PRAGMA user_version` drives ordered migrations; newer unknown schemas are rejected.
Foreign keys are enabled on every connection. Node identity and canonical uniqueness, evidence identity,
source record uniqueness, edge endpoints and the edge-evidence association are enforced. Indexes cover
node type/value and both edge endpoints/relationship type. JSON bodies preserve validated metadata.
WAL is enabled; each API operation opens its own connection with a 10-second busy timeout.
The app targets one local analyst; large concurrent write workloads are not characterized.

Nested savepoints support transactional composition. An IOC batch commits each valid record and rolls
back a failed record, including any nodes created before its failure. A sandbox/generic graph document
is one transaction. ATT&CK objects and memberships are validated separately so invalid objects can be
reported without aborting unrelated objects. Source registration and import history persist even if a
record/document fails. Unexpected process termination can leave an import marked running; review its
status rather than assuming completion. No recovery daemon is implemented.

## Provenance and updates

Observable identities are stable across sources. Processes/files/registry keys use a source, report
and local-ID scope hashed as a tuple; named malware/actor/campaign/report identifiers are source-scoped.
This avoids ambiguous delimiter collisions and accidental merging by names. Source-specific original
representations are preserved; conflicting attribute values are retained in variations rather than
silently replacing earlier assertions. The earliest/latest known seen times are combined without
inventing missing observations. ATT&CK versions accumulate with differing catalog metadata retained.

Evidence IDs use a source and source-record identity; adapter-generated record IDs include parser
version and input digest. Exact reimports neither duplicate records nor add audit entries for unchanged
data. A changed report/parser creates new immutable evidence. A copied upstream claim can be identified
explicitly for scoring; the system cannot discover undisclosed copying automatically.

Edges group one source/origin/status/temporal claim and accumulate distinct evidence references.
Separate sources, statuses, intervals or origins remain separate claims. Rejected/superseded claims
are preserved and omitted from ordinary traversal; `include_inactive` permits neighborhood inspection.
Evidence survives later disagreement. Audit entries retain previous and current bodies for actual
changes, with UTC timestamps. There are no deletion endpoints.

## Data handling and deployment

Raw input files are hashed, referenced by opaque content identifiers, and not changed or copied into
exports. Analysts must retain original artifacts to resolve these references. Database and reports are
sensitive local artifacts even though this software rejects obvious credential fields. No automatic
external requests occur during ingestion. The optional pinned ATT&CK downloader is a standalone,
explicit operation. Frontend assets are local and use a restrictive content-security policy.

Database paths are trusted CLI/deployment configuration. Remote import requests accept JSON documents,
not filesystem paths, and are disabled without explicit admin authentication. The default server is
loopback-only; full multi-user hosting requires additional authentication and operational controls.
