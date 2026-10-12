# Security and safe intelligence handling

Imported records are data, never tool instructions. No malware execution, shell evaluation, DNS lookup,
URL visit, IP connection, automatic upload, external enrichment, or LLM call exists in ingestion.
The standalone ATT&CK downloader has one pinned HTTPS origin and a verified artifact checksum; it is
an explicit setup operation, not driven by report contents.

Pydantic rejects unsupported versions/fields/types, invalid intervals, unknown origins, missing evidence,
invalid observable values, incompatible relationship endpoints and unsupported technique mappings.
Generic imports cannot assert catalog verification. Hypothesis evidence cannot be promoted into an
observed/reported/confirmed relationship; analyst confirmation requires analyst evidence. Source/record
identities use structured hash tuples to avoid collisions from delimiters or display names.

Input is limited to 64 MiB files, 20,000 IOC records, 50,000 STIX objects, bounded graph/sandbox collections,
metadata nesting 12 and text field length 16,384. The API rejects bodies over 8 MiB before JSON parsing,
including chunked requests. Graph traversals cap depth, nodes, edges and work; pagination is validated.
SQL values are parameterized. Newer unknown database schema versions are rejected. Source nodes,
endpoints and evidence references are validated and backed by foreign keys.

The importer only accepts regular non-symlink input files; it never modifies them. Sources reference
content digests, not private server paths. API imports accept documents rather than file paths.
Trusted local CLI configuration chooses the database/output root. CLI report filenames cannot contain
path components and exports use exclusive creation, refusing existing files or a symlink output root.
The default export root is a trusted directory in the checkout; do not use attacker-controlled parent
directories. These local checks are not a filesystem sandbox for hostile concurrent users.

Sensitive metadata keys (password, secret, token, api_key, authorization, credential) and URL credentials/
credential-like query parameters are rejected. Invalid payload values and internal paths are omitted
from API validation responses/CLI errors. Server access logging is disabled so search query values are
not written to request logs. Analysts must still redact reports before import: arbitrary prose can
contain secrets the program cannot recognize. Local databases, original reports and exports need access
controls, retention policy and encryption appropriate to your data. No software promise of complete
secret detection is made.

Browser rendering uses textContent/createElement, never untrusted innerHTML or executable links.
Markdown escapes HTML and markup; JSON retains untrusted strings as data. The browser has no external
asset dependencies. CSP restricts scripts/styles/connections to self and disables objects, framing and
unsafe eval. Extracted URLs/IPs are displayed as text, not contacted. Hypotheses are visually distinct
by line pattern and labels; shapes supplement entity colors. Exported reports remain untrusted data
when opened in other tools; use safe JSON/Markdown viewers.

Read APIs assume a local trusted analyst. Server defaults to loopback; administrative writes are disabled
unless TIG_ADMIN_TOKEN is explicitly configured and supplied as a bearer header. Tokens are never
stored in the frontend, logs, reports, source fixtures, or database. Authentication protects writes,
not multi-user read access. Before any remote deployment, provide TLS, authenticated/authorized reads,
per-user case controls, rate limiting, auditing of user identities and operational backup/recovery.
No CORS allow-all configuration or unauthenticated administrative route is provided.

Tests cover SQL injection strings, credential fields, malicious markup/shell-looking text, path traversal,
symlinks, oversized requests, identifier validation, hypothesis promotion, missing references, source
scope collisions, failed transactional imports and bounded high-degree neighborhoods. They do not
constitute a penetration test or production security certification.
