# Evaluation of the initial release

## Method

Ordinary tests run offline with pytest using synthetic, explicitly labeled observations, documentation
IPs and temporary SQLite databases. They do not use real malware, a paid feed/API, external service, or
LLM. Ruff checks application, tests and scripts. Test names identify expected behavior; failed/skipped
checks are not counted as passes. `scripts/evaluate.py` writes reproducible machine-readable measurements
to `local/evaluation.json`. The captured initial result is `docs/evaluation_results.json`.

The sandbox fixture supplies five ground-truth explicit events: process communication, spawn, file
creation, registry write, and behavior-to-technique mapping. Expected endpoint aliases and relationship
types are compared with extracted edges, not just counts. Precision = TP/(TP+FP); recall = TP/(TP+FN).
Evidence completeness = extracted claims whose evidence IDs are nonempty and resolve / all extracted
claims. These metrics measure the supported explicit-event adapter, not arbitrary natural language
reports or the truth of an external source.

Duplicate tests compare canonical identities and persisted node/edge/evidence counts across equivalent
values and repeated source files. Contradiction tests retain parallel active/disputed attribution and
evidence, checking conservative score rationale. Query tests use a known cycle, chain, isolated nodes,
and star neighborhoods. Expected shortest path length is three, with no path to an isolated node;
small depth and node limits return bounded/truncated results. Temporal tests distinguish unknown
intervals from known filtering. Migration tests verify initial version 1, reopen persistence, and reject
future unknown versions. Security tests include malformed vendor objects, SQL-injection strings, secret
metadata/URL credentials, malicious HTML/shell-looking text, symlinks, unsafe filenames, oversized API
bodies, source delimiter collisions and invalid hypothesis promotion.

## Results actually observed

Final ordinary suite: **40 passed, 0 failed, 0 skipped**. Ruff passed; Node's JavaScript syntax check
passed; `pip check` found no broken requirements. Starlette emits one deprecation warning about its
current httpx TestClient integration; test requests still execute and pass. This dependency warning is
not a failed assertion and is not suppressed.

Chromium smoke validation used the running loopback demo service: search, rendered nodes/edges, evidence
inspector, bounded expansion, saved case opening, and JSON download passed with **0 JavaScript errors**.
The initial test harness's string-evaluation wait conflicted with CSP; replacing the wait with locator
assertions resolved it without relaxing CSP. The final demo view rendered 19 nodes and 27 claims.

Official catalog integration used the pinned MITRE Enterprise ATT&CK **17.1** bundle: 44,879,463 bytes,
22,653 STIX objects. The first import was rejected by the old 20,000-object limit; the catalog-specific
limit was increased to 50,000, retaining the 64 MiB byte limit. The corrected import accepted **1,307**
supported objects/sub-technique relationships with **0 record failures**. Other STIX object types are
outside this adapter's scope, not silently described as imported. The exact versioned origin and SHA256
are in `configs/attack_catalog.json`. Fresh HTTPS download and checksum validation were exercised, not
just a presence check. The full raw catalog is local/ignored; test fixtures remain small and offline.

## Measured synthetic performance

One run on Python **3.12.14**, Linux x86_64, using `perf_counter` wall time. Peak memory uses tracemalloc
around ingestion; it excludes preallocated input, native SQLite allocations and total process RSS.

| Measurement | Observed result |
| --- | --- |
| IOC records | 500 |
| Persisted nodes / edges / evidence | 1,002 / 1,500 / 500 |
| Initial ingestion, with tracemalloc enabled | 5.0555 seconds |
| Repeat ingestion, without tracemalloc | 1.6418 seconds |
| Peak Python allocations during initial ingestion | 0.356 MiB |
| Depth-3 neighborhood, limit 100 | 0.2589 seconds |
| Returned nodes / edges | 100 / 195, explicitly truncated |
| Repeat import graph/evidence/audit identities | Unchanged |
| Ground-truth sandbox events | 5 |
| TP / FP / FN | 5 / 0 / 0 |
| Synthetic extraction precision / recall | 1.0 / 1.0 |
| Evidence-reference completeness | 1.0 |

The comparison of initial versus repeat timing has different instrumentation; do not interpret it as
a speedup benchmark. Import history legitimately grows on repeat runs, while content identities remain
stable. The whole-demo repeat check also retained 25 nodes, 32 edges, 15 evidence records and 74 content
audit entries, while import attempts grew from 5 to 10.

## Limits of the evidence

A tiny explicit-event fixture is not representative of all sandbox reports. No real-world extraction
accuracy, malware detection effectiveness, actor attribution accuracy, calibrated confidence, production
capacity or security certification is claimed. Timings are single-run observations on this machine,
not throughput guarantees or multi-user load results. A pinned historical ATT&CK catalog does not
establish current intelligence. Full STIX semantic validation and arbitrary vendor report adapters are
not implemented. Field quality and upstream independence are supplied claims, not independently audited.
Large multi-source temporal graphs, concurrent write contention and remote multi-user deployment need
separate evaluation before those workflows are advertised.
