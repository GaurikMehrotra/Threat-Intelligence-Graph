# Phase results

The implementation began in an empty repository with no prior files or changes;
no source, dataset or report was deleted. Local databases/artifacts are ignored; early generated demo
state was retained under `local/initial-*` when identity hardening was introduced.

| Phase | Changed files / implementation | Checks executed and outcome | Limitations / next milestone |
| --- | --- | --- | --- |
| 0 Audit | No existing architecture, schema, parser, data, tests or dependencies; Python 3.12.14 available; empty Git status | Repository, HEAD, refs and runtime inspected | Build the initial schema; no reusable implementation exists |
| 1 Schema/storage | `pyproject.toml`, `.gitignore`, package initializers; `src/schemas/models.py`, `src/normalization/entities.py`, `src/storage/sqlite.py`, `tests/test_storage.py` | 10 storage/schema tests passed; Ruff passed after fixes | SQLite only; next: offline adapters |
| 2 Ingestion | `src/ingestion/formats.py`, `pipeline.py`, `tests/test_ingestion.py` | Cumulative 16 tests passed including CSV/JSON, partial failures, repeats, catalog and sandbox imports | Documented formats plus conservative Cuckoo subset; next: extraction checks |
| 3 Extraction | Evidence/source/temporal-aware explicit extraction in `pipeline.py`, endpoint and mapping guards in storage | Same 16-test run verified communication, DNS, no co-occurrence attribution, scoped processes and mapping evidence | No free-text/vendor heuristics; next: bounded investigation queries |
| 4 Queries | `src/analytics/queries.py`, `tests/test_analytics.py` | Cumulative 21 tests passed including neighbors, paths, cycles, isolation, shared nodes, components, degrees and time filters | Capped traversal, truncated results; next: scoring |
| 5 Scoring | `src/correlation/scoring.py`, `configs/scoring.json`, attribution/scoring tests | Same 21-test run verified duplicate stability and preserved disputed attribution | Heuristic only; quality/independence may be unknown; next: CLI/reports |
| 6 CLI/reports | `src/main.py`, `src/reporting/reports.py`, `tests/test_cli_reports.py` | Cumulative 24 tests passed including subprocess CLI runs/help, evidence-rich exports and safe exclusive writes | Current-state seeded investigations, no immutable case snapshots; next: analyst interface |
| 7 API/visualization | `src/api/app.py`, `frontend/index.html`, `style.css`, `app.js`, `tests/test_api.py`, `scripts/browser_smoke.py` | Initial 3 API tests passed; actual Chromium workflow passed with no JS errors | Local read-oriented UI; authenticated administrative API/CLI writes; next: hardening |
| 8 Evaluation/hardening | `tests/test_hardening.py`, fixtures, pinned requirements, catalog/scoring configs, demo/evaluation/catalog/install scripts, README and docs; storage interface isolation; origin and input guards | Final 40 tests passed; Ruff, JS syntax, dependency checks, synthetic demo/repeat, benchmark, browser and official catalog import/download all validated | Synthetic research baseline; remote multi-user/production and real-world accuracy remain unvalidated |

The requested initial phases are implemented. The milestone after this initial release would be
validation against sanitized, permissioned real-world reports and additional explicitly specified
vendor adapters, rather than inferring support from synthetic success. Publishing the cloud environment is separate from versioning source and must be done through environment settings.
