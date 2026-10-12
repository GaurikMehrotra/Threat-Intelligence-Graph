# Reusable cloud environment

The prepared machine uses Python 3.12.14, `/workspace/tig-venv`, and the existing checkout
`/workspace/Threat-Intelligence-Graph`. Each cloud task is already isolated; use this checkout and do not
create a worktree unless explicitly requested. No external database service, LLM, paid API, or mandatory
secret is required. Package registries and raw.githubusercontent.com are the setup destinations; the
provided package-manager preset already permits them. No network policy change is needed.

`bash scripts/install.sh` installs pinned dependencies, checks dependency consistency, verifies/fetches
the pinned official catalog, and creates a synthetic demo only if its database is absent. Tests run
with `/workspace/tig-venv/bin/python -m pytest -q` and Ruff from the same venv. Optional browser automation
uses requirements-browser.txt and existing system Chromium; it is not required for normal development.

`/workspace/tig-venv/bin/python -m src.main --db local/demo.sqlite3 serve --port 8000` starts the read-only
analyst service. Use local `/api/health`, `/api/search?value=c2.example`, and an evidence query for
functional readiness; an open port alone is insufficient. Do not supply user-facing localhost preview
links during onboarding. Processes must restart in new tasks; installed dependencies, source and
local databases can be retained in a published snapshot. Avoid rerunning the demo for real databases.

Installation and startup instructions are saved as cloud configuration draft fields for review.
Saving a draft does not execute it, publish a snapshot, or validate fresh-task restoration. Review/save
and publish through environment settings when ready. The repository contains application source and pinned setup instructions. Ignored databases and the raw
catalog are local artifacts; a new checkout can recreate the demo and fetch the verified catalog.
A current prepared snapshot is distinct from remotely reproducible source.
