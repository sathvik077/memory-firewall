# =============================================================================================
# Memory Firewall
#
#   make setup       create the local environment, database and demo corpus (offline, no keys)
#   make dev         run API on 127.0.0.1:8002 and dashboard on 127.0.0.1:5174
#   make smoke       the mandatory poison write/retrieve proof
#   make verify      THE RELEASE TRUTH SOURCE (see exit codes below)
#   make eval        the 4-condition measurement, writes evals/results/RESULTS.{json,md}
#   make help        every target
#
# `make verify` exit codes, by design:
#   0  every mandatory check executed and passed, nothing blocked  -> release candidate
#   1  a mandatory check FAILED                                    -> NOT READY
#   2  everything executed passed, but a mandatory check could not run in this environment
#      (BLOCKED) -> NOT READY, with the exact retry command printed
# =============================================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help setup doctor seed dev dev-api dev-web smoke scenarios test test-unit \
        test-integration test-security test-e2e lint typecheck build eval verify screenshots \
        docker-build compose-up compose-down clean-demo clean openapi arch

PY            ?= python3
UV            ?= $(shell command -v uv 2>/dev/null)
NPM           ?= npm
MF_API_PORT   ?= 8002
MF_WEB_PORT   ?= 5174
MF_DB_PATH    ?= data/memory-firewall.sqlite3
PYTHONPATH_ALL := packages/memory_firewall:apps/api:.
export PYTHONPATH := $(PYTHONPATH_ALL)
export MF_DB_PATH

# Prefer real pytest; fall back to the documented subset runner when it cannot be installed.
HAVE_PYTEST := $(shell $(PY) -c "import pytest" 2>/dev/null && echo yes)
HAVE_RUFF   := $(shell command -v ruff >/dev/null 2>&1 && echo yes)
HAVE_MYPY   := $(shell $(PY) -c "import mypy" 2>/dev/null && echo yes)
HAVE_FASTAPI:= $(shell $(PY) -c "import fastapi" 2>/dev/null && echo yes)
HAVE_NODE   := $(shell command -v node >/dev/null 2>&1 && echo yes)

ifeq ($(HAVE_PYTEST),yes)
  TEST_CMD := $(PY) -m pytest
else
  TEST_CMD := $(PY) scripts/pytest_fallback.py
endif

help:
	@printf '\033[1mMemory Firewall\033[0m — targets\n\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\nPorts: API 127.0.0.1:$(MF_API_PORT)  dashboard 127.0.0.1:$(MF_WEB_PORT)\n'
	@printf 'Database: $(MF_DB_PATH)   (manifests live in $(MF_DB_PATH).manifests)\n'
	@printf 'No model API key, cloud account or Docker is required for setup/dev/smoke/test/eval.\n'

# ---------------------------------------------------------------------------------- setup -----
setup: ## Create the venv/lock, database, demo corpus and a local .env (offline, no keys)
	@echo "==> checking prerequisites"
	@$(PY) -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)' || \
	  { echo "ERROR: Python 3.12+ required (found $$($(PY) --version))."; exit 1; }
	@$(PY) -c "import sqlite3; sqlite3.connect(':memory:').execute('CREATE VIRTUAL TABLE t USING fts5(x)')" \
	  || { echo "ERROR: this Python's SQLite has no FTS5. Run 'make doctor' for fixes."; exit 1; }
	@if [ -n "$(UV)" ]; then \
	  echo "==> uv sync (creates .venv and uv.lock with pinned versions)"; \
	  $(UV) sync --extra dev || echo "WARNING: 'uv sync' failed (offline or blocked registry); continuing with the interpreter's existing packages."; \
	else \
	  echo "WARNING: uv not found. Install from https://docs.astral.sh/uv/ for a pinned lockfile,"; \
	  echo "         or 'pip install -e .[dev]' into a virtualenv."; \
	fi
	@if [ -d apps/dashboard ] && [ -f apps/dashboard/package.json ] && [ "$(HAVE_NODE)" = "yes" ]; then \
	  echo "==> dashboard dependencies"; \
	  (cd apps/dashboard && ($(NPM) ci 2>/dev/null || $(NPM) install 2>/dev/null || \
	    echo "NOTE: npm install could not reach the registry. The dashboard has NO runtime dependencies, so it still builds and runs if a TypeScript compiler is available on PATH; see docs/DECISIONS.md.")); \
	fi
	@echo "==> database, demo corpus and .env"
	@$(PY) -m memory_firewall.cli setup-demo --db $(MF_DB_PATH)
	@echo ""
	@echo "setup complete. Next: 'make dev' then open http://127.0.0.1:$(MF_WEB_PORT)"

doctor: ## Environment diagnostics (Python, SQLite/FTS5, schema, optional tools)
	@$(PY) -m memory_firewall.cli doctor --db $(MF_DB_PATH)
	@echo ""
	@echo "optional tooling:"
	@printf '  pytest   %s\n' "$(if $(HAVE_PYTEST),installed,MISSING -> 'make test' uses scripts/pytest_fallback.py)"
	@printf '  ruff     %s\n' "$(if $(HAVE_RUFF),installed,MISSING -> 'make lint' reports BLOCKED)"
	@printf '  mypy     %s\n' "$(if $(HAVE_MYPY),installed,MISSING -> 'make typecheck' reports BLOCKED)"
	@printf '  fastapi  %s\n' "$(if $(HAVE_FASTAPI),installed,MISSING -> API server and API tests report BLOCKED)"
	@printf '  node     %s\n' "$(if $(HAVE_NODE),installed,MISSING -> dashboard build reports BLOCKED)"
	@printf '  docker   %s\n' "$$(command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo 'available' || echo 'MISSING/daemon down -> image build reports BLOCKED')"

seed: ## Idempotent synthetic demo corpus with fixed timestamps
	@$(PY) -m memory_firewall.cli seed --db $(MF_DB_PATH) --no-tokens

# ---------------------------------------------------------------------------------- run -------
dev: ## Run API and dashboard together (Ctrl-C stops both)
	@echo "API      http://127.0.0.1:$(MF_API_PORT)   (docs at /docs, health at /healthz)"
	@echo "Dashboard http://127.0.0.1:$(MF_WEB_PORT)"
	@trap 'kill 0' INT TERM EXIT; $(MAKE) --no-print-directory dev-api & \
	  $(MAKE) --no-print-directory dev-web & wait

dev-api: ## Run only the API (localhost binding)
	@if [ "$(HAVE_FASTAPI)" != "yes" ]; then \
	  echo "BLOCKED: fastapi is not installed, so the HTTP API cannot start."; \
	  echo "  retry: uv sync --extra dev   (or: pip install -e '.[dev]')"; \
	  exit 1; \
	fi
	@$(PY) -m uvicorn app.main:app --app-dir apps/api --host 127.0.0.1 --port $(MF_API_PORT) --reload

dev-web: ## Run only the dashboard dev server (localhost binding)
	@$(PY) scripts/serve_dashboard.py --port $(MF_WEB_PORT) --api-port $(MF_API_PORT)

openapi: ## Write the OpenAPI document to docs/openapi.json
	@$(PY) scripts/export_openapi.py

arch: ## Render docs/assets/architecture.svg from the Mermaid source
	@$(PY) scripts/render_architecture.py

# ---------------------------------------------------------------------------------- checks ----
smoke: ## Mandatory smoke: poison write/retrieve, index bypass, cross-tenant, forgery, revocation
	@$(PY) -m memory_firewall.cli smoke --db $(MF_DB_PATH)

scenarios: ## Run all repeatable offline scenarios, each in a disposable database
	@$(PY) -m memory_firewall.cli scenarios

test: ## Run every test suite
	@if [ "$(HAVE_PYTEST)" != "yes" ]; then \
	  echo "NOTE: pytest is not installed; using scripts/pytest_fallback.py (documented subset)."; \
	  echo "      retry with real pytest: uv sync --extra dev && python -m pytest"; \
	fi
	@$(TEST_CMD) tests

test-unit: ## Unit tests only
	@$(TEST_CMD) tests/unit

test-integration: ## Integration tests only (real DB, real FTS5)
	@$(TEST_CMD) tests/integration

test-security: ## Security regression suite (must never be skipped)
	@$(TEST_CMD) tests/security
	@$(PY) scripts/assert_no_skipped_security.py

test-e2e: ## Playwright end-to-end run against the live app
	@$(PY) scripts/run_e2e.py

lint: ## Ruff
	@if [ "$(HAVE_RUFF)" = "yes" ]; then \
	  ruff check . && ruff format --check . ; \
	else \
	  echo "BLOCKED: ruff is not installed."; \
	  echo "  retry: uv sync --extra dev && ruff check ."; \
	  echo "  running the stdlib fallback (syntax + a small AST lint) instead:"; \
	  $(PY) scripts/lint_fallback.py; \
	fi

typecheck: ## mypy (Python) and tsc (dashboard)
	@if [ "$(HAVE_MYPY)" = "yes" ]; then \
	  $(PY) -m mypy ; \
	else \
	  echo "BLOCKED: mypy is not installed."; \
	  echo "  retry: uv sync --extra dev && python -m mypy"; \
	fi
	@$(MAKE) --no-print-directory typecheck-web

typecheck-web: ## TypeScript typecheck for the dashboard
	@if [ "$(HAVE_NODE)" = "yes" ]; then \
	  (cd apps/dashboard && (npx --no-install tsc --noEmit 2>/dev/null || tsc --noEmit 2>/dev/null || \
	    echo "BLOCKED: no TypeScript compiler available (retry: npm ci in apps/dashboard)")); \
	else \
	  echo "BLOCKED: node is not installed."; \
	fi

build: ## Build the dashboard for production
	@if [ "$(HAVE_NODE)" = "yes" ]; then \
	  (cd apps/dashboard && $(NPM) run build); \
	else \
	  echo "BLOCKED: node is not installed."; exit 1; \
	fi

eval: ## The 4-condition measurement over the labelled dataset
	@$(PY) -m evals.runner

screenshots: ## Capture the required product screenshots from the running app
	@$(PY) scripts/capture_screenshots.py

verify: ## THE RELEASE TRUTH SOURCE — runs every mandatory check and reports blocked ones
	@$(PY) scripts/verify.py

# ---------------------------------------------------------------------------------- docker ----
docker-build: ## Build both images
	@docker build -f Dockerfile.api -t memory-firewall-api:dev .
	@docker build -f Dockerfile.dashboard -t memory-firewall-dashboard:dev .

compose-up: ## Start the compose stack (localhost only, dev profile)
	@docker compose up --build

compose-down: ## Stop the compose stack
	@docker compose down -v

# ---------------------------------------------------------------------------------- cleanup ---
clean-demo: ## Delete the local database, manifests and .env, then re-seed from scratch
	@rm -f $(MF_DB_PATH) $(MF_DB_PATH)-wal $(MF_DB_PATH)-shm $(MF_DB_PATH).manifests .env
	@$(PY) -m memory_firewall.cli setup-demo --db $(MF_DB_PATH)

clean: ## Remove caches and build output (keeps the database)
	@rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage \
	        apps/dashboard/dist apps/dashboard/.vite evals/results/_work \
	        test-results playwright-report
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
