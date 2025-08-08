# Codebase Improvements Report

## Executive summary

This repository is rich and mature, but suffers from sprawl, duplicated artifacts, committed environments/data, and uneven conventions across languages. The most valuable changes are consolidation of entrypoints, environment and data hygiene, standardization of testing/linting, and a streamlined deployment pipeline.

## Critical issues (address first)

- Committed environments and binaries
  - `reload_env/`, `lexml_env/`, `Lib/`, `dev-tools/scripts/pip3*.exe`, `dev-tools/scripts/R-4.3.2.tar.gz` should not be versioned. Add to `.gitignore` and remove from Git history.
- Generated data and logs in VCS
  - `data_current/processed/**`, `analytics_output/**`, `logs/**`, root `*.log` files should not be committed. Move to object storage or use DVC/Git LFS. Keep only minimal samples. Add ignore rules.
- Multiple production entrypoints
  - Many `app_*.R` variants at root create confusion. Define one canonical `app.R`. Move variants to `dev-tools/` or `archive/`.
- Security and secrets
  - Ensure no secrets in `logs/**` or committed configs. Migrate to environment variables and secret managers; scrub existing history if needed.

## High-value refactors

- Directory consolidation and naming
  - Rename `R analysis/` to `r_analysis/` (no spaces). Normalize Portuguese/English mix; pick one convention per layer (e.g., English for code paths, PT-BR for docs).
  - Consolidate `docs/` and `documentation/` into a single `docs/` tree to eliminate duplication.
  - Move all `test_*.R` at repo root into `tests/` or `dev-tools/tests/` with structure by domain.
- Script de-duplication
  - Unify duplicate utilities appearing in multiple places (e.g., `lexml_strategy_corrected.py` in `scripts/` vs `implementation/`). Keep a single source under `src/` or `scripts/` and import it where needed.
- Configuration management
  - Centralize config via `.env` + `config.yml` with a thin loader in R (`config` package) and Python (`pydantic-settings`/`dotenv`). Document precedence.
- Data pipeline packaging
  - Convert `src/lexml_refinado` into an installable Python package with versioning. Reference it from `scripts/python/*` instead of duplicating logic.
- Shiny modules structure
  - Ensure each module (`modules/maps/*`) has clear UI/server separation and test coverage. Consider a `R/` package-style structure for reusable components.

## Quality, testing, and tooling

- Linting/formatting
  - Python: `ruff`, `black`, `isort` with `pyproject.toml`.
  - R: `lintr`, `styler`, enforce with pre-commit.
  - SQL: `sqlfluff` with `postgres` dialect for `database/**/*.sql`.
- Testing
  - R: migrate ad-hoc `test_*.R` to `testthat` within a package or a structured `tests/` directory; add snapshot tests for UI where feasible.
  - Python: add `pytest` for `scripts/python/**` and `src/**`; include fixtures for DB and filesystem.
  - Database: add migration smoke tests and `VERIFY` scripts to CI using ephemeral Postgres.
- Pre-commit and CI/CD
  - Add `.pre-commit-config.yaml` to run formatters/linters and forbid large files.
  - GitHub Actions pipeline: matrix for R and Python; run tests, lint, and build Docker image; optional deploy on tag.

## Data management

- Artifacts
  - Treat `data_current/processed/**` and `analytics_output/**` as build artifacts. Publish summaries to releases or S3; keep provenance in `reproducibility_package/`.
- Reproducibility
  - R: adopt `renv` lockfile; Python: `requirements.txt` or `poetry.lock`. Ensure deterministic builds in Docker.
- Schemas and migrations
  - Standardize migration filenames (`YYYYMMDDHHMM_description.sql`). Adopt a migration manager (e.g., `dbmate`, `alembic` if moving Python-based) or keep pure-SQL with verified idempotency.

## Infrastructure and deployment

- Docker
  - Consolidate multiple Dockerfiles into one multi-stage build with build args for mode (dev/prod). Pin base images; cache R package installs; set `--no-cache-dir` for pip.
- Railway and AWS CDK
  - Document single source of truth for env vars. Generate `railway.toml` from templates per environment.
- Observability
  - Centralize logging config (R and Python) with JSON logs and log rotation; ensure PII-safe logs.

## Documentation

- Reduce duplication between `docs/` and `documentation/`; create a single navigation index. Keep detailed analytics reports under `docs/reports/`.
- Add diagrams for database schema and system architecture; link from `README.md`.
- Provide a “Getting Started” quickstart for both R-only and full-stack paths.

## Files and directories to delete or move

Note: Delete only if not referenced by deployment or tests. When in doubt, move to `archive/legacy/` first.

### Safe to delete (generated, caches, binaries)

- Virtual environments and platform libs
  - `reload_env/`, `lexml_env/`, `Lib/`, `data_current/temp_venv/`
- Node and Python binaries
  - `dev-tools/node_modules/`, `dev-tools/scripts/pip3*.exe`, `dev-tools/scripts/R-4.3.2.tar.gz`
- Caches and bytecode
  - Any `**/__pycache__/`, `*.pyc`, `.ruff_cache/`, `.pytest_cache/`
- Logs and runtime outputs
  - `logs/**`, root `*.log` files (e.g., `railway_db_connection.log`, `deployment_*.log`, `import_*.log`)
- Analytics outputs (regenerate from pipelines)
  - `analytics_output/**`
  - Most of `data_current/processed/**` folders like `analytical_results/`, `analytics/**`, `geospatial_analysis_results/`, `citation_network_results/`, `temporal_analysis_results/`, `text_mining_results/`, `simplified_analytical_results/`, `transport_decarbonization_research/`
    - Prefer moving to object storage or using DVC/LFS rather than versioning
- Empty placeholders
  - `exports/` (if unused), `database/seeds/` (if not using seed scripts)
- Empty `R/` directory (currently shows no children)

### Move to legacy/archive (keep for history, not active use)

- Multiple app variants at repo root
  - `app_minimal.R`, `app_minimal_test.R`, `app_railway_minimal.R`, `app_test_incremental.R`, `app_ui_only.R`, `app_debug.R`, `app_backup.R`
- Root debug/test harnesses
  - `debug_*.R`, `syntax_test.R`, `simple_db_test.R`, `verify_fix_deployment.R`, and all root-level `test_*.R` scripts
    - Move to `dev-tools/tests/` or `archive/tests_legacy/`
- Top-level data snapshots
  - `all_municipalities_found.csv`, `existing_municipalities.csv`, `found_municipalities.csv`, `refined_municipalities_found.csv`, `text_mining_municipalities.csv`, `comprehensive_municipality_search_results.csv`, `csv_based_municipalities_found.csv`, `csv_municipality_analysis_report.json`, `csv_municipality_search_results.json`
    - Move to `data_current/production/` or `lexml_overview/use_version/data/processed/` depending on provenance
- Standalone images at repository root
  - `activity_heatmap.png`, `categories_timeline.png`, `coverage_percentage_trend.png`, `document_category_analysis.png`, `municipality_analysis_results.png`, `municipality_coverage_comparison.png`, `state_distribution.png`, `states_timeline.png`, `temporal_analysis.png`, `timeline_decades.png`, `timeline_yearly.png`, `transport_timeline.png`, `img17.png`, `img18.png`
    - Move to `docs/reports/images/` or `archive/media/`
- Duplicate or machine-specific docs
  - `docs/README-DESKTOP-7CFES0M.md` → move to `archive/miscellaneous/` or delete
- Alternative Docker path
  - `r-shiny-app/Dockerfile` (if not used) → move to `dev-tools/docker/` or `archive/docker/`
- One-off fixes
  - `fixes/active/map_data_fix.R` (if applied) → move to `implementation/` (under `applied/`) or `archive/fixes/`

### Candidates to consolidate (choose one location, delete duplicates)

- Documentation
  - Merge `documentation/` into `docs/` and remove the redundant tree
- Migration and scripts
  - Duplicate Python helpers in `implementation/` vs `scripts/` (e.g., `lexml_strategy_corrected.py`) → keep under `src/` or `scripts/` and delete duplicates
- Dockerfiles
  - Keep a single multi-stage Dockerfile at root; move `Dockerfile.railway` content behind build args; archive alt Dockerfiles under `dev-tools/docker/` if needed

### .gitignore additions (suggested)

```gitignore
# environments
reload_env/
lexml_env/
Lib/
**/.venv/

# node
**/node_modules/

# caches and compiled
**/__pycache__/
**/*.pyc
.ruff_cache/
.pytest_cache/

# logs
logs/
*.log

# data artifacts
analytics_output/
data_current/processed/
```

## Cleanup checklist (prioritized)

1. Purge committed environments and large data; extend `.gitignore` (envs, logs, outputs).
2. Choose canonical `app.R`; move other variants under `dev-tools/` or `archive/`.
3. Consolidate `docs/` and `documentation/` into a single `docs/` directory.
4. Set up linters/formatters and pre-commit; create CI workflow.
5. Package `src/lexml_refinado` and refactor scripts to import it.
6. Standardize migration naming and add DB CI smoke tests.
7. Rename `R analysis/` to `r_analysis/`; clean file/dir naming inconsistencies.
8. Consolidate Dockerfiles to one multi-stage; pin dependencies.
9. Establish a config loader for R/Python with `.env`.
10. Migrate ad-hoc R tests to `testthat` or a structured `tests/` folder; add pytest for Python.
