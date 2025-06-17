# PRAGMATIC AUDIT & COST-OPTIMIZED REMEDIATION PLAN (ACADEMIC)

**AUDIT DATE:** 2025-06-17  
**CONTEXT:** Academic Use-Case, Monthly Budget ≤ $60

---

## EXECUTIVE SUMMARY

This audit re-evaluates the repository with strict cost and practicality constraints. The primary goal is to define the most direct and affordable path to a stable, maintainable application suitable for academic research.

The previous "critical audit" identified valid technical debt but prescribed enterprise-grade solutions that are too complex and expensive for this context. This plan supersedes it, focusing on aggressive simplification and low-cost, high-leverage actions. We will prioritize a lean, monolithic deployment over a distributed microservices architecture.

---

### 1. Foundational Housekeeping (Non-Negotiable, Zero-Cost)

*These actions from the previous audit remain critical. They improve quality and security at zero financial cost.*

1.  **Eliminate Directory Duplication:** All `academic_backup_*`, `preserved_core/`, and `preserved_tests/` directories MUST be deleted. Use Git tags for versioning, not file copies. This reduces clutter and prevents catastrophic versioning errors.
2.  **Establish CI/CD Pipeline:** Create a `.github/workflows/ci.yaml`. Use the generous free tier of GitHub Actions to run linting (`ruff`, `eslint`) and tests (`pytest`, `jest`) on every pull request. This is the single most important action for ensuring code quality.
3.  **Unify Frontend:** Choose ONE React application and ONE design system (`design-system/` is the more structured choice). Delete the duplicates. A single, consistent UI is easier to maintain and faster to develop.
4.  **Implement Pre-Commit Hooks:** Create a `.pre-commit-config.yaml` with `trufflehog` (for secret scanning) and `ruff` (for linting). This prevents security leaks and enforces code style automatically.
5.  **Fix Insecure CORS:** The `allow_origins=["*"]` configuration in `LawMapping/core/api/api_service.py` is a security risk. It MUST be replaced with a specific list of allowed domains loaded from an environment variable.

---

### 2. Cost-Optimized Architecture & Deployment Plan ($0 - $40/month)

*This is the blueprint for a low-cost, effective deployment.*

- **High-Level Strategy:** A **modular monolith** deployed via **Docker Compose** on a **single Linux VM**. This approach provides maximum performance and features for the lowest cost.
- **Hosting Provider:** Use a low-cost, high-performance VM provider. A single server with 2-4 vCPUs and 4-8 GB RAM from **Hetzner** or **DigitalOcean** will be more than sufficient and should cost **~$15-30/month**.
- **Frontend (React App):**
    - **Action:** Deploy to **Vercel** or **Netlify**.
    - **Cost:** **$0**. Their free tiers are designed for this use case and include global CDN, CI/CD, and HTTPS. Do not serve the React app from the Python backend.
- **Backend (All Python Services):**
    - **Action:** Consolidate all FastAPI services (`core`, `LawMapping`, `web`) into a single, modular application. Run this application in a Docker container on the VM.
    - **Cost:** **$0** (included in VM cost).
- **Database (PostgreSQL):**
    - **Action:** Run PostgreSQL in a Docker container on the same VM, managed by Docker Compose. **Crucially, implement a script that performs regular `pg_dump` backups to a separate, low-cost object storage service (like Backblaze B2 or AWS S3 Glacier).**
    - **Cost:** **$0** for the database, pennies for backup storage. Avoid expensive managed database services (like RDS) for now.
- **R Shiny Apps:**
    - **Action:** These are resource-intensive. First, attempt to containerize them and run them on the main VM via Docker Compose. If they are unstable or consume too many resources, move them to the free tier of `shinyapps.io`.
    - **Cost:** $0, with a fallback to a paid Shiny plan only if absolutely necessary.
- **Technology to AVOID:**
    - **Kubernetes (EKS, GKE), Terraform (for multi-cloud infra), Service Meshes:** These are powerful but far too complex and expensive for this project's scale and budget.
    - **Multiple VMs / Serverless (Lambda/Functions):** While serverless has a free tier, the cost can be unpredictable, and managing a distributed architecture increases complexity. A single VM is simpler and cheaper at this scale.

---

### 3. Aggressive Simplification for Maintainability

*Complexity is a hidden cost. We must actively remove it.*

1.  **Merge Microservices into a Modular Monolith:**
    - **Finding:** The codebase is split into multiple interacting FastAPI services (`core/`, `LawMapping/`, `web/`). This increases deployment complexity and resource overhead with little benefit for an academic project.
    - **Action:** Create a single new FastAPI application. Migrate the logic from the separate services into distinct Python modules (e.g., `api/routers/search.py`, `api/routers/auth.py`). This simplifies deployment to a single process, reduces memory usage, and makes local development trivial.
2.  **Eliminate Celery:**
    - **Finding:** The project includes a Celery worker (`LawMapping/jobs/optimized_celery.py`). Running a separate worker and message broker (like Redis or RabbitMQ) adds significant complexity and resource consumption.
    - **Action:** **Remove Celery entirely.** For background tasks in an academic context, use FastAPI's built-in `BackgroundTasks`. This is simpler, has zero extra dependencies, and is perfectly adequate for tasks that don't need to be distributed or guaranteed.
3.  **Centralize Configuration:**
    - **Finding:** Configuration is scattered.
    - **Action:** Use a single, clear method for configuration, like Pydantic's `BaseSettings`, which can load settings from environment variables or a `.env` file. This centralizes all settings (database URLs, secret keys, allowed origins) in one place.

---

## REVISED ROADMAP

1.  **Phase 1 (Foundations):**
    - [ ] Execute all actions from **Section 1 (Foundational Housekeeping)**.
2.  **Phase 2 (Simplification):**
    - [ ] Merge the FastAPI services into a single modular monolith.
    - [ ] Replace Celery with FastAPI `BackgroundTasks`.
    - [ ] Consolidate all configuration into a single Pydantic `BaseSettings` model.
3.  **Phase 3 (Deployment):**
    - [ ] Create `Dockerfile` for the unified backend and `docker-compose.yml` for the full stack (backend, db, backup-script).
    - [ ] Set up the VM on a low-cost provider.
    - [ ] Deploy the React frontend to Vercel/Netlify.
    - [ ] Deploy the backend stack to the VM using Docker Compose. 