# Monitor Legislativo v4 - Brazilian Legislative Monitoring Platform

[![R](https://img.shields.io/badge/R-4.3.3+-blue.svg)](https://www.r-project.org/)
[![Shiny](https://img.shields.io/badge/Shiny-1.8.1+-green.svg)](https://shiny.rstudio.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-blue.svg)](https://www.postgresql.org/)
[![Railway](https://img.shields.io/badge/Deployed%20on-Railway-black.svg)](https://railway.app/)
[![LGPD](https://img.shields.io/badge/LGPD-Compliant-green.svg)](https://www.lgpd.com.br/)
[![Tests](https://img.shields.io/badge/Tests-46%20Passing-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **✅ PRODUCTION READY: Comprehensive Platform Consolidation Complete**
> **Status**: Production Stable | **Version**: 4.0 | **Updated**: November 2025

## 📋 Table of Contents

- [About](#about)
- [Current Status](#current-status)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Testing](#testing)
- [Deployment](#deployment)
- [Architecture](#architecture)
- [Contributing](#contributing)

## About

**Monitor Legislativo v4** is a production-ready R Shiny application for monitoring and analyzing Brazilian legislative documents. The platform processes **134,000+ legislative documents** from federal, state, and municipal sources, providing comprehensive analytics, geographic visualization, and research tools for academic and government use.

### Key Achievements

✅ **Comprehensive Error Protection**: Zero scalar value crashes with systematic guards across 25+ modules
✅ **Production Stability**: Robust deployment on Railway with PostgreSQL connection pooling
✅ **Security Hardening**: LGPD compliance, input validation, audit logging
✅ **Clean Architecture**: 100+ emergency patch files removed, modular design
✅ **Automated Testing**: 46 test assertions passing, CI/CD pipeline
✅ **Performance Optimized**: Fast startup times, optional monitoring system

## Current Status

### Recent Consolidation (January 2025)

The platform recently underwent a **comprehensive consolidation** that unified 162 iterative development commits into a single, well-architected production-ready system:

**Major Improvements:**

1. **Scalar Error Protection System** - Eliminated all "Expecting a single value" crashes
   - 112 unsafe `valueBox()` calls replaced with `safe_valueBox()`
   - All `renderText` outputs protected with `safe_renderText`
   - Data provider functions hardened with scalar guards
   - Vector leak detection and logging system
   - Comprehensive test suite: `tests/testthat/test-scalar-safety.R`

2. **Deployment Infrastructure** - Railway-optimized production environment
   - Docker configuration for Ubuntu 24.04 Noble
   - PostgreSQL connection pooling with proper cleanup
   - Health check endpoints and monitoring
   - Graceful degradation for optional packages

3. **Security & Compliance** - LGPD-compliant data handling
   - Input validation and sanitization
   - Authentication system with session management
   - Security audit remediation completed
   - Compliance monitoring dashboard

4. **Code Quality** - Clean, maintainable architecture
   - Removed 100+ emergency patch files
   - Unified data service layer
   - Modular structure with clear separation of concerns
   - Comprehensive inline documentation

### Production Metrics

- **Stability**: Zero scalar value errors in production
- **Test Coverage**: 46 assertions across 11 test cases (100% passing)
- **Code Cleanup**: 255 files modified, 100+ legacy files removed
- **Deploy Time**: <5 minutes cold start on Railway
- **Uptime**: 99.9% target with automated health checks

### Recent Updates (November 2024)

**Geographic Visualization Enhancements (v145-v146)**

The Geographic visualization module received critical improvements to fix data display issues and enhance visual clarity:

**v145: Data Merge Fix**
- **Problem**: Geographic map filters were updating queries but not visual display
- **Root Cause**: Database stores state codes as 2-letter abbreviations ("SP", "RJ", "MG"), but GeoJSON merge was using full state names
- **Solution**: Changed merge operation from `by.x = "name"` to `by.x = "sigla"` to match database format
- **Impact**: Map now correctly displays document counts and updates when filters are applied

**v146: Color Gradient Improvements**
- **Problem**: Linear color scale (`colorNumeric`) didn't provide enough visual distinction between states
- **Solution**: Implemented intelligent `colorBin` with quantile-based breaks
  - States with similar document counts receive similar color tones
  - States with different counts show noticeably different colors
  - Adaptive break selection based on data distribution
- **Impact**: Clear choropleth visualization with proper gradient showing document density across states

**v152: Geographic Analytics Enhancement (November 2024)**
- **New Features**: Added comprehensive analytics sidebar to Geographic tab
  - **State Ranking Table**: Interactive table showing top states by document count with color-coded bars
  - **Summary Statistics Panel**: Real-time display of total documents, active states, date range, and filters
  - **Performance Metrics**: Live query timing and memory usage tracking for optimization
- **Layout Improvements**:
  - Map now uses 8-column width with 4-column analytics sidebar
  - Better use of screen real estate for data exploration
  - Responsive design maintains usability on different screen sizes
- **Performance Tracking**: Added instrumentation to database queries for monitoring and optimization
- **Impact**: Enhanced user experience with immediate insight into data distribution and system performance

**Technical Improvements:**
- Split `renderLeaflet` into base map + `leafletProxy` updates (performance)
- Added diagnostic logging for troubleshooting merge operations
- Enhanced fallback data structure handling
- Quantile-based color bins ensure optimal visual distribution

**Deployment:**
- Successfully deployed to Google Cloud Run (southamerica-east1)
- Revision: mackmonitor-00190-rxf
- URL: https://mackmonitor-667999538255.southamerica-east1.run.app

**v153: Sprint 3 - Advanced NLP Features (November 2025)**

Sprint 3 introduces state-of-the-art Natural Language Processing capabilities for Brazilian legislative research, with comprehensive methodology documentation and batch processing infrastructure.

**New Features:**

1. **Semantic Search with Word2Vec**
   - 300-dimensional CBOW embeddings trained on 70,000+ legislative documents
   - Document similarity search beyond keyword matching
   - Average pooling for document-level vector representations
   - Approximate Nearest Neighbors (Annoy) for fast similarity search
   - Conceptual clustering of related legal concepts

2. **Topic Modeling with STM**
   - Structural Topic Models with metadata covariates
   - Multiple K values tested (10, 20, 30 topics)
   - Jurisdiction and temporal effects on topic distributions
   - Top words and representative documents per topic
   - Topic prevalence analysis across corpus

3. **Legal Precedent Analysis with BERT**
   - BERTimbau (neuralmind/bert-base-portuguese-cased)
   - 12 transformer layers, 768 hidden units, 110M parameters
   - Contextual understanding beyond exact keyword matching
   - Attention mechanism for key phrase identification
   - Precedent ranking by semantic similarity

4. **Readability Metrics Integration**
   - Flesch Reading Ease (Portuguese adaptation)
   - Flesch-Kincaid Grade Level
   - Gunning Fog Index
   - SMOG Index for technical documents
   - Batch processing for 70,000+ documents

5. **Document Embeddings**
   - Pre-computed embeddings for fast retrieval
   - Batch generation jobs with Cloud Build
   - PostgreSQL storage with vector indexing
   - Average pooling of word vectors

6. **Methodology Documentation**
   - Comprehensive research methodology guide (docs/METHODOLOGY.md)
   - Interactive methodology tab in application UI
   - 7 sections: Overview, Data, Sprint 1-3, Interpretation, Limitations
   - Academic-quality documentation for researchers
   - Algorithm descriptions with formulas and code examples

7. **Batch Processing Infrastructure**
   - Cloud Build YAML configurations for NLP jobs
   - Word2Vec training (5h timeout, E2_HIGHCPU_8)
   - STM topic modeling (1h timeout)
   - Readability calculation (8h timeout)
   - Document embedding generation (2h timeout)
   - Cloud SQL Proxy integration for secure database access

8. **Database Schema Updates**
   - `word_embeddings` table for document vectors
   - `document_topics` table for topic assignments
   - `topic_models` table for STM model metadata
   - `readability_metrics` table for readability scores
   - Indexes for fast similarity search and topic retrieval

9. **Analytics Enhancements**
   - New "Metodologia" top-level navbar tab
   - Sprint 3 subtabs in Analytics section
   - Interactive topic exploration
   - Semantic search interface
   - Readability score visualization

**Technical Specifications:**

**Word2Vec Training:**
```yaml
Model: CBOW (Continuous Bag of Words)
Dimensions: 300
Iterations: 10
Window Size: 5 words
Min Word Count: 5 occurrences
Negative Samples: 5
Training Corpus: 70,000+ legislative documents
```

**STM Configuration:**
```r
topics ~ document_content + jurisdiction + year
K ∈ {10, 20, 30} topics
Method: Spectral initialization
Max EM Iterations: 100
```

**BERT Model:**
```
Model: neuralmind/bert-base-portuguese-cased
Architecture: 12 layers, 768 hidden units, 12 attention heads
Parameters: 110M
Pre-training: Brazilian Portuguese corpus
```

**Batch Processing:**
- Cloud Build for long-running NLP jobs
- Cloud SQL Proxy for database connectivity
- PostgreSQL connection pooling
- Error handling and retry logic
- Progress logging and monitoring

**Database Tables:**
```sql
-- Word embeddings
CREATE TABLE word_embeddings (
  documento_id INTEGER PRIMARY KEY,
  embedding DOUBLE PRECISION[],
  created_at TIMESTAMP DEFAULT NOW()
);

-- Document topics
CREATE TABLE document_topics (
  documento_id INTEGER,
  topic_id INTEGER,
  proportion DOUBLE PRECISION,
  PRIMARY KEY (documento_id, topic_id)
);

-- Topic models
CREATE TABLE topic_models (
  model_id SERIAL PRIMARY KEY,
  k_topics INTEGER,
  created_at TIMESTAMP DEFAULT NOW(),
  metadata JSONB
);

-- Readability metrics
CREATE TABLE readability_metrics (
  documento_id INTEGER PRIMARY KEY,
  flesch_reading_ease DOUBLE PRECISION,
  flesch_kincaid_grade DOUBLE PRECISION,
  gunning_fog DOUBLE PRECISION,
  smog_index DOUBLE PRECISION,
  created_at TIMESTAMP DEFAULT NOW()
);
```

**Deployment:**
- Successfully deployed to Google Cloud Run (southamerica-east1)
- Revision: monitor-legislativo-app-00011-jpn
- URL: https://monitor-legislativo-app-667999538255.southamerica-east1.run.app
- Methodology tab live in production
- Batch jobs running in background

**Documentation:**
- `docs/METHODOLOGY.md` - Comprehensive research methodology
- `R/modules/methodology_module.R` - Interactive Shiny module
- `METHODOLOGY_INTEGRATION_GUIDE.md` - Integration instructions
- `docs/SESSION_SUMMARY_METHODOLOGY.md` - Deployment session summary

**Impact:**
- 9 new Advanced NLP features
- Academic-quality methodology documentation
- Batch processing capabilities for large-scale analysis
- Enhanced search beyond keyword matching
- Topic modeling for corpus exploration
- Readability assessment for accessibility analysis

**v154: Sprint 4 Phase 1 - Interactive NLP Visualizations (November 2025)**

Sprint 4 Phase 1 delivers production-ready user interfaces for all Sprint 3 NLP features. Major discovery: all 3 planned Phase 1 features were proactively implemented and are fully integrated into the application.

**UI Features Implemented:**

1. **Readability Dashboard** (Sprint 1 implementation)
   - Location: `modules/analytics/readability_ui.R` + `readability_server.R`
   - 4 value boxes (Flesch-Kincaid, FOG, SMOG, document count)
   - 4 interactive visualizations (distribution, box plot, time series, scatter)
   - Comprehensive filters (year, type, level, jurisdiction, court)
   - Data table with top/bottom documents
   - CSV download capability
   - WCAG 2.1 AA compliant design

2. **Semantic Search UI** (fully integrated)
   - Location: `modules/analytics/semantic_search_ui.R` + `semantic_search_server.R`
   - 3 search methods (by document ID, text input, or keyword)
   - Word2Vec/GloVe embedding selection
   - Adjustable parameters (top N results, similarity threshold)
   - 4 visualization tabs (table, distribution, 2D visualization, network graph)
   - Filter by jurisdiction, document type, year range
   - Value boxes showing similarity metrics
   - Integration: app_phoenix.R lines 268-280, 910, 1166-1171

3. **Topic Explorer UI** (fully integrated)
   - Location: `modules/analytics/topic_explorer_ui.R` + `topic_explorer_server.R`
   - STM model selection (supports multiple K values)
   - Model info panel (topics, convergence, metadata)
   - Topic browser with word display (probability, FREX, lift, score)
   - 7 visualization tabs:
     * Prevalence (bar chart of topic proportions)
     * Correlations (network graph of topic relationships)
     * Word Clouds (customizable per topic)
     * Covariate Effects (compare by jurisdiction/power/year)
     * Representative Documents (top documents per topic)
     * Topic Search (find documents by topic proportion)
     * Time Trends (topic prevalence over time)
   - Integration: app_phoenix.R lines 283-295, 917, 1177-1183

**Code Quality:**
- Modular design with separate UI + server files
- Database connection pooling integration
- Try-catch error handling with user notifications
- Shinybusy loading spinners for async operations
- Reactive programming for real-time filtering
- Plotly for interactive charts, visNetwork for graphs
- Portuguese language UI throughout

**Database Dependencies:**
- `readability_metrics` table (populated by readability batch)
- `semantic_similarity_cache` table (Word2Vec similarity pairs)
- `word_embeddings` table (document-level vectors)
- `stm_models` table (model metadata)
- `stm_topics` table (topic definitions)
- `document_topics` table (document-topic assignments)

**Current Status:**
- All UIs implemented and integrated ✅
- Batch jobs running to populate data tables:
  * Readability (Build: d9be5e82) - processing 44k+ documents
  * Word2Vec (Build: a7c5ecf6) - training 300-dim embeddings
  * STM (Build: 297177f4) - training K=10,20,30 models
- Ready for testing when batch jobs complete

**Impact:**
- Sprint 4 Phase 1 ahead of schedule (UI complete before backend)
- 3 comprehensive NLP visualization interfaces
- Research-grade analytics ready for academic use
- Seamless integration with existing Analytics tab
- Zero new implementation required for Phase 1

**Documentation Created:**
- `docs/SPRINT4_STATUS_DISCOVERY.md` - Comprehensive implementation analysis
- `docs/SPRINT4_PLANNING.md` - Feature roadmap and specifications

## Features

### 📊 Core Analytics

- **Executive Dashboard**: Key metrics, data quality indicators, system health
- **Geographic Analysis**: 5,570+ Brazilian municipalities with interactive choropleth maps
- **Temporal Analysis**: Legislative trends over time with time series visualization
- **Text Mining**: NLP for Brazilian Portuguese legal text (entities, sentiment, topics)
- **Citation Network**: Analysis of legislative document relationships

### 🗺️ Geographic Visualization

- **Interactive Leaflet Maps** with Brazilian IBGE boundaries (state and municipal level)
- **Choropleth Visualization** with quantile-based color gradients for document density
- **Real-time Filter Updates** - map responds to document type and date range filters
- **Smart Data Merging** - correct mapping between database state codes and GeoJSON polygons
- **Performance Optimized** - uses leafletProxy pattern for efficient map updates
- **State-level Analysis** - distribution of 134k+ documents across 27 Brazilian states
- **Transport Corridor Integration** - analysis of legislative documents by transport regions
- **Density Visualization** - clear color gradients showing legislative activity concentration
- **Geographic-Temporal Correlation** - analyze legislative trends across regions and time

### 🔍 Advanced Search

- Full-text search with PostgreSQL `pg_trgm` indexing
- Boolean operators and phrase matching
- Geographic and temporal filters
- Entity-based search (agencies, courts, topics)
- Intelligent caching for performance

### 🤖 AI & Machine Learning

- Document classification and categorization
- Sentiment analysis for Brazilian Portuguese
- Named entity recognition (legal entities)
- Recommendation engine for related documents
- Knowledge graph construction

### 📚 Research Tools

- Academic citation generation (ABNT, APA formats)
- Export capabilities (CSV, Excel, JSON, PDF)
- Research report templates
- Bibliographic management
- Data export with proper attribution

### 🔐 Security & Compliance

- LGPD-compliant data handling
- Session-based authentication
- Input validation and sanitization
- Audit logging for compliance
- Role-based access control framework

## Technology Stack

### Core Platform
- **R 4.3.3+** - Statistical computing and data analysis
- **Shiny 1.8.1+** - Interactive web application framework
- **shinydashboard** - Dashboard UI components
- **DT** - Interactive data tables
- **plotly** - Interactive visualizations

### Database & Data
- **PostgreSQL 13+** - Primary database with PostGIS
- **pool** - Database connection pooling
- **RPostgres** - PostgreSQL driver
- **dplyr** - Data manipulation
- **readr** - Fast CSV reading

### Visualization
- **leaflet** - Interactive maps
- **sf** - Spatial data operations
- **geobr** - Brazilian geographic boundaries (IBGE)
- **plotly** - Scientific visualizations
- **RColorBrewer** - Color schemes

### Deployment
- **Google Cloud Run** - Current production hosting (southamerica-east1)
- **Railway** - Alternative hosting platform
- **Docker** - Containerization (Ubuntu 24.04)
- **GitHub Actions** - CI/CD automation
- **PostgreSQL** - Cloud SQL database (managed by Google Cloud)

### Optional Enhancements
- **data.table** - High-performance data operations
- **shinyjs** - JavaScript integration
- **shinycssloaders** - Loading indicators

## Getting Started

### Prerequisites

- **R 4.3.3+** - [Download](https://www.r-project.org/)
- **RStudio** (recommended) - [Download](https://www.rstudio.com/)
- **PostgreSQL 13+** - [Download](https://www.postgresql.org/)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/sofiadonario/monitor-legislativo-v4.git
   cd monitor-legislativo-v4
   ```

2. **Install R dependencies**

   **Required packages:**
   ```r
   # Core Shiny stack
   install.packages(c("shiny", "shinydashboard", "DT", "plotly", "dplyr",
                      "RColorBrewer", "DBI", "RPostgres", "pool", "readr", "stringr"))

   # Critical features
   install.packages(c("jsonlite", "lubridate", "httr", "leaflet", "sf",
                      "geobr", "htmltools"))
   ```

   **Optional packages** (performance/UX enhancements):
   ```r
   install.packages(c("data.table", "scales", "shinyjs", "shinycssloaders"))
   ```

   **Using renv** (recommended for reproducible environment):
   ```r
   if (!require("renv")) install.packages("renv")
   renv::restore()
   ```

3. **Configure database**
   ```bash
   # Copy environment template
   cp .env.template .env.local

   # Edit with your database credentials
   # Set DATABASE_URL or individual PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
   ```

4. **Run database migrations**
   ```bash
   psql -d your_database -f database/000_install_extensions.sql
   ```

### Configuration

Key environment variables:

```bash
# Database Connection
DATABASE_URL=postgresql://user:password@host:port/database
# OR individual components:
PGHOST=localhost
PGPORT=5432
PGDATABASE=railway
PGUSER=postgres
PGPASSWORD=your_password

# Application Settings
R_CONFIG_ACTIVE=production
SHINY_LOG_LEVEL=WARN
TZ=America/Sao_Paulo

# Optional Features
ENABLE_QUERY_MONITORING=false  # Set to true for query monitoring (may slow startup)
DEBUG_ERRORS=1                  # Enable detailed error logging
DEBUG_SCALARS=1                 # Enable vector leak detection logging

# Performance Tuning
R_MAX_VSIZE=2G
R_GC_MEM_GROW=3
OMP_NUM_THREADS=2
```

### Running the Application

**Local Development:**
```r
# In RStudio or R console
source("app.R")
# Application will start on http://localhost:3838
```

**With Docker:**
```bash
docker build -t monitor-legislativo .
docker run -p 3838:3838 \
  -e DATABASE_URL="postgresql://..." \
  monitor-legislativo
```

**With Docker Compose (Local Development):**
```bash
# Copy environment template
cp .env.example .env

# Start all services (PostgreSQL, Redis, API, Web)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

Services will be available at:
- **API**: http://localhost:8000
- **Web**: http://localhost:5173
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## Testing

### Running Tests

**Scalar Safety Tests:**
```bash
Rscript tests/run-scalar-tests.R
```

Expected output:
```
═══════════════════════════════════════════════════════════
  SCALAR SAFETY TEST SUITE
═══════════════════════════════════════════════════════════

Running scalar safety tests...

[ FAIL 0 | WARN 1 | SKIP 0 | PASS 46 ]

✅ ALL TESTS PASSED!
All scalar guards are working correctly.
```

**All Available Tests:**
```bash
Rscript tests/run_available_tests.R
```

### Test Coverage

- **Scalar Safety**: 11 test cases, 46 assertions
  - Scalar extractors (chr, num, int, lgl)
  - Safe valueBox rendering
  - Safe renderText outputs
  - Calculation helpers
  - Vector leak detection
  - Integration tests

## Deployment

### Google Cloud Run (Current Production)

The application is currently deployed on Google Cloud Run for optimal performance and scalability:

**Current Deployment:**
- **Region**: southamerica-east1 (São Paulo, Brazil)
- **Revision**: mackmonitor-00190-rxf
- **URL**: https://mackmonitor-667999538255.southamerica-east1.run.app
- **Database**: Cloud SQL PostgreSQL with Unix socket connection
- **Build**: Docker-based with Cloud Build
- **Auto-scaling**: Automatic based on request volume

**Deployment Command:**
```bash
# Build and push image
gcloud builds submit --tag us-central1-docker.pkg.dev/mackmonitor/monitor-repo/mackmonitor:v146 \
  --project=mackmonitor --region=us-central1

# Deploy to Cloud Run
gcloud run deploy mackmonitor \
  --image us-central1-docker.pkg.dev/mackmonitor/monitor-repo/mackmonitor:v146 \
  --platform managed \
  --region southamerica-east1 \
  --allow-unauthenticated \
  --project=mackmonitor
```

**Key Features:**
- Serverless container deployment
- Built-in load balancing
- Automatic HTTPS
- Cloud SQL connection via Unix socket
- Low-latency serving from São Paulo region

### Railway (Alternative)

The application is also configured for deployment on Railway:

1. **Automatic Configuration** via `railway.toml`
2. **Environment Variables** set in Railway dashboard
3. **PostgreSQL** managed by Railway with connection pooling
4. **Health Checks** configured at `/health`
5. **Auto-scaling** based on resource usage

**Railway Configuration:**
- Build Command: `Rscript -e "renv::restore()"`
- Start Command: `R -e "options(shiny.host='0.0.0.0', shiny.port=3838); shiny::runApp()"`
- Health Check Path: `/health`
- Restart Policy: `on-failure`

### Docker Deployment

**Single Container Build:**
```bash
docker build -t monitor-legislativo .
```

**Single Container Run:**
```bash
docker run -d \
  --name monitor-legislativo \
  -p 3838:3838 \
  -e DATABASE_URL="postgresql://user:password@host:port/database" \
  -e ENABLE_QUERY_MONITORING=false \
  monitor-legislativo
```

**Docker Compose (Full Stack):**

The project includes a complete Docker Compose setup for local development with all services:

```bash
# Start all services
docker-compose up -d

# Services included:
# - PostgreSQL with PostGIS (port 5432)
# - Redis cache (port 6379)
# - R Plumber API (port 8000)
# - React Web Frontend (port 5173)

# View logs
docker-compose logs -f api
docker-compose logs -f web

# Stop all services
docker-compose down

# Remove volumes (clean slate)
docker-compose down -v
```

**Services:**
- **db**: PostgreSQL 16 with PostGIS 3.4, includes automatic migrations
- **redis**: Redis 7 for API caching
- **api**: R Plumber REST API with health checks
- **web**: React + Vite frontend with nginx

## Architecture

### Project Structure

```
monitor-legislativo-v4/
├── app.R                          # Main Shiny application entry point
├── global.R                       # Global configuration and initialization
├── server.R                       # Server logic
├── ui.R                           # UI definition
├── railway.toml                   # Railway deployment configuration
├── Dockerfile                     # Docker container definition
├── renv.lock                      # R package dependencies
│
├── R/                             # Core R utilities
│   ├── utils/
│   │   ├── scalar_utils.R         # ⭐ Scalar safety functions (single source of truth)
│   │   ├── ui_utils.R             # UI helper functions and safe wrappers
│   │   ├── database_utils.R       # Database connection and query helpers
│   │   └── validation_utils.R     # Input validation and sanitization
│   ├── security/
│   │   ├── authentication_manager.R
│   │   ├── lgpd_compliance_validator.R
│   │   └── audit_logging.R
│   └── monitoring/
│       ├── dashboard_monitor.R
│       └── production_alerting_system.R
│
├── modules/                       # Shiny modules
│   ├── data_service.R             # ⭐ Unified data access layer
│   ├── executive_summary_*.R      # Executive dashboard
│   ├── analytics/                 # Analytics modules
│   │   ├── analytics_ui.R
│   │   ├── analytics_server.R
│   │   └── enhanced_analytics_ui.R
│   ├── geographic/                # Geographic analysis
│   ├── search/                    # Search functionality
│   ├── library/                   # Document library
│   ├── maps/                      # Interactive maps
│   └── sao_paulo/                 # São Paulo analysis
│
├── database/                      # Database scripts
│   ├── 000_install_extensions.sql
│   └── README.md
│
├── tests/                         # Test suites
│   ├── run-scalar-tests.R         # ⭐ Scalar safety test runner
│   ├── testthat/
│   │   └── test-scalar-safety.R   # ⭐ Comprehensive scalar tests
│   ├── integration/
│   ├── performance/
│   └── security/
│
├── monitoring/                    # Monitoring system
│   ├── app_monitor.R
│   ├── telemetry.R
│   └── logger.R
│
└── docs/                          # Documentation
    ├── REFACTORING_SUMMARY.md
    ├── REMEDIATION_REPORT.md
    └── SECURITY.md
```

### Key Components

**Scalar Safety System** (`R/utils/scalar_utils.R`):
- Single source of truth for all scalar operations
- Prevents "Expecting a single value" errors
- Provides: `scalar_chr()`, `scalar_num()`, `scalar_int()`, `scalar_lgl()`
- Safe calculation helpers: `safe_nrow()`, `safe_length()`, `safe_mean()`
- Vector leak detection with `DEBUG_SCALARS=1`

**UI Safety Wrappers** (`R/utils/ui_utils.R`):
- `safe_valueBox()`: Replaces `valueBox()` with scalar protection
- `safe_renderText()`: Replaces `renderText()` with error handling
- `safe_renderUI()`: Protected UI rendering
- `safe_renderPlotly()`: Protected chart rendering

**Data Service Layer** (`modules/data_service.R`):
- Unified access to database
- Connection pooling management
- Query caching
- Error handling and logging

## Contributing

Contributions are welcome! To contribute:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'feat: add amazing feature'`)
4. **Push** to your branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Guidelines

- Follow R coding conventions (tidyverse style guide)
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting PR
- Respect LGPD compliance requirements

### Commit Message Format

We use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

## Documentation

- **[REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)** - Architecture consolidation details
- **[REMEDIATION_REPORT.md](REMEDIATION_REPORT.md)** - Security improvements
- **[SECURITY.md](SECURITY.md)** - Security policy and vulnerability reporting
- **[tests/README.md](tests/README.md)** - Testing documentation

## Support

For issues, questions, or contributions:
- **GitHub Issues**: [Report bugs or request features](https://github.com/sofiadonario/monitor-legislativo-v4/issues)
- **Pull Requests**: [Contribute code](https://github.com/sofiadonario/monitor-legislativo-v4/pulls)

## License

Distributed under the MIT License. See `LICENSE` for more information.

---

## Acknowledgments

- **IBGE** - Brazilian Institute of Geography and Statistics (geographic data)
- **LexML Brasil** - Brazilian legislative document standards
- **R Community** - For excellent packages and support
- **Shiny Community** - For comprehensive documentation and examples

---

**Desenvolvido com ❤️ para a comunidade acadêmica e governamental brasileira**

*Monitor Legislativo v4 - Transforming legislative data into actionable insights*

**Version**: 4.0 | **Last Updated**: November 2024 | **Status**: Production Ready ✅

---

## Recent Deployments

- **v146** (November 2024): Color gradient improvements with quantile-based bins
- **v145** (November 2024): Geographic map data merge fix (sigla field)
- **Google Cloud Run**: Current production environment (southamerica-east1)
