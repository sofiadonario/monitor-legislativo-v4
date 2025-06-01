# Monitor Legislativo v4 - Repository Structure

## 📁 Repository Organization

This document describes the comprehensive organization structure of the Monitor Legislativo v4 repository, implemented to provide clear separation of concerns and improved maintainability.

## 🏗️ Root Structure

```
monitor_legislativo_v4/
├── 📋 planning/                    # Project planning, roadmaps, and PRDs
├── 📚 documentation/              # All documentation, guides, and reports
├── 🔧 development/                # Development tools, scripts, and research
├── 🌐 external/                   # External libraries and third-party tools
├── 🐍 Backend Components
│   ├── core/                      # Core Python backend services
│   ├── main_app/                  # FastAPI main application
│   ├── web/                       # Additional web endpoints
│   ├── services/                  # Microservices (admin, collector)
│   ├── r-shiny-app/              # R Shiny analytics application
│   └── desktop/                   # Desktop application (experimental)
├── ⚛️ Frontend Components
│   ├── src/                       # React TypeScript application
│   ├── public/                    # Static assets and data
│   └── dist/                      # Build output (generated)
├── 🗃️ Data & Configuration
│   ├── data/                      # Data storage (exports, processed, raw)
│   ├── configs/                   # Configuration files
│   ├── migrations/                # Database migration scripts
│   └── tests/                     # Integration tests
└── 🚀 Deployment & Build
    ├── Dockerfile*                # Container definitions
    ├── docker-compose.yml         # Multi-container setup
    ├── package.json               # Node.js dependencies
    ├── requirements*.txt          # Python dependencies
    └── railway.json               # Railway deployment config
```

## 📋 Planning Directory

**Location**: `/planning/`

Contains all project planning documents, roadmaps, and feature specifications.

### Structure:
```
planning/
├── PRD-Implementation-Roadmap.md  # Master implementation roadmap
├── projectplan.md                 # Current project execution plan
├── Phase-1-Core-Infrastructure.md # Phase 1 planning document
├── Phase-2-Data-Collection-Service.md # Phase 2 planning document
└── features/                      # Feature-specific planning
    ├── api-optimization/
    │   ├── PRD.md
    │   └── PHASE4-VALIDATION.md
    └── real-time-search-integration/
        └── PRD.md
```

### Purpose:
- Centralized project planning and roadmap management
- Feature specifications and requirements documentation
- Phase-based development planning
- Sprint and milestone tracking

## 📚 Documentation Directory

**Location**: `/documentation/`

Comprehensive documentation hub covering all aspects of the project.

### Structure:
```
documentation/
├── deployment/                    # Deployment guides and checklists
│   ├── DEPLOYMENT_CHECKLIST.md
│   ├── DEPLOYMENT_INSTRUCTIONS.md
│   ├── DEPLOYMENT_NOTES.md
│   ├── RAILWAY_DEPLOYMENT_CHECKLIST.md
│   └── aws-mackintegridade-deployment/
│       ├── PRD-AWS-MACKENZIE-DEPLOYMENT.md
│       ├── aws-infrastructure.yml
│       ├── deployment-plan.md
│       ├── configs/
│       ├── docker/
│       ├── scripts/
│       ├── mackintegridade-integration.md
│       └── typo3-integration-guide.md
├── guides/                        # User and developer guides
│   ├── database-configuration-guide.md
│   ├── supabase-integration-prd.md
│   └── docs/                      # Original docs folder
│       └── guia-legislacao-transporte.md
├── reports/                       # Technical reports and summaries
│   ├── O3_MAX_MODE_TECHNICAL_REPORT.md
│   ├── PHASE-1-COMPLETION-SUMMARY.md
│   ├── THREE_TIER_SEARCH_FIX_REPORT.md
│   └── integration-status-report.md
└── legacy/                        # Historical documents
    ├── PRD: LexML Brasil Integration Fix.d
    ├── lexml_implementation_instructions.pdf
    └── useful screenshots/
        ├── img1 - outdated.png
        ├── img2 - outdated.png
        ├── img3 - outdated.png
        ├── img4 - outdated.png
        ├── img5 - outdated.png
        ├── img6 - outdated.png
        └── img7.png
```

### Purpose:
- Deployment procedures and environment setup
- User guides and technical documentation
- Progress reports and technical analyses
- Historical document preservation

## 🔧 Development Directory

**Location**: `/development/`

Development tools, utilities, scripts, and research materials.

### Structure:
```
development/
├── scripts/                      # Development and utility scripts
│   ├── dev-setup.sh              # Development environment setup
│   ├── debug-start.sh            # Debug startup script
│   ├── setup_database.bat        # Database setup (Windows)
│   ├── setup_database.sh         # Database setup (Unix)
│   └── initialize_database.py    # Database initialization
├── test-scripts/                 # Testing and validation scripts
│   ├── test_api_endpoints.py     # API endpoint testing
│   ├── test_database.py          # Database testing
│   ├── test_lexml_standalone.py  # LexML testing
│   ├── test_search_issue.py      # Search functionality testing
│   ├── test_simple_fallback.py   # Fallback mechanism testing
│   ├── test_tier3_fallback.py    # Tier 3 fallback testing
│   ├── verify_lexml_implementation.py # LexML verification
│   ├── verify_setup.py           # Setup verification
│   ├── demo_lexml_features.py    # Feature demonstration
│   ├── minimal_app.py            # Minimal application test
│   └── launch.py                 # Application launcher
└── research/                     # Research and experimental code
    ├── transport_research/        # Transport legislation research
    │   ├── __init__.py
    │   ├── enhanced_lexml_search.py
    │   ├── lexml_search_example.py
    │   ├── lexml_transport_search.py
    │   ├── lexml_working_scraper.py
    │   └── transport_terms.txt
    └── transport_terms.txt        # Transport terminology
```

### Purpose:
- Development environment setup and maintenance
- Testing and validation scripts
- Research prototypes and experimental code
- Debugging and troubleshooting tools

## 🌐 External Directory

**Location**: `/external/`

External libraries, third-party tools, and vendor dependencies.

### Structure:
```
external/
└── lexml-toolkit-3.4.3/         # LexML official toolkit
    └── lexml-toolkit-3.4.3/
        ├── LexML_Brasil-Parte_4a-Kit_Provedor_de_Dados.pdf
        ├── Perfil Provedor de Dados.xls
        ├── bin/
        ├── lib/
        │   ├── jtds-0.9.jar
        │   ├── lexml-toolkit-common-3.4.3-jar-with-dependencies.jar
        │   ├── mysql-connector-java-5.1.8-bin.jar
        │   └── postgresql-8.4-701.jdbc3.jar
        ├── license-*.txt
        └── oai/
            └── oai.war
```

### Purpose:
- Third-party library management
- External tool integration
- Vendor dependency isolation
- License compliance tracking

## 🐍 Backend Components

### Core (`/core/`)
**Purpose**: Core Python backend services and business logic

```
core/
├── api/           # API service implementations
├── cache/         # Caching layer
├── config/        # Configuration management
├── database/      # Database access layer
├── jobs/          # Background job processing
├── lexml/         # LexML integration
├── models/        # Data models
└── utils/         # Utility functions
```

### Main App (`/main_app/`)
**Purpose**: FastAPI main application entry point

```
main_app/
├── main.py        # FastAPI application
├── models/        # API models
├── routers/       # API route handlers
└── services/      # Application services
```

### Services (`/services/`)
**Purpose**: Microservices architecture

```
services/
├── admin/         # Administrative interface (React/Vite)
└── collector/     # Data collection service (Prefect)
```

### R Shiny App (`/r-shiny-app/`)
**Purpose**: R-based analytics dashboard

```
r-shiny-app/
├── app.R          # Main Shiny application
├── R/             # R modules and functions
├── *.R            # Utility and deployment scripts
└── *.md           # R-specific documentation
```

## ⚛️ Frontend Components

### Source (`/src/`)
**Purpose**: React TypeScript frontend application

```
src/
├── components/    # React components
├── pages/         # Page-level components
├── hooks/         # Custom React hooks
├── services/      # Frontend services
├── config/        # Frontend configuration
├── styles/        # CSS and styling
├── types/         # TypeScript type definitions
├── utils/         # Utility functions
├── features/      # Feature-specific code
└── data/          # Static data and constants
```

### Key Features:
- **R Shiny Integration**: Secure iframe embedding with data synchronization
- **Real-time Updates**: SSE-based real-time dashboard updates
- **Advanced Search**: Saved queries with tag-based organization
- **Mobile Responsive**: Touch-friendly interface with accessibility features

## 🗃️ Data & Configuration

### Data (`/data/`)
**Purpose**: Data storage and processing

```
data/
├── exports/       # Exported data files
├── processed/     # Processed data
└── raw/           # Raw data files
```

### Configurations (`/configs/`)
**Purpose**: Application configuration files

```
configs/
├── alert_config.json    # Alert system configuration
└── demo_config.json     # Demo mode configuration
```

### Migrations (`/migrations/`)
**Purpose**: Database schema management

```
migrations/
├── 001_two_tier_schema.sql      # Two-tier architecture schema
├── 002_document_fingerprints.sql # Document fingerprinting
├── 003_export_logs.sql          # Export logging
└── 004_alerts_table.sql         # Alert system tables
```

## 🚀 Deployment & Build

### Container Definitions
- `Dockerfile` - Main application container
- `Dockerfile.frontend` - Frontend container
- `docker-compose.yml` - Multi-container orchestration

### Dependencies
- `package.json` - Node.js frontend dependencies
- `requirements.txt` - Python production dependencies
- `requirements-production.txt` - Production-specific dependencies
- `runtime.txt` - Python runtime version

### Configuration
- `railway.json` - Railway deployment configuration
- `jest.config.js` - Jest testing configuration
- `tsconfig*.json` - TypeScript configuration
- `vite*.config.ts` - Vite build configuration

## 🔄 Migration from Old Structure

The reorganization involved:

1. **Planning Consolidation**: All PRDs, roadmaps, and planning documents moved to `/planning/`
2. **Documentation Centralization**: Created structured documentation hub with categorized content
3. **Development Tools**: Separated development scripts, tests, and research materials
4. **External Dependencies**: Isolated third-party libraries and tools
5. **Cleanup**: Removed duplicate files and desktop-specific artifacts

## 🛠️ Maintenance

### File Location Guidelines

When adding new files, follow these guidelines:

- **Planning Documents**: Add to `/planning/` or appropriate subfolder
- **Documentation**: Use `/documentation/` with appropriate category
- **Scripts**: Development scripts go to `/development/scripts/`
- **Tests**: Test files go to `/development/test-scripts/`
- **External Tools**: Add to `/external/` with proper organization
- **Source Code**: Follow existing patterns in `/src/`, `/core/`, etc.

### Reference Updates

After reorganization, update any hardcoded paths in:

- Import statements in source code
- Configuration files
- Documentation references
- Script file paths
- CI/CD pipeline configurations

## 📞 Support

For questions about the repository structure or file locations, refer to:

1. This structure document
2. Individual README files in each directory
3. Planning documents in `/planning/`
4. Technical documentation in `/documentation/guides/`

---

**Last Updated**: Phase 3 Week 10 (R Shiny Integration Completion)  
**Structure Version**: 2.0  
**Maintained By**: Claude Code Assistant