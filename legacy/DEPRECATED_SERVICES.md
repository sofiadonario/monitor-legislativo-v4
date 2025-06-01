# Deprecated Services

⚠️ **DEPRECATED** - These services are no longer maintained as part of the Monitor Legislativo v4 architecture migration.

## Architecture Migration Summary

Monitor Legislativo v4 has migrated from a **multi-service architecture** to a **unified R-Shiny service**:

- **Before**: Backend (Python/FastAPI) + Frontend (React/TypeScript) + R-Shiny (Analytics)
- **After**: Unified R-Shiny service with PostgreSQL and Redis

## Legacy Services Directory Structure

```
legacy/
├── backend/                # Python FastAPI service (deprecated)
│   ├── src/               # FastAPI application code
│   ├── tests/             # Backend tests
│   └── railway.json       # Old Railway config
├── frontend/              # React TypeScript service (deprecated)
│   ├── src/               # React application code
│   ├── public/            # Static assets
│   └── package.json       # Node.js dependencies
├── r-shiny/              # Old R-Shiny variants (deprecated)
│   ├── r-shiny-app/      # Original R-Shiny application
│   ├── r-shiny-consolidated/ # Consolidated R-Shiny with advanced features
│   ├── r-shiny-minimal/  # Minimal R-Shiny deployment
│   └── r-shiny-standalone/ # Standalone R-Shiny service
└── config/               # Old configuration files (deprecated)
    ├── railway.toml       # Old backend config
    └── railway.frontend.json # Old frontend config
```

## Migration Status

- **Current Active Service**: Root directory unified R-Shiny service (`railway-unified.toml`)
- **Status**: All legacy services archived for reference only
- **Deployment**: **DO NOT** deploy legacy services in production

## Deprecated Components

### Backend Service (Python/FastAPI)
- **Location**: `legacy/backend/`
- **Purpose**: REST API endpoints, database management, caching
- **Replacement**: R-Shiny with direct database access
- **Status**: Fully migrated to R implementation

### Frontend Service (React/TypeScript)
- **Location**: `legacy/frontend/`
- **Purpose**: User interface, search, visualizations
- **Replacement**: R-Shiny UI with equivalent functionality
- **Status**: All features migrated to R-Shiny

### Legacy R-Shiny Variants
- **Location**: `legacy/r-shiny/`
- **Purpose**: Analytics, dashboards, reports
- **Replacement**: Unified R-Shiny service in root directory
- **Status**: Consolidated into single service

## Security Notice

⚠️ **SECURITY**: Legacy configuration files have been sanitized to remove hardcoded credentials. 
- All sensitive configuration moved to Railway environment variables
- No credentials stored in legacy files
- Safe for archival purposes

## Cleanup Actions Performed

1. **Service Migration**: Moved backend, frontend, and old R-Shiny services to legacy/
2. **Configuration Cleanup**: Removed hardcoded credentials from all config files
3. **Architecture Simplification**: Consolidated to single unified service
4. **Documentation**: Updated to reflect new architecture
5. **Security**: Sanitized all legacy configuration files

## Reference Use Only

These legacy services are maintained for:
- **Historical Reference**: Understanding previous implementation
- **Feature Comparison**: Comparing old vs new implementations
- **Development Reference**: Code patterns and solutions
- **Academic Documentation**: Research and development history

## Migration Guide

See `ARCHITECTURE_MIGRATION.md` in the root directory for:
- Complete migration overview
- Feature mapping between old and new services
- Performance improvements
- Development workflow changes

## Contact

For questions about the migration or legacy services:
- See main project documentation
- Review `ARCHITECTURE_MIGRATION.md`
- Check unified service documentation in root directory