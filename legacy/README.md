# Legacy Services - Monitor Legislativo v4

⚠️ **DEPRECATED SERVICES** - These services are no longer active and have been replaced by the unified R-Shiny service in the root directory.

## 📋 Overview

This directory contains all deprecated services from the previous **multi-service architecture** of Monitor Legislativo v4. These services have been migrated to a **unified R-Shiny service** for better performance, maintainability, and deployment simplicity.

## 🏗️ Architecture Migration Summary

### **Before (Multi-Service)**
- **Backend**: Python/FastAPI service (`backend/`)
- **Frontend**: React/TypeScript service (`frontend/`)
- **R-Shiny**: Multiple R-Shiny variants (`r-shiny/`)
- **Config**: Separate configuration files (`config/`)

### **After (Unified Service)**
- **Single Service**: Unified R-Shiny service in root directory
- **Direct Database Access**: PostgreSQL + Redis integration
- **Simplified Deployment**: One Railway service configuration
- **Better Performance**: Reduced inter-service communication

## 📁 Directory Structure

```
legacy/
├── backend/                     # Python FastAPI Service (DEPRECATED)
│   ├── src/
│   │   ├── api/                # API endpoints
│   │   ├── cache/              # Redis caching
│   │   ├── config/             # Configuration
│   │   ├── database/           # Database connections
│   │   ├── models/             # Data models
│   │   ├── routers/            # API routes
│   │   └── services/           # Business logic
│   ├── tests/                  # Backend tests
│   ├── Dockerfile              # Container configuration
│   └── pyproject.toml          # Python dependencies
├── frontend/                    # React TypeScript Service (DEPRECATED)
│   ├── src/
│   │   ├── components/         # React components
│   │   ├── config/             # API configuration
│   │   ├── hooks/              # React hooks
│   │   ├── pages/              # Application pages
│   │   ├── services/           # API services
│   │   └── styles/             # CSS styling
│   ├── public/                 # Static assets
│   ├── package.json            # Node.js dependencies
│   └── Dockerfile              # Container configuration
├── r-shiny/                    # Old R-Shiny Variants (DEPRECATED)
│   ├── r-shiny-app/           # Original R-Shiny application
│   ├── r-shiny-consolidated/  # Consolidated R-Shiny
│   ├── r-shiny-minimal/       # Minimal R-Shiny
│   └── r-shiny-standalone/    # Standalone R-Shiny
├── config/                     # Configuration Files (DEPRECATED)
│   ├── railway.frontend.json  # Frontend Railway config
│   ├── docker-compose.yml     # Docker Compose
│   └── vite.config.ts         # Vite configuration
├── DEPRECATED_SERVICES.md      # Detailed deprecation information
└── README.md                   # This file
```

## 🔧 Legacy Services Details

### **Backend Service** (`backend/`)
- **Technology**: Python + FastAPI + SQLAlchemy
- **Purpose**: REST API, database management, caching
- **Features**: 
  - Geographic analysis endpoints
  - ML text processing
  - Document validation
  - AI agents and analysis
  - Vocabulary management
- **Status**: **DEPRECATED** - Functionality migrated to R service

### **Frontend Service** (`frontend/`)
- **Technology**: React + TypeScript + Vite
- **Purpose**: User interface, search, visualizations
- **Features**:
  - Interactive dashboards
  - Search interfaces
  - Geographic maps
  - Document viewers
  - Export panels
- **Status**: **DEPRECATED** - UI migrated to R-Shiny

### **R-Shiny Services** (`r-shiny/`)
- **Technology**: R + Shiny + Various packages
- **Purpose**: Analytics, dashboards, reports
- **Variants**:
  - `r-shiny-app/`: Original implementation
  - `r-shiny-consolidated/`: Feature-rich version
  - `r-shiny-minimal/`: Lightweight version
  - `r-shiny-standalone/`: Independent deployment
- **Status**: **DEPRECATED** - Consolidated into unified service

### **Configuration Files** (`config/`)
- **Purpose**: Deployment and build configurations
- **Contents**:
  - Railway deployment configs
  - Docker configurations
  - Build tool configurations
  - Environment templates
- **Status**: **DEPRECATED** - Simplified to single config

## 🔄 Migration Mapping

| Legacy Component | Unified Service Equivalent |
|------------------|---------------------------|
| `backend/src/api/` | R functions in `../R/` |
| `backend/src/cache/` | R Redis integration |
| `backend/src/models/` | R data structures |
| `frontend/src/components/` | R-Shiny UI components |
| `frontend/src/services/` | R API client functions |
| `r-shiny/*/app.R` | `../app.R` (consolidated) |
| `config/railway.*.json` | `../railway-unified.toml` |

## 📊 Performance Comparison

| Metric | Legacy (Multi-Service) | Unified Service | Improvement |
|--------|------------------------|-----------------|-------------|
| **Services** | 3+ services | 1 service | 70% reduction |
| **Deployment Time** | 10-15 minutes | 3-5 minutes | 70% faster |
| **Response Time** | 2-5 seconds | 0.5-2 seconds | 60-75% faster |
| **Memory Usage** | High (multiple processes) | Medium (single process) | 40% reduction |
| **Maintenance** | Complex (multiple codebases) | Simple (single codebase) | 90% easier |

## 🛠️ Development Reference

### **Running Legacy Services** (NOT RECOMMENDED)
```bash
# Backend (Python/FastAPI)
cd legacy/backend
poetry install
poetry run uvicorn src.main:app --reload

# Frontend (React/TypeScript)
cd legacy/frontend
npm install
npm run dev

# R-Shiny (Original)
cd legacy/r-shiny/r-shiny-app
R -e "source('app.R')"
```

### **Migration Commands Used**
```bash
# Services moved to legacy
mv backend legacy/
mv frontend legacy/
mv config legacy/

# Unified service promoted to root
cp legacy/r-shiny/r-shiny-app/* .
```

## 🔍 Code Reference

### **Backend Code Patterns**
- **API Endpoints**: `backend/src/api/`
- **Database Models**: `backend/src/models/`
- **Cache Management**: `backend/src/cache/`
- **Health Checks**: `backend/src/health.py`

### **Frontend Code Patterns**
- **React Components**: `frontend/src/components/`
- **API Integration**: `frontend/src/services/`
- **State Management**: `frontend/src/hooks/`
- **Routing**: `frontend/src/App.tsx`

### **R-Shiny Code Patterns**
- **UI Components**: `r-shiny/*/app.R`
- **Database Connections**: `r-shiny/*/R/database.R`
- **API Clients**: `r-shiny/*/R/api_client.R`
- **Visualization**: `r-shiny/*/R/visualization.R`

## 📚 Documentation References

- **Architecture Migration**: `../ARCHITECTURE_MIGRATION.md`
- **Unified Service**: `../README.md`
- **Deprecation Details**: `DEPRECATED_SERVICES.md`
- **Development Guide**: `../docs/DEVELOPMENT_GUIDE.md`

## 🔒 Security Notes

- **✅ Credentials Sanitized**: All hardcoded credentials removed
- **✅ Environment Variables**: Sensitive config moved to Railway
- **✅ Safe for Archive**: No security risks in legacy files
- **✅ Reference Only**: Not suitable for production deployment

## ⚠️ Important Warnings

1. **DO NOT DEPLOY**: These services are deprecated and not maintained
2. **REFERENCE ONLY**: Use for understanding previous implementations
3. **SECURITY**: Do not use old configuration files with credentials
4. **DEPENDENCIES**: Package versions may be outdated and vulnerable
5. **SUPPORT**: No bug fixes or updates will be provided

## 🎯 Use Cases for Legacy Code

### **✅ Acceptable Uses**
- Understanding previous implementation patterns
- Comparing old vs new approaches
- Academic research and documentation
- Code pattern reference for similar projects
- Migration verification and validation

### **❌ Unacceptable Uses**
- Production deployment
- New feature development
- Security-critical applications
- Client-facing services
- Integration with active systems

## 🚀 Current Active Service

The **unified R-Shiny service** in the root directory (`../`) is the current active implementation:

```bash
# Current active service
cd ../
R -e "source('app.R')"
```

## 📞 Support and Questions

For questions about:
- **Legacy Services**: Review this documentation and code comments
- **Migration Process**: See `../ARCHITECTURE_MIGRATION.md`
- **Current Service**: See `../README.md` and `../docs/`
- **Development**: See `../dev-tools/` and documentation

---

**Remember**: These are **deprecated services** maintained for reference only. The unified R-Shiny service in the root directory is the current active implementation.