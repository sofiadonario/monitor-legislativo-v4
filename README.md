# Monitor Legislativo v4 - Unified R Service

🇧🇷 **Monitor Legislativo v4** is a unified R-Shiny application for monitoring Brazilian legislative data, deployed on Railway with PostgreSQL and Redis integration.

## 🏗️ Architecture Overview

**Unified Service Architecture:**
- **Primary Service**: R-Shiny application (`app.R`)
- **Database**: PostgreSQL (Railway managed)
- **Cache**: Redis (Railway managed)
- **Deployment**: Railway platform

## 📁 Project Structure

```
monitor-legislativo-v4/
├── app.R                    # Main R-Shiny application
├── config.yml              # Application configuration
├── railway-unified.toml     # Railway deployment configuration
├── R/                       # R modules and functions
│   ├── api_client.R
│   ├── database_connection.R
│   ├── map_generator.R
│   └── ...
├── data/                    # Data files and exports
├── exports/                 # Generated export files
├── docs/                    # Documentation
├── dev-tools/              # Development tools and scripts
├── legacy/                 # Legacy services (archived)
│   ├── backend/            # Python FastAPI service (deprecated)
│   ├── frontend/           # React frontend (deprecated)
│   └── r-shiny/            # Old R-Shiny variants (deprecated)
└── archive/                # Archived files and media
```

## 🚀 Quick Start

### Prerequisites
- R 4.3+
- PostgreSQL database (Railway managed)
- Redis cache (Railway managed)

### Local Development
```bash
# Start the R-Shiny application
R -e "source('app.R')"
```

### Production Deployment
The application is deployed on Railway using `railway-unified.toml`:
```bash
# Deploy to Railway
railway up
```

## 🔧 Configuration

### Environment Variables
```bash
# Database connection
DATABASE_URL=postgresql://user:password@host:port/database

# Redis cache
REDIS_URL=redis://default:password@host:port

# Application settings
PORT=3838
R_CONFIG_ACTIVE=production
SHINY_LOG_LEVEL=INFO
```

### Database Schema
- **PostgreSQL**: Primary data storage
- **Redis**: Caching layer for performance optimization
- **Data Sources**: Brazilian legislative documents, transport legislation focus

## 📊 Features

- **Real-time Legislative Search**: Search Brazilian legislative documents
- **Geographic Analysis**: Map-based visualization of legislation
- **Transport Focus**: Specialized analysis for transport legislation
- **Academic Tools**: Citation generation and research features
- **Export Capabilities**: CSV, XLSX, and other formats
- **Performance Optimized**: Redis caching for fast responses

## 🏛️ Data Sources

- **LexML Brasil**: Official Brazilian legislative XML
- **IBGE**: Geographic and demographic data
- **Transport Agencies**: Specialized transport legislation
- **Academic Databases**: Research and citation data

## 🔄 Service Migration

This project has been migrated to a unified architecture:

- **Before**: Multi-service architecture (backend, frontend, r-shiny)
- **After**: Unified R-Shiny service with PostgreSQL and Redis
- **Benefits**: Simplified deployment, better performance, easier maintenance

## 📚 Documentation

- **User Guide**: See `docs/USER_GUIDE.md`
- **API Documentation**: See `docs/API_DOCUMENTATION.md`
- **Deployment Guide**: See `docs/DEPLOYMENT_GUIDE.md`
- **Development Guide**: See `docs/DEVELOPMENT_GUIDE.md`

## 🗂️ Legacy Services

Legacy services have been moved to the `legacy/` directory:
- **Backend (Python/FastAPI)**: `legacy/backend/`
- **Frontend (React/TypeScript)**: `legacy/frontend/`
- **Old R-Shiny variants**: `legacy/r-shiny/`

These services are deprecated and maintained for reference only.

## 🛠️ Development Tools

Development tools and scripts are available in `dev-tools/`:
- **Migration scripts**: Database and deployment utilities
- **Test files**: Testing and validation scripts
- **Docker files**: Container configurations
- **Build tools**: Development utilities

## 🔍 Health Monitoring

The application includes comprehensive health monitoring:
- **Application Health**: `/health` endpoint
- **Database Connectivity**: PostgreSQL connection monitoring
- **Cache Performance**: Redis performance metrics
- **Memory Usage**: R session monitoring

## 🤝 Contributing

This is an academic research project. For contributions:
1. Follow R coding standards
2. Update documentation
3. Test with sample data
4. Ensure Railway compatibility

## 📄 License

Academic research project - see license terms in documentation.

## 🎯 Research Focus

Monitor Legislativo v4 is designed for academic research on Brazilian transport legislation, providing tools for:
- Legislative pattern analysis
- Geographic legislation mapping
- Transport policy research
- Academic citation generation

---

**Monitor Legislativo v4** - Unified R Service for Brazilian Legislative Research