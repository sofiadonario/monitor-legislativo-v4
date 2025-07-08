# Monitor Legislativo v4 🇧🇷

**Advanced Academic Research Platform for Brazilian Legislative Data Analysis**

> **Status**: ✅ **PRODUCTION READY** - Week 12 Complete  
> **Architecture**: Pure R Shiny (Consolidated from Multi-stack)  
> **Deployment**: Railway Platform Ready  
> **Version**: 4.0 - R Architecture Consolidation

## 🎯 Project Overview

Monitor Legislativo v4 is a sophisticated academic research platform designed for comprehensive analysis of Brazilian legislative data. Following a strategic architecture consolidation, the platform now operates on a unified R Shiny framework, optimizing for academic research workflows while maintaining professional functionality.

### ✨ Key Features

- **🔍 LexML Enhanced Search**: SKOS vocabulary-aware legislative search
- **🗺️ Geographic Analysis**: Interactive mapping of 5,570 Brazilian municipalities  
- **📊 Advanced Analytics**: 36+ chart types with real-time visualizations
- **📄 Document Analysis**: Academic-grade document processing and comparison
- **🤖 AI Integration**: Document summarization and semantic search (optional)
- **📚 Academic Tools**: Citation generation (ABNT, APA, Chicago) and export capabilities

### 🏗️ Architecture Evolution

**Previous (Multi-stack)**: React + FastAPI + R Shiny  
**Current (Consolidated)**: Pure R Shiny with modern frameworks

**Benefits of Consolidation**:
- 70% reduction in development complexity
- Native statistical integration
- Simplified deployment and maintenance
- Enhanced academic research workflows
- Cost-effective scaling ($15-30/month)

## 🚀 Quick Start

### Production Deployment (Railway - Recommended)

1. **Fork/Clone Repository**
   ```bash
   git clone https://github.com/yourusername/monitor-legislativo-v4.git
   cd monitor-legislativo-v4
   ```

2. **Deploy to Railway**
   - Connect your GitHub repository to [Railway](https://railway.app)
   - Railway will automatically use `r-shiny-app/railway.toml` configuration
   - Add PostgreSQL and Redis services in Railway dashboard
   - Deploy with one click!

3. **Configure Environment** (in Railway dashboard)
   ```env
   POSTGRES_PASSWORD=your_secure_password
   OPENAI_API_KEY=your_key_here      # Optional
   ANTHROPIC_API_KEY=your_key_here   # Optional
   ```

**📖 Detailed Guide**: [Railway Deployment Guide](docs/RAILWAY_DEPLOYMENT_GUIDE.md)

### Local Development

```bash
# Navigate to R application
cd r-shiny-app/

# Install dependencies (using renv)
R -e "renv::restore()"

# Run application
R -e "shiny::runApp('app.R', host='0.0.0.0', port=3838)"
```

### Docker Deployment

```bash
cd r-shiny-app/

# Production deployment
./scripts/deploy.sh production

# Or manual Docker Compose
docker-compose -f docker-compose.production.yml up -d
```

## 📁 Repository Structure

```
monitor_legislativo_v4/
├── r-shiny-app/              # 🎯 Main R Shiny Application
│   ├── app.R                 # Main application entry point
│   ├── R/                    # R modules and services
│   ├── scripts/              # Deployment and utility scripts
│   ├── Dockerfile.production # Production container configuration
│   ├── railway.toml          # Railway deployment configuration
│   └── tests/                # Production testing suite
│
├── docs/                     # 📚 Documentation
│   ├── RAILWAY_DEPLOYMENT_GUIDE.md
│   ├── USER_GUIDE.md
│   ├── PRD-Monitor-Legislativo-v4-R-Architecture.md
│   └── ROADMAP-R-Architecture-Consolidation.md
│
├── .github/workflows/        # 🔄 CI/CD Pipeline
│   └── production-deploy.yml
│
├── frontend/                 # 📦 Legacy Frontend (Deprecated)
├── backend/                  # 📦 Legacy Backend (Deprecated)
└── config/                   # ⚙️ Legacy Configuration (Deprecated)
```

## 🛠️ Technology Stack

### Core Framework
- **R Shiny**: Web application framework
- **bslib**: Bootstrap 5 integration with modern theming
- **echarts4r**: Interactive data visualization (36+ chart types)
- **leaflet**: Interactive mapping and geographic analysis
- **DT**: Advanced data tables with search and export

### Data Processing
- **httr/httr2**: HTTP client for API integration
- **dplyr**: Data manipulation and transformation  
- **stringr**: Text processing and cleaning
- **jsonlite**: JSON processing for LexML APIs
- **DBI/RPostgres**: Database connectivity

### Infrastructure
- **PostgreSQL**: Primary database with connection pooling
- **Redis**: Caching layer for performance optimization
- **Docker**: Containerization for consistent deployment
- **Nginx**: Load balancing and SSL termination (self-hosted)
- **Railway**: Cloud platform for simplified deployment

### Monitoring & Observability
- **Prometheus**: Metrics collection (optional)
- **Grafana**: Visualization dashboards (optional)
- **Built-in Health Checks**: Automatic monitoring endpoints

## 📊 Performance Metrics

- **Response Time**: <2s for vocabulary-enhanced searches
- **Map Rendering**: <3s for municipality-level data
- **Concurrent Users**: 50-100 simultaneous users supported
- **Uptime Target**: 99.5% availability
- **Geographic Coverage**: All 5,570 Brazilian municipalities

## 🧪 Testing

### Automated Testing
```bash
# Run production test suite
cd r-shiny-app/
./scripts/run_tests.sh https://your-app.railway.app
```

### Manual Testing
- Health Check: `https://your-app.railway.app/health`
- Application: `https://your-app.railway.app`

**📋 Testing Guide**: [Production Tests](r-shiny-app/tests/production_tests.R)

## 📖 Documentation

### User Documentation
- **[User Guide](docs/USER_GUIDE.md)**: Complete platform user manual
- **[Railway Deployment](docs/RAILWAY_DEPLOYMENT_GUIDE.md)**: Step-by-step deployment guide
- **[Production README](r-shiny-app/README.production.md)**: Technical deployment documentation

### Technical Documentation  
- **[PRD Document](docs/PRD-Monitor-Legislativo-v4-R-Architecture.md)**: Product requirements and architecture
- **[Implementation Roadmap](docs/ROADMAP-R-Architecture-Consolidation.md)**: 12-week development timeline
- **[CI/CD Pipeline](.github/workflows/production-deploy.yml)**: Automated deployment workflow

## 🔧 Development

### Week-by-Week Progress

- ✅ **Week 1-2**: Foundation & Planning
- ✅ **Week 3-6**: Core Migration & Development  
- ✅ **Week 7-10**: Advanced Features & Integration
- ✅ **Week 11**: Production Deployment & Infrastructure
- ✅ **Week 12**: Testing, Documentation & Launch

### Key Achievements

**Phase 1 (Weeks 1-2)**: Foundation & Architecture
- R development environment setup
- Modern UI framework implementation (bslib)
- Database integration and caching patterns

**Phase 2 (Weeks 3-6)**: Core Features Migration  
- LexML API integration with SKOS vocabulary processing
- Interactive Brazilian municipality mapping (5,570 municipalities)
- Document analysis and academic citation tools
- Advanced data visualization with echarts4r

**Phase 3 (Weeks 7-10)**: Advanced Features
- Authentication and user management system
- Performance optimization with Redis caching
- External API integration and batch processing
- AI integration with document analysis and semantic search

**Phase 4 (Weeks 11-12)**: Production Deployment
- Docker containerization with multi-stage builds
- Load balancing and scaling infrastructure
- CI/CD pipeline with automated testing
- Comprehensive documentation and user guides

## 🔐 Security & Compliance

- **SSL/TLS**: Automatic HTTPS with Railway or custom certificates
- **Input Validation**: Comprehensive sanitization and validation
- **API Security**: Rate limiting and authentication
- **Data Protection**: Secure handling of research data
- **Academic Integrity**: Verifiable and reproducible research data

## 💰 Cost Analysis

### Railway Deployment
- **Hobby Plan**: $0/month (500 hours execution time)
- **Pro Plan**: $20/month + usage (unlimited execution, recommended for production)
- **Database**: PostgreSQL and Redis included in Railway pricing

### Estimated Monthly Costs
- **Small Scale (10-50 users)**: $15-25/month
- **Medium Scale (50-200 users)**: $25-50/month  
- **Large Scale (200+ users)**: $50-100/month

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Set up R development environment
3. Install dependencies with `renv::restore()`
4. Run tests with `./scripts/run_tests.sh`
5. Submit pull requests

### Issue Reporting
- **Bugs**: Use GitHub Issues with detailed reproduction steps
- **Features**: Describe use case and academic benefit
- **Performance**: Include metrics and environment details

## 📄 License

This project is designed for academic research purposes. See LICENSE file for details.

## 🏆 Acknowledgments

- **LexML Brasil**: Legislative XML standards and vocabulary
- **IBGE**: Brazilian geographic data and municipality information
- **R Community**: Shiny, bslib, echarts4r, and leaflet packages
- **Railway**: Simple and reliable cloud deployment platform

## 📞 Support

### Technical Support
- **Health Check**: `https://your-app.railway.app/health`
- **Documentation**: Complete guides in `/docs` folder
- **GitHub Issues**: Bug reports and feature requests

### Academic Support  
- **User Guide**: [Complete platform manual](docs/USER_GUIDE.md)
- **Research Workflows**: Academic methodology guidance
- **Citation Support**: Multiple format generation (ABNT, APA, Chicago)

---

## 🚀 Ready for Production!

Monitor Legislativo v4 has completed its 12-week architecture consolidation and is ready for production deployment. The platform now offers:

- **Unified R Codebase**: 70% reduction in development complexity
- **Modern Academic Features**: Enhanced research workflows with native statistical integration  
- **Production Infrastructure**: Docker containerization, load balancing, and monitoring
- **Cost-Effective Scaling**: Railway deployment within $15-30/month budget
- **Comprehensive Documentation**: User guides, technical docs, and deployment instructions

**🌐 Deploy Now**: [Railway Deployment Guide](docs/RAILWAY_DEPLOYMENT_GUIDE.md)

---

*Monitor Legislativo v4 - Empowering Brazilian Legislative Research*

**Status**: ✅ Production Ready | **Last Updated**: Week 12 - July 2025