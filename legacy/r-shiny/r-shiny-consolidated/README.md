# Monitor Legislativo v4 - R Architecture Consolidation

A modern, unified R Shiny application for monitoring Brazilian legislative data with advanced geographic analysis and AI-enhanced search capabilities.

## 🎯 Overview

This is the consolidated R architecture version of Monitor Legislativo v4, implementing the recommendations from the compass analysis to migrate from a multi-stack system (React + FastAPI + R Shiny) to a pure R solution using modern frameworks.

### Key Features

- **Modern UI**: Built with `bslib` for Bootstrap 5 integration and responsive design
- **Interactive Visualizations**: Advanced charts using `echarts4r` with smooth animations
- **Geographic Analysis**: Interactive maps with `leaflet` and `tmap` for Brazilian legislative data
- **Real-time Search**: Enhanced LexML integration with vocabulary expansion
- **Academic Focus**: Built-in citation generation and research workflow tools
- **Performance Optimized**: Multi-layer caching with Redis integration

## 🏗️ Architecture

### Technology Stack

- **Frontend**: R Shiny with `bslib` Bootstrap 5 theming
- **Visualization**: `echarts4r` for charts, `leaflet` for maps, `tmap` for geographic analysis
- **Database**: PostgreSQL with connection pooling via `pool`
- **Cache**: Redis with `redux` integration and memory fallback
- **API Integration**: Backend API client with automatic fallbacks
- **Deployment**: Docker containers with health checks

### Modern R Frameworks

This application leverages the latest R web development capabilities:

- **bslib**: Modern Bootstrap 5 integration with real-time theming
- **echarts4r**: 36+ chart types with professional animations
- **leaflet**: Interactive maps with clustering and custom markers
- **tmap**: Dual-mode static/interactive geographic visualization
- **DT**: Advanced data tables with search and export capabilities

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- R 4.3+ (for local development)
- Git

### Using Docker (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd monitor_legislativo_v4/r-shiny-consolidated
   ```

2. **Start the application**
   ```bash
   # Production mode
   docker-compose up -d
   
   # Development mode (includes pgAdmin and Redis Commander)
   docker-compose --profile development up -d
   ```

3. **Access the application**
   - Main application: http://localhost:3838
   - pgAdmin (dev): http://localhost:8080
   - Redis Commander (dev): http://localhost:8081

### Local Development

1. **Install R dependencies**
   ```r
   install.packages("renv")
   renv::restore()
   ```

2. **Configure environment**
   ```bash
   cp config.yml.example config.yml
   # Edit config.yml with your settings
   ```

3. **Run the application**
   ```r
   shiny::runApp("app.R", port = 3838)
   ```

## 📊 Features

### 🔍 Enhanced Search & Analysis

- **Vocabulary-aware Search**: SKOS vocabulary expansion for comprehensive results
- **Advanced Filtering**: Date ranges, document types, geographic filters
- **Real-time Results**: Live search with caching for performance
- **Export Capabilities**: CSV, Excel, PDF, HTML, JSON formats

### 🗺️ Geographic Analysis

- **Interactive Maps**: Brazilian states and municipalities with document clustering
- **Choropleth Visualization**: Color-coded maps by document density or recency
- **Geographic Statistics**: Comprehensive coverage analysis and regional distribution
- **IBGE Integration**: Official Brazilian geographic data with 5,570 municipalities

### 📈 Data Visualization

- **Interactive Charts**: Modern charts with `echarts4r` including bar, line, pie, and temporal charts
- **Geographic Visualization**: Advanced mapping with multiple layers and custom markers
- **Comparison Analysis**: Multi-series charts for trend analysis
- **Quality Metrics**: Data quality gauges and summary statistics

### 🎓 Academic Features

- **Citation Generation**: Automatic academic citations in ABNT, APA formats
- **Research Workflows**: Document comparison, annotation, and analysis tools
- **Export Options**: Research-grade data export with metadata preservation
- **Data Integrity**: Quality scoring and validation for academic use

## ⚙️ Configuration

### Environment Variables

```bash
# Database Configuration
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=monitor_legislativo
DATABASE_USER=monitor_user
DATABASE_PASSWORD=your_password

# Redis Cache
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# Backend API
BACKEND_URL=https://monitor-legislativo-v4-production.up.railway.app

# Application Settings
R_CONFIG_ACTIVE=production  # or development
SHINY_PORT=3838
```

### Configuration Files

- `config.yml`: Application configuration with environment-specific settings
- `renv.lock`: R package versions for reproducible deployment
- `DESCRIPTION`: Package metadata and dependencies

## 🛠️ Development

### Project Structure

```
r-shiny-consolidated/
├── app.R                 # Main Shiny application
├── config.yml           # Configuration settings
├── DESCRIPTION           # Package metadata
├── renv.lock            # Package lock file
├── Dockerfile           # Container configuration
├── docker-compose.yml   # Multi-service setup
├── R/                   # R modules
│   ├── api_client.R     # Backend API integration
│   ├── database.R       # Database and cache functions
│   ├── geographic.R     # Geographic analysis
│   ├── visualization.R  # Chart and visualization functions
│   └── utils.R          # Utility functions
├── data/                # Sample and fallback data
├── logs/                # Application logs
└── exports/             # Generated export files
```

### Adding New Features

1. **Create R module**: Add new functionality in `R/` directory
2. **Update dependencies**: Add packages to `DESCRIPTION` and run `renv::snapshot()`
3. **Configure settings**: Add configuration options to `config.yml`
4. **Test locally**: Use `shiny::runApp()` for testing
5. **Update documentation**: Document new features in README

### Database Schema

The application uses PostgreSQL with the following main tables:

- `documents`: Legislative documents with metadata
- `cache_entries`: Application-level caching
- Database indexes for performance optimization

## 🚢 Deployment

### Production Deployment

1. **Configure environment variables** in your deployment platform
2. **Build and deploy** the Docker container
3. **Set up database** with proper migrations
4. **Configure monitoring** and health checks

### Railway Deployment

The application is configured for Railway deployment:

```bash
# Deploy to Railway
railway up
```

### Performance Considerations

- **Caching**: Multi-layer caching (Redis + memory) for optimal performance
- **Connection Pooling**: Database connections managed by `pool` package
- **Async Operations**: Future-based async processing for long-running tasks
- **Resource Management**: Automatic memory management and cleanup

## 📈 Monitoring

### Health Checks

- Application health endpoint at `/health`
- Database connectivity monitoring
- Redis cache status monitoring
- API endpoint availability checks

### Performance Metrics

- Response time tracking
- Cache hit rates
- Database query performance
- Memory usage monitoring

## 🔒 Security

- Input validation and sanitization
- SQL injection protection via parameterized queries
- Rate limiting for API calls
- Secure environment variable handling

## 📚 Academic Use

This platform is designed for academic research with:

- **Data Integrity**: Quality validation and provenance tracking
- **Reproducibility**: Versioned data and analysis capabilities
- **Citation Support**: Automatic citation generation
- **Export Standards**: Research-grade data export formats

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

## 📞 Support

For questions, issues, or feature requests:

- Open an issue on GitHub
- Contact the development team
- Check the documentation in `/docs`

## 🔄 Migration from Multi-Stack

This R architecture consolidation provides:

- **50-70% reduction** in development time
- **Simplified deployment** with single container
- **Enhanced performance** for academic use cases
- **Better integration** with statistical workflows
- **Reduced infrastructure costs**

The migration maintains 100% feature parity with the previous multi-stack system while providing improved maintainability and development velocity.