# R Shiny Setup Instructions - Monitor Legislativo v4

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
cd r-shiny-app/
Rscript setup_and_run.R
```

This script will:
- ✅ Check R version (4.0+ required)
- ✅ Install all required R packages
- ✅ Create necessary directories
- ✅ Test API connectivity
- ✅ Start the application

### Option 2: Manual Setup
```bash
cd r-shiny-app/
Rscript run_local.R
```

## 📋 Prerequisites

### Required Software
- **R** (version 4.0 or higher)
  - Download: https://cloud.r-project.org/
- **RStudio** (optional but recommended)
  - Download: https://posit.co/download/rstudio-desktop/

### System Dependencies

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
  libgdal-dev \
  libudunits2-dev \
  libproj-dev \
  libgeos-dev \
  libcurl4-openssl-dev \
  libssl-dev \
  libxml2-dev
```

#### macOS
```bash
brew install gdal udunits proj geos
```

#### Windows
- No additional system dependencies required
- R packages will handle dependencies automatically

## 🔐 Login Credentials

The application includes a built-in authentication system with test users:

| Role          | Username    | Password      | Access Level |
|---------------|-------------|---------------|--------------|
| Administrator | admin       | admin123      | Full access  |
| Researcher    | researcher  | research123   | Research tools |
| Student       | student     | student123    | View only    |

## 🗂️ Directory Structure

The application will create these directories automatically:
```
r-shiny-app/
├── data/              # Data storage
│   ├── cache/         # API response cache
│   ├── geographic/    # Maps and boundaries
│   └── legislative.db # SQLite database
├── exports/           # User exports
├── logs/              # Application logs
└── www/               # Static assets
```

## 🌐 API Configuration

The application connects to these Brazilian government APIs:
- **Câmara dos Deputados**: https://dadosabertos.camara.leg.br/api/v2
- **Senado Federal**: https://legis.senado.leg.br/dadosabertos
- **LexML Brasil**: https://www.lexml.gov.br/api/v1

All APIs are free and don't require authentication.

## 🚀 Running the Application

### Local Development
```r
# In R or RStudio
shiny::runApp(port = 3838)
```

### Production Deployment

#### Option 1: Shinyapps.io (Recommended for academics)
```r
# Install rsconnect
install.packages("rsconnect")

# Configure account
rsconnect::setAccountInfo(
  name = "your-account",
  token = "your-token",
  secret = "your-secret"
)

# Deploy
rsconnect::deployApp()
```

#### Option 2: Shiny Server (Self-hosted)
```bash
# Copy app to Shiny Server directory
sudo cp -R /path/to/r-shiny-app /srv/shiny-server/monitor-legislativo

# Set permissions
sudo chown -R shiny:shiny /srv/shiny-server/monitor-legislativo
```

#### Option 3: Docker (Coming soon)
```bash
docker build -t monitor-legislativo-shiny .
docker run -p 3838:3838 monitor-legislativo-shiny
```

## 🔧 Troubleshooting

### Package Installation Issues
```r
# If a package fails to install, try:
install.packages("package_name", dependencies = TRUE, repos = "https://cloud.r-project.org/")

# For geographic packages on Linux:
install.packages("sf", configure.args = "--with-proj-lib=/usr/local/lib")
```

### Geographic Data Issues
```r
# If geobr fails, manually download data:
# The app will still work without pre-downloaded geographic data
```

### API Connection Issues
- Check internet connectivity
- Verify firewall settings
- The app includes fallback CSV data if APIs are unavailable

### Memory Issues
```r
# Increase memory limit on Windows
memory.limit(size = 8000)

# Clear cache if needed
unlink("data/cache/*", recursive = TRUE)
```

## 📊 Features Overview

### 1. Legislative Search
- Real-time search across multiple government databases
- Advanced filters by date, type, state, and chamber
- Full-text search with Portuguese language support

### 2. Geographic Visualization
- Interactive maps showing legislation density by state
- Click states for detailed information
- Heatmap visualization of legislative activity

### 3. Data Export
- **CSV**: For spreadsheet analysis
- **Excel**: Multi-sheet workbooks with formatting
- **XML**: Structured data for academic tools
- **HTML**: Formatted reports with citations

### 4. Academic Features
- Automatic citation generation (ABNT format)
- Metadata preservation for research
- Integration with reference managers

## 🔄 Updates and Maintenance

### Updating Packages
```r
# Update all packages
update.packages(ask = FALSE)

# Update specific package
install.packages("package_name")
```

### Clearing Cache
```r
# Clear API cache (preserves database)
unlink("data/cache/*", recursive = TRUE)

# Full reset (removes all data)
unlink("data/*", recursive = TRUE)
```

### Backup Database
```bash
# Create backup
cp data/legislative.db data/legislative_backup_$(date +%Y%m%d).db

# Restore backup
cp data/legislative_backup_20240615.db data/legislative.db
```

## 📞 Support

### Common Issues
1. **"Package not found"**: Run `.Rprofile` or `setup_and_run.R`
2. **"Cannot connect to API"**: Check internet and firewall
3. **"Login failed"**: Use exact credentials (case-sensitive)
4. **"Map not loading"**: Geographic data downloads on first use

### Getting Help
- Check `README.md` for detailed documentation
- Review `PRE_DEPLOYMENT_AUDIT_REPORT.md` for security information
- See application logs in `logs/` directory

## 🎓 Academic Usage

### Citation
```
Monitor Legislativo v4 - R Shiny Edition. (2024). 
Academic Legislative Analysis Platform for Brazilian Law.
Available at: [your-deployment-url]
```

### Data Attribution
All legislative data comes from official Brazilian government sources and should be cited accordingly.

## ✅ Setup Checklist

- [ ] R version 4.0+ installed
- [ ] System dependencies installed (Linux/macOS)
- [ ] Run `setup_and_run.R` successfully
- [ ] Application opens in browser
- [ ] Can login with test credentials
- [ ] Can search for legislation
- [ ] Map visualization works
- [ ] Can export data

---

**Ready to start?** Run `Rscript setup_and_run.R` and the application will guide you through the rest!