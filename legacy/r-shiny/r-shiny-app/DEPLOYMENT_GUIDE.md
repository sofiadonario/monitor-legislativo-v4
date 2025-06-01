# R Shiny Deployment Guide
## Monitor Legislativo v4 - Academic Legislative Monitor

This guide provides comprehensive instructions for deploying the R Shiny application both locally and on Railway.

---

## 🚀 Quick Start Options

### Option 1: Docker (Recommended)
```bash
# Clone and navigate to the project
cd r-shiny-app/

# Build and run with Docker
./run_docker.sh

# Access the application
open http://localhost:3838
```

### Option 2: Native R Installation
```bash
# Install R (4.3+)
# macOS: brew install r
# Ubuntu: sudo apt install r-base
# Windows: Download from https://cloud.r-project.org/

# Navigate to R Shiny directory
cd r-shiny-app/

# Run the application
Rscript run_local.R
```

### Option 3: Railway Deployment
```bash
# Deploy to Railway (requires Railway CLI)
railway login
railway up
```

---

## 📋 Prerequisites

### For Local Development:
- **Docker** (recommended) OR **R 4.3+**
- **8GB RAM** minimum
- **5GB disk space** for R packages
- **Internet connection** for government APIs

### For Railway Deployment:
- **Railway account** (free tier available)
- **Railway CLI** installed
- **GitHub repository** connected

---

## 🐳 Docker Deployment (Recommended)

### Step 1: Install Docker
```bash
# macOS
brew install --cask docker

# Ubuntu
sudo apt install docker.io docker-compose

# Windows
# Download Docker Desktop from https://www.docker.com/products/docker-desktop
```

### Step 2: Build and Run
```bash
cd r-shiny-app/

# Make script executable
chmod +x run_docker.sh

# Build and run
./run_docker.sh
```

### Step 3: Verify Installation
```bash
# Check container status
docker ps

# View logs
docker logs monitor-legislativo-rshiny

# Access application
curl http://localhost:3838/health
```

### Docker Management Commands
```bash
# Stop the application
docker stop monitor-legislativo-rshiny

# Start the application
docker start monitor-legislativo-rshiny

# Restart the application
docker restart monitor-legislativo-rshiny

# Remove container
docker rm monitor-legislativo-rshiny

# Remove image (to rebuild)
docker rmi monitor-legislativo-rshiny
```

---

## 🌐 Railway Deployment

### Step 1: Install Railway CLI
```bash
# macOS
brew install railway

# npm (all platforms)
npm install -g @railway/cli

# Windows
# Download from https://railway.app/cli
```

### Step 2: Login and Initialize
```bash
# Login to Railway
railway login

# Navigate to project root
cd /path/to/monitor_legislativo_v4

# Initialize Railway project
railway init
```

### Step 3: Deploy R Shiny Service
```bash
# Deploy the R Shiny service
railway up --service monitor-legislativo-rshiny

# Monitor deployment
railway logs --service monitor-legislativo-rshiny
```

### Step 4: Configure Environment Variables
```bash
# Set production environment variables
railway env set SHINY_LOG_LEVEL=INFO
railway env set R_LIBS_USER=/app/renv/library
railway env set PORT=3838
```

### Step 5: Get Deployment URL
```bash
# Get the deployed URL
railway domain

# The URL will be something like:
# https://monitor-legislativo-rshiny-production.up.railway.app
```

---

## ⚙️ Configuration

### Environment Variables

#### Local Development (.env.local)
```bash
SHINY_LOG_LEVEL=DEBUG
R_LIBS_USER=./renv/library
ENVIRONMENT=development
```

#### Production (.env.production)
```bash
SHINY_LOG_LEVEL=INFO
R_LIBS_USER=/app/renv/library
ENVIRONMENT=production
PORT=3838
```

### R Package Configuration

The application automatically installs required packages via `.Rprofile`:

```r
# Core Shiny packages
shiny, shinydashboard, DT

# Data manipulation
dplyr, tidyr, stringr, lubridate

# APIs and web
httr, jsonlite, yaml

# Geographic data
sf, geobr, leaflet

# Enhanced visualizations
plotly, highcharter, dygraphs, ggiraph

# Database
DBI, RSQLite

# Authentication
digest

# Export functionality
openxlsx, xml2, htmltools
```

---

## 🔐 Authentication

### Test Credentials

| Role | Username | Password | Access Level |
|------|----------|----------|--------------|
| Administrator | admin | admin123 | Full access |
| Researcher | researcher | research123 | Research tools |
| Student | student | student123 | View only |

### Custom Authentication

To add custom users, edit `R/auth.R`:

```r
# Add new user
users <- data.frame(
  username = c("admin", "researcher", "student", "newuser"),
  password_hash = c(
    digest::digest("admin123", algo = "sha256"),
    digest::digest("research123", algo = "sha256"),
    digest::digest("student123", algo = "sha256"),
    digest::digest("newpassword", algo = "sha256")
  ),
  role = c("admin", "researcher", "student", "custom"),
  stringsAsFactors = FALSE
)
```

---

## 🔗 React Integration

### Update React Configuration

In your React app, update the R Shiny URL:

```typescript
// src/config/rshiny.ts
const productionConfig = {
  baseUrl: 'https://monitor-legislativo-rshiny-production.up.railway.app',
  allowedOrigins: [
    'https://sofiadonario.github.io',
    'https://monitor-legislativo-rshiny-production.up.railway.app'
  ]
};
```

### Environment Variables for React

```bash
# .env.production
REACT_APP_RSHINY_URL=https://monitor-legislativo-rshiny-production.up.railway.app
VITE_RSHINY_URL=https://monitor-legislativo-rshiny-production.up.railway.app
```

---

## 📊 Monitoring and Logs

### Docker Logs
```bash
# View live logs
docker logs -f monitor-legislativo-rshiny

# View last 100 lines
docker logs --tail 100 monitor-legislativo-rshiny
```

### Railway Logs
```bash
# View live logs
railway logs --service monitor-legislativo-rshiny

# View specific timeframe
railway logs --service monitor-legislativo-rshiny --since 1h
```

### Health Monitoring
```bash
# Local health check
curl http://localhost:3838/health

# Production health check
curl https://monitor-legislativo-rshiny-production.up.railway.app/health
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Package Installation Failures
```bash
# Check R logs
docker logs monitor-legislativo-rshiny | grep "Error"

# Rebuild with verbose output
docker build --no-cache -t monitor-legislativo-rshiny .
```

#### 2. Port Already in Use
```bash
# Find process using port 3838
lsof -i :3838

# Kill the process
kill -9 <PID>

# Or use different port
docker run -p 3839:3838 monitor-legislativo-rshiny
```

#### 3. Memory Issues
```bash
# Increase Docker memory limit
# Docker Desktop > Settings > Resources > Memory > 8GB+

# Or run with memory limit
docker run --memory=4g monitor-legislativo-rshiny
```

#### 4. CORS Issues
```bash
# Check browser console for CORS errors
# Ensure allowed origins are correctly configured
# Verify HTTPS/HTTP protocol matching
```

### Railway-Specific Issues

#### 1. Build Timeouts
```bash
# Increase build timeout in railway.toml
[build]
watchPatterns = ["**/*.R", "**/*.yml"]
buildCommand = "echo 'Building R Shiny app...'"
```

#### 2. Memory Limits
```bash
# Upgrade Railway plan for more memory
# Or optimize R package installation
```

#### 3. Domain Configuration
```bash
# Generate custom domain
railway domain generate

# Or use custom domain
railway domain add yourdomain.com
```

---

## 💰 Cost Estimation

### Railway Pricing
- **Hobby Plan**: $5/month (1GB RAM, 1GB disk)
- **Pro Plan**: $20/month (8GB RAM, 100GB disk)
- **Team Plan**: $20/user/month (unlimited resources)

### Resource Requirements
- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 2GB for packages, 5GB recommended
- **CPU**: 1 vCPU minimum
- **Bandwidth**: 10GB/month typical usage

---

## 🔧 Advanced Configuration

### Custom R Packages
```dockerfile
# Add to Dockerfile
RUN R -e "install.packages('your-package-name')"
```

### Performance Optimization
```r
# In app.R, add caching
options(shiny.cache = TRUE)

# Use async processing
library(promises)
library(future)
plan(multisession)
```

### SSL Configuration
```bash
# Railway automatically provides SSL
# For custom domains, configure DNS:
# CNAME record: your-domain.com -> your-app.up.railway.app
```

---

## 📈 Scaling

### Horizontal Scaling
```bash
# Railway Pro plan supports multiple replicas
railway config set replicas=2
```

### Vertical Scaling
```bash
# Increase memory/CPU in Railway dashboard
# Or modify railway.toml
[deploy]
replicas = 1
memoryLimit = "4Gi"
cpuLimit = "2000m"
```

---

## 🔒 Security

### Production Security Checklist
- [ ] Change default passwords
- [ ] Enable HTTPS only
- [ ] Configure CORS properly
- [ ] Set up monitoring
- [ ] Regular security updates
- [ ] Backup data regularly

### Environment Security
```bash
# Never commit sensitive data
echo "*.env" >> .gitignore
echo "config/secrets.yml" >> .gitignore

# Use Railway environment variables
railway env set DATABASE_PASSWORD=your-secure-password
```

---

## 📞 Support

### Getting Help
- **Documentation**: Check `r-shiny-app/README.md`
- **Logs**: Always check application logs first
- **Railway Support**: https://railway.app/help
- **R Community**: https://community.rstudio.com/

### Reporting Issues
1. Check logs for error messages
2. Verify environment variables
3. Test with minimal configuration
4. Provide reproduction steps

---

This deployment guide ensures your R Shiny application runs reliably in both development and production environments with proper monitoring, security, and scalability considerations.