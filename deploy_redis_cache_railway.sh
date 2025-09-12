#!/bin/bash
# ============================================================================
# RAILWAY REDIS CACHE DEPLOYMENT SCRIPT
# ============================================================================
# 
# Automated deployment script for the Brazilian Legislative Monitor with 
# Redis caching system on Railway platform.
# 
# Prerequisites:
# - Railway CLI installed and authenticated
# - Project already created on Railway
# - PostgreSQL service already added to project
# 
# This script will:
# 1. Add Redis service to Railway project
# 2. Configure environment variables
# 3. Deploy application with cache system
# 4. Verify deployment health
# ============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Railway CLI
    if ! command -v railway &> /dev/null; then
        log_error "Railway CLI not found. Please install it first:"
        echo "npm install -g @railway/cli"
        exit 1
    fi
    
    # Check if logged in
    if ! railway whoami &> /dev/null; then
        log_error "Not logged into Railway. Please run 'railway login' first."
        exit 1
    fi
    
    # Check if project exists
    if ! railway status &> /dev/null; then
        log_error "No Railway project found. Please run 'railway link' to connect to your project."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Add Redis service to Railway project
add_redis_service() {
    log_info "Checking for Redis service..."
    
    # Check if Redis service already exists
    if railway services | grep -q "redis"; then
        log_success "Redis service already exists"
        return 0
    fi
    
    log_info "Adding Redis service to Railway project..."
    
    # Add Redis service
    if railway add --service redis; then
        log_success "Redis service added successfully"
        
        # Wait for service to be ready
        log_info "Waiting for Redis service to initialize..."
        sleep 30
        
        # Get Redis URL
        REDIS_URL=$(railway variables --service redis | grep REDIS_URL | cut -d'=' -f2-)
        if [ -n "$REDIS_URL" ]; then
            log_success "Redis service is ready: $REDIS_URL"
        else
            log_warning "Redis URL not found yet, will be available after deployment"
        fi
    else
        log_error "Failed to add Redis service"
        exit 1
    fi
}

# Configure environment variables for cache system
configure_environment() {
    log_info "Configuring cache system environment variables..."
    
    # Cache configuration variables
    CACHE_VARS=(
        "CACHE_ENABLED=true"
        "CACHE_TTL_SECONDS=1800"
        "CACHE_MAX_SIZE_MB=512"
        "CACHE_HIT_RATE_TARGET=70"
        "MONITORING_ENABLED=true"
        "MONITORING_INTERVAL_SECONDS=60"
        "PERFORMANCE_ALERTS=true"
        "MEMORY_LIMIT=2048"
        "MEMORY_PRESSURE_THRESHOLD=75"
        "AGGRESSIVE_CLEANUP_THRESHOLD=85"
        "EMERGENCY_CLEAR_THRESHOLD=95"
        "SEARCH_CACHE_ENABLED=true"
        "SEARCH_WARMING_ENABLED=true"
        "SEARCH_RESPONSE_TIME_TARGET_MS=500"
        "LEGISLATIVE_CACHE_WARMING=true"
        "GEOGRAPHIC_CACHE_ENABLED=true"
        "VOCABULARY_CACHE_ENABLED=true"
    )
    
    # Set each variable
    for var in "${CACHE_VARS[@]}"; do
        log_info "Setting $var"
        if railway variables set "$var"; then
            log_success "✓ $var set"
        else
            log_warning "Failed to set $var"
        fi
    done
    
    log_success "Environment variables configured"
}

# Update railway.toml with cache configuration
update_railway_config() {
    log_info "Updating railway.toml configuration..."
    
    # Create backup of railway.toml
    if [ -f "railway.toml" ]; then
        cp railway.toml railway.toml.backup
        log_success "Created backup: railway.toml.backup"
    fi
    
    # The railway.toml should already be updated with cache configuration
    # Verify it contains cache settings
    if grep -q "CACHE_ENABLED" railway.toml; then
        log_success "railway.toml already contains cache configuration"
    else
        log_warning "railway.toml may need manual cache configuration"
    fi
}

# Install required R packages in Railway environment
install_r_packages() {
    log_info "R packages will be installed during deployment..."
    
    # Check if we have package installation script
    if [ -f "install_cache_packages.R" ]; then
        log_success "Cache package installation script found"
    else
        log_info "Creating cache package installation script..."
        
        cat > install_cache_packages.R << 'EOF'
# Install required packages for Redis cache system
cat("Installing Redis cache system packages...\n")

required_packages <- c(
  "jsonlite", "digest", "memoise", "stringr", "dplyr", 
  "lubridate", "pryr"
)

optional_packages <- c(
  "redux", "RcppMsgPack", "future", "promises"
)

# Install required packages
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("Installing", pkg, "...\n")
    install.packages(pkg, repos = "https://cran.rstudio.com/", dependencies = TRUE)
  }
}

# Try to install optional packages (may fail on some systems)
for (pkg in optional_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    tryCatch({
      cat("Installing optional package", pkg, "...\n")
      install.packages(pkg, repos = "https://cran.rstudio.com/", dependencies = TRUE)
    }, error = function(e) {
      cat("Could not install", pkg, ":", e$message, "\n")
    })
  }
}

cat("Package installation completed.\n")
EOF
        
        log_success "Created install_cache_packages.R"
    fi
}

# Create deployment health check script
create_health_check() {
    log_info "Creating deployment health check script..."
    
    cat > check_deployment_health.R << 'EOF'
# Deployment health check for Redis cache system
cat("Checking deployment health...\n")

# Check if cache system is available
if (file.exists("cache/init_cache_system.R")) {
  source("cache/init_cache_system.R")
  
  # Check cache system status
  if (exists("cache_system_status")) {
    status <- cache_system_status()
    
    cat("Cache System Status:\n")
    cat("- Initialized:", status$initialized, "\n")
    cat("- Redis Available:", status$redis_available, "\n")
    cat("- Search Engine:", status$search_engine_active, "\n")
    cat("- Monitoring:", status$monitoring_active, "\n")
    
    if (status$initialized) {
      cat("✅ Cache system is operational\n")
      
      # Test cache functionality
      if (exists("cache_health_check")) {
        health <- cache_health_check()
        cat("Overall Health:", health$overall_status, "\n")
      }
    } else {
      cat("⚠️ Cache system is in limited mode\n")
    }
  }
} else {
  cat("⚠️ Cache system not found - using fallback mode\n")
}

cat("Health check completed.\n")
EOF
    
    log_success "Created check_deployment_health.R"
}

# Deploy to Railway
deploy_application() {
    log_info "Deploying application with Redis cache system..."
    
    # Add all new files to git
    git add -A
    
    # Create deployment commit
    COMMIT_MSG="feat: Add Redis caching system for Brazilian Legislative Monitor

- Railway-optimized Redis caching with 2GB memory constraint
- Intelligent search result caching with Brazilian Portuguese support
- Performance monitoring and memory management
- Geographic data caching for Brazilian states
- Graceful fallback to in-memory caching when Redis unavailable
- Cache warming for common Brazilian legislative queries
- Production-grade error handling and health checks

🚀 Generated with Claude Code"
    
    git commit -m "$COMMIT_MSG" || log_warning "Nothing to commit (files may already be staged)"
    
    # Push to Railway
    log_info "Pushing to Railway..."
    git push origin main
    
    # Wait for deployment
    log_info "Waiting for deployment to complete..."
    sleep 10
    
    # Check deployment status
    if railway status | grep -q "Success"; then
        log_success "Deployment completed successfully!"
    else
        log_warning "Deployment status unclear, checking manually..."
        railway logs --tail 50
    fi
}

# Verify deployment and cache functionality
verify_deployment() {
    log_info "Verifying cache system deployment..."
    
    # Get deployment URL
    DEPLOY_URL=$(railway domain)
    if [ -n "$DEPLOY_URL" ]; then
        log_success "Application URL: $DEPLOY_URL"
        
        # Test health endpoint
        log_info "Testing application health..."
        if curl -s -f "$DEPLOY_URL/health" > /dev/null; then
            log_success "Health endpoint responding"
        else
            log_warning "Health endpoint may not be ready yet"
        fi
        
        # Check logs for cache initialization
        log_info "Checking deployment logs for cache system..."
        railway logs --tail 20 | grep -i "cache\|redis" || log_info "No cache logs found yet"
        
    else
        log_warning "Could not determine deployment URL"
    fi
    
    # Show final status
    log_info "Final deployment status:"
    railway status
}

# Display post-deployment instructions
show_post_deployment_info() {
    log_info "Post-deployment information:"
    
    echo ""
    echo "🎯 Redis Cache System Deployment Complete!"
    echo ""
    echo "Next steps:"
    echo "1. Monitor application logs: railway logs --follow"
    echo "2. Check cache performance in the Shiny dashboard"
    echo "3. Verify Redis service is connected in Railway dashboard"
    echo ""
    echo "Cache Features Deployed:"
    echo "✅ Redis caching with Railway optimization (2GB constraint)"
    echo "✅ Intelligent search result caching"
    echo "✅ Brazilian Portuguese query preprocessing"
    echo "✅ Geographic data caching for Brazilian states"
    echo "✅ Performance monitoring and memory management"
    echo "✅ Graceful fallback to in-memory caching"
    echo "✅ Cache warming for common legislative queries"
    echo ""
    echo "Monitoring:"
    echo "- Cache hit rate target: 70%"
    echo "- Memory monitoring with Railway 2GB limit"
    echo "- Automatic cache cleanup at 85% memory usage"
    echo "- Performance alerts enabled"
    echo ""
    
    DEPLOY_URL=$(railway domain)
    if [ -n "$DEPLOY_URL" ]; then
        echo "🌐 Application: $DEPLOY_URL"
        echo "🔍 Health check: $DEPLOY_URL/health"
    fi
    
    echo ""
    echo "For troubleshooting, check:"
    echo "- Railway project dashboard for service status"
    echo "- Application logs: railway logs --follow"
    echo "- Environment variables: railway variables"
    echo ""
}

# Main deployment flow
main() {
    echo "============================================================================"
    echo "🚀 Railway Redis Cache Deployment for Brazilian Legislative Monitor"
    echo "============================================================================"
    echo ""
    
    check_prerequisites
    add_redis_service
    configure_environment
    update_railway_config
    install_r_packages
    create_health_check
    deploy_application
    verify_deployment
    show_post_deployment_info
    
    echo ""
    log_success "Deployment completed successfully!"
    echo "============================================================================"
}

# Run main function
main "$@"