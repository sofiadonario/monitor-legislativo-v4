#!/bin/bash
# ============================================================================
# RAILWAY DEPLOYMENT SETUP SCRIPT
# ============================================================================
# 
# This script helps set up the Railway deployment for the Brazilian 
# Legislative Monitor dashboard with proper environment variables and
# database configuration.
#
# Features:
# - Environment variable validation
# - Database connectivity testing
# - Performance optimization
# - Health check setup
# - Logging configuration
#
# Usage: ./railway_deployment_setup.sh
# ============================================================================

echo "🚀 RAILWAY DEPLOYMENT SETUP"
echo "============================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Railway CLI is available
check_railway_cli() {
    log_info "Checking Railway CLI availability..."
    
    if command -v railway &> /dev/null; then
        railway_version=$(railway --version)
        log_success "Railway CLI found: $railway_version"
        return 0
    else
        log_warning "Railway CLI not found. Install it from: https://railway.app/cli"
        log_info "You can still configure environment variables manually in the Railway dashboard"
        return 1
    fi
}

# Check current Railway project status
check_railway_status() {
    log_info "Checking Railway project status..."
    
    if railway status &> /dev/null; then
        project_info=$(railway status 2>/dev/null)
        log_success "Connected to Railway project"
        echo "$project_info"
        return 0
    else
        log_warning "Not connected to a Railway project"
        log_info "Run 'railway login' and 'railway link' to connect to your project"
        return 1
    fi
}

# Generate DATABASE_URL from individual components
generate_database_url() {
    local host="$1"
    local port="$2"
    local database="$3"
    local user="$4"
    local password="$5"
    
    echo "postgresql://${user}:${password}@${host}:${port}/${database}"
}

# Set Railway environment variables
set_railway_environment_variables() {
    log_info "Setting Railway environment variables..."
    
    # Core application settings
    log_info "Setting application configuration..."
    railway variables set R_CONFIG_ACTIVE=production
    railway variables set RAILWAY_ENVIRONMENT=production
    railway variables set TZ=America/Sao_Paulo
    railway variables set SHINY_LOG_LEVEL=WARN
    railway variables set LOG_LEVEL=INFO
    
    # R optimization settings for Railway
    log_info "Setting R optimization variables..."
    railway variables set R_MAX_NUM_DLLS=150
    railway variables set R_GC_MEM_GROW=3
    railway variables set OMP_NUM_THREADS=2
    railway variables set SHINY_WORKER_TIMEOUT=300
    railway variables set R_MAX_VSIZE=2G
    
    # Database connection settings
    log_info "Setting database configuration..."
    railway variables set PGUSER=postgres
    railway variables set PGDATABASE=railway
    railway variables set PGPORT=5432
    
    # Railway deployment settings
    log_info "Setting Railway deployment configuration..."
    railway variables set RAILWAY_DEPLOYMENT=true
    railway variables set HEALTH_CHECK_DETAILED=true
    railway variables set NODE_ENV=production
    
    log_success "Environment variables set successfully"
}

# Test database connection
test_database_connection() {
    log_info "Testing database connection..."
    
    # Check if R is available
    if ! command -v R &> /dev/null; then
        log_warning "R not available for connection testing"
        return 1
    fi
    
    # Create a simple R script to test the connection
    cat > /tmp/test_db_connection.R << 'EOF'
# Load required libraries
suppressPackageStartupMessages({
    library(DBI)
    library(RPostgres)
})

# Get database configuration
get_db_config <- function() {
    database_url <- Sys.getenv("DATABASE_URL")
    
    if (nchar(database_url) > 0) {
        cat("Using DATABASE_URL\n")
        return(database_url)
    }
    
    # Try individual variables
    host <- Sys.getenv("PGHOST", "postgres")
    port <- Sys.getenv("PGPORT", "5432")
    database <- Sys.getenv("PGDATABASE", "railway")
    user <- Sys.getenv("PGUSER", "postgres")
    password <- Sys.getenv("PGPASSWORD", "")
    
    if (nchar(password) == 0) {
        cat("No database password found\n")
        return(NULL)
    }
    
    return(sprintf("postgresql://%s:%s@%s:%s/%s", user, password, host, port, database))
}

# Test connection
config <- get_db_config()
if (!is.null(config)) {
    tryCatch({
        if (grepl("^postgresql://", config)) {
            con <- dbConnect(RPostgres::Postgres(), config)
        } else {
            con <- dbConnect(RPostgres::Postgres(),
                           host = Sys.getenv("PGHOST"),
                           port = as.integer(Sys.getenv("PGPORT")),
                           dbname = Sys.getenv("PGDATABASE"),
                           user = Sys.getenv("PGUSER"),
                           password = Sys.getenv("PGPASSWORD"))
        }
        
        # Test query
        result <- dbGetQuery(con, "SELECT version() as version")
        cat("✅ Database connection successful\n")
        cat("PostgreSQL version:", substr(result$version, 1, 50), "\n")
        
        # Check for documents table
        tables <- dbGetQuery(con, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        cat("Available tables:", nrow(tables), "\n")
        
        if ("documents" %in% tables$tablename) {
            doc_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")
            cat("Documents in database:", doc_count$count, "\n")
        }
        
        dbDisconnect(con)
        cat("SUCCESS\n")
    }, error = function(e) {
        cat("❌ Database connection failed:", e$message, "\n")
        cat("FAILED\n")
    })
} else {
    cat("❌ No database configuration found\n")
    cat("FAILED\n")
}
EOF
    
    # Run the test
    result=$(Rscript /tmp/test_db_connection.R 2>&1)
    
    if echo "$result" | grep -q "SUCCESS"; then
        log_success "Database connection test passed"
        echo "$result" | grep -v "SUCCESS"
        rm -f /tmp/test_db_connection.R
        return 0
    else
        log_error "Database connection test failed"
        echo "$result"
        rm -f /tmp/test_db_connection.R
        return 1
    fi
}

# Generate Railway deployment instructions
generate_deployment_instructions() {
    log_info "Generating deployment instructions..."
    
    cat > railway_deployment_instructions.md << 'EOF'
# Railway Deployment Instructions

## 1. Prerequisites
- Railway account and CLI installed
- PostgreSQL service added to your Railway project
- Repository connected to Railway

## 2. Environment Variables Setup

### Automatic Setup (if Railway CLI is available):
```bash
./railway_deployment_setup.sh
```

### Manual Setup in Railway Dashboard:

#### Application Configuration
- `R_CONFIG_ACTIVE=production`
- `RAILWAY_ENVIRONMENT=production`
- `TZ=America/Sao_Paulo`
- `SHINY_LOG_LEVEL=WARN`
- `LOG_LEVEL=INFO`

#### R Optimization Settings
- `R_MAX_NUM_DLLS=150`
- `R_GC_MEM_GROW=3`
- `OMP_NUM_THREADS=2`
- `SHINY_WORKER_TIMEOUT=300`
- `R_MAX_VSIZE=2G`

#### Database Configuration
The `DATABASE_URL` should be automatically provided by Railway's PostgreSQL service.

If you need to set individual variables:
- `PGHOST=<your-postgres-host>`
- `PGPORT=5432`
- `PGDATABASE=railway`
- `PGUSER=postgres`
- `PGPASSWORD=<your-postgres-password>`

## 3. Database Setup

### Run Migration Script:
```bash
Rscript railway_database_migration.R
```

### Run Diagnostics:
```bash
Rscript railway_database_diagnostics.R
```

## 4. Deploy Application

1. Push your code to the connected repository
2. Railway will automatically build and deploy
3. Check deployment logs for any issues
4. Test the application URL

## 5. Monitoring

- Monitor Railway deployment logs
- Check database connection health
- Monitor memory and CPU usage
- Set up alerts for errors

## 6. Troubleshooting

### Common Issues:

1. **Database Connection Failed**
   - Check DATABASE_URL environment variable
   - Verify PostgreSQL service is running
   - Check firewall/network settings

2. **Memory Issues**
   - Adjust R_MAX_VSIZE setting
   - Monitor memory usage
   - Consider upgrading Railway plan

3. **Package Installation Failed**
   - Check Dockerfile for package dependencies
   - Verify R package repositories
   - Check for conflicting package versions

### Debug Commands:
```bash
# Check Railway status
railway status

# View logs
railway logs

# Connect to PostgreSQL
railway connect postgres

# Check environment variables
railway variables
```

## 7. Performance Optimization

1. Database indexes are created automatically
2. Connection pooling is configured
3. Memory limits are set appropriately
4. SSL/TLS is configured for security

## 8. Backup and Recovery

1. Railway provides automatic PostgreSQL backups
2. Export data regularly using pg_dump
3. Test recovery procedures
4. Monitor backup status

EOF

    log_success "Deployment instructions generated: railway_deployment_instructions.md"
}

# Main execution
main() {
    log_info "Starting Railway deployment setup..."
    
    # Check Railway CLI
    railway_cli_available=false
    if check_railway_cli; then
        railway_cli_available=true
        
        # Check project status
        if check_railway_status; then
            log_info "Ready to configure Railway project"
            
            # Ask user if they want to set environment variables
            echo
            read -p "Do you want to set environment variables now? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                set_railway_environment_variables
            fi
            
            # Ask user if they want to test database connection
            echo
            read -p "Do you want to test database connection? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                test_database_connection
            fi
        fi
    fi
    
    # Generate deployment instructions
    generate_deployment_instructions
    
    echo
    log_success "Railway deployment setup completed!"
    echo
    log_info "Next steps:"
    echo "1. Review and follow the instructions in railway_deployment_instructions.md"
    echo "2. Run the database migration script: Rscript railway_database_migration.R"
    echo "3. Run the diagnostics script: Rscript railway_database_diagnostics.R"
    echo "4. Deploy your application to Railway"
    echo "5. Monitor the deployment logs and test the application"
    echo
    log_info "For troubleshooting, check the generated documentation and Railway logs"
}

# Run main function
main "$@"