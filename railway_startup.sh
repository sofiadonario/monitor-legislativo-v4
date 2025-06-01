#!/bin/bash
# RAILWAY STARTUP SCRIPT WITH ROBUST ERROR HANDLING
# =================================================
# Production-ready startup script for Railway deployment

set -e  # Exit on any error

echo "🚂 Railway Brazilian Legislative Monitor - Starting..."
echo "======================================================="

# Environment information
echo "Environment Information:"
echo "- Node: $(hostname)"
echo "- User: $(whoami)"
echo "- Working Directory: $(pwd)"
echo "- R Version: $(R --version | head -n1)"
echo "- Memory Available: $(free -h | grep '^Mem:' | awk '{print $7}' 2>/dev/null || echo 'Unknown')"

# Check Railway environment
if [ ! -z "$RAILWAY_SERVICE_NAME" ]; then
    echo "- Railway Service: $RAILWAY_SERVICE_NAME"
    echo "- Railway Environment: ${RAILWAY_ENVIRONMENT_NAME:-unknown}"
    echo "- Port: ${PORT:-3838}"
fi

echo ""

# Check file existence
echo "Checking application files:"
files_to_check=(
    "railway_deployment_fix.R"
    "app_railway.R" 
    "app.R"
    "health_check.R"
)

for file in "${files_to_check[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file ($(stat -c%s "$file" 2>/dev/null || echo "unknown size") bytes)"
    else
        echo "❌ $file (missing)"
    fi
done

echo ""

# Check directory structure
echo "Checking directory structure:"
dirs_to_check=(
    "monitoring"
    "auth"
    "db"
    "modules"
    "data"
    "scripts"
)

for dir in "${dirs_to_check[@]}"; do
    if [ -d "$dir" ]; then
        file_count=$(find "$dir" -type f -name "*.R" 2>/dev/null | wc -l)
        echo "✅ $dir/ ($file_count R files)"
    else
        echo "⚠️ $dir/ (missing - will use fallbacks)"
    fi
done

echo ""

# Memory and system checks
echo "System status:"
echo "- Available disk space: $(df -h . | tail -1 | awk '{print $4}' 2>/dev/null || echo 'Unknown')"
echo "- R library path: $R_LIBS_USER"

# Check R packages installation
echo ""
echo "Checking critical R packages..."
R --slave --no-restore --no-save -e "
    critical_packages <- c('shiny', 'shinydashboard', 'DT', 'plotly', 'dplyr')
    for (pkg in critical_packages) {
        if (requireNamespace(pkg, quietly = TRUE)) {
            cat('✅', pkg, 'version', as.character(packageVersion(pkg)), '\n')
        } else {
            cat('❌', pkg, 'NOT AVAILABLE\n')
        }
    }
"

echo ""

# Start the application with error handling
echo "🚀 Starting Shiny application..."
echo "======================================="

# Set Railway-specific R options
export R_MAX_VSIZE=2G
export PORT=${PORT:-3838}

# Function to start Railway-optimized app
start_railway_app() {
    echo "Attempting to start Railway-optimized application..."
    R --slave --no-restore --no-save -e "
        options(warn = 1)
        tryCatch({
            cat('Loading Railway deployment fixes...\n')
            source('railway_deployment_fix.R')
            cat('Loading Railway-optimized application...\n')
            source('app_railway.R')
        }, error = function(e) {
            cat('ERROR in Railway app:', e\$message, '\n')
            quit(status = 1)
        })
    "
}

# Function to start fallback app
start_fallback_app() {
    echo "Attempting to start fallback application..."
    R --slave --no-restore --no-save -e "
        options(warn = 1)
        tryCatch({
            cat('Loading fallback application...\n')
            shiny::runApp('app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))
        }, error = function(e) {
            cat('ERROR in fallback app:', e\$message, '\n')
            quit(status = 1)
        })
    "
}

# Try Railway-optimized version first
if [ -f "app_railway.R" ] && [ -f "railway_deployment_fix.R" ]; then
    echo "Railway-optimized files found. Starting Railway version..."
    if ! start_railway_app; then
        echo "⚠️ Railway-optimized version failed. Falling back to original..."
        sleep 2
        start_fallback_app
    fi
else
    echo "Railway-optimized files not found. Starting fallback version..."
    start_fallback_app
fi