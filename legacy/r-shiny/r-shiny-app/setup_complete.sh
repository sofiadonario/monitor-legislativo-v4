#!/bin/bash

# Complete R Shiny Setup Script
# Monitor Legislativo v4 - Academic Legislative Monitor

echo "=================================================="
echo "   MONITOR LEGISLATIVO v4 - COMPLETE SETUP      "
echo "   R Shiny + Railway Deployment Configuration    "
echo "=================================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if R is installed
check_r_installation() {
    print_info "Checking R installation..."
    
    if command -v R &> /dev/null; then
        R_VERSION=$(R --version | head -n1)
        print_status "R is installed: $R_VERSION"
        return 0
    else
        print_error "R is not installed or not in PATH"
        print_info "Please install R from: https://cloud.r-project.org/"
        return 1
    fi
}

# Install R packages
install_r_packages() {
    print_info "Installing R packages..."
    
    # Create .Rprofile if it doesn't exist
    if [ ! -f ".Rprofile" ]; then
        print_warning ".Rprofile not found, creating minimal version"
        cat > .Rprofile << 'EOF'
# Minimal R Profile for Academic Legislative Monitor
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Install required packages
packages <- c(
    "shiny", "shinydashboard", "DT",
    "dplyr", "tidyr", "stringr", "lubridate",
    "httr", "jsonlite", "yaml",
    "sf", "geobr", "leaflet",
    "DBI", "RSQLite", "digest",
    "openxlsx", "xml2", "htmltools",
    "ggplot2", "viridis", "plotly"
)

for (pkg in packages) {
    if (!require(pkg, character.only = TRUE)) {
        install.packages(pkg, dependencies = TRUE)
    }
}

cat("✅ R packages loaded successfully\n")
EOF
    fi
    
    # Run R to install packages
    print_info "Installing R packages (this may take 10-15 minutes)..."
    R -e "source('.Rprofile')" 2>&1 | tee r_package_install.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        print_status "R packages installed successfully"
    else
        print_error "R package installation failed. Check r_package_install.log"
        return 1
    fi
}

# Setup directories
setup_directories() {
    print_info "Setting up directory structure..."
    
    directories=("data" "data/cache" "data/geographic" "www" "logs")
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Created directory: $dir"
        else
            print_status "Directory exists: $dir"
        fi
    done
}

# Test R Shiny app
test_shiny_app() {
    print_info "Testing R Shiny application..."
    
    # Check if app.R exists
    if [ ! -f "app.R" ]; then
        print_error "app.R not found! Please ensure you're in the r-shiny-app directory"
        return 1
    fi
    
    # Test R syntax
    R -e "
    if (file.exists('app.R')) {
        tryCatch({
            source('app.R', echo = FALSE)
            cat('✅ R Shiny app syntax is valid\n')
        }, error = function(e) {
            cat('❌ R Shiny app has syntax errors:\n')
            cat(e\$message, '\n')
            quit(status = 1)
        })
    }
    " 2>&1 | tee shiny_test.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        print_status "R Shiny app syntax test passed"
    else
        print_error "R Shiny app syntax test failed. Check shiny_test.log"
        return 1
    fi
}

# Start R Shiny server
start_shiny_server() {
    print_info "Starting R Shiny server..."
    print_warning "This will start the server in the background"
    print_warning "Use 'pkill -f shiny' to stop it later"
    
    # Start Shiny server in background
    nohup R -e "
    cat('🚀 Starting Academic Legislative Monitor...\n')
    cat('📍 URL: http://localhost:3838\n')
    cat('🔐 Login with: admin / admin123\n')
    cat('🛑 Press Ctrl+C to stop\n\n')
    
    shiny::runApp(
        port = 3838,
        host = '0.0.0.0',
        launch.browser = FALSE
    )
    " > shiny_server.log 2>&1 &
    
    SHINY_PID=$!
    echo $SHINY_PID > shiny_server.pid
    
    print_status "R Shiny server started with PID: $SHINY_PID"
    print_info "Server logs: tail -f shiny_server.log"
    
    # Wait a moment and test if server is responding
    sleep 5
    if curl -s http://localhost:3838/health > /dev/null 2>&1; then
        print_status "R Shiny server is responding at http://localhost:3838"
    else
        print_warning "R Shiny server may still be starting. Check logs if needed."
    fi
}

# Show status information
show_status() {
    echo ""
    echo "=================================================="
    echo "           SETUP COMPLETE - STATUS SUMMARY        "
    echo "=================================================="
    echo ""
    echo "🌐 Application URLs:"
    echo "───────────────────────────────────────────"
    echo "📍 Local:      http://localhost:3838"
    echo "📍 Production: https://monitor-legislativo-rshiny-production.up.railway.app"
    echo ""
    echo "🔐 Test Credentials:"
    echo "───────────────────────────────────────────"
    echo "👨‍💼 Administrator: admin / admin123"
    echo "👨‍🔬 Researcher:   researcher / research123"
    echo "👨‍🎓 Student:      student / student123"
    echo ""
    echo "📊 Management Commands:"
    echo "───────────────────────────────────────────"
    echo "🔍 View logs:      tail -f shiny_server.log"
    echo "🛑 Stop server:    pkill -f shiny"
    echo "🔄 Restart:        ./setup_complete.sh"
    echo "📋 Health check:   curl http://localhost:3838/health"
    echo ""
    echo "🚀 Railway Deployment:"
    echo "───────────────────────────────────────────"
    echo "🏗️  Deploy:         railway up"
    echo "📋 View logs:      railway logs"
    echo "🌐 Get URL:        railway domain"
    echo ""
    echo "=================================================="
}

# Main execution
main() {
    print_info "Starting complete R Shiny setup..."
    
    # Check R installation
    if ! check_r_installation; then
        print_error "Setup cannot continue without R installation"
        exit 1
    fi
    
    # Setup directories
    setup_directories
    
    # Install R packages
    if ! install_r_packages; then
        print_error "Package installation failed"
        exit 1
    fi
    
    # Test Shiny app
    if ! test_shiny_app; then
        print_error "Shiny app test failed"
        exit 1
    fi
    
    # Start Shiny server
    start_shiny_server
    
    # Show status
    show_status
    
    print_status "Setup completed successfully!"
    print_info "Open http://localhost:3838 in your browser"
}

# Run main function
main "$@"