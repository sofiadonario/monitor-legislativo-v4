#!/bin/bash

# Deploy Full 134k+ Document Dataset to Railway PostgreSQL
# ========================================================

set -e  # Exit on any error

echo "🚀 RAILWAY POSTGRESQL FULL DATASET DEPLOYMENT"
echo "=============================================="
echo ""
echo "This script will:"
echo "✅ Set up Railway PostgreSQL environment variables"  
echo "✅ Test database connection"
echo "✅ Import 134k+ documents from CSV"
echo "✅ Optimize database for performance"
echo "✅ Verify import success"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m' 
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Step 1: Setup environment
log_info "Setting up Railway PostgreSQL environment variables..."

export DATABASE_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
export PGHOST="nozomi.proxy.rlwy.net" 
export PGPORT="44844"
export PGDATABASE="railway"
export PGUSER="postgres"
export PGPASSWORD="smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
export R_DATABASE_URL="$DATABASE_URL"

log_success "Environment variables configured"

# Step 2: Check dependencies
log_info "Checking Python dependencies..."

if ! python3 -c "import psycopg2" 2>/dev/null; then
    log_warning "Installing psycopg2-binary..."
    pip3 install psycopg2-binary
fi

log_success "Python dependencies ready"

# Step 3: Test database connection
log_info "Testing Railway PostgreSQL connection..."

if python3 test_railway_connection.py; then
    log_success "Database connection successful"
else
    log_error "Database connection failed"
    log_info "Please check:"
    log_info "  - Internet connectivity"
    log_info "  - Railway PostgreSQL service status"
    log_info "  - Firewall settings"
    exit 1
fi

# Step 4: Find CSV dataset
log_info "Locating dataset files..."

CSV_FILE=""
CSV_CANDIDATES=(
    "data_current/processed/production/lexml_unified_dataset.csv"
    "data_current/processed/production/lexml_enhanced_simple.csv"
    "data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated_FIXED.csv"
    "data_current/processed/production/lexml_sample_for_railway.csv"
)

for candidate in "${CSV_CANDIDATES[@]}"; do
    if [[ -f "$candidate" ]]; then
        CSV_FILE="$candidate"
        CSV_SIZE=$(stat -f%z "$candidate" 2>/dev/null || stat -c%s "$candidate" 2>/dev/null || echo "unknown")
        CSV_SIZE_MB=$((CSV_SIZE / 1024 / 1024))
        log_success "Found dataset: $candidate (${CSV_SIZE_MB}MB)"
        break
    fi
done

if [[ -z "$CSV_FILE" ]]; then
    log_error "No CSV dataset found!"
    log_info "Please ensure one of these files exists:"
    for candidate in "${CSV_CANDIDATES[@]}"; do
        log_info "  - $candidate"
    done
    exit 1
fi

# Step 5: Estimate import time
log_info "Dataset analysis:"
if [[ "$CSV_FILE" == *"sample"* ]]; then
    log_warning "Using sample dataset - will import ~100-1000 documents"
    ESTIMATED_TIME="1-2 minutes"
else
    log_success "Using full dataset - will import 134k+ documents"  
    ESTIMATED_TIME="10-30 minutes"
fi
log_info "Estimated import time: $ESTIMATED_TIME"

# Step 6: Confirm import
echo ""
read -p "🤔 Proceed with import? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Import cancelled by user"
    exit 0
fi

# Step 7: Execute import
log_info "Starting bulk import to Railway PostgreSQL..."
echo ""

if python3 railway_import_simple.py; then
    log_success "Bulk import completed successfully!"
else
    log_error "Import failed"
    log_info "Check railway_import.log for details"
    exit 1
fi

# Step 8: Verify import
log_info "Verifying import results..."

python3 test_railway_connection.py

# Step 9: App configuration check
log_info "Checking app configuration..."

if grep -q "RE-ENABLE DATABASE CONNECTION" app.R; then
    log_success "App.R configured for database connection"
else
    log_warning "App.R may need manual configuration"
fi

# Step 10: Final status
echo ""
log_success "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!"
echo ""
log_info "Next steps:"
log_info "1. Start the R Shiny app: runApp('app.R')"  
log_info "2. Or deploy to Railway: railway up"
log_info "3. Verify the dashboard shows 134k+ documents"
echo ""
log_info "Expected results:"
log_info "📊 Dashboard: 134,014+ documents instead of 3"
log_info "🔍 Library: Full-text search across entire dataset"  
log_info "📈 Analytics: Real data distributions"
log_info "🗺️  Maps: Actual geographic coverage"
echo ""
log_success "The Brazilian Legislative Monitoring app is ready!"