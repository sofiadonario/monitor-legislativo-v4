#!/bin/bash

# Implementation Verification Script
# ==================================
# Verifies that all components of the optimized free tier implementation are working

echo "========================================="
echo "IMPLEMENTATION VERIFICATION"
echo "========================================="
echo "Date: $(date)"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Function to check if file exists
check_file() {
    local file=$1
    local description=$2
    
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅${NC} $description exists"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}❌${NC} $description missing: $file"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Function to check if directory exists
check_dir() {
    local dir=$1
    local description=$2
    
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✅${NC} $description exists"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}❌${NC} $description missing: $dir"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Function to check for hardcoded credentials
check_no_credentials() {
    local pattern=$1
    local description=$2
    
    # Search for the pattern, excluding backup directories
    result=$(grep -r "$pattern" . \
        --exclude-dir=backup_before_credential_cleanup_\* \
        --exclude-dir=.git \
        --exclude-dir=node_modules \
        --exclude-dir=renv \
        --exclude="*.RData" \
        --exclude="*.rds" \
        --exclude="verify_implementation.sh" \
        2>/dev/null | wc -l)
    
    if [ "$result" -eq 0 ]; then
        echo -e "${GREEN}✅${NC} No $description found"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}❌${NC} Found $result instances of $description"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

echo "1. SECURITY COMPONENTS"
echo "======================"
check_file "db/connection.R" "Secure database connection module"
check_file "auth/oauth_middleware.R" "OAuth authentication middleware"
check_file "docker/Dockerfile.secure" "Secure Docker configuration"
check_no_credentials "smNCedRjMKeNsoqpurLWXjGEUZxORwVY" "hardcoded password"
check_no_credentials "RAILWAY_PRODUCTION_DB_FIX.R" "dangerous connection file"
echo ""

echo "2. PERFORMANCE OPTIMIZATION"
echo "==========================="
check_file "db/performance_optimization.R" "Performance optimization module"
check_file "db/query_monitor.R" "Query monitoring module"
check_file "db/migrations/001_performance_indexes.sql" "Performance indexes migration"
check_file "db/migrations/002_materialized_views.sql" "Materialized views migration"
check_file "db/execute_migrations.sh" "Migration execution script"
echo ""

echo "3. MONITORING & LOGGING"
echo "======================="
check_dir "monitoring" "Monitoring directory"
check_file "monitoring/logger.R" "Logger module"
check_file "monitoring/app_monitor.R" "Application monitor"
check_file "monitoring/telemetry.R" "Telemetry module"
check_file "monitoring/monitoring_ui.R" "Monitoring UI"
echo ""

echo "4. AUTHENTICATION SYSTEM"
echo "========================"
check_dir "auth" "Authentication directory"
check_file "auth/auth_utils.R" "Authentication utilities"
check_file "auth/auth_ui.R" "Authentication UI"
check_file "auth/auth_server.R" "Authentication server"
echo ""

echo "5. DEPLOYMENT CONFIGURATION"
echo "==========================="
check_file "railway.toml" "Railway configuration"
check_file "Dockerfile" "Main Dockerfile"
check_file "docker/Dockerfile.secure" "Secure Dockerfile"
check_file "config/config.yml" "Application configuration"
echo ""

echo "6. SECURITY TOOLS"
echo "================="
check_file "scripts/security/remove_hardcoded_credentials.sh" "Credential cleanup script"
check_file "scripts/security/mcp_scan_setup.sh" "MCP-Scan setup script"
check_file "CREDENTIAL_ROTATION_GUIDE.md" "Credential rotation guide"
echo ""

echo "7. APPLICATION INTEGRATION"
echo "=========================="
# Check if performance modules are loaded in app.R
if grep -q "source(\"db/performance_optimization.R\")" app.R 2>/dev/null; then
    echo -e "${GREEN}✅${NC} Performance optimization integrated in app.R"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️${NC} Performance optimization not found in app.R"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "source(\"db/query_monitor.R\")" app.R 2>/dev/null; then
    echo -e "${GREEN}✅${NC} Query monitoring integrated in app.R"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️${NC} Query monitoring not found in app.R"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "source(\"db/connection.R\")" app.R 2>/dev/null; then
    echo -e "${GREEN}✅${NC} Secure connection integrated in app.R"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌${NC} Secure connection not integrated in app.R"
    FAILED=$((FAILED + 1))
fi
echo ""

echo "8. DATABASE VALIDATION"
echo "======================"
# Check for DATABASE_URL environment variable
if [ -n "$DATABASE_URL" ]; then
    echo -e "${GREEN}✅${NC} DATABASE_URL environment variable is set"
    PASSED=$((PASSED + 1))
    
    # Try to extract just the host for display (hide password)
    if [[ $DATABASE_URL =~ @([^:/]+) ]]; then
        echo "   Host: ${BASH_REMATCH[1]}"
    fi
else
    echo -e "${YELLOW}⚠️${NC} DATABASE_URL environment variable not set"
    echo "   Set it with: export DATABASE_URL='your_connection_string'"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

echo "========================================="
echo "VERIFICATION SUMMARY"
echo "========================================="
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC} $FAILED"
echo ""

# Calculate implementation percentage
TOTAL=$((PASSED + WARNINGS + FAILED))
if [ $TOTAL -gt 0 ]; then
    PERCENTAGE=$((PASSED * 100 / TOTAL))
    echo "Implementation Completeness: ${PERCENTAGE}%"
else
    echo "Implementation Completeness: Unable to calculate"
fi
echo ""

# Provide recommendations based on results
echo "RECOMMENDATIONS"
echo "==============="

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Critical Issues Found:${NC}"
    echo "1. Review failed checks above"
    echo "2. Ensure all required files are present"
    echo "3. Check for any remaining hardcoded credentials"
    echo ""
fi

if [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}Warnings to Address:${NC}"
    echo "1. Set DATABASE_URL environment variable if not set"
    echo "2. Integrate any missing modules in app.R"
    echo "3. Run database migrations if not completed"
    echo ""
fi

if [ $FAILED -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}🎉 All checks passed! Implementation is complete.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Rotate database credentials in Railway"
    echo "2. Run database migrations: ./db/execute_migrations.sh"
    echo "3. Deploy to Railway: railway up"
    echo "4. Monitor application logs for any issues"
fi

echo ""
echo "========================================="
echo "For detailed security scan, run:"
echo "  ./scripts/security/mcp_scan_setup.sh"
echo ""
echo "To execute database migrations, run:"
echo "  export DATABASE_URL='your_connection_string'"
echo "  ./db/execute_migrations.sh"
echo "========================================="

exit $FAILED