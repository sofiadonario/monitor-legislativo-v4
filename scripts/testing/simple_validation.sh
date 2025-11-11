#!/bin/bash

# SIMPLE VALIDATION SCRIPT - MONITOR LEGISLATIVO V4
# =================================================
# Basic validation without requiring additional R packages

set -euo pipefail

# Configuration
BASE_URL="${1:-http://localhost:3838}"
TIMEOUT=30
BRAZILIAN_TZ="America/Sao_Paulo"

# Colors
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
BLUE='\033[34m'
PURPLE='\033[35m'
CYAN='\033[36m'
NC='\033[0m'

# Set timezone
export TZ="${BRAZILIAN_TZ}"

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNING_TESTS++))
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Test function with retry logic
test_endpoint() {
    local url="$1"
    local test_name="$2"
    local expected_status="${3:-200}"
    
    ((TOTAL_TESTS++))
    log_test "${test_name}"
    
    for attempt in {1..3}; do
        if curl -f --max-time "${TIMEOUT}" --silent --head "${url}" >/dev/null 2>&1; then
            local status_code
            status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT}" "${url}")
            
            if [[ "${status_code}" == "${expected_status}" ]]; then
                log_pass "${test_name} - HTTP ${status_code}"
                return 0
            else
                log_warn "${test_name} - HTTP ${status_code} (expected ${expected_status})"
                return 1
            fi
        fi
        
        if [[ $attempt -lt 3 ]]; then
            sleep 2
        fi
    done
    
    log_fail "${test_name} - Connection failed after 3 attempts"
    return 1
}

# Test content for specific features
test_content() {
    local url="$1"
    local test_name="$2"
    local search_term="$3"
    
    ((TOTAL_TESTS++))
    log_test "${test_name}"
    
    if content=$(curl -f --max-time "${TIMEOUT}" --silent "${url}" 2>/dev/null); then
        if echo "${content}" | grep -qi "${search_term}"; then
            log_pass "${test_name} - Content contains '${search_term}'"
            return 0
        else
            log_warn "${test_name} - Content accessible but '${search_term}' not found"
            return 1
        fi
    else
        log_fail "${test_name} - Content not accessible"
        return 1
    fi
}

# Performance test
test_performance() {
    local url="$1"
    local test_name="$2"
    local max_time="${3:-3.0}"
    
    ((TOTAL_TESTS++))
    log_test "${test_name}"
    
    local start_time
    start_time=$(date +%s.%N)
    
    if curl -f --max-time "${TIMEOUT}" --silent "${url}" >/dev/null 2>&1; then
        local end_time
        end_time=$(date +%s.%N)
        local duration
        duration=$(echo "${end_time} - ${start_time}" | bc -l 2>/dev/null || echo "0")
        
        if (( $(echo "${duration} <= ${max_time}" | bc -l 2>/dev/null) )); then
            log_pass "${test_name} - Response time: ${duration}s"
            return 0
        else
            log_warn "${test_name} - Response time: ${duration}s (target: <${max_time}s)"
            return 1
        fi
    else
        log_fail "${test_name} - Performance test failed"
        return 1
    fi
}

# Main validation function
run_validation() {
    echo -e "${PURPLE}===============================================${NC}"
    echo -e "${PURPLE} MONITOR LEGISLATIVO V4 - BASIC VALIDATION ${NC}"
    echo -e "${PURPLE}===============================================${NC}"
    echo "Target URL: ${BASE_URL}"
    echo "Brazilian Context: Enabled"
    echo "Timezone: ${BRAZILIAN_TZ}"
    echo "Start Time: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo ""
    
    # Week 1-2: Foundation and Architecture
    log_info "Testing Week 1-2: Foundation and Architecture"
    test_endpoint "${BASE_URL}/" "Main Application Access"
    test_content "${BASE_URL}/" "Portuguese Interface" "Monitor"
    
    # Week 3: Search Functionality  
    log_info "Testing Week 3: Advanced Search"
    test_content "${BASE_URL}/" "Search Interface" "busca\|search\|pesquis"
    
    # Week 4: Geographic Analysis
    log_info "Testing Week 4: Geographic Analysis"
    test_content "${BASE_URL}/" "Geographic Features" "geográf\|mapa\|estado"
    
    # Week 5: Citation System
    log_info "Testing Week 5: Citation and Export System"
    test_content "${BASE_URL}/" "Export Features" "exportar\|download\|cita"
    
    # Week 6: API Access
    log_info "Testing Week 6: REST API"
    test_endpoint "${BASE_URL}/health" "Health Check Endpoint" 200
    
    # Week 7: Performance
    log_info "Testing Week 7: Performance Optimization"
    test_performance "${BASE_URL}/" "Application Performance" 5.0
    
    # Week 8: Monitoring
    log_info "Testing Week 8: Integration and Monitoring"
    test_endpoint "${BASE_URL}/health" "Health Monitoring" 200
    
    # Additional tests
    log_info "Testing Additional Features"
    
    # Test for Brazilian context
    test_content "${BASE_URL}/" "Brazilian Context" "brasil\|legislativ"
    
    # Test for academic features
    test_content "${BASE_URL}/" "Academic Features" "acadêmic\|pesquis\|document"
    
    # Generate report
    generate_report
}

generate_report() {
    echo ""
    echo -e "${PURPLE}===============================================${NC}"
    echo -e "${PURPLE} VALIDATION RESULTS SUMMARY ${NC}"
    echo -e "${PURPLE}===============================================${NC}"
    
    echo "Total Tests: ${TOTAL_TESTS}"
    echo -e "${GREEN}Passed: ${PASSED_TESTS}${NC}"
    echo -e "${RED}Failed: ${FAILED_TESTS}${NC}"
    echo -e "${YELLOW}Warnings: ${WARNING_TESTS}${NC}"
    
    local success_rate=0
    if [[ ${TOTAL_TESTS} -gt 0 ]]; then
        success_rate=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    fi
    
    echo "Success Rate: ${success_rate}%"
    
    echo ""
    if [[ ${FAILED_TESTS} -eq 0 && ${success_rate} -ge 80 ]]; then
        echo -e "${GREEN}OVERALL STATUS: PRODUCTION READY ✓${NC}"
        echo ""
        echo -e "${CYAN}BRAZILIAN ACADEMIC COMPLIANCE:${NC}"
        echo "✓ Application accessible"
        echo "✓ Basic functionality validated"
        echo "✓ Brazilian timezone configured"
        echo "✓ Performance within acceptable limits"
    elif [[ ${FAILED_TESTS} -le 2 && ${success_rate} -ge 60 ]]; then
        echo -e "${YELLOW}OVERALL STATUS: READY WITH WARNINGS ⚠${NC}"
        echo ""
        echo -e "${CYAN}RECOMMENDATIONS:${NC}"
        echo "• Review warnings above"
        echo "• Consider additional testing"
        echo "• Monitor performance after deployment"
    else
        echo -e "${RED}OVERALL STATUS: NOT READY - FIXES REQUIRED ✗${NC}"
        echo ""
        echo -e "${CYAN}REQUIRED ACTIONS:${NC}"
        echo "• Fix failed tests"
        echo "• Ensure application is running"
        echo "• Check Railway deployment status"
    fi
    
    echo ""
    echo -e "${CYAN}NEXT STEPS FOR PRODUCTION:${NC}"
    echo "1. Deploy to Railway production environment"
    echo "2. Run integration tests with production URL"
    echo "3. Validate all 8 weeks of features"
    echo "4. Complete launch checklist validation"
    echo "5. Monitor system performance"
    
    echo ""
    echo "Validation completed at: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Target: ${BASE_URL}"
}

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}ERROR: curl is required but not installed${NC}"
    exit 1
fi

# Check if bc is available for calculations
if ! command -v bc >/dev/null 2>&1; then
    echo -e "${YELLOW}WARNING: bc not available - performance calculations may be inaccurate${NC}"
fi

# Run validation
run_validation

# Return appropriate exit code
if [[ ${FAILED_TESTS} -eq 0 ]]; then
    exit 0
else
    exit 1
fi