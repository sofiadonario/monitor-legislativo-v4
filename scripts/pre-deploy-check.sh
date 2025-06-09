#!/bin/bash
#
# PRE-DEPLOYMENT VERIFICATION SCRIPT
# Monitor Legislativo v4 - Final Production Readiness Check
#
# This script performs comprehensive pre-deployment verification
# ensuring all systems are ready for production deployment.
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0
CRITICAL_FAILURES=0

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
}

warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
}

error() {
    echo -e "${RED}[✗]${NC} $1" >&2
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
}

critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" >&2
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
}

run_check() {
    local check_name="$1"
    local check_function="$2"
    
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    echo ""
    log "Running check: $check_name"
    
    if $check_function; then
        success "$check_name"
        return 0
    else
        error "$check_name"
        return 1
    fi
}

# Security checks
check_security() {
    local security_score=0
    local security_total=5
    
    # Check AWS credentials
    if ! grep -r "AKIA" . --exclude-dir=.git --exclude-dir=venv --exclude="*.sh" &>/dev/null; then
        success "No AWS credentials in code"
        security_score=$((security_score + 1))
    else
        critical "AWS credentials found in code"
    fi
    
    # Check environment file
    if [[ -f ".env.production" ]]; then
        if [[ "$(stat -c %a .env.production 2>/dev/null || echo 644)" == "600" ]]; then
            success "Production environment file secured"
            security_score=$((security_score + 1))
        else
            error "Production environment file not properly secured"
        fi
    else
        critical "Production environment file missing"
    fi
    
    # Check security headers
    if [[ -f "web/middleware/security_headers.py" ]]; then
        if grep -q "X-Content-Type-Options\|X-Frame-Options\|Strict-Transport-Security" "web/middleware/security_headers.py"; then
            success "Security headers implemented"
            security_score=$((security_score + 1))
        else
            error "Security headers incomplete"
        fi
    else
        critical "Security headers middleware missing"
    fi
    
    # Check rate limiting
    if [[ -f "web/middleware/rate_limit_middleware.py" ]]; then
        success "Rate limiting implemented"
        security_score=$((security_score + 1))
    else
        error "Rate limiting middleware missing"
    fi
    
    # Check .gitignore
    if grep -q ".env\|*.key\|*.pem" .gitignore; then
        success "Git ignore configured for secrets"
        security_score=$((security_score + 1))
    else
        error "Git ignore missing credential patterns"
    fi
    
    local security_percentage=$((security_score * 100 / security_total))
    log "Security score: $security_score/$security_total ($security_percentage%)"
    
    [[ $security_percentage -ge 80 ]]
}

# Environment checks
check_environment() {
    if [[ ! -f ".env.production" ]]; then
        critical "Production environment file missing"
        return 1
    fi
    
    local required_vars=(
        "APP_ENV" "DB_PASSWORD" "REDIS_PASSWORD" "SECRET_KEY" "JWT_SECRET_KEY"
    )
    
    source .env.production
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            critical "Required environment variable missing: $var"
            return 1
        else
            success "Environment variable configured: $var"
        fi
    done
    
    # Check password strength
    if [[ ${#DB_PASSWORD} -lt 16 ]]; then
        error "Database password too short"
        return 1
    fi
    
    if [[ ${#REDIS_PASSWORD} -lt 16 ]]; then
        error "Redis password too short"
        return 1
    fi
    
    return 0
}

# Docker configuration checks
check_docker_config() {
    if [[ ! -f "docker-compose.yml" ]]; then
        critical "Docker Compose file missing"
        return 1
    fi
    
    # Check for hardcoded passwords
    if grep -q "postgres123\|redis123\|admin:admin" docker-compose.yml; then
        critical "Hardcoded passwords found in Docker Compose"
        return 1
    fi
    
    # Check for environment variable usage
    if grep -q "\${.*PASSWORD}" docker-compose.yml; then
        success "Docker Compose uses environment variables"
    else
        error "Docker Compose not using environment variables"
        return 1
    fi
    
    return 0
}

# Health checks
check_health_endpoints() {
    if [[ ! -f "web/api/health_checks.py" ]]; then
        error "Health checks module missing"
        return 1
    fi
    
    # Check for required health endpoints
    local required_endpoints=("live" "ready" "metrics")
    
    for endpoint in "${required_endpoints[@]}"; do
        if grep -q "$endpoint" "web/api/health_checks.py"; then
            success "Health endpoint implemented: $endpoint"
        else
            error "Health endpoint missing: $endpoint"
            return 1
        fi
    done
    
    return 0
}

# Monitoring checks
check_monitoring() {
    local monitoring_score=0
    local monitoring_total=4
    
    # Check logging configuration
    if [[ -f "core/monitoring/production_logger.py" ]]; then
        success "Production logging configured"
        monitoring_score=$((monitoring_score + 1))
    else
        error "Production logging missing"
    fi
    
    # Check alerts configuration
    if [[ -f "monitoring/production-alerts.yml" ]]; then
        success "Production alerts configured"
        monitoring_score=$((monitoring_score + 1))
    else
        error "Production alerts missing"
    fi
    
    # Check Prometheus configuration
    if [[ -f "monitoring/prometheus.yml" ]]; then
        success "Prometheus configuration present"
        monitoring_score=$((monitoring_score + 1))
    else
        warning "Prometheus configuration missing"
    fi
    
    # Check Grafana dashboards
    if [[ -d "monitoring/grafana/dashboards" ]]; then
        success "Grafana dashboards present"
        monitoring_score=$((monitoring_score + 1))
    else
        warning "Grafana dashboards missing"
    fi
    
    local monitoring_percentage=$((monitoring_score * 100 / monitoring_total))
    log "Monitoring score: $monitoring_score/$monitoring_total ($monitoring_percentage%)"
    
    [[ $monitoring_percentage -ge 75 ]]
}

# Deployment scripts checks
check_deployment_scripts() {
    local required_scripts=(
        "scripts/deploy-production.sh"
        "validate-security-fixes.py"
    )
    
    for script in "${required_scripts[@]}"; do
        if [[ -f "$script" ]]; then
            if [[ -x "$script" ]]; then
                success "Deployment script ready: $script"
            else
                error "Deployment script not executable: $script"
                return 1
            fi
        else
            error "Deployment script missing: $script"
            return 1
        fi
    done
    
    return 0
}

# Documentation checks
check_documentation() {
    local required_docs=(
        "PRODUCTION_GUIDE.md"
        "SECURITY_DEPLOYMENT_SUMMARY.md"
        ".env.production.template"
    )
    
    for doc in "${required_docs[@]}"; do
        if [[ -f "$doc" ]]; then
            success "Documentation present: $doc"
        else
            error "Documentation missing: $doc"
            return 1
        fi
    done
    
    return 0
}

# Government APIs checks
check_government_apis() {
    local apis=("antt" "dou" "camara" "senado" "dnit" "lexml")
    local api_files_found=0
    
    for api in "${apis[@]}"; do
        if find . -name "*${api}*" -type f | head -1 | grep -q .; then
            success "API integration found: $api"
            api_files_found=$((api_files_found + 1))
        else
            warning "API integration not found: $api"
        fi
    done
    
    if [[ $api_files_found -ge 4 ]]; then
        success "Sufficient government API integrations ($api_files_found/6)"
        return 0
    else
        error "Insufficient government API integrations ($api_files_found/6)"
        return 1
    fi
}

# Performance checks
check_performance_config() {
    # Check for performance middleware
    if [[ -f "web/middleware/performance_middleware.py" ]]; then
        success "Performance middleware present"
    else
        warning "Performance middleware missing"
    fi
    
    # Check for caching configuration
    if [[ -f "core/utils/cache_manager.py" ]] || [[ -f "core/utils/smart_cache.py" ]]; then
        success "Caching system present"
    else
        error "Caching system missing"
        return 1
    fi
    
    # Check for rate limiting
    if [[ -f "core/utils/rate_limiter.py" ]]; then
        success "Rate limiter present"
    else
        error "Rate limiter missing"
        return 1
    fi
    
    return 0
}

# Final report
print_final_report() {
    echo ""
    echo "=============================================="
    echo "  PRODUCTION READINESS VERIFICATION REPORT"
    echo "=============================================="
    echo ""
    
    local success_percentage=0
    if [[ $CHECKS_TOTAL -gt 0 ]]; then
        success_percentage=$((CHECKS_PASSED * 100 / CHECKS_TOTAL))
    fi
    
    echo "Total Checks: $CHECKS_TOTAL"
    echo "Passed: $CHECKS_PASSED"
    echo "Failed: $CHECKS_FAILED"
    echo "Critical Failures: $CRITICAL_FAILURES"
    echo "Success Rate: $success_percentage%"
    echo ""
    
    if [[ $CRITICAL_FAILURES -eq 0 ]] && [[ $success_percentage -ge 90 ]]; then
        success "🚀 SYSTEM READY FOR PRODUCTION DEPLOYMENT!"
        echo ""
        echo "Next steps:"
        echo "1. Review any warnings above"
        echo "2. Execute: ./scripts/deploy-production.sh"
        echo "3. Monitor: https://monitor-legislativo.gov.br/health/ready"
        echo ""
        return 0
    elif [[ $CRITICAL_FAILURES -eq 0 ]] && [[ $success_percentage -ge 80 ]]; then
        warning "⚠️  SYSTEM MOSTLY READY - Address warnings before deployment"
        return 1
    else
        error "❌ SYSTEM NOT READY FOR PRODUCTION"
        echo ""
        echo "Critical issues must be resolved before deployment:"
        echo "- $CRITICAL_FAILURES critical failures detected"
        echo "- Success rate: $success_percentage% (minimum: 90%)"
        echo ""
        return 1
    fi
}

# Main execution
main() {
    echo ""
    log "🔍 MONITOR LEGISLATIVO v4 - PRE-DEPLOYMENT VERIFICATION"
    log "=============================================="
    echo ""
    
    # Run all checks
    run_check "Security Configuration" check_security
    run_check "Environment Variables" check_environment
    run_check "Docker Configuration" check_docker_config
    run_check "Health Endpoints" check_health_endpoints
    run_check "Monitoring Setup" check_monitoring
    run_check "Deployment Scripts" check_deployment_scripts
    run_check "Documentation" check_documentation
    run_check "Government APIs" check_government_apis
    run_check "Performance Configuration" check_performance_config
    
    # Print final report
    print_final_report
}

# Execute main function
main "$@"