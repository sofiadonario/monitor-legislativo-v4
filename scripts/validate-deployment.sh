#!/bin/bash
# =============================================================================
# DEPLOYMENT VALIDATION SCRIPT - Monitor Legislativo v4
# Validates deployment configuration and infrastructure readiness
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Validation results
VALIDATION_PASSED=0
VALIDATION_FAILED=0
VALIDATION_WARNINGS=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((VALIDATION_PASSED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((VALIDATION_WARNINGS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((VALIDATION_FAILED++))
}

# Validate file existence
validate_file() {
    local file="$1"
    local description="$2"
    local critical="${3:-true}"
    
    if [[ -f "$file" ]]; then
        log_success "$description exists: $file"
        return 0
    else
        if [[ "$critical" == "true" ]]; then
            log_error "$description missing: $file"
        else
            log_warning "$description missing (optional): $file"
        fi
        return 1
    fi
}

# Validate directory existence
validate_directory() {
    local dir="$1"
    local description="$2"
    local critical="${3:-true}"
    
    if [[ -d "$dir" ]]; then
        log_success "$description exists: $dir"
        return 0
    else
        if [[ "$critical" == "true" ]]; then
            log_error "$description missing: $dir"
        else
            log_warning "$description missing (optional): $dir"
        fi
        return 1
    fi
}

# Validate Cloud Run configuration
validate_cloud_run_config() {
    log_info "Validating Cloud Run configuration..."

    # Check for app.yaml or Cloud Run configuration (optional)
    if [[ -f "$PROJECT_ROOT/app.yaml" ]]; then
        validate_file "$PROJECT_ROOT/app.yaml" "Cloud Run app.yaml configuration" "false"
    else
        log_info "No app.yaml found (using defaults from gcloud deploy)"
    fi

    # Validate gcloud configuration
    if command -v gcloud &> /dev/null; then
        local project_id=$(gcloud config get-value project 2>/dev/null || echo "")
        if [[ -n "$project_id" ]]; then
            log_success "GCP project configured: $project_id"
        else
            log_warning "GCP project not configured in gcloud"
        fi

        local region=$(gcloud config get-value run/region 2>/dev/null || echo "")
        if [[ -n "$region" ]]; then
            log_success "Cloud Run region configured: $region"
        else
            log_info "Cloud Run region not configured (will use default: southamerica-east1)"
        fi
    else
        log_warning "gcloud CLI not available for configuration validation"
    fi

    # Check for service configuration
    log_info "Expected Cloud Run service: mackmonitor"
    log_info "Expected region: southamerica-east1"
    log_info "Expected URL: https://mackmonitor-667999538255.southamerica-east1.run.app"
}

# Validate Docker configuration
validate_docker_config() {
    log_info "Validating Docker configuration..."
    
    validate_file "$PROJECT_ROOT/Dockerfile" "Main Dockerfile"
    
    # Check if Docker is available for syntax validation
    if command -v docker &> /dev/null; then
        log_info "Testing Dockerfile syntax..."
        if docker build --dry-run -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" &> /dev/null; then
            log_success "Dockerfile syntax is valid"
        else
            log_error "Dockerfile syntax is invalid"
        fi
    else
        log_warning "Docker not available for syntax validation"
    fi
}

# Validate GitHub Actions workflows
validate_github_actions() {
    log_info "Validating GitHub Actions workflows..."
    
    validate_directory "$PROJECT_ROOT/.github/workflows" "GitHub Actions workflows directory"
    
    validate_file "$PROJECT_ROOT/.github/workflows/production-deploy.yml" "Production deployment workflow"
    
    if [[ -f "$PROJECT_ROOT/.github/workflows/production-deploy.yml" ]]; then
        # Check for required jobs
        if grep -q "jobs:" "$PROJECT_ROOT/.github/workflows/production-deploy.yml"; then
            log_success "GitHub Actions jobs defined"
            
            # Check for specific jobs
            if grep -q "test:" "$PROJECT_ROOT/.github/workflows/production-deploy.yml"; then
                log_success "Test job configured"
            else
                log_warning "Test job not configured"
            fi
            
            if grep -q "deploy-production:" "$PROJECT_ROOT/.github/workflows/production-deploy.yml"; then
                log_success "Production deployment job configured"
            else
                log_error "Production deployment job missing"
            fi
        else
            log_error "No jobs defined in production deployment workflow"
        fi
        
        # Check for GCP credentials reference
        if grep -q "GCP_SA_KEY\|GOOGLE_CREDENTIALS\|workload_identity_provider" "$PROJECT_ROOT/.github/workflows/production-deploy.yml"; then
            log_success "GCP credentials configured in workflow"
        else
            log_warning "GCP credentials not configured in workflow"
        fi
    fi
}

# Validate application files
validate_application() {
    log_info "Validating application files..."

    # Main application file
    validate_file "$PROJECT_ROOT/app.R" "Main application file"

    # Health check system
    validate_file "$PROJECT_ROOT/health_check.R" "Health check system"

    # Monitoring system
    validate_file "$PROJECT_ROOT/monitoring/production_monitoring.R" "Production monitoring system" "false"

    # Essential directories
    validate_directory "$PROJECT_ROOT/db" "Database modules directory" "false"
    validate_directory "$PROJECT_ROOT/modules" "Application modules directory" "false"
    validate_directory "$PROJECT_ROOT/monitoring" "Monitoring directory" "false"

    # Check R syntax for critical files
    if command -v Rscript &> /dev/null; then
        log_info "Validating R syntax..."

        if Rscript -e "tryCatch({source('$PROJECT_ROOT/app.R', echo=FALSE); cat('OK\n')}, error=function(e){cat('ERROR:', e\$message, '\n'); quit(status=1)})" 2>/dev/null | grep -q "OK"; then
            log_success "app.R syntax is valid"
        else
            log_warning "app.R has syntax issues"
        fi
    else
        log_warning "R not available for syntax validation"
    fi
}

# Validate deployment scripts
validate_deployment_scripts() {
    log_info "Validating deployment scripts..."

    validate_file "$PROJECT_ROOT/scripts/deployment/zero_downtime_deploy.sh" "Zero-downtime deployment script" "false"

    # Check if deployment script is executable
    if [[ -f "$PROJECT_ROOT/scripts/deployment/zero_downtime_deploy.sh" && -x "$PROJECT_ROOT/scripts/deployment/zero_downtime_deploy.sh" ]]; then
        log_success "Deployment script is executable"
    else
        log_warning "Deployment script is not executable"
    fi

    # Check for required tools
    log_info "Checking required tools..."

    if command -v gcloud &> /dev/null; then
        log_success "gcloud CLI is available"

        # Check gcloud authentication
        if gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
            log_success "gcloud is authenticated"
        else
            log_warning "gcloud is not authenticated (run: gcloud auth login)"
        fi
    else
        log_error "gcloud CLI not installed (install from: https://cloud.google.com/sdk/docs/install)"
    fi

    if command -v docker &> /dev/null; then
        log_success "Docker is available"
    else
        log_warning "Docker not available (optional for local testing)"
    fi

    if command -v git &> /dev/null; then
        log_success "Git is available"
    else
        log_error "Git not available"
    fi
}

# Validate environment configuration
validate_environment() {
    log_info "Validating environment configuration..."
    
    # Check for environment files (should not exist in production)
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        log_warning ".env file found - should not be committed to repository"
    else
        log_success "No .env file found in repository (good)"
    fi
    
    # Check gitignore
    if [[ -f "$PROJECT_ROOT/.gitignore" ]]; then
        log_success ".gitignore exists"
        
        if grep -q "\.env" "$PROJECT_ROOT/.gitignore"; then
            log_success ".env files are ignored by git"
        else
            log_warning ".env files not explicitly ignored in .gitignore"
        fi
    else
        log_warning ".gitignore missing"
    fi
    
    # Check for sensitive files that shouldn't be committed
    local sensitive_files=("*.key" "*.pem" "*.p12" "*password*" "*secret*")
    for pattern in "${sensitive_files[@]}"; do
        if find "$PROJECT_ROOT" -name "$pattern" -type f | grep -v .git | head -1 &> /dev/null; then
            log_error "Potentially sensitive files found matching pattern: $pattern"
        fi
    done
}

# Validate monitoring and health checks
validate_monitoring() {
    log_info "Validating monitoring and health check system..."

    # Health check endpoint
    validate_file "$PROJECT_ROOT/health_check.R" "Health check endpoint"

    # Production monitoring
    validate_file "$PROJECT_ROOT/monitoring/production_monitoring.R" "Production monitoring system" "false"

    # Cloud Run health checks are configured via service settings
    log_info "Cloud Run health checks should be configured via:"
    log_info "  - Startup probe: /health endpoint"
    log_info "  - Liveness probe: /health endpoint"
    log_info "  - Container port: 8080 (default Shiny port)"
}

# Generate deployment readiness report
generate_report() {
    echo ""
    echo "==============================================="
    echo "         DEPLOYMENT READINESS REPORT"
    echo "==============================================="
    echo ""
    echo "Summary:"
    echo "  ✅ Validations Passed: $VALIDATION_PASSED"
    echo "  ⚠️  Warnings:          $VALIDATION_WARNINGS"
    echo "  ❌ Validations Failed: $VALIDATION_FAILED"
    echo ""
    
    if [[ $VALIDATION_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✅ DEPLOYMENT READY${NC}"
        echo ""
        echo "The application is ready for deployment to production."
        
        if [[ $VALIDATION_WARNINGS -gt 0 ]]; then
            echo -e "${YELLOW}⚠️  Consider addressing the warnings above before deployment.${NC}"
        fi
        
        echo ""
        echo "Next steps:"
        echo "1. Run: ./scripts/deployment/zero_downtime_deploy.sh"
        echo "2. Monitor deployment at Cloud Run console"
        echo "3. Verify health check: curl -f https://mackmonitor-667999538255.southamerica-east1.run.app/health"
        
        return 0
    else
        echo -e "${RED}❌ DEPLOYMENT NOT READY${NC}"
        echo ""
        echo "Critical issues must be resolved before deployment:"
        echo "• Fix the failed validations listed above"
        echo "• Ensure all required files are present and correctly configured"
        echo "• Test locally before attempting production deployment"
        
        return 1
    fi
}

# Main validation flow
main() {
    echo "==============================================="
    echo "    DEPLOYMENT VALIDATION - Monitor Legislativo v4"
    echo "==============================================="
    echo ""
    
    cd "$PROJECT_ROOT"

    validate_cloud_run_config
    validate_docker_config
    validate_github_actions
    validate_application
    validate_deployment_scripts
    validate_environment
    validate_monitoring

    generate_report
}

# Run main validation
main "$@"