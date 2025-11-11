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

# Validate Railway configuration
validate_railway_config() {
    log_info "Validating Railway configuration..."
    
    # Main railway.toml
    if validate_file "$PROJECT_ROOT/railway.toml" "Main Railway configuration"; then
        # Check for required sections
        if grep -q "^\[build\]" "$PROJECT_ROOT/railway.toml"; then
            log_success "Railway build section configured"
        else
            log_error "Railway build section missing"
        fi
        
        if grep -q "^\[deploy\]" "$PROJECT_ROOT/railway.toml"; then
            log_success "Railway deploy section configured"
        else
            log_error "Railway deploy section missing"
        fi
        
        # Check for health check configuration
        if grep -q "healthcheckPath" "$PROJECT_ROOT/railway.toml"; then
            log_success "Health check endpoint configured"
        else
            log_warning "Health check endpoint not configured"
        fi
        
        # Check Dockerfile path
        local dockerfile_path=$(grep "dockerfilePath" "$PROJECT_ROOT/railway.toml" | cut -d'"' -f2 || echo "")
        if [[ -n "$dockerfile_path" && -f "$PROJECT_ROOT/$dockerfile_path" ]]; then
            log_success "Dockerfile path is valid: $dockerfile_path"
        else
            log_error "Dockerfile path is invalid or file missing: $dockerfile_path"
        fi
    fi
    
    # Production configuration
    validate_file "$PROJECT_ROOT/.railway/railway-production.toml" "Production Railway configuration" "false"
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
        
        # Check for Railway token reference
        if grep -q "RAILWAY_TOKEN" "$PROJECT_ROOT/.github/workflows/production-deploy.yml"; then
            log_success "Railway token configured in workflow"
        else
            log_error "Railway token not configured in workflow"
        fi
    fi
}

# Validate application files
validate_application() {
    log_info "Validating application files..."
    
    # Main application file
    validate_file "$PROJECT_ROOT/app.R" "Main application file"
    
    # Railway startup scripts
    validate_file "$PROJECT_ROOT/railway_full_app.R" "Railway production server"
    
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
        
        if [[ -f "$PROJECT_ROOT/railway_full_app.R" ]]; then
            if Rscript -e "tryCatch({source('$PROJECT_ROOT/railway_full_app.R', echo=FALSE); cat('OK\n')}, error=function(e){cat('ERROR:', e\$message, '\n'); quit(status=1)})" 2>/dev/null | grep -q "OK"; then
                log_success "railway_full_app.R syntax is valid"
            else
                log_warning "railway_full_app.R has syntax issues"
            fi
        fi
    else
        log_warning "R not available for syntax validation"
    fi
}

# Validate deployment scripts
validate_deployment_scripts() {
    log_info "Validating deployment scripts..."
    
    validate_file "$PROJECT_ROOT/scripts/deploy-production.sh" "Production deployment script"
    
    # Check if deployment script is executable
    if [[ -f "$PROJECT_ROOT/scripts/deploy-production.sh" && -x "$PROJECT_ROOT/scripts/deploy-production.sh" ]]; then
        log_success "Deployment script is executable"
    else
        log_warning "Deployment script is not executable"
    fi
    
    # Check for required tools
    log_info "Checking required tools..."
    
    if command -v railway &> /dev/null; then
        log_success "Railway CLI is available"
    else
        log_warning "Railway CLI not installed (install with: npm install -g @railway/cli)"
    fi
    
    if command -v docker &> /dev/null; then
        log_success "Docker is available"
    else
        log_warning "Docker not available"
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
    
    # Monitoring configuration in Railway config
    if [[ -f "$PROJECT_ROOT/railway.toml" ]]; then
        if grep -q "MONITORING_ENABLED" "$PROJECT_ROOT/railway.toml"; then
            log_success "Monitoring enabled in Railway configuration"
        else
            log_warning "Monitoring not explicitly enabled in Railway configuration"
        fi
        
        if grep -q "HEALTH_CHECK_DETAILED" "$PROJECT_ROOT/railway.toml"; then
            log_success "Detailed health checks configured"
        else
            log_warning "Detailed health checks not configured"
        fi
    fi
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
        echo "1. Run: ./scripts/deploy-production.sh"
        echo "2. Monitor deployment at Railway dashboard"
        echo "3. Verify health check: curl -f https://your-app.railway.app/health"
        
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
    
    validate_railway_config
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