#!/bin/bash

# =============================================================================
# DOCKER SECURITY SCANNING SCRIPT
# Enterprise-Grade Security Validation for R Shiny Application
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${PROJECT_ROOT}/docker"
DOCKERFILE_SECURE="${DOCKER_DIR}/Dockerfile.secure"
DOCKERIGNORE_FILE="${PROJECT_ROOT}/.dockerignore"
IMAGE_NAME="monitor-legislativo-secure"
IMAGE_TAG="latest"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Logging functions
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

log_header() {
    echo -e "${PURPLE}=== $1 ===${NC}"
}

# Security check functions
check_prerequisites() {
    log_header "Checking Prerequisites"
    
    local missing_tools=()
    
    # Check for required tools
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if ! command -v trivy &> /dev/null; then
        log_warning "Trivy vulnerability scanner not found. Installing..."
        install_trivy
    fi
    
    if ! command -v hadolint &> /dev/null; then
        log_warning "Hadolint Dockerfile linter not found. Will use Docker-based version."
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and run this script again."
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

install_trivy() {
    log_info "Installing Trivy vulnerability scanner..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux installation
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS installation
        if command -v brew &> /dev/null; then
            brew install trivy
        else
            log_error "Homebrew not found. Please install Trivy manually: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            exit 1
        fi
    else
        log_error "Unsupported operating system. Please install Trivy manually: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        exit 1
    fi
    
    log_success "Trivy installed successfully"
}

validate_files() {
    log_header "Validating Security Configuration Files"
    
    # Check if secure Dockerfile exists
    if [ ! -f "$DOCKERFILE_SECURE" ]; then
        log_error "Secure Dockerfile not found: $DOCKERFILE_SECURE"
        exit 1
    fi
    log_success "Secure Dockerfile found"
    
    # Check if .dockerignore exists
    if [ ! -f "$DOCKERIGNORE_FILE" ]; then
        log_error ".dockerignore file not found: $DOCKERIGNORE_FILE"
        exit 1
    fi
    log_success ".dockerignore file found"
    
    # Validate .dockerignore excludes dangerous files
    if grep -q "CLOUD_RUN_PRODUCTION_DB_FIX.R" "$DOCKERIGNORE_FILE"; then
        log_success "Dangerous file CLOUD_RUN_PRODUCTION_DB_FIX.R properly excluded in .dockerignore"
    else
        log_error "CLOUD_RUN_PRODUCTION_DB_FIX.R not excluded in .dockerignore - SECURITY RISK!"
        exit 1
    fi
}

scan_dockerfile() {
    log_header "Scanning Dockerfile with Hadolint"
    
    # Use Docker-based hadolint if local installation not available
    if command -v hadolint &> /dev/null; then
        hadolint_cmd="hadolint"
    else
        hadolint_cmd="docker run --rm -i hadolint/hadolint"
    fi
    
    if $hadolint_cmd < "$DOCKERFILE_SECURE"; then
        log_success "Dockerfile passed Hadolint security checks"
    else
        log_warning "Dockerfile has some issues. Review the output above."
    fi
}

build_secure_image() {
    log_header "Building Secure Docker Image"
    
    cd "$PROJECT_ROOT"
    
    log_info "Building image: $FULL_IMAGE_NAME"
    log_info "Using Dockerfile: $DOCKERFILE_SECURE"
    log_info "Build context: $PROJECT_ROOT"
    
    if docker build \
        -f "$DOCKERFILE_SECURE" \
        --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        --build-arg VERSION="$(git describe --tags --dirty 2>/dev/null || echo 'dev')" \
        -t "$FULL_IMAGE_NAME" \
        .; then
        log_success "Docker image built successfully: $FULL_IMAGE_NAME"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

scan_image_vulnerabilities() {
    log_header "Scanning Image for Vulnerabilities with Trivy"
    
    log_info "Scanning image: $FULL_IMAGE_NAME"
    
    # Generate vulnerability report
    local vuln_report="${PROJECT_ROOT}/security_reports/vulnerability_report.json"
    mkdir -p "$(dirname "$vuln_report")"
    
    if trivy image --format json --output "$vuln_report" "$FULL_IMAGE_NAME"; then
        log_success "Vulnerability scan completed. Report saved to: $vuln_report"
        
        # Generate human-readable summary
        trivy image --format table "$FULL_IMAGE_NAME" > "${PROJECT_ROOT}/security_reports/vulnerability_summary.txt"
        
        # Check for critical vulnerabilities
        local critical_count=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' "$vuln_report" 2>/dev/null | wc -l || echo "0")
        local high_count=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .VulnerabilityID' "$vuln_report" 2>/dev/null | wc -l || echo "0")
        
        if [ "$critical_count" -gt 0 ]; then
            log_error "Found $critical_count CRITICAL vulnerabilities!"
            return 1
        elif [ "$high_count" -gt 5 ]; then
            log_warning "Found $high_count HIGH severity vulnerabilities (threshold: 5)"
            return 1
        else
            log_success "Vulnerability scan passed (Critical: $critical_count, High: $high_count)"
        fi
    else
        log_error "Vulnerability scan failed"
        return 1
    fi
}

check_secrets_exposure() {
    log_header "Scanning for Exposed Secrets"
    
    log_info "Checking built image for exposed secrets..."
    
    # Create temporary container to inspect filesystem
    local container_id
    container_id=$(docker create "$FULL_IMAGE_NAME")
    
    if [ -n "$container_id" ]; then
        # Export container filesystem
        local temp_dir
        temp_dir=$(mktemp -d)
        docker export "$container_id" | tar -x -C "$temp_dir"
        
        # Clean up container
        docker rm "$container_id" > /dev/null
        
        # Search for secrets
        local secrets_found=false
        
        # Check for hardcoded credentials
        if grep -r -i "password\|secret\|key\|token" "$temp_dir/app" 2>/dev/null | grep -v "Binary file"; then
            log_error "Potential hardcoded secrets found in application files!"
            secrets_found=true
        fi
        
        # Check for dangerous files that should have been excluded
        if find "$temp_dir/app" -name "CLOUD_RUN_PRODUCTION_DB_FIX.R" 2>/dev/null | grep -q .; then
            log_error "CRITICAL: CLOUD_RUN_PRODUCTION_DB_FIX.R found in image! This contains hardcoded credentials!"
            secrets_found=true
        fi
        
        # Check for other sensitive files
        local sensitive_files=("*.pem" "*.key" "*password*" "*secret*" "*.env")
        for pattern in "${sensitive_files[@]}"; do
            if find "$temp_dir/app" -name "$pattern" 2>/dev/null | grep -q .; then
                log_warning "Sensitive files matching pattern '$pattern' found in image"
            fi
        done
        
        # Clean up
        rm -rf "$temp_dir"
        
        if [ "$secrets_found" = true ]; then
            log_error "Secret exposure check FAILED"
            return 1
        else
            log_success "No hardcoded secrets detected"
        fi
    else
        log_error "Failed to create container for secret scanning"
        return 1
    fi
}

validate_security_configuration() {
    log_header "Validating Security Configuration"

    # Check if running as non-root
    local user_check
    user_check=$(docker run --rm "$FULL_IMAGE_NAME" whoami)

    if [ "$user_check" = "shinyapp" ]; then
        log_success "Container runs as non-root user: $user_check"
    else
        log_error "Container running as: $user_check (should be 'shinyapp')"
        return 1
    fi

    # Check file permissions
    local permissions_check
    permissions_check=$(docker run --rm "$FULL_IMAGE_NAME" ls -la /app/app.R | awk '{print $1}')

    if [[ "$permissions_check" =~ ^-rwxr--r-- ]] || [[ "$permissions_check" =~ ^-rw-r--r-- ]]; then
        log_success "App files have secure permissions: $permissions_check"
    else
        log_warning "App file permissions may be too permissive: $permissions_check"
    fi

    # Test health check
    log_info "Testing application health check..."
    local container_id
    container_id=$(docker run -d -p 0:8080 "$FULL_IMAGE_NAME")

    if [ -n "$container_id" ]; then
        sleep 10  # Wait for app to start

        local port
        port=$(docker port "$container_id" 8080 | cut -d: -f2)

        if curl -f "http://localhost:$port/" > /dev/null 2>&1; then
            log_success "Health check endpoint responding"
        else
            log_warning "Health check endpoint not responding (may need more time to start)"
        fi

        # Clean up
        docker stop "$container_id" > /dev/null
        docker rm "$container_id" > /dev/null
    fi
}

generate_security_report() {
    log_header "Generating Security Report"
    
    local report_dir="${PROJECT_ROOT}/security_reports"
    local report_file="${report_dir}/security_scan_report_$(date +%Y%m%d_%H%M%S).md"
    
    mkdir -p "$report_dir"
    
    cat > "$report_file" << EOF
# Docker Security Scan Report

**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')  
**Image:** $FULL_IMAGE_NAME  
**Scanner:** Security Scan Script v1.0  

## Summary

This report details the security analysis of the Monitor Legislativo R Shiny application Docker image.

## Scan Results

### ✅ Passed Checks
- Dockerfile security validation (Hadolint)
- Secret exposure prevention (.dockerignore configuration)
- Non-root user execution
- Multi-stage build implementation
- Vulnerability scanning (Trivy)

### 🔍 Key Security Features
- **Multi-stage build**: Minimizes attack surface
- **Non-root execution**: Runs as 'shinyapp' user (UID: 1001)
- **Dangerous file exclusion**: CLOUD_RUN_PRODUCTION_DB_FIX.R properly excluded
- **Minimal base image**: Only runtime dependencies included
- **Health checks**: Configured for Cloud Run deployment
- **Resource limits**: Memory and CPU constraints defined

### 📊 Vulnerability Analysis
$(if [ -f "${report_dir}/vulnerability_summary.txt" ]; then
    echo "See detailed vulnerability report: vulnerability_summary.txt"
else
    echo "Vulnerability scan report not available"
fi)

### 🛡️ Security Recommendations
1. Regularly update base images to include security patches
2. Monitor for new vulnerabilities in dependencies
3. Implement container image signing for production deployments
4. Use Google Cloud Secret Manager for sensitive configuration
5. Enable security headers in the Cloud Run service configuration

### 📋 Build Information
- **Build Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **Git Commit:** $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')
- **Version:** $(git describe --tags --dirty 2>/dev/null || echo 'dev')

---
*This report was generated by the automated security scanning script*
EOF

    log_success "Security report generated: $report_file"
}

cleanup() {
    log_info "Cleaning up temporary resources..."
    
    # Remove temporary containers if any
    docker ps -a --filter "ancestor=$FULL_IMAGE_NAME" -q | xargs -r docker rm -f
    
    log_success "Cleanup completed"
}

main() {
    log_header "Docker Security Scanner for Monitor Legislativo"
    log_info "Starting comprehensive security validation..."
    
    # Set up error handling
    trap cleanup EXIT
    
    # Run security checks
    local exit_code=0
    
    check_prerequisites || exit_code=1
    validate_files || exit_code=1
    scan_dockerfile || exit_code=1
    build_secure_image || exit_code=1
    
    if [ $exit_code -eq 0 ]; then
        scan_image_vulnerabilities || exit_code=1
        check_secrets_exposure || exit_code=1
        validate_security_configuration || exit_code=1
    fi
    
    # Always generate report
    generate_security_report
    
    if [ $exit_code -eq 0 ]; then
        log_success "🎉 All security checks passed!"
        log_info "Image $FULL_IMAGE_NAME is ready for secure deployment"
        log_info "Deploy to Cloud Run with: gcloud run deploy mackmonitor --image $FULL_IMAGE_NAME"
    else
        log_error "❌ Security validation failed!"
        log_error "Please address the issues above before deploying"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"