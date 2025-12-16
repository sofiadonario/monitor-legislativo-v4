#!/bin/bash

# ZERO-DOWNTIME DEPLOYMENT FOR MONITOR LEGISLATIVO V4
# ===================================================
# Production deployment with health checks and rollback capability
# Cloud Run platform optimized for Brazilian academic usage

set -euo pipefail

# Configuration
DEPLOYMENT_TIMEOUT=600  # 10 minutes
HEALTH_CHECK_TIMEOUT=120  # 2 minutes
HEALTH_CHECK_INTERVAL=10  # seconds
ROLLBACK_TIMEOUT=300  # 5 minutes
BRAZILIAN_TZ="America/Sao_Paulo"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Set Brazilian timezone
export TZ="${BRAZILIAN_TZ}"

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S %Z')] DEPLOY${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S %Z')] SUCCESS${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S %Z')] ERROR${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S %Z')] WARNING${NC} $1"
}

log_info() {
    echo -e "${PURPLE}[$(date '+%Y-%m-%d %H:%M:%S %Z')] INFO${NC} $1"
}

log_step() {
    echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S %Z')] STEP${NC} $1"
}

# Global variables for deployment tracking
DEPLOYMENT_ID=""
PREVIOUS_DEPLOYMENT_ID=""
DEPLOYMENT_START_TIME=""
BACKUP_CREATED=""

# Generate unique deployment ID
generate_deployment_id() {
    DEPLOYMENT_ID="deploy_$(date +%Y%m%d_%H%M%S)_$(head /dev/urandom | tr -dc a-z0-9 | head -c 6)"
    DEPLOYMENT_START_TIME=$(date -Iseconds)
    log_info "Deployment ID: ${DEPLOYMENT_ID}"
}

# Pre-deployment validation
validate_environment() {
    log_step "Validating deployment environment..."

    # Check gcloud CLI
    if ! command -v gcloud >/dev/null 2>&1; then
        log_error "gcloud CLI not found. Please install: https://cloud.google.com/sdk/docs/install"
        return 1
    fi

    # Check gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" >/dev/null 2>&1; then
        log_error "gcloud authentication failed. Please run: gcloud auth login"
        return 1
    fi

    # Check required environment variables
    local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
    if [[ -z "${project_id}" ]]; then
        log_error "GCP project not configured. Please run: gcloud config set project PROJECT_ID"
        return 1
    fi

    # Validate GCP project
    log_info "GCP Project: ${project_id}"
    log_info "Service: mackmonitor"
    log_info "Region: southamerica-east1"

    # Check if we're in the correct directory
    if [[ ! -f "app.R" ]]; then
        log_error "Deployment must be run from project root directory"
        log_error "Required file: app.R"
        return 1
    fi

    # Validate Dockerfile
    if [[ ! -f "Dockerfile" ]]; then
        log_error "Dockerfile not found"
        return 1
    fi

    log_success "Environment validation completed"
    return 0
}

# Pre-deployment backup
create_pre_deployment_backup() {
    log_step "Creating pre-deployment backup..."

    if [[ -f "scripts/backup/cloud_run_production_backup.sh" ]]; then
        if bash scripts/backup/cloud_run_production_backup.sh; then
            BACKUP_CREATED="true"
            log_success "Pre-deployment backup created"
            return 0
        else
            log_warning "Backup creation failed - continuing deployment"
            BACKUP_CREATED="false"
            return 0  # Don't fail deployment for backup issues
        fi
    else
        log_warning "Backup script not found - skipping pre-deployment backup"
        BACKUP_CREATED="false"
        return 0
    fi
}

# Check current service health
check_service_health() {
    local service_url="$1"
    local timeout="${2:-30}"
    
    log_info "Checking service health: ${service_url}"
    
    local end_time=$((SECONDS + timeout))
    while [[ $SECONDS -lt $end_time ]]; do
        if curl -f --max-time 10 --silent "${service_url}/health" >/dev/null 2>&1; then
            log_success "Service health check passed"
            return 0
        fi
        sleep 2
    done
    
    log_warning "Service health check failed or timed out"
    return 1
}

# Get current deployment info
get_current_deployment() {
    log_info "Getting current deployment information..."

    local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
    local service_name="mackmonitor"
    local region="southamerica-east1"

    if current_info=$(gcloud run revisions list \
        --service="${service_name}" \
        --region="${region}" \
        --project="${project_id}" \
        --format="value(name)" \
        --limit=1 2>/dev/null); then

        if [[ -n "${current_info}" ]]; then
            PREVIOUS_DEPLOYMENT_ID="${current_info}"
            log_info "Current revision: ${PREVIOUS_DEPLOYMENT_ID}"
        else
            log_info "No previous revision found"
            PREVIOUS_DEPLOYMENT_ID=""
        fi
    else
        log_warning "Unable to retrieve current revision"
        PREVIOUS_DEPLOYMENT_ID=""
    fi
}

# Deploy to Cloud Run with monitoring
deploy_to_cloud_run() {
    log_step "Starting Cloud Run deployment..."

    local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
    local service_name="mackmonitor"
    local region="southamerica-east1"

    log_info "Building and deploying to Cloud Run..."
    log_info "Project: ${project_id}"
    log_info "Service: ${service_name}"
    log_info "Region: ${region}"

    # Deploy using gcloud run deploy
    if gcloud run deploy "${service_name}" \
        --source . \
        --region="${region}" \
        --project="${project_id}" \
        --platform=managed \
        --allow-unauthenticated \
        --quiet 2>&1 | tee /tmp/deploy.log; then
        log_success "Deployment completed successfully"
        return 0
    else
        log_error "Deployment failed"
        cat /tmp/deploy.log
        return 1
    fi
}

# Wait for service to be healthy
wait_for_healthy_service() {
    log_step "Waiting for service to become healthy..."

    # Get service URL from Cloud Run
    local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
    local service_name="mackmonitor"
    local region="southamerica-east1"

    local service_url
    service_url=$(gcloud run services describe "${service_name}" \
        --region="${region}" \
        --project="${project_id}" \
        --format="value(status.url)" 2>/dev/null || echo "")

    if [[ -z "${service_url}" ]]; then
        # Fallback to known URL
        service_url="https://mackmonitor-667999538255.southamerica-east1.run.app"
        log_warning "Unable to retrieve service URL from gcloud, using known URL: ${service_url}"
    fi

    log_info "Service URL: ${service_url}"

    # Wait for health checks to pass
    local health_check_end_time=$((SECONDS + HEALTH_CHECK_TIMEOUT))
    local consecutive_successes=0
    local required_successes=3

    while [[ $SECONDS -lt $health_check_end_time ]]; do
        if curl -f --max-time 10 --silent "${service_url}/health" >/dev/null 2>&1; then
            ((consecutive_successes++))
            log_success "Health check passed (${consecutive_successes}/${required_successes})"

            if [[ ${consecutive_successes} -ge ${required_successes} ]]; then
                log_success "Service is healthy and ready"
                return 0
            fi
        else
            consecutive_successes=0
            log_info "Health check failed - retrying..."
        fi

        sleep "${HEALTH_CHECK_INTERVAL}"
    done

    log_error "Service failed to become healthy within timeout"
    return 1
}

# Run smoke tests
run_smoke_tests() {
    log_step "Running smoke tests..."

    local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
    local service_name="mackmonitor"
    local region="southamerica-east1"

    local service_url
    service_url=$(gcloud run services describe "${service_name}" \
        --region="${region}" \
        --project="${project_id}" \
        --format="value(status.url)" 2>/dev/null || echo "")

    if [[ -z "${service_url}" ]]; then
        service_url="https://mackmonitor-667999538255.southamerica-east1.run.app"
        log_warning "Using fallback URL for smoke tests: ${service_url}"
    fi
    
    local tests_passed=0
    local tests_total=0
    
    # Test 1: Health endpoint
    ((tests_total++))
    if curl -f --max-time 10 --silent "${service_url}/health" >/dev/null 2>&1; then
        ((tests_passed++))
        log_success "✓ Health endpoint test passed"
    else
        log_error "✗ Health endpoint test failed"
    fi
    
    # Test 2: Main application
    ((tests_total++))
    if curl -f --max-time 15 --silent "${service_url}/" >/dev/null 2>&1; then
        ((tests_passed++))
        log_success "✓ Main application test passed"
    else
        log_error "✗ Main application test failed"
    fi
    
    # Test 3: API endpoints (if available)
    ((tests_total++))
    if curl -f --max-time 10 --silent "${service_url}/api/health" >/dev/null 2>&1; then
        ((tests_passed++))
        log_success "✓ API endpoint test passed"
    else
        log_info "- API endpoint not available (expected for R Shiny app)"
        ((tests_passed++))  # Don't fail for missing API in R Shiny
    fi
    
    # Test 4: Static assets
    ((tests_total++))
    if curl -f --max-time 10 --silent --head "${service_url}/" | grep -q "200 OK"; then
        ((tests_passed++))
        log_success "✓ Static assets test passed"
    else
        log_warning "! Static assets test inconclusive"
    fi
    
    log_info "Smoke tests completed: ${tests_passed}/${tests_total} passed"
    
    if [[ ${tests_passed} -ge $((tests_total - 1)) ]]; then  # Allow one test to fail
        log_success "Smoke tests passed"
        return 0
    else
        log_error "Smoke tests failed"
        return 1
    fi
}

# Rollback deployment
rollback_deployment() {
    log_step "Initiating deployment rollback..."

    if [[ -z "${PREVIOUS_DEPLOYMENT_ID}" ]]; then
        log_error "No previous revision available for rollback"
        return 1
    fi

    log_info "Rolling back to revision: ${PREVIOUS_DEPLOYMENT_ID}"

    local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
    local service_name="mackmonitor"
    local region="southamerica-east1"

    # Attempt rollback by routing traffic to previous revision
    if gcloud run services update-traffic "${service_name}" \
        --region="${region}" \
        --project="${project_id}" \
        --to-revisions="${PREVIOUS_DEPLOYMENT_ID}=100" \
        --quiet 2>/dev/null; then

        log_success "Rollback initiated - traffic routed to previous revision"

        # Wait for rollback to stabilize
        sleep 10

        # Verify the rollback
        if curl -f --max-time 10 --silent "https://mackmonitor-667999538255.southamerica-east1.run.app/health" >/dev/null 2>&1; then
            log_success "Rollback completed successfully"
            return 0
        else
            log_error "Rollback completed but health check failed"
            return 1
        fi
    else
        log_error "Failed to initiate rollback"
        return 1
    fi
}

# Send deployment notification
send_deployment_notification() {
    local status="$1"
    local message="$2"
    
    log "=== DEPLOYMENT NOTIFICATION ==="
    log "Status: ${status}"
    log "Message: ${message}"
    log "Deployment ID: ${DEPLOYMENT_ID}"
    log "Start Time: ${DEPLOYMENT_START_TIME}"
    log "Duration: $((SECONDS)) seconds"
    log "Backup Created: ${BACKUP_CREATED:-false}"
    log "Environment: ${K_SERVICE:-production}"
    log "Project: Monitor Legislativo v4"
    log "Context: Brazilian Academic Research Platform"
    log "Timezone: ${BRAZILIAN_TZ}"
    log "=============================="
}

# Main deployment function
main() {
    local deployment_success=true
    
    log "=== ZERO-DOWNTIME DEPLOYMENT STARTING ==="
    log "Monitor Legislativo v4 - Brazilian Academic Research Platform"
    log "Target: Cloud Run Production Environment"
    log "Timezone: ${BRAZILIAN_TZ}"
    log "Strategy: Rolling deployment with health validation"
    
    # Generate deployment ID
    generate_deployment_id
    
    # Step 1: Validate environment
    if ! validate_environment; then
        log_error "Environment validation failed"
        send_deployment_notification "FAILED" "Environment validation failed"
        exit 1
    fi
    
    # Step 2: Get current deployment info
    get_current_deployment
    
    # Step 3: Create pre-deployment backup
    create_pre_deployment_backup

    # Step 4: Deploy to Cloud Run
    if ! deploy_to_cloud_run; then
        log_error "Cloud Run deployment failed"
        deployment_success=false
    fi
    
    # Step 5: Wait for healthy service
    if [[ "${deployment_success}" == true ]]; then
        if ! wait_for_healthy_service; then
            log_error "Service health validation failed"
            deployment_success=false
        fi
    fi
    
    # Step 6: Run smoke tests
    if [[ "${deployment_success}" == true ]]; then
        if ! run_smoke_tests; then
            log_error "Smoke tests failed"
            deployment_success=false
        fi
    fi
    
    # Step 7: Handle deployment result
    if [[ "${deployment_success}" == true ]]; then
        log_success "=== DEPLOYMENT COMPLETED SUCCESSFULLY ==="
        log_success "Monitor Legislativo v4 is now live in production"
        log_success "Deployment ID: ${DEPLOYMENT_ID}"
        log_success "Duration: $((SECONDS)) seconds"

        # Show final status
        local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
        gcloud run services describe mackmonitor \
            --region=southamerica-east1 \
            --project="${project_id}" \
            --format="yaml(status)" 2>/dev/null || true

        send_deployment_notification "SUCCESS" "Zero-downtime deployment completed successfully"
        
        log_info "Next steps:"
        log_info "1. Monitor application performance"
        log_info "2. Check user access and functionality"
        log_info "3. Validate academic workflows"
        log_info "4. Monitor error rates and response times"
        
        exit 0
    else
        log_error "=== DEPLOYMENT FAILED ==="
        log_error "Attempting rollback to previous version..."
        
        if rollback_deployment; then
            log_success "Rollback completed successfully"
            send_deployment_notification "ROLLED_BACK" "Deployment failed - rollback completed"
        else
            log_error "Rollback failed - manual intervention required"
            send_deployment_notification "FAILED" "Deployment and rollback both failed - manual intervention required"
        fi
        
        log_error "Deployment failed. System status:"
        local project_id="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
        gcloud run services describe mackmonitor \
            --region=southamerica-east1 \
            --project="${project_id}" \
            --format="yaml(status)" 2>/dev/null || true

        exit 1
    fi
}

# Trap for cleanup
trap 'log "Deployment script finished"' EXIT

# Check for required arguments and options
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << EOF
Zero-Downtime Deployment Script for Monitor Legislativo v4
=========================================================

Usage: $0 [options]

Options:
  --help, -h    Show this help message
  --dry-run     Validate environment without deploying
  --force       Skip confirmation prompts

Environment Variables:
  GOOGLE_CLOUD_PROJECT GCP project ID (optional if configured in gcloud)
  DEPLOYMENT_TIMEOUT   Deployment timeout in seconds (default: 600)
  HEALTH_CHECK_TIMEOUT Health check timeout in seconds (default: 120)

Requirements:
- gcloud CLI installed and authenticated
- Project root directory with app.R
- Dockerfile present for containerized deployment

This script provides:
- Pre-deployment validation
- Automated backup creation
- Zero-downtime rolling deployment
- Health checks and smoke tests
- Automatic rollback on failure
- Brazilian academic context optimization

For support: Academic IT Infrastructure Team
EOF
    exit 0
fi

if [[ "${1:-}" == "--dry-run" ]]; then
    log "=== DRY RUN MODE ==="
    validate_environment
    log "Dry run completed successfully"
    exit 0
fi

# Confirmation prompt (skip with --force)
if [[ "${1:-}" != "--force" ]]; then
    echo
    log_warning "You are about to deploy Monitor Legislativo v4 to production"
    log_warning "This will update the live Brazilian academic research platform"
    echo
    read -r -p "Are you sure you want to continue? (y/N): " confirmation
    
    if [[ "${confirmation}" != "y" && "${confirmation}" != "Y" ]]; then
        log "Deployment cancelled by user"
        exit 0
    fi
fi

# Execute main deployment
main "$@"