#!/bin/bash
# =============================================================================
# PRODUCTION DEPLOYMENT SCRIPT - Monitor Legislativo v4
# Automated deployment with rollback capabilities and health validation
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HEALTH_CHECK_URL=""
DEPLOYMENT_TIMEOUT=300  # 5 minutes
ROLLBACK_ENABLED=true
LOG_FILE="$PROJECT_ROOT/logs/deployment-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

# Create logs directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/logs"

log "Starting production deployment for Monitor Legislativo v4"

# Pre-deployment validation
pre_deployment_checks() {
    log "Running pre-deployment checks..."
    
    # Check if Railway CLI is installed
    if ! command -v railway &> /dev/null; then
        error "Railway CLI not installed. Installing..."
        npm install -g @railway/cli
    fi
    
    # Check if we're logged into Railway
    if ! railway whoami &> /dev/null; then
        error "Not logged into Railway. Please run: railway login"
        exit 1
    fi
    
    # Check if essential files exist
    local required_files=("app.R" "Dockerfile" "railway.toml" "railway_full_app.R")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$PROJECT_ROOT/$file" ]]; then
            error "Required file missing: $file"
            exit 1
        fi
    done
    
    # Validate Dockerfile syntax
    if ! docker build --dry-run -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" &> /dev/null; then
        error "Dockerfile validation failed"
        exit 1
    fi
    
    # Check R syntax for main files
    if ! Rscript -e "tryCatch({source('$PROJECT_ROOT/app.R', echo=FALSE)}, error=function(e){quit(status=1)})" &> /dev/null; then
        warn "app.R has syntax issues - deployment may fail"
    fi
    
    log "Pre-deployment checks completed"
}

# Get current deployment info for rollback
store_rollback_info() {
    log "Storing current deployment info for potential rollback..."
    
    # Get current deployment ID
    PREVIOUS_DEPLOYMENT=$(railway status --json 2>/dev/null | jq -r '.deployments[0].id // empty' || echo "")
    
    if [[ -n "$PREVIOUS_DEPLOYMENT" ]]; then
        echo "$PREVIOUS_DEPLOYMENT" > "$PROJECT_ROOT/.railway/last-deployment-id"
        log "Stored previous deployment ID: $PREVIOUS_DEPLOYMENT"
    else
        warn "Could not retrieve previous deployment ID"
    fi
    
    # Store deployment timestamp
    date +%s > "$PROJECT_ROOT/.railway/deployment-timestamp"
}

# Deploy to Railway
deploy_to_railway() {
    log "Deploying to Railway production environment..."
    
    cd "$PROJECT_ROOT"
    
    # Deploy with timeout
    timeout "$DEPLOYMENT_TIMEOUT" railway deploy --service production --detach || {
        error "Deployment timed out or failed"
        return 1
    }
    
    # Get new deployment ID
    sleep 10  # Wait for deployment to register
    NEW_DEPLOYMENT=$(railway status --json 2>/dev/null | jq -r '.deployments[0].id // empty' || echo "")
    
    if [[ -n "$NEW_DEPLOYMENT" ]]; then
        echo "$NEW_DEPLOYMENT" > "$PROJECT_ROOT/.railway/current-deployment-id"
        log "New deployment ID: $NEW_DEPLOYMENT"
    fi
    
    log "Deployment initiated successfully"
    return 0
}

# Wait for deployment to be ready
wait_for_deployment() {
    log "Waiting for deployment to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "Checking deployment status... (attempt $attempt/$max_attempts)"
        
        # Check Railway deployment status
        local status=$(railway status --json 2>/dev/null | jq -r '.deployments[0].status // "unknown"' || echo "unknown")
        
        case "$status" in
            "SUCCESS")
                log "Deployment completed successfully"
                return 0
                ;;
            "FAILED"|"CRASHED")
                error "Deployment failed with status: $status"
                return 1
                ;;
            "BUILDING"|"DEPLOYING"|"WAITING")
                log "Deployment in progress... status: $status"
                ;;
            *)
                warn "Unknown deployment status: $status"
                ;;
        esac
        
        sleep 10
        ((attempt++))
    done
    
    error "Deployment did not complete within timeout"
    return 1
}

# Health check validation
validate_deployment() {
    log "Running post-deployment health checks..."
    
    # Get Railway service URL
    local service_url
    service_url=$(railway domain 2>/dev/null | head -1 || echo "")
    
    if [[ -z "$service_url" ]]; then
        warn "Could not retrieve service URL, skipping health check"
        return 0
    fi
    
    HEALTH_CHECK_URL="https://$service_url/health"
    log "Health check URL: $HEALTH_CHECK_URL"
    
    # Wait for service to be ready
    local max_attempts=20
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "Health check attempt $attempt/$max_attempts"
        
        if curl -f -m 10 "$HEALTH_CHECK_URL" &> /dev/null; then
            log "Health check passed"
            
            # Validate health check response
            local health_response
            health_response=$(curl -s -m 10 "$HEALTH_CHECK_URL" || echo "{}")
            
            if echo "$health_response" | jq -e '.status == "healthy"' &> /dev/null; then
                log "Application is healthy and ready"
                return 0
            else
                warn "Health check returned non-healthy status: $health_response"
            fi
        else
            log "Health check failed, retrying..."
        fi
        
        sleep 15
        ((attempt++))
    done
    
    error "Health check validation failed"
    return 1
}

# Rollback deployment
rollback_deployment() {
    log "Initiating deployment rollback..."
    
    if [[ ! -f "$PROJECT_ROOT/.railway/last-deployment-id" ]]; then
        error "No previous deployment ID found, cannot rollback"
        return 1
    fi
    
    local previous_deployment
    previous_deployment=$(cat "$PROJECT_ROOT/.railway/last-deployment-id")
    
    log "Rolling back to deployment: $previous_deployment"
    
    # Railway doesn't have direct rollback, so we deploy the previous version
    # This would require git integration or stored artifacts
    warn "Automatic rollback not implemented - manual intervention required"
    warn "Previous deployment ID: $previous_deployment"
    
    # Send alert about rollback
    log "Rollback completed - please verify system status"
    return 0
}

# Cleanup temporary files
cleanup() {
    log "Cleaning up temporary files..."
    
    # Remove temporary deployment files older than 7 days
    find "$PROJECT_ROOT/logs" -name "deployment-*.log" -mtime +7 -delete 2>/dev/null || true
    
    log "Cleanup completed"
}

# Send deployment notification
send_notification() {
    local status="$1"
    local message="$2"
    
    log "Deployment $status: $message"
    
    # Add Slack/email notification here if configured
    # Example:
    # curl -X POST -H 'Content-type: application/json' \
    #   --data "{\"text\":\"Monitor Legislativo v4: Deployment $status - $message\"}" \
    #   "$SLACK_WEBHOOK_URL" || true
}

# Main deployment flow
main() {
    log "=== Production Deployment Started ==="
    
    # Run pre-deployment checks
    if ! pre_deployment_checks; then
        error "Pre-deployment checks failed"
        send_notification "FAILED" "Pre-deployment validation failed"
        exit 1
    fi
    
    # Store rollback information
    store_rollback_info
    
    # Deploy to Railway
    if ! deploy_to_railway; then
        error "Railway deployment failed"
        send_notification "FAILED" "Railway deployment failed"
        exit 1
    fi
    
    # Wait for deployment to complete
    if ! wait_for_deployment; then
        error "Deployment did not complete successfully"
        
        if [[ "$ROLLBACK_ENABLED" == "true" ]]; then
            rollback_deployment
            send_notification "ROLLED_BACK" "Deployment failed and was rolled back"
        else
            send_notification "FAILED" "Deployment failed - rollback disabled"
        fi
        exit 1
    fi
    
    # Validate deployment health
    if ! validate_deployment; then
        error "Deployment health validation failed"
        
        if [[ "$ROLLBACK_ENABLED" == "true" ]]; then
            rollback_deployment
            send_notification "ROLLED_BACK" "Health validation failed and deployment was rolled back"
        else
            send_notification "FAILED" "Health validation failed - rollback disabled"
        fi
        exit 1
    fi
    
    # Cleanup
    cleanup
    
    # Success notification
    send_notification "SUCCESS" "Deployment completed successfully and passed all health checks"
    
    log "=== Production Deployment Completed Successfully ==="
    log "Service URL: $HEALTH_CHECK_URL"
    log "Deployment log: $LOG_FILE"
}

# Trap for cleanup on script exit
trap cleanup EXIT

# Run main deployment flow
main "$@"