#\!/bin/bash
#
# PRODUCTION DEPLOYMENT SCRIPT
# Monitor Legislativo v4 - Brazilian Government Transport Monitoring System
#

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VERSION=${1:-"latest"}

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

main() {
    log "🚀 Starting production deployment of Monitor Legislativo v4"
    log "Version: $VERSION"
    
    # Load production environment
    if [[ -f ".env.production" ]]; then
        set -a
        source .env.production
        set +a
        success "Environment loaded"
    else
        error "Production environment file not found"
        exit 1
    fi
    
    # Start services
    log "🔄 Starting services..."
    docker-compose --env-file .env.production up -d
    
    # Health check
    log "🏥 Running health check..."
    sleep 10
    
    if docker-compose ps  < /dev/null |  grep -q "Up"; then
        success "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!"
        log "Services are running"
        docker-compose ps
    else
        error "Deployment failed - check logs"
        exit 1
    fi
}

main "$@"
