#!/bin/bash
# Health Check and Failover Management Script
# Monitor Legislativo v4 - Production Health Monitoring
# Phase 4 Week 13: Automated health checks and failover

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.loadbalancer.yml"
LOG_FILE="/var/log/monitor-legislativo/health-checks.log"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"
MAX_FAILURES=3
CHECK_INTERVAL=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] INFO${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR${NC} $1" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG${NC} $1" | tee -a "$LOG_FILE"
    fi
}

# Service definitions with health check configurations
declare -A SERVICES=(
    ["api1"]="http://localhost:8000/health"
    ["api2"]="http://localhost:8000/health"
    ["api3"]="http://localhost:8000/health"
    ["shiny1"]="http://localhost:3838"
    ["shiny2"]="http://localhost:3838"
    ["ws1"]="http://localhost:8001/health"
    ["ws2"]="http://localhost:8001/health"
    ["loadbalancer"]="http://localhost:9090/lb-health"
    ["postgres"]="postgresql://localhost:5432"
    ["postgres-replica"]="postgresql://localhost:5433"
    ["redis1"]="redis://localhost:6379"
    ["redis2"]="redis://localhost:6380"
)

declare -A SERVICE_PORTS=(
    ["api1"]="8000"
    ["api2"]="8000"
    ["api3"]="8000"
    ["shiny1"]="3838"
    ["shiny2"]="3838"
    ["ws1"]="8001"
    ["ws2"]="8001"
    ["loadbalancer"]="80"
    ["postgres"]="5432"
    ["postgres-replica"]="5433"
    ["redis1"]="6379"
    ["redis2"]="6380"
)

declare -A FAILURE_COUNTS=()

# Initialize failure counts
for service in "${!SERVICES[@]}"; do
    FAILURE_COUNTS["$service"]=0
done

# Setup logging directory
setup_logging() {
    local log_dir="$(dirname "$LOG_FILE")"
    if [[ ! -d "$log_dir" ]]; then
        sudo mkdir -p "$log_dir"
        sudo chown "$(whoami):$(whoami)" "$log_dir"
    fi
}

# Check if a service container is running
is_container_running() {
    local service="$1"
    local container_name="monitor-legislativo-$service"
    
    if docker ps --filter "name=$container_name" --filter "status=running" | grep -q "$container_name"; then
        return 0
    else
        return 1
    fi
}

# HTTP health check
check_http_health() {
    local service="$1"
    local url="$2"
    local timeout="${3:-10}"
    
    log_debug "Checking HTTP health for $service at $url"
    
    if curl -sf --max-time "$timeout" "$url" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# PostgreSQL health check
check_postgres_health() {
    local service="$1"
    local container_name="monitor-legislativo-$service"
    
    log_debug "Checking PostgreSQL health for $service"
    
    if docker exec "$container_name" pg_isready -U "${DB_USER:-postgres}" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Redis health check
check_redis_health() {
    local service="$1"
    local container_name="monitor-legislativo-$service"
    
    log_debug "Checking Redis health for $service"
    
    if docker exec "$container_name" redis-cli ping | grep -q "PONG"; then
        return 0
    else
        return 1
    fi
}

# Comprehensive service health check
check_service_health() {
    local service="$1"
    local url="${SERVICES[$service]}"
    
    # First check if container is running
    if ! is_container_running "$service"; then
        log_error "Container for service $service is not running"
        return 1
    fi
    
    # Service-specific health checks
    case "$service" in
        postgres|postgres-replica)
            check_postgres_health "$service"
            ;;
        redis1|redis2)
            check_redis_health "$service"
            ;;
        *)
            check_http_health "$service" "$url"
            ;;
    esac
}

# Send alert notification
send_alert() {
    local service="$1"
    local action="$2"
    local message="$3"
    
    local alert_data="{
        \"service\": \"$service\",
        \"action\": \"$action\",
        \"message\": \"$message\",
        \"timestamp\": \"$(date -Iseconds)\",
        \"hostname\": \"$(hostname)\"
    }"
    
    log_warn "ALERT: $action for service $service - $message"
    
    # Send webhook notification if configured
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        curl -X POST \
             -H "Content-Type: application/json" \
             -d "$alert_data" \
             "$ALERT_WEBHOOK" \
             --max-time 10 \
             --silent \
             --fail > /dev/null 2>&1 || {
            log_error "Failed to send alert webhook for service $service"
        }
    fi
    
    # Log to system journal if available
    if command -v systemd-cat > /dev/null 2>&1; then
        echo "$alert_data" | systemd-cat -t monitor-legislativo-health -p warning
    fi
}

# Restart a failed service
restart_service() {
    local service="$1"
    
    log_warn "Restarting service: $service"
    
    if docker-compose -f "$COMPOSE_FILE" restart "$service"; then
        log_info "Successfully restarted service: $service"
        send_alert "$service" "restart_success" "Service $service restarted successfully"
        
        # Reset failure count
        FAILURE_COUNTS["$service"]=0
        
        # Wait for service to stabilize
        sleep 30
        
        # Verify restart was successful
        if check_service_health "$service"; then
            log_info "Service $service is healthy after restart"
            return 0
        else
            log_error "Service $service is still unhealthy after restart"
            return 1
        fi
    else
        log_error "Failed to restart service: $service"
        send_alert "$service" "restart_failed" "Failed to restart service $service"
        return 1
    fi
}

# Scale up a service (add backup instance)
scale_up_service() {
    local service="$1"
    
    log_warn "Scaling up service: $service"
    
    case "$service" in
        api1|api2)
            # Start backup API instance
            if docker-compose -f "$COMPOSE_FILE" up -d api3; then
                log_info "Backup API instance (api3) started"
                send_alert "$service" "scale_up" "Started backup API instance due to $service failure"
            fi
            ;;
        shiny1|shiny2)
            log_warn "R Shiny scaling not implemented - manual intervention required"
            send_alert "$service" "scale_up_needed" "R Shiny service $service failed - manual scaling required"
            ;;
        *)
            log_warn "Scaling not configured for service: $service"
            ;;
    esac
}

# Handle service failure
handle_service_failure() {
    local service="$1"
    local failure_count="${FAILURE_COUNTS[$service]}"
    
    log_error "Service $service health check failed (failure $failure_count/$MAX_FAILURES)"
    
    # Increment failure count
    FAILURE_COUNTS["$service"]=$((failure_count + 1))
    
    if [[ "${FAILURE_COUNTS[$service]}" -ge "$MAX_FAILURES" ]]; then
        log_error "Service $service has exceeded maximum failures ($MAX_FAILURES)"
        send_alert "$service" "service_failed" "Service $service failed $MAX_FAILURES consecutive health checks"
        
        # Attempt restart
        if restart_service "$service"; then
            log_info "Service $service recovered after restart"
        else
            log_error "Service $service restart failed - attempting scale up"
            scale_up_service "$service"
        fi
    else
        send_alert "$service" "health_check_failed" "Service $service health check failed ($failure_count/$MAX_FAILURES)"
    fi
}

# Handle service recovery
handle_service_recovery() {
    local service="$1"
    local previous_failures="${FAILURE_COUNTS[$service]}"
    
    if [[ "$previous_failures" -gt 0 ]]; then
        log_info "Service $service recovered (was failing for $previous_failures checks)"
        send_alert "$service" "service_recovered" "Service $service is now healthy after $previous_failures failures"
        
        # Reset failure count
        FAILURE_COUNTS["$service"]=0
    fi
}

# Check all services
check_all_services() {
    log_debug "Starting health check cycle"
    
    local total_services=0
    local healthy_services=0
    local failed_services=()
    
    for service in "${!SERVICES[@]}"; do
        total_services=$((total_services + 1))
        
        if check_service_health "$service"; then
            log_debug "Service $service is healthy"
            healthy_services=$((healthy_services + 1))
            handle_service_recovery "$service"
        else
            log_error "Service $service is unhealthy"
            failed_services+=("$service")
            handle_service_failure "$service"
        fi
    done
    
    log_info "Health check complete: $healthy_services/$total_services services healthy"
    
    if [[ "${#failed_services[@]}" -gt 0 ]]; then
        log_warn "Failed services: ${failed_services[*]}"
    fi
}

# Generate health report
generate_health_report() {
    local report_file="$PROJECT_ROOT/logs/health-report-$(date +%Y%m%d-%H%M%S).json"
    
    local report="{
        \"timestamp\": \"$(date -Iseconds)\",
        \"services\": {"
    
    local first=true
    for service in "${!SERVICES[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            report+=","
        fi
        
        local status="unknown"
        local last_check="null"
        
        if check_service_health "$service"; then
            status="healthy"
        else
            status="unhealthy"
        fi
        
        report+="
            \"$service\": {
                \"status\": \"$status\",
                \"failure_count\": ${FAILURE_COUNTS[$service]},
                \"last_check\": \"$(date -Iseconds)\",
                \"endpoint\": \"${SERVICES[$service]}\",
                \"port\": \"${SERVICE_PORTS[$service]}\"
            }"
    done
    
    report+="
        }
    }"
    
    echo "$report" > "$report_file"
    log_info "Health report generated: $report_file"
}

# Continuous monitoring mode
continuous_monitoring() {
    log_info "Starting continuous health monitoring (interval: ${CHECK_INTERVAL}s)"
    
    trap 'log_info "Health monitoring stopped"; exit 0' SIGTERM SIGINT
    
    while true; do
        check_all_services
        
        # Generate report every hour
        if [[ $(($(date +%M) % 60)) -eq 0 ]]; then
            generate_health_report
        fi
        
        sleep "$CHECK_INTERVAL"
    done
}

# Interactive mode for manual checks
interactive_mode() {
    while true; do
        echo ""
        echo "Monitor Legislativo v4 - Health Check Menu"
        echo "1. Check all services"
        echo "2. Check specific service"
        echo "3. Restart service"
        echo "4. Generate health report"
        echo "5. View service status"
        echo "6. Start continuous monitoring"
        echo "7. Exit"
        echo ""
        read -p "Select option (1-7): " choice
        
        case "$choice" in
            1)
                check_all_services
                ;;
            2)
                echo "Available services: ${!SERVICES[*]}"
                read -p "Enter service name: " service
                if [[ -n "${SERVICES[$service]:-}" ]]; then
                    if check_service_health "$service"; then
                        echo "Service $service is healthy"
                    else
                        echo "Service $service is unhealthy"
                    fi
                else
                    echo "Invalid service name"
                fi
                ;;
            3)
                echo "Available services: ${!SERVICES[*]}"
                read -p "Enter service name to restart: " service
                if [[ -n "${SERVICES[$service]:-}" ]]; then
                    restart_service "$service"
                else
                    echo "Invalid service name"
                fi
                ;;
            4)
                generate_health_report
                ;;
            5)
                docker-compose -f "$COMPOSE_FILE" ps
                ;;
            6)
                continuous_monitoring
                ;;
            7)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
    done
}

# Help function
show_help() {
    cat << EOF
Health Check and Failover Management Script for Monitor Legislativo v4

Usage: $0 [OPTIONS] [COMMAND]

Commands:
    check              Run health check once for all services
    check SERVICE      Run health check for specific service
    monitor            Start continuous monitoring
    restart SERVICE    Restart a specific service
    report             Generate health report
    interactive        Start interactive mode (default)

Options:
    -h, --help         Show this help message
    -d, --debug        Enable debug logging
    -i, --interval N   Set check interval in seconds (default: 30)
    -f, --failures N   Set max failures before restart (default: 3)
    --webhook URL      Set alert webhook URL

Environment Variables:
    ALERT_WEBHOOK      Webhook URL for sending alerts
    DEBUG              Enable debug logging (true/false)
    DB_USER            Database username for health checks

Examples:
    $0                          # Start interactive mode
    $0 check                    # Check all services once
    $0 check api1               # Check specific service
    $0 monitor                  # Start continuous monitoring
    $0 restart api2             # Restart specific service
    $0 --interval 60 monitor    # Monitor with 60s interval

EOF
}

# Main function
main() {
    local command="${1:-interactive}"
    local service="${2:-}"
    
    # Parse command line options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--debug)
                export DEBUG=true
                shift
                ;;
            -i|--interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            -f|--failures)
                MAX_FAILURES="$2"
                shift 2
                ;;
            --webhook)
                ALERT_WEBHOOK="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$command" ]] || [[ "$command" == "interactive" ]]; then
                    command="$1"
                elif [[ -z "$service" ]]; then
                    service="$1"
                fi
                shift
                ;;
        esac
    done
    
    setup_logging
    
    log_info "Starting health check system for Monitor Legislativo v4"
    log_info "Max failures: $MAX_FAILURES, Check interval: ${CHECK_INTERVAL}s"
    
    case "$command" in
        check)
            if [[ -n "$service" ]]; then
                if [[ -n "${SERVICES[$service]:-}" ]]; then
                    if check_service_health "$service"; then
                        log_info "Service $service is healthy"
                        exit 0
                    else
                        log_error "Service $service is unhealthy"
                        exit 1
                    fi
                else
                    log_error "Invalid service name: $service"
                    exit 1
                fi
            else
                check_all_services
            fi
            ;;
        monitor)
            continuous_monitoring
            ;;
        restart)
            if [[ -n "$service" ]] && [[ -n "${SERVICES[$service]:-}" ]]; then
                restart_service "$service"
            else
                log_error "Service name required for restart command"
                exit 1
            fi
            ;;
        report)
            generate_health_report
            ;;
        interactive)
            interactive_mode
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Script entry point
main "$@"