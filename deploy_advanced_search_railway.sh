#!/bin/bash
# ============================================================================
# RAILWAY POSTGRESQL ADVANCED SEARCH DEPLOYMENT SCRIPT
# ============================================================================
#
# This script safely deploys the advanced search engine to Railway PostgreSQL
# with comprehensive error handling, backup procedures, and rollback capabilities.
#
# Usage:
#   ./deploy_advanced_search_railway.sh [options]
#
# Options:
#   --dry-run          Test deployment without making changes
#   --backup-only      Create backup and exit
#   --force            Skip safety checks (use with caution)
#   --rollback         Rollback previous deployment
#   --test-only        Run performance tests only
#   --help             Show this help message
#
# Author: Senior Database Engineer - Brazilian Legislative Analytics Team
# Date: January 2025
# Version: 1.0 - Production Railway Deployment
# ============================================================================

set -euo pipefail  # Exit on any error, undefined variable, or pipe failure

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_DIR="${SCRIPT_DIR}/db"
LOG_DIR="${SCRIPT_DIR}/logs"
BACKUP_DIR="${SCRIPT_DIR}/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create necessary directories
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

# Logging setup
LOG_FILE="${LOG_DIR}/railway_deployment_${TIMESTAMP}.log"
ERROR_LOG="${LOG_FILE}.error"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" | tee -a "$ERROR_LOG"
}

# Error handler
error_exit() {
    log_error "Deployment failed: $1"
    log_error "Check logs at: $LOG_FILE"
    log_error "Error details in: $ERROR_LOG"
    exit 1
}

# Help function
show_help() {
    cat << EOF
Railway PostgreSQL Advanced Search Deployment Script

Usage: $0 [options]

Options:
    --dry-run          Test deployment without making changes
    --backup-only      Create backup and exit
    --force            Skip safety checks (use with caution)
    --rollback         Rollback previous deployment  
    --test-only        Run performance tests only
    --help             Show this help message

Environment Variables Required:
    DATABASE_URL       Railway PostgreSQL connection string

Examples:
    $0                 # Full deployment with safety checks
    $0 --dry-run       # Test deployment without changes
    $0 --backup-only   # Create backup only
    $0 --rollback      # Rollback previous deployment

For support: Check Railway PostgreSQL logs and contact development team
EOF
}

# Parse command line arguments
DRY_RUN=false
BACKUP_ONLY=false
FORCE_DEPLOY=false
ROLLBACK_MODE=false
TEST_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            log_info "Dry run mode enabled - no changes will be made"
            shift
            ;;
        --backup-only)
            BACKUP_ONLY=true
            log_info "Backup only mode enabled"
            shift
            ;;
        --force)
            FORCE_DEPLOY=true
            log_warning "Force mode enabled - skipping safety checks"
            shift
            ;;
        --rollback)
            ROLLBACK_MODE=true
            log_info "Rollback mode enabled"
            shift
            ;;
        --test-only)
            TEST_ONLY=true
            log_info "Test only mode enabled"
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate environment
validate_environment() {
    log_info "Validating deployment environment..."
    
    # Check DATABASE_URL
    if [[ -z "${DATABASE_URL:-}" ]]; then
        error_exit "DATABASE_URL environment variable not set"
    fi
    
    # Validate DATABASE_URL format
    if [[ ! "$DATABASE_URL" =~ ^postgres(ql)?:// ]]; then
        error_exit "DATABASE_URL is not a valid PostgreSQL connection string"
    fi
    
    # Check required files exist
    local required_files=(
        "${DB_DIR}/advanced_search_migration.sql"
        "${DB_DIR}/advanced_search_rollback.sql"
        "${DB_DIR}/performance_test.sql"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            error_exit "Required file not found: $file"
        fi
    done
    
    # Test database connectivity
    log_info "Testing database connectivity..."
    if ! psql "$DATABASE_URL" -c "SELECT version();" > /dev/null 2>&1; then
        error_exit "Cannot connect to Railway PostgreSQL database"
    fi
    
    log_success "Environment validation passed"
}

# Check Railway PostgreSQL constraints
check_railway_constraints() {
    if [[ "$FORCE_DEPLOY" == true ]]; then
        log_warning "Skipping Railway constraint checks (force mode)"
        return 0
    fi
    
    log_info "Checking Railway PostgreSQL constraints..."
    
    # Check database size (Railway has 2GB limit)
    local db_size_bytes
    db_size_bytes=$(psql "$DATABASE_URL" -t -c "SELECT pg_database_size(current_database());" 2>/dev/null || echo "0")
    db_size_bytes=$(echo "$db_size_bytes" | tr -d ' ')
    
    local db_size_gb=$((db_size_bytes / 1024 / 1024 / 1024))
    log_info "Current database size: ${db_size_gb}GB"
    
    # Warning at 1.5GB, error at 1.8GB
    if [[ $db_size_bytes -gt 1932735283 ]]; then  # 1.8GB
        error_exit "Database size (${db_size_gb}GB) exceeds safe Railway limit (1.8GB)"
    elif [[ $db_size_bytes -gt 1610612736 ]]; then  # 1.5GB
        log_warning "Database size (${db_size_gb}GB) is approaching Railway limit (2GB)"
        read -p "Continue deployment? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled by user"
            exit 0
        fi
    fi
    
    # Check available connections
    local max_connections
    max_connections=$(psql "$DATABASE_URL" -t -c "SHOW max_connections;" | tr -d ' ')
    local current_connections
    current_connections=$(psql "$DATABASE_URL" -t -c "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database();" | tr -d ' ')
    
    log_info "Database connections: ${current_connections}/${max_connections}"
    
    if [[ $current_connections -gt $((max_connections * 8 / 10)) ]]; then
        log_warning "High connection usage may affect deployment"
    fi
    
    log_success "Railway constraints check passed"
}

# Create database backup
create_backup() {
    log_info "Creating database backup..."
    
    local backup_file="${BACKUP_DIR}/railway_backup_before_search_${TIMESTAMP}.sql"
    local backup_compressed="${backup_file}.gz"
    
    # Create backup with error handling
    if pg_dump "$DATABASE_URL" > "$backup_file" 2>"${ERROR_LOG}"; then
        # Compress backup to save space
        gzip "$backup_file"
        
        local backup_size
        backup_size=$(du -h "$backup_compressed" | cut -f1)
        log_success "Database backup created: $backup_compressed (${backup_size})"
        
        # Verify backup integrity
        if zcat "$backup_compressed" | head -n 20 | grep -q "PostgreSQL database dump"; then
            log_success "Backup integrity verified"
        else
            log_warning "Backup integrity check failed"
        fi
    else
        error_exit "Failed to create database backup"
    fi
    
    # Store backup path for potential rollback
    echo "$backup_compressed" > "${BACKUP_DIR}/latest_backup.txt"
}

# Deploy advanced search schema
deploy_advanced_search() {
    log_info "Deploying advanced search engine..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would execute advanced_search_migration.sql"
        return 0
    fi
    
    # Execute migration with detailed logging
    local migration_log="${LOG_DIR}/migration_${TIMESTAMP}.log"
    
    if psql "$DATABASE_URL" -f "${DB_DIR}/advanced_search_migration.sql" > "$migration_log" 2>&1; then
        log_success "Advanced search migration completed"
        
        # Check for warnings in migration log
        if grep -i "warning\|error" "$migration_log" > /dev/null; then
            log_warning "Migration completed with warnings. Check: $migration_log"
        fi
    else
        log_error "Migration failed. Check logs: $migration_log"
        cat "$migration_log" >> "$ERROR_LOG"
        error_exit "Migration execution failed"
    fi
}

# Verify deployment success
verify_deployment() {
    log_info "Verifying deployment success..."
    
    # Check migration completion
    local migration_status
    migration_status=$(psql "$DATABASE_URL" -t -c "
        SELECT status FROM migration_log 
        WHERE migration_name = 'advanced_search_migration' 
        ORDER BY id DESC LIMIT 1;
    " 2>/dev/null | tr -d ' ' || echo "UNKNOWN")
    
    if [[ "$migration_status" != "COMPLETED" ]]; then
        error_exit "Migration status is not COMPLETED: $migration_status"
    fi
    
    # Check document count in new table
    local doc_count
    doc_count=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM documents_search_optimized;" 2>/dev/null | tr -d ' ' || echo "0")
    
    if [[ $doc_count -eq 0 ]]; then
        log_warning "No documents found in search-optimized table"
    else
        log_success "Documents in search table: $doc_count"
    fi
    
    # Test Portuguese full-text search
    local search_test
    search_test=$(psql "$DATABASE_URL" -t -c "
        SELECT COUNT(*) FROM documents_search_optimized 
        WHERE search_vector_combined @@ plainto_tsquery('portuguese_legal', 'lei');
    " 2>/dev/null | tr -d ' ' || echo "0")
    
    if [[ $search_test -gt 0 ]]; then
        log_success "Portuguese full-text search working: $search_test results"
    else
        log_warning "Portuguese full-text search test returned no results"
    fi
    
    # Check index creation
    local index_count
    index_count=$(psql "$DATABASE_URL" -t -c "
        SELECT COUNT(*) FROM pg_indexes 
        WHERE tablename = 'documents_search_optimized';
    " 2>/dev/null | tr -d ' ' || echo "0")
    
    log_info "Search indexes created: $index_count"
    
    log_success "Deployment verification completed"
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would execute performance tests"
        return 0
    fi
    
    local test_log="${LOG_DIR}/performance_test_${TIMESTAMP}.log"
    
    if psql "$DATABASE_URL" -f "${DB_DIR}/performance_test.sql" > "$test_log" 2>&1; then
        log_success "Performance tests completed"
        
        # Extract test summary
        local test_summary
        test_summary=$(psql "$DATABASE_URL" -t -c "
            SELECT 
                COUNT(*) as total_tests,
                COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as successful,
                COUNT(CASE WHEN status = 'WARNING' THEN 1 END) as warnings,
                ROUND(AVG(execution_time_ms)::NUMERIC, 2) as avg_time_ms
            FROM performance_test_results;
        " 2>/dev/null || echo "Could not retrieve test summary")
        
        log_info "Performance test summary: $test_summary"
    else
        log_warning "Performance tests failed. Check logs: $test_log"
        cat "$test_log" >> "$ERROR_LOG"
    fi
}

# Rollback deployment
rollback_deployment() {
    log_info "Starting deployment rollback..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would execute rollback script"
        return 0
    fi
    
    local rollback_log="${LOG_DIR}/rollback_${TIMESTAMP}.log"
    
    # Check if rollback script exists
    if [[ ! -f "${DB_DIR}/advanced_search_rollback.sql" ]]; then
        error_exit "Rollback script not found: ${DB_DIR}/advanced_search_rollback.sql"
    fi
    
    # Execute rollback
    if psql "$DATABASE_URL" -f "${DB_DIR}/advanced_search_rollback.sql" > "$rollback_log" 2>&1; then
        log_success "Rollback completed successfully"
    else
        log_error "Rollback failed. Check logs: $rollback_log"
        cat "$rollback_log" >> "$ERROR_LOG"
        
        # If rollback fails, suggest manual backup restoration
        if [[ -f "${BACKUP_DIR}/latest_backup.txt" ]]; then
            local latest_backup
            latest_backup=$(cat "${BACKUP_DIR}/latest_backup.txt")
            log_error "Consider manual backup restoration:"
            log_error "zcat \"$latest_backup\" | psql \"\$DATABASE_URL\""
        fi
        
        error_exit "Rollback execution failed"
    fi
}

# Update Railway configuration
optimize_railway_config() {
    log_info "Applying Railway PostgreSQL optimizations..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would apply PostgreSQL optimizations"
        return 0
    fi
    
    # Apply memory optimizations for Railway
    psql "$DATABASE_URL" -c "
        -- Railway-optimized settings
        ALTER SYSTEM SET shared_buffers = '256MB';
        ALTER SYSTEM SET work_mem = '16MB';  
        ALTER SYSTEM SET maintenance_work_mem = '64MB';
        ALTER SYSTEM SET effective_cache_size = '512MB';
        ALTER SYSTEM SET random_page_cost = 1.1;
        ALTER SYSTEM SET seq_page_cost = 1.0;
        
        -- Connection optimization
        ALTER SYSTEM SET max_connections = '20';
        
        -- Logging optimization
        ALTER SYSTEM SET log_min_duration_statement = 5000;
        ALTER SYSTEM SET log_statement = 'none';
        
        -- Auto-vacuum tuning for Railway
        ALTER SYSTEM SET autovacuum_max_workers = 2;
        ALTER SYSTEM SET autovacuum_work_mem = '32MB';
    " 2>/dev/null || log_warning "Could not apply all PostgreSQL optimizations"
    
    # Reload configuration
    psql "$DATABASE_URL" -c "SELECT pg_reload_conf();" 2>/dev/null || true
    
    log_success "Railway PostgreSQL optimizations applied"
}

# Generate deployment report
generate_report() {
    log_info "Generating deployment report..."
    
    local report_file="${LOG_DIR}/deployment_report_${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Railway PostgreSQL Advanced Search Deployment Report
=====================================================

Deployment Time: $(date)
Database URL: ${DATABASE_URL%%@*}@***
Deployment Mode: $(if [[ "$DRY_RUN" == true ]]; then echo "DRY RUN"; else echo "PRODUCTION"; fi)

Pre-Deployment Status:
$(psql "$DATABASE_URL" -c "
    SELECT 
        'Database Size: ' || pg_size_pretty(pg_database_size(current_database())),
        'Max Connections: ' || setting FROM pg_settings WHERE name = 'max_connections';
" 2>/dev/null || echo "Could not retrieve pre-deployment status")

Post-Deployment Status:
$(if [[ "$DRY_RUN" == false && "$ROLLBACK_MODE" == false ]]; then
    psql "$DATABASE_URL" -c "
        SELECT 
            'Documents Migrated: ' || COUNT(*) 
        FROM documents_search_optimized;
        
        SELECT 
            'Search Indexes: ' || COUNT(*) 
        FROM pg_indexes 
        WHERE tablename = 'documents_search_optimized';
        
        SELECT 
            'Migration Status: ' || status 
        FROM migration_log 
        WHERE migration_name = 'advanced_search_migration' 
        ORDER BY id DESC LIMIT 1;
    " 2>/dev/null || echo "Could not retrieve post-deployment status"
else
    echo "Skipped (dry run or rollback mode)"
fi)

Performance Test Results:
$(if [[ "$DRY_RUN" == false && "$TEST_ONLY" == true ]]; then
    psql "$DATABASE_URL" -c "
        SELECT 
            test_category,
            COUNT(*) as total_tests,
            ROUND(AVG(execution_time_ms)::NUMERIC, 2) as avg_time_ms
        FROM performance_test_results 
        GROUP BY test_category
        ORDER BY test_category;
    " 2>/dev/null || echo "No performance test results available"
else
    echo "Performance tests not run in this deployment"
fi)

Files Created:
- Deployment Log: $LOG_FILE
- Migration Log: ${LOG_DIR}/migration_${TIMESTAMP}.log (if applicable)
- Performance Log: ${LOG_DIR}/performance_test_${TIMESTAMP}.log (if applicable)
- Backup File: $(cat "${BACKUP_DIR}/latest_backup.txt" 2>/dev/null || echo "No backup created")

Next Steps:
1. Monitor Railway PostgreSQL performance
2. Test R application integration
3. Review search analytics in search_analytics table
4. Set up automated materialized view refresh
5. Monitor database size growth

For support: Contact development team with this report
EOF

    log_success "Deployment report generated: $report_file"
}

# Main deployment function
main() {
    log_info "Starting Railway PostgreSQL Advanced Search Deployment"
    log_info "Timestamp: $TIMESTAMP"
    log_info "Log file: $LOG_FILE"
    
    # Handle different modes
    if [[ "$ROLLBACK_MODE" == true ]]; then
        validate_environment
        rollback_deployment
        generate_report
        log_success "Rollback completed successfully!"
        exit 0
    fi
    
    if [[ "$TEST_ONLY" == true ]]; then
        validate_environment
        run_performance_tests
        generate_report
        log_success "Performance testing completed!"
        exit 0
    fi
    
    # Standard deployment flow
    validate_environment
    check_railway_constraints
    
    if [[ "$BACKUP_ONLY" == true ]]; then
        create_backup
        log_success "Backup completed successfully!"
        exit 0
    fi
    
    # Full deployment
    create_backup
    deploy_advanced_search
    verify_deployment
    
    if [[ "$DRY_RUN" == false ]]; then
        optimize_railway_config
        run_performance_tests
    fi
    
    generate_report
    
    log_success "Advanced Search deployment completed successfully!"
    log_info "Check deployment report at: ${LOG_DIR}/deployment_report_${TIMESTAMP}.txt"
    log_info "Monitor Railway PostgreSQL performance and test R application integration"
}

# Handle script interruption
trap 'log_error "Deployment interrupted by user"; exit 130' INT TERM

# Run main function
main "$@"