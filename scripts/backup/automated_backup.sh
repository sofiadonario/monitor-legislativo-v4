#!/bin/bash

# Automated Backup Script for Monitor Legislativo v4
# Railway PostgreSQL Database Backup with Academic Data Protection
# ================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
BACKUP_DIR="/tmp/backups"
LOG_FILE="/tmp/backup.log"
DATE=$(date +"%Y%m%d_%H%M%S")
RETENTION_DAYS=30
MAX_BACKUP_SIZE_MB=500

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR $(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS $(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING $(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "${LOG_FILE}"
}

# Create backup directory
mkdir -p "${BACKUP_DIR}"

log "Starting automated backup process for Monitor Legislativo v4"
log "Backup directory: ${BACKUP_DIR}"
log "Retention period: ${RETENTION_DAYS} days"

# Check if running in Railway environment
if [ -z "${DATABASE_URL:-}" ]; then
    log_error "DATABASE_URL not set - backup cannot proceed"
    exit 1
fi

# Validate backup directory space
available_space_kb=$(df "${BACKUP_DIR}" | awk 'NR==2 {print $4}')
available_space_mb=$((available_space_kb / 1024))

if [ "${available_space_mb}" -lt 1000 ]; then
    log_warning "Low disk space: ${available_space_mb}MB available"
    if [ "${available_space_mb}" -lt 200 ]; then
        log_error "Insufficient disk space for backup (less than 200MB)"
        exit 1
    fi
fi

log "Available disk space: ${available_space_mb}MB"

# Function to perform database backup
perform_database_backup() {
    local backup_type=$1
    local backup_name="monitor_legislativo_${backup_type}_${DATE}"
    local backup_file="${BACKUP_DIR}/${backup_name}.sql"
    local compressed_backup="${backup_file}.gz"
    
    log "Starting ${backup_type} database backup..."
    
    # Perform the backup with Railway PostgreSQL
    if pg_dump "${DATABASE_URL}" \
        --no-password \
        --verbose \
        --format=plain \
        --no-tablespaces \
        --no-owner \
        --no-privileges \
        --exclude-table-data='cache_entries' \
        --exclude-table-data='query_performance_log' > "${backup_file}" 2>>"${LOG_FILE}"; then
        
        log_success "Database backup completed: ${backup_file}"
        
        # Compress the backup
        if gzip "${backup_file}"; then
            local backup_size_mb=$(( $(stat -f%z "${compressed_backup}" 2>/dev/null || stat -c%s "${compressed_backup}") / 1024 / 1024 ))
            log_success "Backup compressed: ${compressed_backup} (${backup_size_mb}MB)"
            
            # Validate backup size
            if [ "${backup_size_mb}" -gt "${MAX_BACKUP_SIZE_MB}" ]; then
                log_warning "Backup size (${backup_size_mb}MB) exceeds maximum (${MAX_BACKUP_SIZE_MB}MB)"
            fi
            
            return 0
        else
            log_error "Failed to compress backup"
            return 1
        fi
    else
        log_error "Database backup failed"
        # Clean up partial backup file
        [ -f "${backup_file}" ] && rm -f "${backup_file}"
        return 1
    fi
}

# Function to backup specific tables for academic research
perform_research_data_backup() {
    local backup_name="research_data_${DATE}"
    local backup_file="${BACKUP_DIR}/${backup_name}.sql"
    local compressed_backup="${backup_file}.gz"
    
    log "Starting research data backup (critical tables only)..."
    
    # Backup only essential tables for academic research
    if pg_dump "${DATABASE_URL}" \
        --no-password \
        --verbose \
        --format=plain \
        --no-tablespaces \
        --no-owner \
        --no-privileges \
        --table=documents \
        --table=proposicoes \
        --table=votacoes \
        --table=parlamentares \
        --table=partidos > "${backup_file}" 2>>"${LOG_FILE}"; then
        
        log_success "Research data backup completed: ${backup_file}"
        
        if gzip "${backup_file}"; then
            local backup_size_mb=$(( $(stat -f%z "${compressed_backup}" 2>/dev/null || stat -c%s "${compressed_backup}") / 1024 / 1024 ))
            log_success "Research data backup compressed: ${compressed_backup} (${backup_size_mb}MB)"
            return 0
        else
            log_error "Failed to compress research data backup"
            return 1
        fi
    else
        log_error "Research data backup failed"
        [ -f "${backup_file}" ] && rm -f "${backup_file}"
        return 1
    fi
}

# Function to create data export for external storage
create_data_export() {
    local export_name="data_export_${DATE}"
    local export_file="${BACKUP_DIR}/${export_name}.csv"
    
    log "Creating CSV data export for external storage..."
    
    # Export key data to CSV format for external backup
    if psql "${DATABASE_URL}" -c "\\copy (SELECT * FROM documents ORDER BY data_documento DESC LIMIT 1000) TO '${export_file}' WITH CSV HEADER" 2>>"${LOG_FILE}"; then
        
        if [ -f "${export_file}" ]; then
            local export_size_kb=$(( $(stat -f%z "${export_file}" 2>/dev/null || stat -c%s "${export_file}") / 1024 ))
            log_success "Data export created: ${export_file} (${export_size_kb}KB)"
            
            # Compress the export
            if gzip "${export_file}"; then
                log_success "Data export compressed: ${export_file}.gz"
            fi
            
            return 0
        else
            log_error "Data export file not created"
            return 1
        fi
    else
        log_error "Data export failed"
        return 1
    fi
}

# Function to cleanup old backups
cleanup_old_backups() {
    log "Cleaning up backups older than ${RETENTION_DAYS} days..."
    
    local deleted_count=0
    
    # Find and delete old backup files
    if command -v find >/dev/null 2>&1; then
        # Using find command
        while IFS= read -r -d '' old_backup; do
            log "Deleting old backup: $(basename "${old_backup}")"
            rm -f "${old_backup}"
            ((deleted_count++))
        done < <(find "${BACKUP_DIR}" -name "*.sql.gz" -type f -mtime +${RETENTION_DAYS} -print0 2>/dev/null)
        
        while IFS= read -r -d '' old_export; do
            log "Deleting old export: $(basename "${old_export}")"
            rm -f "${old_export}"
            ((deleted_count++))
        done < <(find "${BACKUP_DIR}" -name "*.csv.gz" -type f -mtime +${RETENTION_DAYS} -print0 2>/dev/null)
    else
        # Fallback cleanup (less precise)
        log_warning "Find command not available, using basic cleanup"
        # This is a simple cleanup - in production, you might want a more sophisticated approach
    fi
    
    if [ "${deleted_count}" -gt 0 ]; then
        log_success "Cleaned up ${deleted_count} old backup files"
    else
        log "No old backup files to clean up"
    fi
}

# Function to validate backup integrity
validate_backup_integrity() {
    local backup_file=$1
    
    log "Validating backup integrity: $(basename "${backup_file}")"
    
    # Basic validation - check if file exists and is not empty
    if [ -f "${backup_file}" ] && [ -s "${backup_file}" ]; then
        # Try to uncompress and check first few lines
        if zcat "${backup_file}" 2>/dev/null | head -10 | grep -q "PostgreSQL database dump" 2>/dev/null; then
            log_success "Backup integrity validated: $(basename "${backup_file}")"
            return 0
        else
            log_error "Backup integrity validation failed: invalid content"
            return 1
        fi
    else
        log_error "Backup integrity validation failed: file missing or empty"
        return 1
    fi
}

# Function to send backup notification (for monitoring)
send_backup_notification() {
    local status=$1
    local message=$2
    
    # In a production environment, you might want to send notifications via:
    # - Webhook to monitoring service
    # - Email notification
    # - Slack/Discord notification
    # - Railway logs (which we're already doing)
    
    log "BACKUP NOTIFICATION: ${status} - ${message}"
    
    # Example webhook notification (uncomment if you have a monitoring service)
    # curl -X POST -H "Content-Type: application/json" \
    #      -d "{\"status\":\"${status}\", \"message\":\"${message}\", \"timestamp\":\"$(date -Iseconds)\"}" \
    #      "${BACKUP_WEBHOOK_URL}" 2>/dev/null || true
}

# Main backup execution
main() {
    local backup_success=true
    local backup_count=0
    
    log "=== STARTING BACKUP PROCESS ==="
    
    # Cleanup old backups first
    cleanup_old_backups
    
    # Perform full database backup
    if perform_database_backup "full"; then
        ((backup_count++))
    else
        backup_success=false
    fi
    
    # Perform research data backup
    if perform_research_data_backup; then
        ((backup_count++))
    else
        backup_success=false
    fi
    
    # Create data export
    if create_data_export; then
        ((backup_count++))
    else
        log_warning "Data export failed but continuing..."
    fi
    
    # Validate recent backups
    local validation_errors=0
    for backup_file in "${BACKUP_DIR}"/*_${DATE}.sql.gz; do
        if [ -f "${backup_file}" ]; then
            if ! validate_backup_integrity "${backup_file}"; then
                ((validation_errors++))
            fi
        fi
    done
    
    # Final status report
    log "=== BACKUP PROCESS COMPLETED ==="
    log "Backups created: ${backup_count}"
    log "Validation errors: ${validation_errors}"
    
    if [ "${backup_success}" = true ] && [ "${validation_errors}" -eq 0 ]; then
        log_success "All backups completed successfully"
        send_backup_notification "SUCCESS" "All backups completed successfully (${backup_count} backups)"
        exit 0
    else
        log_error "Backup process completed with errors"
        send_backup_notification "ERROR" "Backup process completed with errors"
        exit 1
    fi
}

# Trap to ensure cleanup on script exit
trap 'log "Backup script interrupted or completed"' EXIT

# Check if PostgreSQL tools are available
if ! command -v pg_dump >/dev/null 2>&1; then
    log_error "pg_dump not found - PostgreSQL client tools required"
    exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
    log_error "psql not found - PostgreSQL client tools required"
    exit 1
fi

# Run main backup process
main "$@"