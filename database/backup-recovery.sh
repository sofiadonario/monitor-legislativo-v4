#!/bin/bash
# Database Backup and Disaster Recovery System
# Monitor Legislativo v4 - Phase 4 Week 14
# Comprehensive backup strategy with point-in-time recovery and monitoring

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/monitor-legislativo}"
LOG_FILE="${LOG_FILE:-/var/log/monitor-legislativo/backup.log}"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/backup-config.conf}"

# Default configuration (can be overridden by config file)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-monitor_legislativo}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-}"
PGPASSFILE="${PGPASSFILE:-$HOME/.pgpass}"

# Backup settings
RETENTION_DAYS="${RETENTION_DAYS:-30}"
COMPRESSION_LEVEL="${COMPRESSION_LEVEL:-6}"
PARALLEL_JOBS="${PARALLEL_JOBS:-2}"
WAL_ARCHIVE_DIR="${WAL_ARCHIVE_DIR:-$BACKUP_DIR/wal}"
INCREMENTAL_BACKUP_INTERVAL="${INCREMENTAL_BACKUP_INTERVAL:-6}"  # hours

# Monitoring and alerting
ALERT_EMAIL="${ALERT_EMAIL:-}"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
MONITORING_ENABLED="${MONITORING_ENABLED:-true}"

# S3 settings for remote backup (optional)
S3_BUCKET="${S3_BUCKET:-}"
S3_REGION="${S3_REGION:-us-east-1}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    local message="$1"
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] INFO${NC} $message" | tee -a "$LOG_FILE"
}

log_warn() {
    local message="$1"
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN${NC} $message" | tee -a "$LOG_FILE"
}

log_error() {
    local message="$1"
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR${NC} $message" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG${NC} $1" | tee -a "$LOG_FILE"
    fi
}

# Load configuration file if it exists
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

# Setup directories and prerequisites
setup_environment() {
    log_info "Setting up backup environment..."
    
    # Create backup directories
    mkdir -p "$BACKUP_DIR"/{full,incremental,wal,logs,temp}
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Set up WAL archiving directory
    mkdir -p "$WAL_ARCHIVE_DIR"
    
    # Check required tools
    local required_tools=("pg_dump" "pg_dumpall" "pg_basebackup" "psql" "gzip" "openssl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check optional tools
    if [[ -n "$S3_BUCKET" ]]; then
        if ! command -v "aws" &> /dev/null; then
            log_warn "AWS CLI not found - S3 backup disabled"
            S3_BUCKET=""
        fi
    fi
    
    # Setup PostgreSQL password file if needed
    if [[ -n "$DB_PASSWORD" ]] && [[ ! -f "$PGPASSFILE" ]]; then
        log_info "Creating PostgreSQL password file"
        echo "$DB_HOST:$DB_PORT:$DB_NAME:$DB_USER:$DB_PASSWORD" > "$PGPASSFILE"
        chmod 600 "$PGPASSFILE"
    fi
    
    log_info "Environment setup completed"
}

# Test database connectivity
test_connection() {
    log_info "Testing database connectivity..."
    
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
        log_info "Database connection successful"
        return 0
    else
        log_error "Database connection failed"
        return 1
    fi
}

# Create full database backup
create_full_backup() {
    local backup_date=$(date '+%Y%m%d_%H%M%S')
    local backup_file="$BACKUP_DIR/full/monitor_legislativo_full_$backup_date.sql"
    local compressed_file="$backup_file.gz"
    local metadata_file="$backup_file.metadata.json"
    
    log_info "Starting full database backup..."
    
    local start_time=$(date +%s)
    
    # Get database size before backup
    local db_size=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" | xargs)
    
    # Create full backup with pg_dump
    if pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
               -d "$DB_NAME" \
               --verbose \
               --format=custom \
               --no-owner \
               --no-privileges \
               --compress="$COMPRESSION_LEVEL" \
               --jobs="$PARALLEL_JOBS" \
               --file="$backup_file" 2>&1 | tee -a "$LOG_FILE"; then
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local backup_size=$(stat -f%z "$backup_file" 2>/dev/null || stat -c%s "$backup_file" 2>/dev/null || echo "0")
        
        # Create metadata file
        cat > "$metadata_file" << EOF
{
    "backup_type": "full",
    "database": "$DB_NAME",
    "timestamp": "$(date -Iseconds)",
    "duration_seconds": $duration,
    "database_size": "$db_size",
    "backup_size_bytes": $backup_size,
    "backup_file": "$(basename "$backup_file")",
    "compression_level": $COMPRESSION_LEVEL,
    "parallel_jobs": $PARALLEL_JOBS,
    "hostname": "$(hostname)",
    "postgresql_version": "$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT version();" | head -1 | xargs)",
    "checksum": "$(openssl dgst -sha256 "$backup_file" | awk '{print $2}')"
}
EOF
        
        log_info "Full backup completed successfully"
        log_info "Backup file: $backup_file"
        log_info "Duration: ${duration}s"
        log_info "Database size: $db_size"
        log_info "Backup size: $(format_bytes $backup_size)"
        
        # Upload to S3 if configured
        if [[ -n "$S3_BUCKET" ]]; then
            upload_to_s3 "$backup_file" "full/$(basename "$backup_file")"
            upload_to_s3 "$metadata_file" "full/$(basename "$metadata_file")"
        fi
        
        # Send success notification
        send_notification "success" "Full backup completed" "Backup duration: ${duration}s, Size: $(format_bytes $backup_size)"
        
        return 0
    else
        log_error "Full backup failed"
        send_notification "error" "Full backup failed" "Check logs for details"
        return 1
    fi
}

# Create incremental backup using WAL files
create_incremental_backup() {
    local backup_date=$(date '+%Y%m%d_%H%M%S')
    local backup_dir="$BACKUP_DIR/incremental/monitor_legislativo_incr_$backup_date"
    local metadata_file="$backup_dir.metadata.json"
    
    log_info "Starting incremental backup..."
    
    local start_time=$(date +%s)
    
    # Create incremental backup using pg_basebackup
    if pg_basebackup -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
                     -D "$backup_dir" \
                     -Ft \
                     -z \
                     -P \
                     -W 2>&1 | tee -a "$LOG_FILE"; then
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local backup_size=$(du -sb "$backup_dir" | cut -f1)
        
        # Create metadata file
        cat > "$metadata_file" << EOF
{
    "backup_type": "incremental",
    "database": "$DB_NAME",
    "timestamp": "$(date -Iseconds)",
    "duration_seconds": $duration,
    "backup_size_bytes": $backup_size,
    "backup_directory": "$(basename "$backup_dir")",
    "hostname": "$(hostname)",
    "wal_files_included": true
}
EOF
        
        log_info "Incremental backup completed successfully"
        log_info "Backup directory: $backup_dir"
        log_info "Duration: ${duration}s"
        log_info "Backup size: $(format_bytes $backup_size)"
        
        # Upload to S3 if configured
        if [[ -n "$S3_BUCKET" ]]; then
            upload_directory_to_s3 "$backup_dir" "incremental/$(basename "$backup_dir")"
            upload_to_s3 "$metadata_file" "incremental/$(basename "$metadata_file")"
        fi
        
        return 0
    else
        log_error "Incremental backup failed"
        return 1
    fi
}

# Backup database schemas and roles
backup_schemas_and_roles() {
    local backup_date=$(date '+%Y%m%d_%H%M%S')
    local schema_file="$BACKUP_DIR/full/monitor_legislativo_schema_$backup_date.sql"
    local roles_file="$BACKUP_DIR/full/monitor_legislativo_roles_$backup_date.sql"
    
    log_info "Backing up database schemas and roles..."
    
    # Backup schema only
    if pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
               -d "$DB_NAME" \
               --schema-only \
               --no-owner \
               --no-privileges \
               --file="$schema_file" 2>&1 | tee -a "$LOG_FILE"; then
        log_info "Schema backup completed: $schema_file"
    else
        log_error "Schema backup failed"
    fi
    
    # Backup roles and global objects
    if pg_dumpall -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
                  --roles-only \
                  --file="$roles_file" 2>&1 | tee -a "$LOG_FILE"; then
        log_info "Roles backup completed: $roles_file"
    else
        log_error "Roles backup failed"
    fi
}

# Validate backup integrity
validate_backup() {
    local backup_file="$1"
    local metadata_file="$2"
    
    log_info "Validating backup integrity: $(basename "$backup_file")"
    
    # Check if backup file exists and is not empty
    if [[ ! -f "$backup_file" ]] || [[ ! -s "$backup_file" ]]; then
        log_error "Backup file is missing or empty"
        return 1
    fi
    
    # Verify checksum if metadata exists
    if [[ -f "$metadata_file" ]]; then
        local stored_checksum=$(jq -r '.checksum' "$metadata_file" 2>/dev/null || echo "")
        if [[ -n "$stored_checksum" ]]; then
            local actual_checksum=$(openssl dgst -sha256 "$backup_file" | awk '{print $2}')
            if [[ "$stored_checksum" == "$actual_checksum" ]]; then
                log_info "Checksum validation passed"
            else
                log_error "Checksum validation failed"
                return 1
            fi
        fi
    fi
    
    # Test restore to temporary database (for full backups)
    if [[ "$backup_file" == *.sql ]]; then
        local test_db="test_restore_$(date +%s)"
        
        log_info "Testing restore to temporary database: $test_db"
        
        # Create test database
        if createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$test_db" 2>/dev/null; then
            # Attempt restore
            if pg_restore -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
                         -d "$test_db" \
                         --jobs="$PARALLEL_JOBS" \
                         --no-owner \
                         --no-privileges \
                         "$backup_file" 2>/dev/null; then
                log_info "Backup validation successful"
                
                # Check if core tables exist
                local table_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$test_db" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | xargs)
                log_info "Restored $table_count tables"
                
                # Cleanup test database
                dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$test_db" 2>/dev/null || true
                return 0
            else
                log_error "Backup validation failed - restore test unsuccessful"
                dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$test_db" 2>/dev/null || true
                return 1
            fi
        else
            log_error "Could not create test database for validation"
            return 1
        fi
    fi
    
    log_info "Backup validation completed"
    return 0
}

# Upload backup to S3
upload_to_s3() {
    local local_file="$1"
    local s3_key="$2"
    
    if [[ -z "$S3_BUCKET" ]]; then
        return 0
    fi
    
    log_info "Uploading to S3: s3://$S3_BUCKET/$s3_key"
    
    if aws s3 cp "$local_file" "s3://$S3_BUCKET/$s3_key" \
           --region "$S3_REGION" \
           --storage-class STANDARD_IA 2>&1 | tee -a "$LOG_FILE"; then
        log_info "S3 upload successful"
        return 0
    else
        log_error "S3 upload failed"
        return 1
    fi
}

# Upload directory to S3
upload_directory_to_s3() {
    local local_dir="$1"
    local s3_prefix="$2"
    
    if [[ -z "$S3_BUCKET" ]]; then
        return 0
    fi
    
    log_info "Uploading directory to S3: s3://$S3_BUCKET/$s3_prefix"
    
    if aws s3 sync "$local_dir" "s3://$S3_BUCKET/$s3_prefix" \
           --region "$S3_REGION" \
           --storage-class STANDARD_IA 2>&1 | tee -a "$LOG_FILE"; then
        log_info "S3 directory upload successful"
        return 0
    else
        log_error "S3 directory upload failed"
        return 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."
    
    local deleted_count=0
    
    # Cleanup local backups
    while IFS= read -r -d '' file; do
        log_debug "Deleting old backup: $file"
        rm -rf "$file"
        ((deleted_count++))
    done < <(find "$BACKUP_DIR" -type f -name "*.sql*" -mtime +"$RETENTION_DAYS" -print0)
    
    # Cleanup old incremental backup directories
    while IFS= read -r -d '' dir; do
        log_debug "Deleting old incremental backup: $dir"
        rm -rf "$dir"
        ((deleted_count++))
    done < <(find "$BACKUP_DIR/incremental" -type d -name "monitor_legislativo_incr_*" -mtime +"$RETENTION_DAYS" -print0)
    
    # Cleanup S3 backups if configured
    if [[ -n "$S3_BUCKET" ]]; then
        local cutoff_date=$(date -d "$RETENTION_DAYS days ago" +%Y-%m-%d)
        
        # List and delete old S3 objects
        aws s3api list-objects-v2 \
            --bucket "$S3_BUCKET" \
            --query "Contents[?LastModified<='$cutoff_date'].{Key: Key}" \
            --output text | while read -r key; do
            if [[ -n "$key" ]]; then
                aws s3 rm "s3://$S3_BUCKET/$key"
                ((deleted_count++))
            fi
        done
    fi
    
    log_info "Cleanup completed: $deleted_count items removed"
}

# Restore database from backup
restore_database() {
    local backup_file="$1"
    local target_db="${2:-$DB_NAME}"
    local drop_existing="${3:-false}"
    
    log_info "Starting database restore from: $backup_file"
    log_info "Target database: $target_db"
    
    # Verify backup file exists
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    # Drop existing database if requested
    if [[ "$drop_existing" == "true" ]]; then
        log_warn "Dropping existing database: $target_db"
        dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$target_db" 2>/dev/null || true
    fi
    
    # Create target database if it doesn't exist
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$target_db"; then
        log_info "Creating database: $target_db"
        createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$target_db"
    fi
    
    # Perform restore
    local start_time=$(date +%s)
    
    if pg_restore -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
                  -d "$target_db" \
                  --verbose \
                  --jobs="$PARALLEL_JOBS" \
                  --no-owner \
                  --no-privileges \
                  "$backup_file" 2>&1 | tee -a "$LOG_FILE"; then
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_info "Database restore completed successfully"
        log_info "Restore duration: ${duration}s"
        
        # Verify restore
        local table_count=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$target_db" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | xargs)
        log_info "Restored database contains $table_count tables"
        
        return 0
    else
        log_error "Database restore failed"
        return 1
    fi
}

# Point-in-time recovery setup
setup_pitr() {
    log_info "Setting up Point-in-Time Recovery (PITR)..."
    
    # Configure WAL archiving
    cat > "$BACKUP_DIR/postgresql-pitr.conf" << EOF
# Point-in-Time Recovery Configuration for Monitor Legislativo v4
# Add these settings to postgresql.conf

# WAL settings
wal_level = replica
archive_mode = on
archive_command = 'test ! -f $WAL_ARCHIVE_DIR/%f && cp %p $WAL_ARCHIVE_DIR/%f'
archive_timeout = 300  # 5 minutes

# Checkpoint settings
checkpoint_completion_target = 0.7
checkpoint_timeout = 10min

# Recovery settings
restore_command = 'cp $WAL_ARCHIVE_DIR/%f %p'
recovery_target_timeline = 'latest'
EOF
    
    log_info "PITR configuration created: $BACKUP_DIR/postgresql-pitr.conf"
    log_info "Apply these settings to postgresql.conf and restart PostgreSQL"
}

# Monitor backup health
monitor_backup_health() {
    local report_file="$BACKUP_DIR/logs/backup-health-$(date +%Y%m%d).json"
    
    log_info "Generating backup health report..."
    
    # Analyze backup files
    local full_backups=$(find "$BACKUP_DIR/full" -name "*.sql" -type f | wc -l)
    local incremental_backups=$(find "$BACKUP_DIR/incremental" -name "monitor_legislativo_incr_*" -type d | wc -l)
    local latest_full=$(find "$BACKUP_DIR/full" -name "*.sql" -type f -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
    local latest_incremental=$(find "$BACKUP_DIR/incremental" -name "monitor_legislativo_incr_*" -type d -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
    
    # Calculate ages
    local full_age_hours=0
    local incr_age_hours=0
    
    if [[ -n "$latest_full" ]]; then
        local full_timestamp=$(stat -c %Y "$latest_full")
        full_age_hours=$(( ($(date +%s) - full_timestamp) / 3600 ))
    fi
    
    if [[ -n "$latest_incremental" ]]; then
        local incr_timestamp=$(stat -c %Y "$latest_incremental")
        incr_age_hours=$(( ($(date +%s) - incr_timestamp) / 3600 ))
    fi
    
    # Determine health status
    local health_status="healthy"
    local issues=()
    
    if [[ $full_age_hours -gt 168 ]]; then  # 1 week
        health_status="critical"
        issues+=("Full backup is over 1 week old")
    elif [[ $full_age_hours -gt 48 ]]; then  # 2 days
        health_status="warning"
        issues+=("Full backup is over 2 days old")
    fi
    
    if [[ $incr_age_hours -gt 12 ]]; then
        if [[ "$health_status" != "critical" ]]; then
            health_status="warning"
        fi
        issues+=("Incremental backup is over 12 hours old")
    fi
    
    # Generate report
    cat > "$report_file" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "health_status": "$health_status",
    "issues": $(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .),
    "statistics": {
        "full_backups_count": $full_backups,
        "incremental_backups_count": $incremental_backups,
        "latest_full_backup": "$(basename "$latest_full" 2>/dev/null || echo "none")",
        "latest_incremental_backup": "$(basename "$latest_incremental" 2>/dev/null || echo "none")",
        "full_backup_age_hours": $full_age_hours,
        "incremental_backup_age_hours": $incr_age_hours
    },
    "storage": {
        "local_backup_size": "$(du -sh "$BACKUP_DIR" | cut -f1)",
        "wal_archive_size": "$(du -sh "$WAL_ARCHIVE_DIR" | cut -f1)",
        "disk_usage_percent": "$(df "$BACKUP_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')"
    }
}
EOF
    
    log_info "Backup health report generated: $report_file"
    
    # Send alert if unhealthy
    if [[ "$health_status" != "healthy" ]]; then
        local issue_text=$(printf '%s; ' "${issues[@]}")
        send_notification "warning" "Backup health issues detected" "$issue_text"
    fi
    
    echo "$report_file"
}

# Send notifications
send_notification() {
    local level="$1"
    local title="$2"
    local message="$3"
    
    if [[ "$MONITORING_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Email notification
    if [[ -n "$ALERT_EMAIL" ]] && command -v mail &> /dev/null; then
        echo "$message" | mail -s "[$level] Monitor Legislativo Backup: $title" "$ALERT_EMAIL"
    fi
    
    # Slack notification
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        local color="good"
        case "$level" in
            error|critical) color="danger" ;;
            warning) color="warning" ;;
        esac
        
        local payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "$color",
            "title": "Monitor Legislativo Backup - $title",
            "text": "$message",
            "footer": "$(hostname)",
            "ts": $(date +%s)
        }
    ]
}
EOF
)
        
        curl -X POST -H 'Content-type: application/json' \
             --data "$payload" \
             "$SLACK_WEBHOOK" &> /dev/null || true
    fi
    
    # Generic webhook
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        local webhook_data=$(cat << EOF
{
    "level": "$level",
    "title": "$title", 
    "message": "$message",
    "timestamp": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "service": "monitor-legislativo-backup"
}
EOF
)
        
        curl -X POST -H 'Content-type: application/json' \
             --data "$webhook_data" \
             "$ALERT_WEBHOOK" &> /dev/null || true
    fi
}

# Utility function to format bytes
format_bytes() {
    local bytes=$1
    local units=("B" "KB" "MB" "GB" "TB")
    local unit=0
    local size=$bytes
    
    while [[ $size -gt 1024 ]] && [[ $unit -lt 4 ]]; do
        size=$((size / 1024))
        ((unit++))
    done
    
    echo "${size}${units[$unit]}"
}

# List available backups
list_backups() {
    echo "Available Backups for Monitor Legislativo v4"
    echo "==========================================="
    echo
    
    echo "Full Backups:"
    find "$BACKUP_DIR/full" -name "*.sql*" -type f -printf '%TY-%Tm-%Td %TH:%TM  %10s  %f\n' | sort -r
    echo
    
    echo "Incremental Backups:"
    find "$BACKUP_DIR/incremental" -name "monitor_legislativo_incr_*" -type d -printf '%TY-%Tm-%Td %TH:%TM  %10s  %f\n' | sort -r
    echo
    
    echo "Schema Backups:"
    find "$BACKUP_DIR/full" -name "*_schema_*.sql" -type f -printf '%TY-%Tm-%Td %TH:%TM  %10s  %f\n' | sort -r
}

# Show help
show_help() {
    cat << EOF
Database Backup and Recovery System for Monitor Legislativo v4

Usage: $0 [OPTIONS] COMMAND [ARGS]

Commands:
    backup-full              Create full database backup
    backup-incremental       Create incremental backup using WAL
    backup-schema           Backup database schema and roles only
    restore FILE [DB]       Restore database from backup file
    validate FILE           Validate backup file integrity
    cleanup                 Remove old backups based on retention policy
    list                    List available backups
    health                  Generate backup health report
    setup-pitr              Setup Point-in-Time Recovery
    test-connection         Test database connectivity

Options:
    -h, --help              Show this help message
    -c, --config FILE       Use custom configuration file
    -d, --debug             Enable debug logging
    -f, --force             Force operation (bypass confirmations)
    -q, --quiet             Suppress non-error output

Environment Variables:
    DB_HOST                 Database hostname (default: localhost)
    DB_PORT                 Database port (default: 5432)
    DB_NAME                 Database name (default: monitor_legislativo)
    DB_USER                 Database user (default: postgres)
    DB_PASSWORD             Database password
    BACKUP_DIR              Backup directory (default: /var/backups/monitor-legislativo)
    RETENTION_DAYS          Backup retention in days (default: 30)
    S3_BUCKET               S3 bucket for remote backup storage
    ALERT_EMAIL             Email address for alerts
    SLACK_WEBHOOK           Slack webhook URL for notifications

Examples:
    $0 backup-full                          # Create full backup
    $0 backup-incremental                   # Create incremental backup
    $0 restore /path/to/backup.sql          # Restore to original database
    $0 restore /path/to/backup.sql test_db  # Restore to different database
    $0 cleanup                              # Remove old backups
    $0 health                               # Check backup health

Configuration:
    Create $CONFIG_FILE to override default settings.
    
EOF
}

# Main function
main() {
    local command="${1:-}"
    
    # Parse command line options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -d|--debug)
                export DEBUG=true
                shift
                ;;
            -f|--force)
                export FORCE=true
                shift
                ;;
            -q|--quiet)
                export QUIET=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$command" ]]; then
                    command="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Load configuration and setup environment
    load_config
    setup_environment
    
    # Execute command
    case "$command" in
        backup-full)
            test_connection && create_full_backup
            ;;
        backup-incremental)
            test_connection && create_incremental_backup
            ;;
        backup-schema)
            test_connection && backup_schemas_and_roles
            ;;
        restore)
            if [[ $# -lt 2 ]]; then
                log_error "Restore command requires backup file path"
                exit 1
            fi
            restore_database "$2" "$3" "${FORCE:-false}"
            ;;
        validate)
            if [[ $# -lt 2 ]]; then
                log_error "Validate command requires backup file path"
                exit 1
            fi
            validate_backup "$2" "${2}.metadata.json"
            ;;
        cleanup)
            cleanup_old_backups
            ;;
        list)
            list_backups
            ;;
        health)
            monitor_backup_health
            ;;
        setup-pitr)
            setup_pitr
            ;;
        test-connection)
            test_connection
            ;;
        "")
            log_error "No command specified"
            show_help
            exit 1
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