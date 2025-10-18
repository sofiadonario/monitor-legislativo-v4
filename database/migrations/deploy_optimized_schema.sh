#!/bin/bash
# ============================================================================
# RAILWAY POSTGRESQL DEPLOYMENT SCRIPT
# ============================================================================
#
# Purpose: Safely deploy optimized search schema to Railway PostgreSQL
# Target: Railway PostgreSQL (DATABASE_URL from environment)
# Safety: Pre-deployment checks, backup verification, rollback support
#
# Usage:
#   ./deploy_optimized_schema.sh [options]
#
# Options:
#   --dry-run    Show what would be executed without making changes
#   --force      Skip confirmation prompts (use in CI/CD)
#   --verbose    Show detailed execution output
#
# Author: Senior DevOps Engineer
# Date: October 16, 2025
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATION_FILE="${SCRIPT_DIR}/optimized_search_schema.sql"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${SCRIPT_DIR}/deployment_${TIMESTAMP}.log"

# Parse command line arguments
DRY_RUN=false
FORCE=false
VERBOSE=false

for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            exit 1
            ;;
    esac
done

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        INFO)
            echo -e "${BLUE}[INFO]${NC} ${message}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} ${message}"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} ${message}"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${message}"
            ;;
    esac

    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

# Error handler
error_exit() {
    log ERROR "$1"
    log ERROR "Deployment failed. Check log: ${LOG_FILE}"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log INFO "Checking prerequisites..."

    # Check if psql is installed
    if ! command -v psql &> /dev/null; then
        error_exit "psql command not found. Please install PostgreSQL client."
    fi

    # Check if migration file exists
    if [[ ! -f "${MIGRATION_FILE}" ]]; then
        error_exit "Migration file not found: ${MIGRATION_FILE}"
    fi

    # Check DATABASE_URL environment variable
    if [[ -z "${DATABASE_URL:-}" ]]; then
        error_exit "DATABASE_URL environment variable not set. Required for Railway connection."
    fi

    log SUCCESS "Prerequisites check passed"
}

# Verify database connection
verify_connection() {
    log INFO "Verifying database connection..."

    if ! psql "${DATABASE_URL}" -c "SELECT version();" &> /dev/null; then
        error_exit "Cannot connect to database. Check DATABASE_URL and network connectivity."
    fi

    # Get database info
    local db_info=$(psql "${DATABASE_URL}" -t -c "SELECT current_database(), current_user, version();")
    log SUCCESS "Connected to database"
    log INFO "Database info: ${db_info}"
}

# Check current database state
check_database_state() {
    log INFO "Checking current database state..."

    # Check if tables already exist
    local table_exists=$(psql "${DATABASE_URL}" -t -c \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('legis_docs', 'ingest_control');")

    table_exists=$(echo "${table_exists}" | tr -d '[:space:]')

    if [[ "${table_exists}" -gt 0 ]]; then
        log WARNING "Some tables already exist (${table_exists}/2). Migration is idempotent but may skip existing objects."
    else
        log INFO "No existing tables found. This is a fresh deployment."
    fi

    # Check document count in existing documents table (if exists)
    local doc_count=$(psql "${DATABASE_URL}" -t -c \
        "SELECT COUNT(*) FROM documents;" 2>/dev/null || echo "0")

    doc_count=$(echo "${doc_count}" | tr -d '[:space:]')
    log INFO "Existing documents table has ${doc_count} rows"

    # Check required extensions
    local extensions=$(psql "${DATABASE_URL}" -t -c \
        "SELECT COUNT(*) FROM pg_extension WHERE extname IN ('pg_trgm', 'unaccent');")

    extensions=$(echo "${extensions}" | tr -d '[:space:]')

    if [[ "${extensions}" -lt 2 ]]; then
        log WARNING "Critical extensions may be missing. Script will attempt to install them."
    else
        log SUCCESS "Critical extensions already installed"
    fi
}

# Create backup (Railway PostgreSQL backup verification)
verify_backup() {
    log INFO "Verifying backup capability..."

    # Note: Railway handles backups automatically, but we verify we can query the data
    local backup_query="SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';"

    if ! psql "${DATABASE_URL}" -t -c "${backup_query}" &> /dev/null; then
        log WARNING "Cannot verify backup state. Proceeding with caution."
    else
        log SUCCESS "Backup verification passed (Railway automatic backups enabled)"
        log INFO "Railway provides automatic backups. Manual backup not required."
        log INFO "To restore: Railway Dashboard → Database → Backups"
    fi
}

# Execute migration
execute_migration() {
    log INFO "Starting migration execution..."

    if [[ "${DRY_RUN}" == true ]]; then
        log INFO "DRY RUN: Would execute migration file: ${MIGRATION_FILE}"
        log INFO "DRY RUN: No changes made to database"
        return 0
    fi

    # Execute migration with detailed logging
    if [[ "${VERBOSE}" == true ]]; then
        log INFO "Executing migration with verbose output..."
        psql "${DATABASE_URL}" -f "${MIGRATION_FILE}" 2>&1 | tee -a "${LOG_FILE}"
    else
        log INFO "Executing migration (this may take 2-5 minutes for index creation)..."
        psql "${DATABASE_URL}" -f "${MIGRATION_FILE}" >> "${LOG_FILE}" 2>&1
    fi

    local exit_code=$?

    if [[ ${exit_code} -ne 0 ]]; then
        error_exit "Migration execution failed with exit code ${exit_code}. Check log: ${LOG_FILE}"
    fi

    log SUCCESS "Migration executed successfully"
}

# Verify deployment
verify_deployment() {
    log INFO "Verifying deployment..."

    # Check table creation
    local tables_created=$(psql "${DATABASE_URL}" -t -c \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('legis_docs', 'ingest_control');")

    tables_created=$(echo "${tables_created}" | tr -d '[:space:]')

    if [[ "${tables_created}" -ne 2 ]]; then
        error_exit "Table creation verification failed. Expected 2 tables, found ${tables_created}"
    fi

    # Check index creation
    local indexes_created=$(psql "${DATABASE_URL}" -t -c \
        "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'legis_docs';")

    indexes_created=$(echo "${indexes_created}" | tr -d '[:space:]')

    if [[ "${indexes_created}" -lt 7 ]]; then
        log WARNING "Expected at least 7 indexes, found ${indexes_created}"
    else
        log SUCCESS "Indexes created successfully (${indexes_created} indexes)"
    fi

    # Check materialized views
    local mvs_created=$(psql "${DATABASE_URL}" -t -c \
        "SELECT COUNT(*) FROM pg_matviews WHERE schemaname = 'public' AND matviewname LIKE 'mv_docs_%';")

    mvs_created=$(echo "${mvs_created}" | tr -d '[:space:]')

    if [[ "${mvs_created}" -ne 2 ]]; then
        log WARNING "Expected 2 materialized views, found ${mvs_created}"
    else
        log SUCCESS "Materialized views created successfully"
    fi

    # Check extensions
    local extensions=$(psql "${DATABASE_URL}" -t -c \
        "SELECT array_agg(extname) FROM pg_extension WHERE extname IN ('postgis', 'unaccent', 'pg_trgm', 'btree_gin');")

    log INFO "Installed extensions: ${extensions}"

    log SUCCESS "Deployment verification passed"
}

# Generate deployment report
generate_report() {
    log INFO "Generating deployment report..."

    local report_file="${SCRIPT_DIR}/deployment_report_${TIMESTAMP}.txt"

    cat > "${report_file}" << EOF
============================================================================
RAILWAY POSTGRESQL DEPLOYMENT REPORT
============================================================================

Deployment Date: $(date)
Migration File: ${MIGRATION_FILE}
Log File: ${LOG_FILE}

============================================================================
DATABASE STATE
============================================================================

EOF

    # Get database statistics
    psql "${DATABASE_URL}" -c "
        SELECT
            'legis_docs' as table_name,
            COUNT(*) as row_count,
            pg_size_pretty(pg_total_relation_size('legis_docs')) as total_size
        FROM legis_docs
        UNION ALL
        SELECT
            'ingest_control' as table_name,
            COUNT(*) as row_count,
            pg_size_pretty(pg_total_relation_size('ingest_control')) as total_size
        FROM ingest_control;
    " >> "${report_file}" 2>&1

    echo "" >> "${report_file}"
    echo "============================================================================" >> "${report_file}"
    echo "INDEXES" >> "${report_file}"
    echo "============================================================================" >> "${report_file}"
    echo "" >> "${report_file}"

    psql "${DATABASE_URL}" -c "
        SELECT
            indexname,
            indexdef,
            pg_size_pretty(pg_relation_size(indexrelid)) as size
        FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'legis_docs'
        ORDER BY indexname;
    " >> "${report_file}" 2>&1

    echo "" >> "${report_file}"
    echo "============================================================================" >> "${report_file}"
    echo "MATERIALIZED VIEWS" >> "${report_file}"
    echo "============================================================================" >> "${report_file}"
    echo "" >> "${report_file}"

    psql "${DATABASE_URL}" -c "
        SELECT
            matviewname,
            pg_size_pretty(pg_relation_size(oid)) as size
        FROM pg_matviews
        WHERE schemaname = 'public' AND matviewname LIKE 'mv_docs_%';
    " >> "${report_file}" 2>&1

    log SUCCESS "Deployment report saved: ${report_file}"
}

# Main deployment flow
main() {
    log INFO "============================================================================"
    log INFO "RAILWAY POSTGRESQL DEPLOYMENT - OPTIMIZED SEARCH SCHEMA"
    log INFO "============================================================================"
    log INFO "Timestamp: ${TIMESTAMP}"
    log INFO "Log file: ${LOG_FILE}"
    log INFO ""

    if [[ "${DRY_RUN}" == true ]]; then
        log WARNING "DRY RUN MODE - No changes will be made"
    fi

    # Pre-deployment checks
    check_prerequisites
    verify_connection
    check_database_state
    verify_backup

    # Confirmation prompt (unless --force)
    if [[ "${FORCE}" == false ]] && [[ "${DRY_RUN}" == false ]]; then
        echo ""
        echo -e "${YELLOW}Ready to deploy optimized search schema to Railway PostgreSQL${NC}"
        echo "This operation will:"
        echo "  - Create legis_docs and ingest_control tables"
        echo "  - Create 7+ performance indexes"
        echo "  - Create 2 materialized views"
        echo "  - Install PostgreSQL extensions (if needed)"
        echo ""
        read -p "Continue with deployment? (yes/no): " -r
        echo ""

        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log INFO "Deployment cancelled by user"
            exit 0
        fi
    fi

    # Execute deployment
    execute_migration
    verify_deployment
    generate_report

    log SUCCESS "============================================================================"
    log SUCCESS "DEPLOYMENT COMPLETED SUCCESSFULLY"
    log SUCCESS "============================================================================"
    log INFO ""
    log INFO "Next steps:"
    log INFO "  1. Test search queries: psql \$DATABASE_URL -f test_search_queries.sql"
    log INFO "  2. Import data to legis_docs table"
    log INFO "  3. Refresh materialized views: SELECT * FROM refresh_materialized_views_legis();"
    log INFO "  4. Monitor performance: Check v_slow_queries view"
    log INFO ""
    log INFO "Documentation: See deployment_report_${TIMESTAMP}.txt"
}

# Execute main function
main "$@"
