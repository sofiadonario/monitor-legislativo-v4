#!/bin/bash
# ============================================================================
# DEPLOY HIGH-PERFORMANCE SCHEMA TO RAILWAY POSTGRESQL
# ============================================================================
# Usage: ./deploy_to_railway.sh
# Prerequisites: psql installed, DATABASE_URL environment variable set
# ============================================================================

set -e  # Exit on error

echo "============================================================================"
echo "RAILWAY POSTGRESQL SCHEMA DEPLOYMENT"
echo "============================================================================"
echo ""

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "❌ ERROR: DATABASE_URL environment variable not set"
    echo ""
    echo "Set it with:"
    echo "  export DATABASE_URL='postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway'"
    echo ""
    exit 1
fi

# Extract database connection info for verification
DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')

echo "📋 Connection Details:"
echo "   Host: $DB_HOST"
echo "   Database: $DB_NAME"
echo ""

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "❌ ERROR: psql not found. Install PostgreSQL client tools:"
    echo "   macOS: brew install postgresql@15"
    echo "   Linux: apt-get install postgresql-client"
    echo ""
    exit 1
fi

echo "✓ PostgreSQL client found: $(psql --version)"
echo ""

# Confirm before proceeding
read -p "⚠️  This will create new tables and indexes. Continue? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

echo ""
echo "============================================================================"
echo "STEP 1: Testing Database Connection"
echo "============================================================================"
if psql "$DATABASE_URL" -c "SELECT version();" > /dev/null 2>&1; then
    echo "✓ Database connection successful"
else
    echo "❌ Database connection failed. Check your DATABASE_URL."
    exit 1
fi

echo ""
echo "============================================================================"
echo "STEP 2: Backing Up Existing Schema"
echo "============================================================================"
BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
echo "Creating backup: $BACKUP_FILE"
pg_dump "$DATABASE_URL" --schema-only > "$BACKUP_FILE"
echo "✓ Schema backup created: $BACKUP_FILE"

echo ""
echo "============================================================================"
echo "STEP 3: Deploying High-Performance Schema"
echo "============================================================================"
echo "Executing: high_performance_search_schema.sql"
echo ""

# Execute the migration script
psql "$DATABASE_URL" -f high_performance_search_schema.sql

echo ""
echo "============================================================================"
echo "STEP 4: Verifying Installation"
echo "============================================================================"

# Check if tables were created
TABLES_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('legis_docs', 'ingest_control');")
echo "Tables created: $TABLES_COUNT/2"

# Check if materialized views were created
MV_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_matviews WHERE schemaname = 'public';")
echo "Materialized views: $MV_COUNT"

# Check if extensions are installed
EXT_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_extension WHERE extname IN ('postgis', 'unaccent', 'pg_trgm', 'btree_gin');")
echo "Extensions installed: $EXT_COUNT/4"

echo ""
echo "============================================================================"
echo "DEPLOYMENT COMPLETE"
echo "============================================================================"
echo ""
echo "Next Steps:"
echo ""
echo "1. Verify the schema:"
echo "   psql \"\$DATABASE_URL\" -c '\\dt+ legis_docs'"
echo ""
echo "2. Check indexes:"
echo "   psql \"\$DATABASE_URL\" -c '\\di+ idx_fts_docs'"
echo ""
echo "3. Insert test data:"
echo "   INSERT INTO legis_docs (id, title, full_text, jurisdiction, state, date)"
echo "   VALUES ('test-001', 'Lei de Mobilidade Urbana', 'Texto completo...', 'federal', 'SP', '2024-01-01');"
echo ""
echo "4. Test full-text search:"
echo "   SELECT * FROM legis_docs"
echo "   WHERE search_vector @@ to_tsquery('portuguese', 'mobilidade');"
echo ""
echo "5. Monitor performance:"
echo "   SELECT * FROM v_slow_queries;"
echo ""
echo "📁 Backup saved to: $BACKUP_FILE"
echo ""
echo "============================================================================"
