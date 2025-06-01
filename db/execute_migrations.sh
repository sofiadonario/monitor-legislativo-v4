#!/bin/bash

# Database Migration Execution Script for Railway PostgreSQL
# ============================================================
# This script executes performance optimization migrations on the Railway database

echo "========================================="
echo "DATABASE MIGRATION EXECUTION"
echo "========================================="
echo ""

# Check for DATABASE_URL environment variable
if [ -z "$DATABASE_URL" ]; then
    echo "❌ ERROR: DATABASE_URL environment variable not set"
    echo ""
    echo "Please set DATABASE_URL with your Railway PostgreSQL connection string:"
    echo "export DATABASE_URL='postgresql://user:password@host:port/database'"
    exit 1
fi

echo "✅ DATABASE_URL found"
echo ""

# Function to execute SQL file
execute_sql_file() {
    local file=$1
    local description=$2
    
    echo "Executing: $description"
    echo "File: $file"
    
    if [ ! -f "$file" ]; then
        echo "  ❌ File not found: $file"
        return 1
    fi
    
    # Execute the SQL file
    psql "$DATABASE_URL" -f "$file" 2>&1 | while IFS= read -r line; do
        # Filter out NOTICE messages for cleaner output
        if [[ ! "$line" =~ ^NOTICE: ]]; then
            echo "  $line"
        fi
    done
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "  ✅ Success: $description"
        return 0
    else
        echo "  ❌ Failed: $description"
        return 1
    fi
}

# Track migration status
MIGRATIONS_SUCCESS=0
MIGRATIONS_FAILED=0

echo "========================================="
echo "EXECUTING MIGRATIONS"
echo "========================================="
echo ""

# Migration 1: Performance Indexes
echo "1. Performance Indexes Migration"
echo "---------------------------------"
if execute_sql_file "db/migrations/001_performance_indexes.sql" "Create performance indexes"; then
    MIGRATIONS_SUCCESS=$((MIGRATIONS_SUCCESS + 1))
else
    MIGRATIONS_FAILED=$((MIGRATIONS_FAILED + 1))
fi
echo ""

# Migration 2: Materialized Views
echo "2. Materialized Views Migration"
echo "--------------------------------"
if execute_sql_file "db/migrations/002_materialized_views.sql" "Create materialized views"; then
    MIGRATIONS_SUCCESS=$((MIGRATIONS_SUCCESS + 1))
else
    MIGRATIONS_FAILED=$((MIGRATIONS_FAILED + 1))
fi
echo ""

# Migration 3: Query Monitoring Tables
echo "3. Query Monitoring Tables"
echo "---------------------------"
cat > /tmp/query_monitoring.sql << 'EOF'
-- Query Monitoring Tables for Performance Analysis
CREATE TABLE IF NOT EXISTS query_performance_log (
    id SERIAL PRIMARY KEY,
    query_hash VARCHAR(32),
    query_text TEXT,
    execution_time_ms INTEGER,
    rows_returned INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(100),
    user_session VARCHAR(100),
    cache_hit BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_query_performance_timestamp 
ON query_performance_log(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_query_performance_hash 
ON query_performance_log(query_hash);

CREATE INDEX IF NOT EXISTS idx_query_performance_slow 
ON query_performance_log(execution_time_ms) 
WHERE execution_time_ms > 2000;

-- Create summary view for monitoring dashboard
CREATE OR REPLACE VIEW query_performance_summary AS
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    COUNT(*) as total_queries,
    AVG(execution_time_ms) as avg_execution_ms,
    MAX(execution_time_ms) as max_execution_ms,
    SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END)::FLOAT / COUNT(*) * 100 as cache_hit_rate,
    COUNT(DISTINCT user_session) as unique_sessions
FROM query_performance_log
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', timestamp)
ORDER BY hour DESC;
EOF

if execute_sql_file "/tmp/query_monitoring.sql" "Create query monitoring tables"; then
    MIGRATIONS_SUCCESS=$((MIGRATIONS_SUCCESS + 1))
else
    MIGRATIONS_FAILED=$((MIGRATIONS_FAILED + 1))
fi
echo ""

# Migration 4: Cache Management Tables
echo "4. Cache Management Tables"
echo "--------------------------"
cat > /tmp/cache_management.sql << 'EOF'
-- Cache Management Tables
CREATE TABLE IF NOT EXISTS cache_entries (
    cache_key VARCHAR(32) PRIMARY KEY,
    cache_value JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    hit_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cache_expires 
ON cache_entries(expires_at) 
WHERE expires_at IS NOT NULL;

-- Function to clean expired cache entries
CREATE OR REPLACE FUNCTION clean_expired_cache() 
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM cache_entries 
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Schedule periodic cache cleanup (if pg_cron is available)
-- Note: Uncomment if pg_cron extension is available
-- SELECT cron.schedule('clean-cache', '*/15 * * * *', 'SELECT clean_expired_cache();');
EOF

if execute_sql_file "/tmp/cache_management.sql" "Create cache management tables"; then
    MIGRATIONS_SUCCESS=$((MIGRATIONS_SUCCESS + 1))
else
    MIGRATIONS_FAILED=$((MIGRATIONS_FAILED + 1))
fi
echo ""

# Migration 5: Refresh Materialized Views
echo "5. Initial Materialized View Refresh"
echo "-------------------------------------"
cat > /tmp/refresh_views.sql << 'EOF'
-- Refresh all materialized views with data
DO $$
BEGIN
    -- Check if views exist before refreshing
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_document_metrics') THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_document_metrics;
        RAISE NOTICE 'Refreshed mv_document_metrics';
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_state_document_counts') THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_state_document_counts;
        RAISE NOTICE 'Refreshed mv_state_document_counts';
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_document_type_summary') THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_document_type_summary;
        RAISE NOTICE 'Refreshed mv_document_type_summary';
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_monthly_document_trends') THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_monthly_document_trends;
        RAISE NOTICE 'Refreshed mv_monthly_document_trends';
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_municipality_coverage') THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_municipality_coverage;
        RAISE NOTICE 'Refreshed mv_municipality_coverage';
    END IF;
END $$;
EOF

if execute_sql_file "/tmp/refresh_views.sql" "Refresh materialized views"; then
    MIGRATIONS_SUCCESS=$((MIGRATIONS_SUCCESS + 1))
else
    MIGRATIONS_FAILED=$((MIGRATIONS_FAILED + 1))
fi
echo ""

# Clean up temporary files
rm -f /tmp/query_monitoring.sql /tmp/cache_management.sql /tmp/refresh_views.sql

echo "========================================="
echo "MIGRATION SUMMARY"
echo "========================================="
echo "✅ Successful migrations: $MIGRATIONS_SUCCESS"
echo "❌ Failed migrations: $MIGRATIONS_FAILED"
echo ""

if [ $MIGRATIONS_FAILED -eq 0 ]; then
    echo "🎉 All migrations completed successfully!"
    echo ""
    echo "Your database is now optimized with:"
    echo "• Performance indexes for fast queries"
    echo "• Materialized views for dashboard metrics"
    echo "• Query monitoring for performance analysis"
    echo "• Cache management for improved response times"
    exit 0
else
    echo "⚠️ Some migrations failed. Please review the errors above."
    echo ""
    echo "To retry failed migrations individually:"
    echo "psql \$DATABASE_URL -f db/migrations/001_performance_indexes.sql"
    echo "psql \$DATABASE_URL -f db/migrations/002_materialized_views.sql"
    exit 1
fi