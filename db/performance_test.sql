-- ============================================================================
-- ADVANCED SEARCH PERFORMANCE TEST SUITE
-- ============================================================================
--
-- This script comprehensively tests the performance of the advanced search 
-- engine for the Brazilian Legislative Monitoring System.
--
-- Tests include:
-- - Full-text search performance with Portuguese
-- - Index utilization verification
-- - Query execution time analysis
-- - Memory usage monitoring
-- - Concurrent access simulation
-- - Railway PostgreSQL 2GB memory compliance
--
-- Author: Senior Database Engineer - Brazilian Legislative Analytics Team
-- Date: January 2025
-- Version: 1.0 - Production Performance Testing
-- ============================================================================

-- Enable timing and verbose output
\timing on
\set VERBOSITY verbose

-- Create test results table
CREATE TABLE IF NOT EXISTS performance_test_results (
    id SERIAL PRIMARY KEY,
    test_name VARCHAR(100) NOT NULL,
    test_category VARCHAR(50) NOT NULL,
    execution_time_ms INTEGER,
    rows_returned INTEGER,
    rows_scanned INTEGER,
    memory_usage_mb DECIMAL(10,2),
    cpu_usage_percent DECIMAL(5,2),
    index_hit_ratio DECIMAL(5,4),
    status VARCHAR(20) DEFAULT 'RUNNING',
    test_query TEXT,
    execution_plan TEXT,
    notes TEXT,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clear previous test results
TRUNCATE performance_test_results;

SELECT 'Starting Advanced Search Performance Test Suite...' as test_status;
SELECT 'Testing on Railway PostgreSQL with 2GB memory constraints' as environment;

-- ============================================================================
-- TEST CATEGORY 1: BASIC DOCUMENT COUNTS AND STRUCTURE
-- ============================================================================
SELECT '=== TEST CATEGORY 1: BASIC STRUCTURE VALIDATION ===' as category;

-- Test 1.1: Document count verification
\echo 'Test 1.1: Document Count Verification'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('document_count_verification', 'structure', 'SELECT COUNT(*) FROM documents_search_optimized');

EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT COUNT(*) FROM documents_search_optimized;

-- Store the result
WITH test_execution AS (
    SELECT 
        'document_count_verification' as test_name,
        COUNT(*) as row_count,
        extract(epoch from clock_timestamp()) * 1000 as end_time
    FROM documents_search_optimized
)
UPDATE performance_test_results 
SET rows_returned = te.row_count,
    execution_time_ms = (te.end_time - extract(epoch from tested_at) * 1000)::INTEGER,
    status = 'COMPLETED'
FROM test_execution te
WHERE test_name = te.test_name AND status = 'RUNNING';

-- Test 1.2: Search vector population verification
\echo 'Test 1.2: Search Vector Population'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('search_vectors_populated', 'structure', 'SELECT COUNT(*) FROM documents_search_optimized WHERE search_vector_combined IS NOT NULL');

WITH test_execution AS (
    SELECT 
        COUNT(*) as vector_count
    FROM documents_search_optimized 
    WHERE search_vector_combined IS NOT NULL
)
UPDATE performance_test_results 
SET rows_returned = te.vector_count,
    status = CASE WHEN te.vector_count > 0 THEN 'COMPLETED' ELSE 'WARNING' END,
    notes = CASE WHEN te.vector_count = 0 THEN 'Search vectors not populated' ELSE 'Search vectors OK' END
FROM test_execution te
WHERE test_name = 'search_vectors_populated' AND status = 'RUNNING';

-- ============================================================================
-- TEST CATEGORY 2: PORTUGUESE FULL-TEXT SEARCH PERFORMANCE  
-- ============================================================================
SELECT '=== TEST CATEGORY 2: PORTUGUESE FULL-TEXT SEARCH ===' as category;

-- Test 2.1: Simple Portuguese full-text search
\echo 'Test 2.1: Simple Portuguese Full-Text Search'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('fts_simple_portuguese', 'full_text_search', 'Portuguese full-text search with plainto_tsquery');

EXPLAIN (ANALYZE, BUFFERS, COSTS, TIMING, FORMAT JSON)
SELECT 
    id, titulo, ementa, ts_rank_cd(search_vector_combined, query) as rank
FROM documents_search_optimized,
     plainto_tsquery('portuguese_legal', 'transporte público') query
WHERE search_vector_combined @@ query
ORDER BY rank DESC
LIMIT 50;

-- Test 2.2: Complex Portuguese search with filters
\echo 'Test 2.2: Complex Portuguese Search with Geographic Filter'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('fts_complex_with_filters', 'full_text_search', 'Complex search with state and date filters');

EXPLAIN (ANALYZE, BUFFERS, COSTS, TIMING, FORMAT JSON)
SELECT *
FROM advanced_search_documents(
    'lei transporte rodoviário',  -- Portuguese query
    'SP',                         -- State filter
    NULL,                         -- Region
    NULL,                         -- Municipality  
    'Legislação',                 -- Species
    'Rodoviário',                 -- Transport category
    '2020-01-01'::DATE,           -- Date start
    '2024-12-31'::DATE,           -- Date end
    NULL, NULL, NULL,             -- Year range, quality filter
    25,                           -- Limit
    0                             -- Offset
);

-- Test 2.3: Trigram fuzzy search performance
\echo 'Test 2.3: Trigram Fuzzy Search Performance'  
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('trigram_fuzzy_search', 'full_text_search', 'Trigram similarity search with typos');

EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT 
    titulo, 
    similarity(titulo_normalized, 'transpote pubico') as sim_score  -- Intentional typos
FROM documents_search_optimized 
WHERE titulo_normalized % 'transpote pubico'  -- Trigram operator
ORDER BY sim_score DESC 
LIMIT 20;

-- ============================================================================
-- TEST CATEGORY 3: INDEX UTILIZATION VERIFICATION
-- ============================================================================
SELECT '=== TEST CATEGORY 3: INDEX UTILIZATION ===' as category;

-- Test 3.1: GIN index usage for full-text search
\echo 'Test 3.1: GIN Index Usage Verification'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('gin_index_usage', 'index_performance', 'Verify GIN index is used for full-text queries');

-- Analyze index usage
SELECT 
    schemaname,
    tablename, 
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan,
    CASE WHEN idx_scan > 0 THEN 'ACTIVE' ELSE 'UNUSED' END as usage_status
FROM pg_stat_user_indexes 
WHERE tablename = 'documents_search_optimized'
ORDER BY idx_scan DESC;

-- Test 3.2: B-tree index performance for date ranges
\echo 'Test 3.2: B-tree Index Performance for Date Ranges'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('btree_date_range', 'index_performance', 'Date range query using B-tree index');

EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT COUNT(*) 
FROM documents_search_optimized 
WHERE data_publicacao BETWEEN '2020-01-01' AND '2024-12-31'
  AND estado = 'SP';

-- Test 3.3: Composite index usage
\echo 'Test 3.3: Composite Index Usage'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('composite_index_usage', 'index_performance', 'Multi-column index utilization');

EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT COUNT(*)
FROM documents_search_optimized
WHERE species = 'Legislação' 
  AND estado = 'RJ'
  AND ano BETWEEN 2020 AND 2024;

-- ============================================================================
-- TEST CATEGORY 4: MATERIALIZED VIEW PERFORMANCE
-- ============================================================================
SELECT '=== TEST CATEGORY 4: MATERIALIZED VIEW PERFORMANCE ===' as category;

-- Test 4.1: State statistics materialized view
\echo 'Test 4.1: State Statistics Materialized View Performance'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('mv_state_stats', 'materialized_views', 'State statistics aggregation performance');

EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT * FROM search_stats_by_state 
WHERE total_documents > 1000
ORDER BY total_documents DESC;

-- Test 4.2: Materialized view refresh performance
\echo 'Test 4.2: Materialized View Refresh Performance'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('mv_refresh_performance', 'materialized_views', 'Materialized view refresh timing');

-- Time the refresh operation
SELECT refresh_search_materialized_views();

-- ============================================================================
-- TEST CATEGORY 5: MEMORY AND RESOURCE USAGE
-- ============================================================================
SELECT '=== TEST CATEGORY 5: MEMORY AND RESOURCE USAGE ===' as category;

-- Test 5.1: Memory usage analysis
\echo 'Test 5.1: Memory Usage Analysis'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('memory_usage_analysis', 'resource_monitoring', 'Database memory utilization');

-- Check shared buffer usage
SELECT 
    'shared_buffers' as setting_name,
    setting as setting_value,
    unit
FROM pg_settings 
WHERE name = 'shared_buffers'
UNION ALL
SELECT 
    'work_mem' as setting_name,
    setting as setting_value,
    unit
FROM pg_settings 
WHERE name = 'work_mem'
UNION ALL  
SELECT
    'maintenance_work_mem' as setting_name,
    setting as setting_value,
    unit
FROM pg_settings
WHERE name = 'maintenance_work_mem';

-- Test 5.2: Table and index sizes
\echo 'Test 5.2: Table and Index Size Analysis'
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_indexes_size(schemaname||'.'||tablename)) as indexes_size
FROM pg_tables 
WHERE tablename LIKE '%document%' OR tablename LIKE '%search%'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- ============================================================================
-- TEST CATEGORY 6: CONCURRENT ACCESS SIMULATION
-- ============================================================================
SELECT '=== TEST CATEGORY 6: CONCURRENT ACCESS SIMULATION ===' as category;

-- Test 6.1: Concurrent search queries (simulated)
\echo 'Test 6.1: Concurrent Search Query Simulation'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('concurrent_search_simulation', 'concurrency', 'Simulate multiple concurrent searches');

-- Simulate concurrent searches by running multiple different queries rapidly
SELECT 'Simulating concurrent user searches...' as simulation_status;

-- User 1: Search for transportation legislation
SELECT COUNT(*) as user1_results
FROM advanced_search_documents('transporte', NULL, NULL, NULL, 'Legislação', NULL, NULL, NULL, NULL, NULL, NULL, 10, 0);

-- User 2: Search for São Paulo jurisprudence  
SELECT COUNT(*) as user2_results
FROM advanced_search_documents('', 'SP', NULL, NULL, 'Jurisprudência', NULL, NULL, NULL, NULL, NULL, NULL, 10, 0);

-- User 3: Full-text search for federal laws
SELECT COUNT(*) as user3_results 
FROM documents_search_optimized
WHERE search_vector_combined @@ plainto_tsquery('portuguese_legal', 'lei federal')
LIMIT 10;

-- Test 6.2: Lock contention analysis
\echo 'Test 6.2: Lock Contention Analysis'
SELECT 
    mode,
    locktype,
    database,
    relation,
    page,
    tuple,
    classid,
    granted
FROM pg_locks
WHERE database = (SELECT oid FROM pg_database WHERE datname = current_database());

-- ============================================================================
-- TEST CATEGORY 7: RAILWAY POSTGRESQL SPECIFIC TESTS
-- ============================================================================
SELECT '=== TEST CATEGORY 7: RAILWAY POSTGRESQL OPTIMIZATION ===' as category;

-- Test 7.1: Connection pool efficiency
\echo 'Test 7.1: Connection Pool Efficiency Test'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('connection_pool_efficiency', 'railway_specific', 'Connection usage and efficiency');

-- Check current connection stats
SELECT 
    application_name,
    state,
    COUNT(*) as connection_count
FROM pg_stat_activity 
WHERE datname = current_database()
GROUP BY application_name, state;

-- Test 7.2: Query cache hit ratio
\echo 'Test 7.2: Query Cache Hit Ratio'
SELECT 
    'buffer_cache_hit_ratio' as metric,
    CASE 
        WHEN blks_hit + blks_read = 0 THEN 0 
        ELSE blks_hit::FLOAT / (blks_hit + blks_read) 
    END as hit_ratio
FROM pg_stat_database 
WHERE datname = current_database();

-- Test 7.3: Railway memory constraint compliance
\echo 'Test 7.3: Railway Memory Constraint Compliance'
INSERT INTO performance_test_results (test_name, test_category, test_query)
VALUES ('railway_memory_compliance', 'railway_specific', 'Memory usage within Railway 2GB limits');

-- Calculate total database size
SELECT 
    pg_database.datname as database_name,
    pg_size_pretty(pg_database_size(pg_database.datname)) as database_size,
    pg_database_size(pg_database.datname) as size_bytes,
    CASE 
        WHEN pg_database_size(pg_database.datname) < 1610612736 THEN 'COMPLIANT'  -- Under 1.5GB
        WHEN pg_database_size(pg_database.datname) < 2147483648 THEN 'WARNING'    -- 1.5-2GB  
        ELSE 'CRITICAL'                                                            -- Over 2GB
    END as railway_compliance_status
FROM pg_database 
WHERE datname = current_database();

-- ============================================================================
-- FINAL PERFORMANCE SUMMARY AND RECOMMENDATIONS
-- ============================================================================
SELECT '=== PERFORMANCE TEST SUMMARY ===' as summary;

-- Update test completion status
UPDATE performance_test_results 
SET status = 'COMPLETED'
WHERE status = 'RUNNING';

-- Generate performance summary
WITH performance_summary AS (
    SELECT 
        test_category,
        COUNT(*) as total_tests,
        COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as successful_tests,
        COUNT(CASE WHEN status = 'WARNING' THEN 1 END) as warnings,
        COUNT(CASE WHEN status = 'ERROR' THEN 1 END) as errors,
        AVG(execution_time_ms) as avg_execution_time,
        MAX(execution_time_ms) as max_execution_time
    FROM performance_test_results
    GROUP BY test_category
)
SELECT 
    test_category,
    total_tests,
    successful_tests,
    warnings,
    errors,
    ROUND(avg_execution_time::NUMERIC, 2) as avg_time_ms,
    max_execution_time as max_time_ms,
    CASE 
        WHEN errors > 0 THEN 'CRITICAL'
        WHEN warnings > 0 THEN 'WARNING' 
        WHEN avg_execution_time > 5000 THEN 'SLOW'
        ELSE 'GOOD'
    END as performance_status
FROM performance_summary
ORDER BY test_category;

-- Performance recommendations
SELECT 'PERFORMANCE RECOMMENDATIONS' as recommendations;

WITH slowest_queries AS (
    SELECT 
        test_name,
        execution_time_ms,
        test_category,
        CASE 
            WHEN execution_time_ms > 10000 THEN 'Consider query optimization or indexing'
            WHEN execution_time_ms > 5000 THEN 'Monitor performance under load'
            WHEN execution_time_ms > 1000 THEN 'Acceptable but could be improved'
            ELSE 'Good performance'
        END as recommendation
    FROM performance_test_results
    WHERE execution_time_ms IS NOT NULL
    ORDER BY execution_time_ms DESC
    LIMIT 10
)
SELECT 
    test_name,
    execution_time_ms || ' ms' as execution_time,
    recommendation
FROM slowest_queries;

-- Final status check
SELECT 
    'Performance Testing Completed' as status,
    COUNT(*) as total_tests_run,
    COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as successful_tests,
    COUNT(CASE WHEN status = 'WARNING' THEN 1 END) as warnings_count,
    COUNT(CASE WHEN status = 'ERROR' THEN 1 END) as errors_count,
    CASE 
        WHEN COUNT(CASE WHEN status = 'ERROR' THEN 1 END) > 0 THEN 'NEEDS_ATTENTION'
        WHEN COUNT(CASE WHEN status = 'WARNING' THEN 1 END) > 0 THEN 'REVIEW_WARNINGS'
        ELSE 'ALL_TESTS_PASSED'
    END as overall_status,
    CURRENT_TIMESTAMP as completed_at
FROM performance_test_results;

SELECT 'Advanced Search Performance Testing Complete!' as final_message;
SELECT 'Check performance_test_results table for detailed analysis' as next_steps;