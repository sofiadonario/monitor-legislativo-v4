
-- Monitor Legislativo v4 - REAL DATA Migration
-- Generated on: 2025-07-08 13:39:04
-- From: Supabase PostgreSQL (REAL DATA)
-- To: Railway PostgreSQL

-- ============================================================================
-- REAL TABLES DISCOVERED FROM SUPABASE
-- ============================================================================


-- Found table: search_cache
-- Sample data structure: 0 records

-- Found table: search_history
-- Sample data structure: 0 records

-- Found table: document_fingerprints
-- Sample data structure: 0 records

-- Found table: alerts
-- Sample data structure: 0 records

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

SELECT 'Real data migration completed!' as status;
SELECT 'search_cache' as table_name, COUNT(*) as record_count FROM search_cache;
SELECT 'search_history' as table_name, COUNT(*) as record_count FROM search_history;
SELECT 'document_fingerprints' as table_name, COUNT(*) as record_count FROM document_fingerprints;
SELECT 'alerts' as table_name, COUNT(*) as record_count FROM alerts;
