-- =============================================================================
-- MackMonitor Legislative Dataset - Root Cause Analysis for Data Duplication
-- =============================================================================
-- 
-- This SQL script investigates the root causes of data duplication in the
-- MackMonitor legislative dataset by examining collection patterns, source
-- differences, and data quality issues.
--
-- Author: Claude Code (Senior Data Scientist)
-- Date: 2025-08-01
-- =============================================================================

-- ============================================================================= 
-- 1. OVERVIEW OF DUPLICATION PATTERNS
-- =============================================================================

-- Get overall duplication statistics across all lexml tables
SELECT 'OVERALL DUPLICATION ANALYSIS' as analysis_type;

-- Check if documents view exists
SELECT 
    CASE 
        WHEN EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'documents') 
        THEN 'Documents view exists'
        ELSE 'Documents view does not exist'
    END as view_status;

-- List all lexml tables and their record counts
SELECT 
    table_name,
    (xpath('/row/count/text()', 
           query_to_xml(format('SELECT COUNT(*) AS count FROM %I', table_name), 
                        false, true, '')))[1]::text::int AS record_count
FROM information_schema.tables
WHERE table_schema = 'public' 
  AND table_name LIKE 'lexml_%'
  AND table_type = 'BASE TABLE'
ORDER BY record_count DESC;

-- =============================================================================
-- 2. URN-BASED DUPLICATION ANALYSIS
-- =============================================================================

SELECT 'URN DUPLICATION ANALYSIS' as analysis_type;

-- Check URN duplication patterns across the documents view (if available)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'documents') THEN
        RAISE NOTICE 'Analyzing URN duplicates in documents view...';
        
        -- Find URNs with multiple occurrences
        CREATE TEMP TABLE IF NOT EXISTS urn_duplicates AS
        SELECT 
            urn,
            COUNT(*) as duplicate_count,
            STRING_AGG(DISTINCT species, ', ') as document_types,
            STRING_AGG(DISTINCT transport_category, ', ') as categories,
            MIN(created_at) as first_collection,
            MAX(created_at) as last_collection,
            MAX(created_at) - MIN(created_at) as collection_span,
            STRING_AGG(DISTINCT estado, ', ') as states,
            COUNT(DISTINCT data_publicacao) as different_dates
        FROM documents 
        WHERE urn IS NOT NULL AND urn != ''
        GROUP BY urn
        HAVING COUNT(*) > 1
        ORDER BY duplicate_count DESC;
        
        -- Show summary of URN duplicates
        SELECT COUNT(*) as total_duplicate_urns,
               SUM(duplicate_count) as total_duplicate_records,
               ROUND(AVG(duplicate_count), 2) as avg_duplicates_per_urn,
               MAX(duplicate_count) as max_duplicates_per_urn
        FROM urn_duplicates;
        
        -- Show top URN duplicates
        SELECT * FROM urn_duplicates LIMIT 20;
        
    ELSE
        RAISE NOTICE 'Documents view not available, checking individual lexml tables...';
    END IF;
END $$;

-- =============================================================================
-- 3. COLLECTION DATE PATTERN ANALYSIS
-- =============================================================================

SELECT 'COLLECTION DATE PATTERN ANALYSIS' as analysis_type;

-- Analyze collection patterns if documents view exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'documents') THEN
        -- Collection date patterns
        CREATE TEMP TABLE IF NOT EXISTS collection_patterns AS
        SELECT 
            DATE(created_at) as collection_date,
            COUNT(*) as records_collected,
            COUNT(DISTINCT urn) as unique_urns,
            COUNT(DISTINCT titulo) as unique_titles,
            ROUND((COUNT(*) - COUNT(DISTINCT urn))::numeric / COUNT(*) * 100, 2) as urn_duplication_rate,
            ROUND((COUNT(*) - COUNT(DISTINCT titulo))::numeric / COUNT(*) * 100, 2) as title_duplication_rate
        FROM documents
        WHERE created_at IS NOT NULL
        GROUP BY DATE(created_at)
        ORDER BY urn_duplication_rate DESC;
        
        -- Show collection dates with highest duplication
        SELECT * FROM collection_patterns LIMIT 15;
        
    END IF;
END $$;

-- =============================================================================
-- 4. CROSS-TABLE DUPLICATION ANALYSIS
-- =============================================================================

SELECT 'CROSS-TABLE DUPLICATION ANALYSIS' as analysis_type;

-- Check if same documents appear across different lexml tables
-- This requires dynamic SQL due to variable table names

DO $$
DECLARE
    table_record record;
    sql_text text;
BEGIN
    -- Create a temporary table to store cross-table duplicates
    DROP TABLE IF EXISTS temp_cross_table_analysis;
    CREATE TEMP TABLE temp_cross_table_analysis (
        urn text,
        table_name text,
        titulo text,
        data_publicacao date,
        created_at timestamp
    );
    
    -- Loop through all lexml tables
    FOR table_record IN 
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
          AND table_name LIKE 'lexml_%' 
          AND table_type = 'BASE TABLE'
    LOOP
        -- Check if table has required columns
        IF EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = table_record.table_name 
              AND column_name IN ('urn', 'titulo')
        ) THEN
            sql_text := format('
                INSERT INTO temp_cross_table_analysis 
                SELECT urn, %L as table_name, titulo, data, data_coleta
                FROM %I 
                WHERE urn IS NOT NULL AND urn != ''''',
                table_record.table_name, table_record.table_name
            );
            
            EXECUTE sql_text;
        END IF;
    END LOOP;
    
    -- Analyze cross-table duplicates
    SELECT 
        urn,
        COUNT(DISTINCT table_name) as appears_in_tables,
        STRING_AGG(DISTINCT table_name, ', ') as table_list,
        COUNT(*) as total_occurrences
    FROM temp_cross_table_analysis
    GROUP BY urn
    HAVING COUNT(DISTINCT table_name) > 1
    ORDER BY appears_in_tables DESC, total_occurrences DESC
    LIMIT 20;
    
END $$;

-- =============================================================================
-- 5. CONTENT SIMILARITY ANALYSIS
-- =============================================================================

SELECT 'CONTENT SIMILARITY ANALYSIS' as analysis_type;

-- Analyze similar titles that might be the same document
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'documents') THEN
        -- Find titles with high similarity (same length, similar structure)
        CREATE TEMP TABLE IF NOT EXISTS similar_titles AS
        SELECT 
            LENGTH(titulo) as title_length,
            LEFT(titulo, 50) as title_prefix,
            COUNT(*) as count_similar,
            STRING_AGG(DISTINCT species, ', ') as document_types,
            MIN(titulo) as sample_title
        FROM documents
        WHERE titulo IS NOT NULL AND titulo != ''
        GROUP BY LENGTH(titulo), LEFT(titulo, 50)
        HAVING COUNT(*) > 5
        ORDER BY count_similar DESC;
        
        SELECT * FROM similar_titles LIMIT 10;
    END IF;
END $$;

-- =============================================================================
-- 6. DATA QUALITY ISSUES ANALYSIS
-- =============================================================================

SELECT 'DATA QUALITY ISSUES ANALYSIS' as analysis_type;

-- Check for various data quality issues that might cause duplicates
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'documents') THEN
        
        -- Missing URNs analysis
        SELECT 'Missing URNs' as issue_type,
               COUNT(*) as affected_records,
               ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM documents) * 100, 2) as percentage
        FROM documents
        WHERE urn IS NULL OR urn = '';
        
        -- Malformed URNs analysis
        SELECT 'Potentially Malformed URNs' as issue_type,
               COUNT(*) as affected_records,
               ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM documents WHERE urn IS NOT NULL) * 100, 2) as percentage
        FROM documents
        WHERE urn IS NOT NULL 
          AND urn != ''
          AND (
            LENGTH(urn) < 20 OR  -- URNs too short
            urn NOT LIKE 'urn:lex:%' OR  -- Not standard LexML format
            urn LIKE '%undefined%' OR  -- Contains undefined
            urn LIKE '%null%'  -- Contains null
          );
        
        -- Title encoding issues
        SELECT 'Title Encoding Issues' as issue_type,
               COUNT(*) as affected_records,
               ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM documents) * 100, 2) as percentage
        FROM documents
        WHERE titulo LIKE '%<%' OR titulo LIKE '%>%' OR titulo LIKE '%&%';
        
        -- Date inconsistencies
        SELECT 'Date Inconsistencies' as issue_type,
               COUNT(*) as affected_records,
               ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM documents) * 100, 2) as percentage
        FROM documents
        WHERE data_publicacao IS NULL 
           OR data_publicacao < '1900-01-01'::date 
           OR data_publicacao > CURRENT_DATE + INTERVAL '1 year';
           
    END IF;
END $$;

-- =============================================================================
-- 7. RECOMMENDATION QUERIES FOR DEDUPLICATION
-- =============================================================================

SELECT 'DEDUPLICATION RECOMMENDATION QUERIES' as analysis_type;

-- Query to identify the "best" record for each URN duplicate group
-- (Most complete record, earliest collection date, longest content)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'documents') THEN
        
        CREATE TEMP TABLE IF NOT EXISTS best_records_per_urn AS
        WITH ranked_duplicates AS (
            SELECT *,
                   ROW_NUMBER() OVER (
                       PARTITION BY urn 
                       ORDER BY 
                           -- Prefer records with more complete data
                           CASE WHEN conteudo IS NOT NULL AND LENGTH(conteudo) > 10 THEN 1 ELSE 2 END,
                           LENGTH(COALESCE(conteudo, '')) DESC,
                           -- Prefer earlier collection dates (original sources)
                           created_at ASC,
                           -- Prefer records with more metadata
                           CASE WHEN document_summary IS NOT NULL THEN 1 ELSE 2 END
                   ) as rn
            FROM documents 
            WHERE urn IS NOT NULL AND urn != ''
        )
        SELECT * FROM ranked_duplicates WHERE rn = 1;
        
        -- Show statistics of what would be kept vs removed
        SELECT 
            'Deduplication Impact' as analysis_type,
            (SELECT COUNT(*) FROM documents WHERE urn IS NOT NULL) as total_records_with_urn,
            COUNT(*) as records_to_keep,
            (SELECT COUNT(*) FROM documents WHERE urn IS NOT NULL) - COUNT(*) as records_to_remove,
            ROUND(((SELECT COUNT(*) FROM documents WHERE urn IS NOT NULL) - COUNT(*))::numeric / 
                  (SELECT COUNT(*) FROM documents WHERE urn IS NOT NULL) * 100, 2) as removal_percentage
        FROM best_records_per_urn;
        
    END IF;
END $$;

-- =============================================================================
-- 8. SUGGESTED DATABASE IMPROVEMENTS
-- =============================================================================

SELECT 'SUGGESTED DATABASE IMPROVEMENTS' as analysis_type;

-- Queries to implement better data integrity

-- 1. Create unique constraints (commented out for safety)
/*
-- Add unique constraint on URN (after deduplication)
ALTER TABLE documents ADD CONSTRAINT unique_urn UNIQUE (urn);

-- Create partial unique index for non-null URNs
CREATE UNIQUE INDEX CONCURRENTLY idx_documents_urn_unique 
ON documents (urn) 
WHERE urn IS NOT NULL AND urn != '';
*/

-- 2. Create indexes for better duplicate detection performance
/*
CREATE INDEX CONCURRENTLY idx_documents_titulo_hash 
ON documents (MD5(LOWER(TRIM(titulo))));

CREATE INDEX CONCURRENTLY idx_documents_content_hash 
ON documents (MD5(COALESCE(conteudo, '')));

CREATE INDEX CONCURRENTLY idx_documents_collection_date 
ON documents (DATE(created_at));
*/

-- 3. Create a view for deduplicated documents
/*
CREATE VIEW documents_deduplicated AS
WITH ranked_documents AS (
    SELECT *,
           ROW_NUMBER() OVER (
               PARTITION BY COALESCE(urn, MD5(titulo || COALESCE(data_publicacao::text, '')))
               ORDER BY 
                   CASE WHEN urn IS NOT NULL THEN 1 ELSE 2 END,
                   LENGTH(COALESCE(conteudo, '')) DESC,
                   created_at ASC
           ) as rn
    FROM documents
)
SELECT * FROM ranked_documents WHERE rn = 1;
*/

SELECT 'Analysis complete. Review temp tables and recommendations above.' as status;