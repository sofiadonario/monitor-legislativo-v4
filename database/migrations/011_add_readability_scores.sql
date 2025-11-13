-- ==============================================================================
-- MIGRATION 011: ADD READABILITY SCORES TO DOCUMENTS TABLE
-- ==============================================================================
-- Adds columns to store readability metrics for legislative documents
-- These metrics help analyze document complexity and accessibility
--
-- Author: Data Science Team
-- Date: 2025-11-12
-- Target: 118,920 documents
-- Estimated Time: ~2-3 minutes (DDL operations, no data population)
-- ==============================================================================

-- ==============================================================================
-- SECTION 1: ADD READABILITY SCORE COLUMNS
-- ==============================================================================
-- These columns will store calculated readability metrics
-- Initial values are NULL; calculation performed by R application layer

DO $$
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE 'MIGRATION 011: Readability Scores';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Adding readability metric columns...';
    RAISE NOTICE '';
END $$;

-- Add readability score columns
ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS flesch_kincaid_score NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS fog_index NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS smog_index NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS avg_sentence_length NUMERIC(6,2),
    ADD COLUMN IF NOT EXISTS avg_word_length NUMERIC(4,2),
    ADD COLUMN IF NOT EXISTS readability_updated_at TIMESTAMP;

-- ==============================================================================
-- SECTION 2: ADD COLUMN DOCUMENTATION
-- ==============================================================================
-- PostgreSQL comments provide metadata for each metric

COMMENT ON COLUMN documents.flesch_kincaid_score IS
    'Flesch Reading Ease score (0-100): Higher scores indicate easier readability.
     90-100: Very Easy (5th grade), 60-70: Standard (8th-9th grade),
     0-30: Very Difficult (College graduate)';

COMMENT ON COLUMN documents.fog_index IS
    'Gunning Fog Index: Estimates years of education needed to understand text.
     Values typically range from 6 (elementary) to 17+ (college graduate).
     Ideal target: 7-8 for general public documents';

COMMENT ON COLUMN documents.smog_index IS
    'SMOG (Simple Measure of Gobbledygook) Index: Estimates years of education
     required to understand text. Generally correlates with Fog Index.
     Lower values indicate greater accessibility';

COMMENT ON COLUMN documents.avg_sentence_length IS
    'Average sentence length in words. Brazilian Portuguese legislative documents
     typically range from 15-40 words per sentence. Shorter sentences improve clarity';

COMMENT ON COLUMN documents.avg_word_length IS
    'Average word length in characters. Portuguese legislative texts typically
     average 5-7 characters per word. Technical/legal texts tend higher';

COMMENT ON COLUMN documents.readability_updated_at IS
    'Timestamp of last readability score calculation. Used to track stale metrics
     and trigger recalculation when document content changes';

-- ==============================================================================
-- SECTION 3: CREATE INDEXES FOR QUERY PERFORMANCE
-- ==============================================================================
-- Partial indexes on non-NULL values optimize queries filtering by readability

DO $$
BEGIN
    RAISE NOTICE 'Creating performance indexes...';
END $$;

-- Index for Flesch-Kincaid queries (most commonly used metric)
CREATE INDEX IF NOT EXISTS idx_documents_flesch_kincaid
    ON documents(flesch_kincaid_score)
    WHERE flesch_kincaid_score IS NOT NULL;

-- Index for Fog Index queries
CREATE INDEX IF NOT EXISTS idx_documents_fog_index
    ON documents(fog_index)
    WHERE fog_index IS NOT NULL;

-- Index for SMOG Index queries
CREATE INDEX IF NOT EXISTS idx_documents_smog_index
    ON documents(smog_index)
    WHERE smog_index IS NOT NULL;

-- Composite index for dashboard queries (tipo + nivel + readability)
CREATE INDEX IF NOT EXISTS idx_documents_readability_dashboard
    ON documents(tipo_documento, nivel, flesch_kincaid_score)
    WHERE flesch_kincaid_score IS NOT NULL;

-- Index for finding documents needing recalculation
CREATE INDEX IF NOT EXISTS idx_documents_readability_stale
    ON documents(readability_updated_at)
    WHERE texto_completo IS NOT NULL
      AND readability_updated_at IS NULL;

-- ==============================================================================
-- SECTION 4: CREATE READABILITY SUMMARY VIEW
-- ==============================================================================
-- Materialized view for analytics dashboards and reporting

DO $$
BEGIN
    RAISE NOTICE 'Creating readability summary view...';
END $$;

CREATE OR REPLACE VIEW readability_summary AS
SELECT
    -- Document classification
    tipo_documento,
    nivel,
    poder,
    ano,

    -- Document counts
    COUNT(*) as total_documents,
    COUNT(flesch_kincaid_score) as analyzed_documents,
    ROUND(100.0 * COUNT(flesch_kincaid_score) / NULLIF(COUNT(*), 0), 2) as pct_analyzed,

    -- Flesch-Kincaid Statistics
    ROUND(AVG(flesch_kincaid_score)::numeric, 2) as avg_flesch_score,
    ROUND(STDDEV(flesch_kincaid_score)::numeric, 2) as stddev_flesch_score,
    ROUND(MIN(flesch_kincaid_score)::numeric, 2) as min_flesch_score,
    ROUND(MAX(flesch_kincaid_score)::numeric, 2) as max_flesch_score,
    ROUND(PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY flesch_kincaid_score)::numeric, 2) as q25_flesch_score,
    ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY flesch_kincaid_score)::numeric, 2) as median_flesch_score,
    ROUND(PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY flesch_kincaid_score)::numeric, 2) as q75_flesch_score,

    -- Fog Index Statistics
    ROUND(AVG(fog_index)::numeric, 2) as avg_fog_index,
    ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY fog_index)::numeric, 2) as median_fog_index,

    -- SMOG Index Statistics
    ROUND(AVG(smog_index)::numeric, 2) as avg_smog_index,
    ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY smog_index)::numeric, 2) as median_smog_index,

    -- Sentence and Word Statistics
    ROUND(AVG(avg_sentence_length)::numeric, 2) as avg_sentence_len,
    ROUND(AVG(avg_word_length)::numeric, 2) as avg_word_len,

    -- Readability Grade Classification (based on Flesch score)
    COUNT(CASE WHEN flesch_kincaid_score >= 90 THEN 1 END) as very_easy_count,
    COUNT(CASE WHEN flesch_kincaid_score >= 80 AND flesch_kincaid_score < 90 THEN 1 END) as easy_count,
    COUNT(CASE WHEN flesch_kincaid_score >= 70 AND flesch_kincaid_score < 80 THEN 1 END) as fairly_easy_count,
    COUNT(CASE WHEN flesch_kincaid_score >= 60 AND flesch_kincaid_score < 70 THEN 1 END) as standard_count,
    COUNT(CASE WHEN flesch_kincaid_score >= 50 AND flesch_kincaid_score < 60 THEN 1 END) as fairly_difficult_count,
    COUNT(CASE WHEN flesch_kincaid_score >= 30 AND flesch_kincaid_score < 50 THEN 1 END) as difficult_count,
    COUNT(CASE WHEN flesch_kincaid_score < 30 THEN 1 END) as very_difficult_count,

    -- Metadata
    MAX(readability_updated_at) as last_update

FROM documents
WHERE texto_completo IS NOT NULL  -- Only include documents with text
GROUP BY tipo_documento, nivel, poder, ano
HAVING COUNT(flesch_kincaid_score) > 0  -- Only groups with analyzed documents
ORDER BY COUNT(*) DESC;

COMMENT ON VIEW readability_summary IS
    'Aggregated readability statistics by document type, level, branch of government,
     and year. Used for dashboard analytics and comparative analysis of document complexity
     across different legislative contexts. Updated in real-time as documents are analyzed';

-- ==============================================================================
-- SECTION 5: CREATE HELPER VIEW FOR DOCUMENT PRIORITIZATION
-- ==============================================================================
-- View to identify which documents need readability analysis

DO $$
BEGIN
    RAISE NOTICE 'Creating document prioritization view...';
END $$;

CREATE OR REPLACE VIEW readability_analysis_queue AS
SELECT
    id,
    urn,
    tipo_documento,
    nivel,
    poder,
    ano,
    LENGTH(texto_completo) as text_length,
    data_publicacao,
    CASE
        WHEN readability_updated_at IS NULL THEN 'never_analyzed'
        WHEN updated_at > readability_updated_at THEN 'content_changed'
        WHEN readability_updated_at < (CURRENT_TIMESTAMP - INTERVAL '30 days') THEN 'stale'
        ELSE 'current'
    END as analysis_status,
    -- Priority score: recent documents with longer text get higher priority
    (
        CASE
            WHEN ano >= EXTRACT(YEAR FROM CURRENT_DATE) THEN 100
            WHEN ano >= EXTRACT(YEAR FROM CURRENT_DATE) - 1 THEN 50
            ELSE 10
        END +
        CASE
            WHEN LENGTH(texto_completo) > 10000 THEN 20
            WHEN LENGTH(texto_completo) > 5000 THEN 10
            ELSE 5
        END
    ) as priority_score
FROM documents
WHERE texto_completo IS NOT NULL
    AND texto_completo != ''
    AND (
        readability_updated_at IS NULL
        OR updated_at > readability_updated_at
        OR readability_updated_at < (CURRENT_TIMESTAMP - INTERVAL '30 days')
    )
ORDER BY priority_score DESC, ano DESC, id;

COMMENT ON VIEW readability_analysis_queue IS
    'Documents requiring readability analysis, prioritized by recency and text length.
     Used by background jobs to efficiently process documents in optimal order.
     Status values: never_analyzed, content_changed, stale, current';

-- ==============================================================================
-- SECTION 6: CREATE FUNCTION TO UPDATE READABILITY TIMESTAMP
-- ==============================================================================
-- Trigger function to track when readability scores change

DO $$
BEGIN
    RAISE NOTICE 'Creating trigger function for timestamp tracking...';
END $$;

CREATE OR REPLACE FUNCTION update_readability_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    -- Only update timestamp if readability scores actually changed
    IF (NEW.flesch_kincaid_score IS DISTINCT FROM OLD.flesch_kincaid_score
        OR NEW.fog_index IS DISTINCT FROM OLD.fog_index
        OR NEW.smog_index IS DISTINCT FROM OLD.smog_index) THEN
        NEW.readability_updated_at := CURRENT_TIMESTAMP;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop trigger if exists (for idempotency)
DROP TRIGGER IF EXISTS trigger_update_readability_timestamp ON documents;

-- Create trigger
CREATE TRIGGER trigger_update_readability_timestamp
    BEFORE UPDATE ON documents
    FOR EACH ROW
    EXECUTE FUNCTION update_readability_timestamp();

COMMENT ON FUNCTION update_readability_timestamp() IS
    'Automatically updates readability_updated_at timestamp when readability scores change';

-- ==============================================================================
-- SECTION 7: VERIFICATION AND SUMMARY
-- ==============================================================================

DO $$
DECLARE
    total_docs INTEGER;
    docs_with_text INTEGER;
    column_count INTEGER;
    index_count INTEGER;
    view_count INTEGER;
BEGIN
    -- Count documents
    SELECT COUNT(*) INTO total_docs FROM documents;
    SELECT COUNT(*) INTO docs_with_text
    FROM documents
    WHERE texto_completo IS NOT NULL AND texto_completo != '';

    -- Count new columns
    SELECT COUNT(*) INTO column_count
    FROM information_schema.columns
    WHERE table_name = 'documents'
        AND column_name IN (
            'flesch_kincaid_score',
            'fog_index',
            'smog_index',
            'avg_sentence_length',
            'avg_word_length',
            'readability_updated_at'
        );

    -- Count new indexes
    SELECT COUNT(*) INTO index_count
    FROM pg_indexes
    WHERE tablename = 'documents'
        AND indexname LIKE 'idx_documents_%readability%'
           OR indexname IN ('idx_documents_flesch_kincaid', 'idx_documents_fog_index', 'idx_documents_smog_index');

    -- Count new views
    SELECT COUNT(*) INTO view_count
    FROM information_schema.views
    WHERE table_name IN ('readability_summary', 'readability_analysis_queue');

    RAISE NOTICE '';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'MIGRATION 011 SUMMARY';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Columns added: %', column_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Views created: %', view_count;
    RAISE NOTICE '';
    RAISE NOTICE 'Database Statistics:';
    RAISE NOTICE '  Total documents: %', total_docs;
    RAISE NOTICE '  Documents with text: % (%.1f%%)',
                 docs_with_text,
                 (100.0 * docs_with_text / NULLIF(total_docs, 0));
    RAISE NOTICE '  Ready for analysis: %', docs_with_text;
    RAISE NOTICE '';
    RAISE NOTICE 'Next Steps:';
    RAISE NOTICE '  1. Run R scripts to calculate readability scores';
    RAISE NOTICE '  2. Query readability_analysis_queue to prioritize processing';
    RAISE NOTICE '  3. Use readability_summary view for dashboard analytics';
    RAISE NOTICE '';
    RAISE NOTICE '✅ Migration 011 completed successfully!';
    RAISE NOTICE '========================================';
END $$;

-- ==============================================================================
-- ROLLBACK SCRIPT (For reference - DO NOT EXECUTE automatically)
-- ==============================================================================
-- To rollback this migration, execute:
--
-- DROP TRIGGER IF EXISTS trigger_update_readability_timestamp ON documents;
-- DROP FUNCTION IF EXISTS update_readability_timestamp();
-- DROP VIEW IF EXISTS readability_analysis_queue;
-- DROP VIEW IF EXISTS readability_summary;
-- DROP INDEX IF EXISTS idx_documents_readability_stale;
-- DROP INDEX IF EXISTS idx_documents_readability_dashboard;
-- DROP INDEX IF EXISTS idx_documents_smog_index;
-- DROP INDEX IF EXISTS idx_documents_fog_index;
-- DROP INDEX IF EXISTS idx_documents_flesch_kincaid;
-- ALTER TABLE documents DROP COLUMN IF EXISTS readability_updated_at;
-- ALTER TABLE documents DROP COLUMN IF EXISTS avg_word_length;
-- ALTER TABLE documents DROP COLUMN IF EXISTS avg_sentence_length;
-- ALTER TABLE documents DROP COLUMN IF EXISTS smog_index;
-- ALTER TABLE documents DROP COLUMN IF EXISTS fog_index;
-- ALTER TABLE documents DROP COLUMN IF EXISTS flesch_kincaid_score;
--
-- ==============================================================================
