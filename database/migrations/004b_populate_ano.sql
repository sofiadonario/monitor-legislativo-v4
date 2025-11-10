-- ============================================================================
-- MIGRATION 004b: Populate ano from URN
-- ============================================================================
-- Purpose: Extract year from URN date patterns
--
-- Impact: ~117,208 documents (87.5% coverage)
-- Estimated time: ~6 minutes
--
-- URN Format: urn:lex:br;{state};{municipality}:{level}:{type}:{date};{number}
-- Example: urn:lex:br;rio.janeiro;nova.friburgo:municipal:lei:2017-10-02;4584
-- Extract: 2017
-- ============================================================================

\timing on

BEGIN;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 004b: Populate ano from URN';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Extracting year from URN date patterns';
    RAISE NOTICE 'Started at: %', now();
    RAISE NOTICE '';
END $$;

-- Create backup of current state
CREATE TABLE IF NOT EXISTS documents_backup_004b AS
SELECT * FROM documents WHERE ano IS NOT NULL AND ano != '';

DO $$
BEGIN
    RAISE NOTICE '✓ Created backup table';
END $$;

-- ============================================================================
-- POPULATE ano (Year)
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Populating ano field...';
END $$;

-- Extract year from URN date pattern (YYYY-MM-DD)
UPDATE documents
SET ano = substring(urn from '(\d{4})-\d{2}-\d{2}')
WHERE urn IS NOT NULL
  AND urn ~ '\d{4}-\d{2}-\d{2}'
  AND (ano IS NULL OR ano = '');

DO $$
DECLARE
    updated_count INTEGER;
    total_populated INTEGER;
    coverage_pct NUMERIC;
BEGIN
    GET DIAGNOSTICS updated_count = ROW_COUNT;

    SELECT COUNT(*) INTO total_populated
    FROM documents
    WHERE ano IS NOT NULL AND ano != '';

    coverage_pct := ROUND(100.0 * total_populated / (SELECT COUNT(*) FROM documents), 2);

    RAISE NOTICE '✓ Populated ano for % documents', updated_count;
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 004b COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'ano: % docs (%.2f%% coverage)', total_populated, coverage_pct;
    RAISE NOTICE 'Completed at: %', now();
    RAISE NOTICE '============================================================================';
END $$;

-- Sample of populated data
SELECT
    ano,
    COUNT(*) as count
FROM documents
WHERE ano IS NOT NULL AND ano != ''
GROUP BY ano
ORDER BY ano DESC
LIMIT 20;

COMMIT;

\timing off
