-- ============================================================================
-- MIGRATION 004a: Populate tipo from URN
-- ============================================================================
-- Purpose: Extract document type from URN patterns
--
-- Impact: ~117,208 documents (87.5% coverage)
-- Estimated time: ~6 minutes
--
-- URN Format: urn:lex:br;{state};{municipality}:{level}:{type}:{date};{number}
-- Example: urn:lex:br;rio.janeiro;nova.friburgo:municipal:lei:2017-10-02;4584
-- Extract: lei
-- ============================================================================

\timing on

BEGIN;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 004a: Populate tipo from URN';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Extracting document type from URN patterns';
    RAISE NOTICE 'Started at: %', now();
    RAISE NOTICE '';
END $$;

-- Create backup of current state
CREATE TABLE IF NOT EXISTS documents_backup_004a AS
SELECT * FROM documents WHERE tipo IS NOT NULL AND tipo != '';

DO $$
BEGIN
    RAISE NOTICE '✓ Created backup table';
END $$;

-- ============================================================================
-- POPULATE tipo (Document Type)
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Populating tipo field...';
END $$;

-- Extract raw tipo value from URN (simple, fast extraction)
UPDATE documents
SET tipo = substring(urn from ':([^:;]+):\d{4}-\d{2}-\d{2}')
WHERE urn IS NOT NULL
  AND urn ~ ':[^:]+:\d{4}-\d{2}-\d{2}'
  AND (tipo IS NULL OR tipo = '');

DO $$
DECLARE
    updated_count INTEGER;
    total_populated INTEGER;
    coverage_pct NUMERIC;
BEGIN
    GET DIAGNOSTICS updated_count = ROW_COUNT;

    SELECT COUNT(*) INTO total_populated
    FROM documents
    WHERE tipo IS NOT NULL AND tipo != '';

    coverage_pct := ROUND(100.0 * total_populated / (SELECT COUNT(*) FROM documents), 2);

    RAISE NOTICE '✓ Populated tipo for % documents', updated_count;
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 004a COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'tipo: % docs (%.2f%% coverage)', total_populated, coverage_pct;
    RAISE NOTICE 'Completed at: %', now();
    RAISE NOTICE '============================================================================';
END $$;

-- Sample of populated data
SELECT
    tipo,
    COUNT(*) as count
FROM documents
WHERE tipo IS NOT NULL AND tipo != ''
GROUP BY tipo
ORDER BY count DESC
LIMIT 20;

COMMIT;

\timing off
