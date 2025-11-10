-- ============================================================================
-- MIGRATION 004c: Populate numero from URN
-- ============================================================================
-- Purpose: Extract document number from URN patterns
--
-- Impact: ~72,559 documents (54.2% coverage)
-- Estimated time: ~4 minutes
--
-- URN Format: urn:lex:br;{state};{municipality}:{level}:{type}:{date};{number}
-- Example: urn:lex:br;rio.janeiro;nova.friburgo:municipal:lei:2017-10-02;4584
-- Extract: 4584
-- ============================================================================

\timing on

BEGIN;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 004c: Populate numero from URN';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Extracting document number from URN patterns';
    RAISE NOTICE 'Started at: %', now();
    RAISE NOTICE '';
END $$;

-- Create backup of current state
CREATE TABLE IF NOT EXISTS documents_backup_004c AS
SELECT * FROM documents WHERE numero IS NOT NULL AND numero != '';

DO $$
BEGIN
    RAISE NOTICE '✓ Created backup table';
END $$;

-- ============================================================================
-- POPULATE numero (Document Number)
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Populating numero field...';
END $$;

-- Extract document number from end of URN (;{number})
UPDATE documents
SET numero = substring(urn from ';(\d+)$')
WHERE urn IS NOT NULL
  AND urn ~ ';\d+$'
  AND (numero IS NULL OR numero = '');

DO $$
DECLARE
    updated_count INTEGER;
    total_populated INTEGER;
    coverage_pct NUMERIC;
BEGIN
    GET DIAGNOSTICS updated_count = ROW_COUNT;

    SELECT COUNT(*) INTO total_populated
    FROM documents
    WHERE numero IS NOT NULL AND numero != '';

    coverage_pct := ROUND(100.0 * total_populated / (SELECT COUNT(*) FROM documents), 2);

    RAISE NOTICE '✓ Populated numero for % documents', updated_count;
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 004c COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'numero: % docs (%.2f%% coverage)', total_populated, coverage_pct;
    RAISE NOTICE 'Completed at: %', now();
    RAISE NOTICE '============================================================================';
END $$;

-- Sample of populated data
SELECT
    estado,
    tipo,
    ano,
    numero,
    substring(urn from 1 for 80) as urn_preview
FROM documents
WHERE numero IS NOT NULL AND numero != ''
ORDER BY ano DESC, numero DESC
LIMIT 20;

COMMIT;

\timing off
