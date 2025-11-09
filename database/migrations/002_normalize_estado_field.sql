-- ============================================================================
-- NORMALIZE ESTADO FIELD FOR BRAZILIAN LEGISLATIVE DOCUMENTS
-- ============================================================================
--
-- Purpose: Fix inconsistent estado values ('Federal', empty strings, etc.)
-- Problem: Geographic queries fail when estado contains 'Federal' instead of 'DF'
-- Solution: Normalize all estado values to proper 2-letter state codes
--
-- Changes:
-- - 'Federal' → 'DF' (Distrito Federal represents federal legislation)
-- - '' (empty) → NULL (for proper handling)
-- - Trim whitespace and uppercase all values
-- - Validate against Brazilian state codes
--
-- Safe: Creates backup before changes
-- Rollback: Backup table available
--
-- Author: DevOps Engineering Team
-- Date: 2025-11-09
-- ============================================================================

\timing on
\set ON_ERROR_STOP on

BEGIN;

-- ============================================================================
-- 1. ANALYSIS OF CURRENT ESTADO VALUES
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'ESTADO FIELD NORMALIZATION ANALYSIS';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Analyzing current estado distribution...';
    RAISE NOTICE '';
END $$;

-- Show current distribution
SELECT
    CASE
        WHEN estado IS NULL THEN '<NULL>'
        WHEN estado = '' THEN '<EMPTY STRING>'
        ELSE estado
    END as estado_value,
    COUNT(*) as document_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM documents
GROUP BY estado
ORDER BY document_count DESC;

-- ============================================================================
-- 2. CREATE BACKUP TABLE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Creating backup table...';
END $$;

-- Drop backup if exists from previous run
DROP TABLE IF EXISTS documents_estado_backup;

-- Create backup table
CREATE TABLE documents_estado_backup AS
SELECT id, urn, estado as estado_original, created_at
FROM documents;

-- Add index for fast restoration if needed
CREATE INDEX idx_estado_backup_id ON documents_estado_backup(id);

DO $$
DECLARE
    backup_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO backup_count FROM documents_estado_backup;
    RAISE NOTICE '✓ Backup created: % records', backup_count;
END $$;

-- ============================================================================
-- 3. CREATE BRAZILIAN STATES REFERENCE TABLE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Creating Brazilian states reference table...';
END $$;

CREATE TABLE IF NOT EXISTS estados_brasil_ref (
    codigo VARCHAR(2) PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    regiao VARCHAR(20) NOT NULL,
    is_federal BOOLEAN DEFAULT FALSE
);

-- Clear and insert all Brazilian states
TRUNCATE estados_brasil_ref;

INSERT INTO estados_brasil_ref (codigo, nome, regiao, is_federal) VALUES
('AC', 'Acre', 'Norte', FALSE),
('AL', 'Alagoas', 'Nordeste', FALSE),
('AP', 'Amapá', 'Norte', FALSE),
('AM', 'Amazonas', 'Norte', FALSE),
('BA', 'Bahia', 'Nordeste', FALSE),
('CE', 'Ceará', 'Nordeste', FALSE),
('DF', 'Distrito Federal', 'Centro-Oeste', TRUE),
('ES', 'Espírito Santo', 'Sudeste', FALSE),
('GO', 'Goiás', 'Centro-Oeste', FALSE),
('MA', 'Maranhão', 'Nordeste', FALSE),
('MT', 'Mato Grosso', 'Centro-Oeste', FALSE),
('MS', 'Mato Grosso do Sul', 'Centro-Oeste', FALSE),
('MG', 'Minas Gerais', 'Sudeste', FALSE),
('PA', 'Pará', 'Norte', FALSE),
('PB', 'Paraíba', 'Nordeste', FALSE),
('PR', 'Paraná', 'Sul', FALSE),
('PE', 'Pernambuco', 'Nordeste', FALSE),
('PI', 'Piauí', 'Nordeste', FALSE),
('RJ', 'Rio de Janeiro', 'Sudeste', FALSE),
('RN', 'Rio Grande do Norte', 'Nordeste', FALSE),
('RS', 'Rio Grande do Sul', 'Sul', FALSE),
('RO', 'Rondônia', 'Norte', FALSE),
('RR', 'Roraima', 'Norte', FALSE),
('SC', 'Santa Catarina', 'Sul', FALSE),
('SP', 'São Paulo', 'Sudeste', FALSE),
('SE', 'Sergipe', 'Nordeste', FALSE),
('TO', 'Tocantins', 'Norte', FALSE);

DO $$
BEGIN
    RAISE NOTICE '✓ Brazilian states reference table created (27 states)';
END $$;

-- ============================================================================
-- 4. NORMALIZE ESTADO VALUES
-- ============================================================================

DO $$
DECLARE
    federal_count INTEGER;
    empty_count INTEGER;
    whitespace_count INTEGER;
    invalid_count INTEGER;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Normalizing estado values...';
    RAISE NOTICE '';

    -- Step 1: Convert 'Federal' to 'DF'
    UPDATE documents
    SET estado = 'DF'
    WHERE UPPER(TRIM(estado)) = 'FEDERAL';

    GET DIAGNOSTICS federal_count = ROW_COUNT;
    RAISE NOTICE '✓ Converted % ''Federal'' values to ''DF''', federal_count;

    -- Step 2: Convert empty strings to NULL
    UPDATE documents
    SET estado = NULL
    WHERE estado = '' OR estado IS NULL;

    GET DIAGNOSTICS empty_count = ROW_COUNT;
    RAISE NOTICE '✓ Converted % empty/null values to NULL', empty_count;

    -- Step 3: Trim whitespace and uppercase
    UPDATE documents
    SET estado = UPPER(TRIM(estado))
    WHERE estado IS NOT NULL
      AND (estado != UPPER(TRIM(estado)));

    GET DIAGNOSTICS whitespace_count = ROW_COUNT;
    RAISE NOTICE '✓ Trimmed and uppercased % values', whitespace_count;

    -- Step 4: Identify invalid state codes
    SELECT COUNT(*) INTO invalid_count
    FROM documents d
    WHERE d.estado IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM estados_brasil_ref e WHERE e.codigo = d.estado
      );

    IF invalid_count > 0 THEN
        RAISE WARNING '⚠ Found % documents with invalid state codes:', invalid_count;

        -- Show invalid codes
        RAISE NOTICE 'Invalid state codes found:';
        FOR rec IN (
            SELECT DISTINCT d.estado, COUNT(*) as count
            FROM documents d
            WHERE d.estado IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM estados_brasil_ref e WHERE e.codigo = d.estado
              )
            GROUP BY d.estado
            ORDER BY count DESC
        )
        LOOP
            RAISE NOTICE '  - ''%'': % documents', rec.estado, rec.count;
        END LOOP;

        RAISE NOTICE '';
        RAISE NOTICE 'Recommendation: Review these codes and update manually if needed';
    ELSE
        RAISE NOTICE '✓ All state codes are valid';
    END IF;

END $$;

-- ============================================================================
-- 5. ADD FOREIGN KEY CONSTRAINT (OPTIONAL - COMMENTED OUT)
-- ============================================================================

-- Uncomment to enforce referential integrity
-- This will prevent invalid state codes from being inserted

/*
ALTER TABLE documents DROP CONSTRAINT IF EXISTS fk_documents_estado;
ALTER TABLE documents
ADD CONSTRAINT fk_documents_estado
FOREIGN KEY (estado) REFERENCES estados_brasil_ref(codigo)
ON DELETE SET NULL
ON UPDATE CASCADE;

DO $$ BEGIN
    RAISE NOTICE '✓ Foreign key constraint added';
END $$;
*/

-- ============================================================================
-- 6. VERIFICATION QUERIES
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'NORMALIZATION VERIFICATION';
    RAISE NOTICE '============================================================================';
END $$;

-- Show current distribution after normalization
SELECT
    'After Normalization' as status,
    COALESCE(estado, '<NULL>') as estado_value,
    COUNT(*) as document_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM documents
GROUP BY estado
ORDER BY document_count DESC;

-- Verify 'Federal' values are gone
DO $$
DECLARE
    federal_remaining INTEGER;
BEGIN
    SELECT COUNT(*) INTO federal_remaining
    FROM documents
    WHERE UPPER(TRIM(estado)) = 'FEDERAL';

    IF federal_remaining > 0 THEN
        RAISE WARNING '⚠ Still have % ''Federal'' values remaining!', federal_remaining;
    ELSE
        RAISE NOTICE '✓ No ''Federal'' values remaining';
    END IF;
END $$;

-- Verify all states are valid
DO $$
DECLARE
    valid_count INTEGER;
    total_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO total_count
    FROM documents WHERE estado IS NOT NULL;

    SELECT COUNT(*) INTO valid_count
    FROM documents d
    WHERE d.estado IS NOT NULL
      AND EXISTS (
          SELECT 1 FROM estados_brasil_ref e WHERE e.codigo = d.estado
      );

    RAISE NOTICE '✓ Valid state codes: % / % (%.1f%%)',
        valid_count, total_count,
        (valid_count::FLOAT / NULLIF(total_count, 0) * 100);
END $$;

-- ============================================================================
-- 7. UPDATE INDEXES (if they exist)
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE 'Reindexing estado column...';
END $$;

-- Reindex the estado column to optimize new values
REINDEX INDEX CONCURRENTLY IF EXISTS idx_documents_estado;

-- Analyze table to update statistics
ANALYZE documents;

DO $$
BEGIN
    RAISE NOTICE '✓ Indexes updated and statistics refreshed';
END $$;

-- ============================================================================
-- 8. COMPLETION SUMMARY
-- ============================================================================

DO $$
DECLARE
    total_docs INTEGER;
    with_estado INTEGER;
    federal_df INTEGER;
BEGIN
    SELECT COUNT(*) INTO total_docs FROM documents;
    SELECT COUNT(*) INTO with_estado FROM documents WHERE estado IS NOT NULL;
    SELECT COUNT(*) INTO federal_df FROM documents WHERE estado = 'DF';

    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'ESTADO NORMALIZATION COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Total documents: %', total_docs;
    RAISE NOTICE 'Documents with estado: %', with_estado;
    RAISE NOTICE 'Federal documents (DF): %', federal_df;
    RAISE NOTICE 'Backup table: documents_estado_backup';
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '1. Test geographic queries to verify functionality';
    RAISE NOTICE '2. Update R/Shiny code to handle DF for federal documents';
    RAISE NOTICE '3. Drop backup table after verification:';
    RAISE NOTICE '   DROP TABLE documents_estado_backup;';
    RAISE NOTICE '============================================================================';
END $$;

COMMIT;

-- ============================================================================
-- ROLLBACK SCRIPT (if needed)
-- ============================================================================

/*
-- ROLLBACK: Restore original estado values from backup
BEGIN;

UPDATE documents d
SET estado = b.estado_original
FROM documents_estado_backup b
WHERE d.id = b.id;

RAISE NOTICE 'Estado values restored from backup';

-- Optionally drop backup
DROP TABLE documents_estado_backup;

COMMIT;
*/

-- ============================================================================
-- TESTING QUERIES
-- ============================================================================

-- Test 1: Verify federal documents are now DF
SELECT COUNT(*) as federal_documents
FROM documents
WHERE estado = 'DF';

-- Test 2: Check for any remaining problematic values
SELECT
    estado,
    COUNT(*) as count
FROM documents
WHERE estado IS NOT NULL
  AND (
      LENGTH(estado) != 2
      OR estado !~ '^[A-Z]{2}$'
      OR NOT EXISTS (SELECT 1 FROM estados_brasil_ref WHERE codigo = estado)
  )
GROUP BY estado;

-- Test 3: Geographic query performance
EXPLAIN ANALYZE
SELECT estado, COUNT(*) as doc_count
FROM documents
WHERE estado IN ('SP', 'RJ', 'MG', 'DF')
GROUP BY estado;
