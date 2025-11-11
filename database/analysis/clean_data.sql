-- ==============================================================================
-- DATA CLEANING SCRIPT FOR MONITOR LEGISLATIVO
-- ==============================================================================
-- This script fixes data quality issues identified in the analysis
--
-- IMPORTANT:
-- - Review the analysis results before running this script
-- - Test on a development/staging database first
-- - Create a backup before running: pg_dump -Fc dbname > backup.dump
-- - Run in a transaction so you can rollback if needed
-- ==============================================================================

-- Start transaction for safety
BEGIN;

\echo '================================================================================'
\echo 'MONITOR LEGISLATIVO - DATA CLEANING'
\echo 'Started:', current_timestamp
\echo '================================================================================'

-- Create backup table before making changes
\echo '\n--- CREATING BACKUP TABLE ---'
DROP TABLE IF EXISTS documents_backup_before_cleaning;
CREATE TABLE documents_backup_before_cleaning AS SELECT * FROM documents;
SELECT COUNT(*) as backup_record_count FROM documents_backup_before_cleaning;

\echo '\n--- INITIAL DATA QUALITY CHECK ---'
SELECT
  COUNT(*) as total_records,
  COUNT(*) FILTER (WHERE titulo LIKE '%  %') as double_spaces,
  COUNT(*) FILTER (WHERE titulo LIKE '% ,%' OR titulo LIKE '% .%') as space_before_punct,
  COUNT(*) FILTER (WHERE tipo != TRIM(tipo)) as tipo_has_whitespace,
  (SELECT COUNT(*) FROM (
    SELECT titulo, tipo, data, COUNT(*) as cnt
    FROM documents
    GROUP BY titulo, tipo, data
    HAVING COUNT(*) > 1
  ) AS dups) as duplicate_groups
FROM documents;

-- ==============================================================================
-- 1. FIX TEXT FORMATTING ISSUES
-- ==============================================================================

\echo '\n--- FIXING DOUBLE SPACES IN TITULO ---'
UPDATE documents
SET titulo = REGEXP_REPLACE(titulo, ' +', ' ', 'g')
WHERE titulo LIKE '%  %';

\echo 'Rows affected:', @@ROWCOUNT;

\echo '\n--- FIXING SPACE BEFORE PUNCTUATION ---'
UPDATE documents
SET titulo = REGEXP_REPLACE(titulo, ' ([,.])', '\1', 'g')
WHERE titulo LIKE '% ,%' OR titulo LIKE '% .%';

\echo 'Rows affected:', @@ROWCOUNT;

\echo '\n--- TRIMMING LEADING/TRAILING SPACES FROM TITULO ---'
UPDATE documents
SET titulo = TRIM(titulo)
WHERE titulo != TRIM(titulo);

\echo 'Rows affected:', @@ROWCOUNT;

\echo '\n--- TRIMMING LEADING/TRAILING SPACES FROM TIPO ---'
UPDATE documents
SET tipo = TRIM(tipo)
WHERE tipo != TRIM(tipo);

\echo 'Rows affected:', @@ROWCOUNT;

-- ==============================================================================
-- 2. NORMALIZE TIPO VALUES
-- ==============================================================================

\echo '\n--- NORMALIZING TIPO CAPITALIZATION ---'
-- Ensure consistent capitalization (Title Case)
-- Adjust these rules based on actual data patterns

-- Common patterns to fix:
UPDATE documents
SET tipo = INITCAP(tipo)
WHERE tipo ~ '^[a-z]';  -- Starts with lowercase

\echo 'Rows affected:', @@ROWCOUNT;

-- ==============================================================================
-- 3. HANDLE DUPLICATES (COMMENTED OUT - REVIEW FIRST)
-- ==============================================================================

-- ⚠️ CAUTION: This will delete duplicate records
-- Uncomment only after reviewing the duplicate groups
-- This keeps the record with the LOWEST id (oldest)

\echo '\n--- DUPLICATE HANDLING (DRY RUN) ---'
SELECT
  titulo,
  tipo,
  data,
  COUNT(*) as duplicate_count,
  ARRAY_AGG(id ORDER BY id) as all_ids,
  MIN(id) as id_to_keep
FROM documents
GROUP BY titulo, tipo, data
HAVING COUNT(*) > 1
ORDER BY COUNT(*) DESC
LIMIT 20;

-- Uncomment to actually remove duplicates:
-- \echo '\n--- REMOVING DUPLICATES (KEEPING OLDEST ID) ---'
-- DELETE FROM documents
-- WHERE id NOT IN (
--   SELECT MIN(id)
--   FROM documents
--   GROUP BY titulo, tipo, data
-- );
-- \echo 'Duplicate records deleted:', @@ROWCOUNT;

-- ==============================================================================
-- 4. VALIDATE AND FIX DATA INTEGRITY
-- ==============================================================================

\echo '\n--- FIXING NULL OR EMPTY VALUES ---'
-- Count records with NULL or empty critical fields
SELECT
  COUNT(*) FILTER (WHERE titulo IS NULL OR titulo = '') as empty_titulo,
  COUNT(*) FILTER (WHERE tipo IS NULL OR tipo = '') as empty_tipo,
  COUNT(*) FILTER (WHERE data IS NULL) as empty_data
FROM documents;

-- Option 1: Delete records with missing critical data (uncomment if desired)
-- DELETE FROM documents WHERE titulo IS NULL OR titulo = '' OR tipo IS NULL OR tipo = '';

-- Option 2: Set default values (uncomment and adjust if desired)
-- UPDATE documents SET tipo = 'Desconhecido' WHERE tipo IS NULL OR tipo = '';

\echo '\n--- FIXING FUTURE DATES (if any) ---'
SELECT COUNT(*) as future_dates FROM documents WHERE data > CURRENT_DATE;

-- Fix future dates by setting them to today (uncomment if desired)
-- UPDATE documents SET data = CURRENT_DATE WHERE data > CURRENT_DATE;

\echo '\n--- FIXING ANCIENT DATES (before 1900) ---'
SELECT COUNT(*) as ancient_dates FROM documents WHERE data < '1900-01-01';

-- You may want to review and manually fix these, or delete them
-- DELETE FROM documents WHERE data < '1900-01-01';

-- ==============================================================================
-- 5. FINAL DATA QUALITY CHECK
-- ==============================================================================

\echo '\n--- FINAL DATA QUALITY CHECK ---'
SELECT
  COUNT(*) as total_records,
  COUNT(*) FILTER (WHERE titulo LIKE '%  %') as double_spaces,
  COUNT(*) FILTER (WHERE titulo LIKE '% ,%' OR titulo LIKE '% .%') as space_before_punct,
  COUNT(*) FILTER (WHERE tipo != TRIM(tipo)) as tipo_has_whitespace,
  (SELECT COUNT(*) FROM (
    SELECT titulo, tipo, data, COUNT(*) as cnt
    FROM documents
    GROUP BY titulo, tipo, data
    HAVING COUNT(*) > 1
  ) AS dups) as duplicate_groups,
  COUNT(*) FILTER (WHERE titulo IS NULL OR titulo = '') as empty_titulo,
  COUNT(*) FILTER (WHERE tipo IS NULL OR tipo = '') as empty_tipo,
  COUNT(*) FILTER (WHERE data IS NULL) as empty_data
FROM documents;

-- ==============================================================================
-- 6. SHOW SUMMARY OF CHANGES
-- ==============================================================================

\echo '\n--- SUMMARY OF CHANGES ---'
SELECT
  (SELECT COUNT(*) FROM documents_backup_before_cleaning) as original_count,
  (SELECT COUNT(*) FROM documents) as current_count,
  (SELECT COUNT(*) FROM documents_backup_before_cleaning) - (SELECT COUNT(*) FROM documents) as records_deleted
FROM documents
LIMIT 1;

\echo '\n================================================================================'
\echo 'DATA CLEANING COMPLETE'
\echo 'Finished:', current_timestamp
\echo '================================================================================'
\echo ''
\echo 'NEXT STEPS:'
\echo '1. Review the changes above'
\echo '2. If satisfied, run: COMMIT;'
\echo '3. If not satisfied, run: ROLLBACK;'
\echo '4. After commit, run: VACUUM ANALYZE documents;'
\echo '5. Backup table will remain as: documents_backup_before_cleaning'
\echo '6. To remove backup: DROP TABLE documents_backup_before_cleaning;'
\echo '================================================================================'

-- DO NOT AUTO-COMMIT - Let user review and decide
-- User must manually run COMMIT or ROLLBACK
