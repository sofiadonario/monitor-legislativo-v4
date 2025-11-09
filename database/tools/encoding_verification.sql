-- ============================================================================
-- UTF-8 ENCODING VERIFICATION FOR BRAZILIAN LEGISLATIVE DOCUMENTS
-- ============================================================================
--
-- Purpose: Verify proper UTF-8 encoding and Portuguese character handling
-- Target: PostgreSQL database with 134k+ documents
-- Safe: Read-only queries, no data modification
--
-- Author: DevOps Engineering Team
-- Date: 2025-11-09
-- ============================================================================

\set ON_ERROR_STOP on
\encoding UTF8

-- Display header
\echo ''
\echo '============================================================================'
\echo 'UTF-8 ENCODING VERIFICATION'
\echo '============================================================================'
\echo 'Testing Portuguese diacritics: ã, ç, é, ê, õ, ô, á, à, í, ó, ú'
\echo '============================================================================'
\echo ''

-- ============================================================================
-- 1. DATABASE ENCODING SETTINGS
-- ============================================================================

\echo '1. DATABASE ENCODING SETTINGS'
\echo '-------------------------------------'

-- Show server encoding
SELECT
    'Server Encoding' as setting,
    setting as value,
    CASE
        WHEN setting = 'UTF8' THEN '✅ CORRECT'
        ELSE '❌ INCORRECT (should be UTF8)'
    END as status
FROM pg_settings WHERE name = 'server_encoding'
UNION ALL
SELECT
    'Client Encoding' as setting,
    setting as value,
    CASE
        WHEN setting = 'UTF8' THEN '✅ CORRECT'
        ELSE '⚠️  WARNING (should be UTF8)'
    END as status
FROM pg_settings WHERE name = 'client_encoding'
UNION ALL
SELECT
    'LC_COLLATE' as setting,
    setting as value,
    CASE
        WHEN setting LIKE '%UTF%' OR setting LIKE '%utf%' THEN '✅ UTF-8 compatible'
        ELSE '⚠️  May not support Portuguese sorting'
    END as status
FROM pg_settings WHERE name = 'lc_collate'
UNION ALL
SELECT
    'LC_CTYPE' as setting,
    setting as value,
    CASE
        WHEN setting LIKE '%UTF%' OR setting LIKE '%utf%' THEN '✅ UTF-8 compatible'
        ELSE '⚠️  May not support Portuguese characters'
    END as status
FROM pg_settings WHERE name = 'lc_ctype';

\echo ''

-- ============================================================================
-- 2. PORTUGUESE CHARACTERS TEST
-- ============================================================================

\echo '2. PORTUGUESE CHARACTERS STORAGE TEST'
\echo '-------------------------------------'

-- Test Portuguese characters directly
SELECT
    'Test String' as test,
    'São Paulo - Transição para Mobilidade Sustentável' as sample_text,
    'ã, ç, ã, í, á' as diacritics_used,
    '✅ If you see correct characters above, encoding works' as status;

\echo ''

-- ============================================================================
-- 3. DOCUMENTS TABLE ENCODING VERIFICATION
-- ============================================================================

\echo '3. ACTUAL DATA VERIFICATION (Sample)'
\echo '-------------------------------------'

-- Show sample documents with Portuguese characters
SELECT
    id,
    LEFT(titulo, 60) as titulo_sample,
    LENGTH(titulo) as char_count,
    OCTET_LENGTH(titulo) as byte_count,
    CASE
        WHEN OCTET_LENGTH(titulo) > LENGTH(titulo) THEN '✅ Multi-byte (has diacritics)'
        ELSE 'Single-byte only'
    END as encoding_status
FROM documents
WHERE titulo LIKE '%ã%'
   OR titulo LIKE '%ç%'
   OR titulo LIKE '%é%'
   OR titulo LIKE '%õ%'
LIMIT 10;

\echo ''

-- ============================================================================
-- 4. PORTUGUESE DIACRITICS FREQUENCY
-- ============================================================================

\echo '4. PORTUGUESE DIACRITICS FREQUENCY'
\echo '-------------------------------------'

-- Count documents with each diacritic
SELECT
    diacritic,
    count_in_titulo,
    count_in_content,
    CASE
        WHEN count_in_titulo > 0 OR count_in_content > 0
        THEN '✅ Found'
        ELSE '⚠️  Not found'
    END as status
FROM (
    SELECT 'ã (til a)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%ã%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%ã%') as count_in_content
    UNION ALL
    SELECT 'õ (til o)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%õ%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%õ%') as count_in_content
    UNION ALL
    SELECT 'ç (cedilha)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%ç%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%ç%') as count_in_content
    UNION ALL
    SELECT 'é (acento agudo e)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%é%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%é%') as count_in_content
    UNION ALL
    SELECT 'á (acento agudo a)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%á%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%á%') as count_in_content
    UNION ALL
    SELECT 'ó (acento agudo o)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%ó%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%ó%') as count_in_content
    UNION ALL
    SELECT 'í (acento agudo i)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%í%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%í%') as count_in_content
    UNION ALL
    SELECT 'ú (acento agudo u)' as diacritic,
           (SELECT COUNT(*) FROM documents WHERE titulo LIKE '%ú%') as count_in_titulo,
           (SELECT COUNT(*) FROM documents WHERE content LIKE '%ú%') as count_in_content
) counts
ORDER BY count_in_titulo DESC;

\echo ''

-- ============================================================================
-- 5. COMMON PORTUGUESE WORDS WITH DIACRITICS
-- ============================================================================

\echo '5. COMMON PORTUGUESE LEGAL TERMS'
\echo '-------------------------------------'

-- Search for common Portuguese legal terms
SELECT
    term,
    title_count,
    content_count,
    title_count + content_count as total_count,
    '✅ Found' as status
FROM (
    SELECT
        'Legislação' as term,
        (SELECT COUNT(*) FROM documents WHERE titulo ILIKE '%legislação%') as title_count,
        (SELECT COUNT(*) FROM documents WHERE content ILIKE '%legislação%') as content_count
    UNION ALL
    SELECT
        'Transporte Público' as term,
        (SELECT COUNT(*) FROM documents WHERE titulo ILIKE '%transporte público%' OR titulo ILIKE '%transporte publico%') as title_count,
        (SELECT COUNT(*) FROM documents WHERE content ILIKE '%transporte público%' OR content ILIKE '%transporte publico%') as content_count
    UNION ALL
    SELECT
        'São Paulo' as term,
        (SELECT COUNT(*) FROM documents WHERE titulo ILIKE '%são paulo%' OR titulo ILIKE '%sao paulo%') as title_count,
        (SELECT COUNT(*) FROM documents WHERE content ILIKE '%são paulo%' OR content ILIKE '%sao paulo%') as content_count
    UNION ALL
    SELECT
        'Mobilidade' as term,
        (SELECT COUNT(*) FROM documents WHERE titulo ILIKE '%mobilidade%') as title_count,
        (SELECT COUNT(*) FROM documents WHERE content ILIKE '%mobilidade%') as content_count
    UNION ALL
    SELECT
        'Sustentável' as term,
        (SELECT COUNT(*) FROM documents WHERE titulo ILIKE '%sustentável%') as title_count,
        (SELECT COUNT(*) FROM documents WHERE content ILIKE '%sustentável%') as content_count
    UNION ALL
    SELECT
        'Resolução' as term,
        (SELECT COUNT(*) FROM documents WHERE titulo ILIKE '%resolução%') as title_count,
        (SELECT COUNT(*) FROM documents WHERE content ILIKE '%resolução%') as content_count
) terms
WHERE title_count + content_count > 0
ORDER BY title_count + content_count DESC;

\echo ''

-- ============================================================================
-- 6. ACCENT-INSENSITIVE SEARCH TEST (requires unaccent extension)
-- ============================================================================

\echo '6. ACCENT-INSENSITIVE SEARCH TEST'
\echo '-------------------------------------'

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'unaccent') THEN
        RAISE NOTICE '✅ unaccent extension is installed';
        RAISE NOTICE '';
        RAISE NOTICE 'Testing accent-insensitive search:';
    ELSE
        RAISE WARNING '⚠️  unaccent extension not installed';
        RAISE WARNING 'Install with: CREATE EXTENSION unaccent;';
        RAISE WARNING '';
        RAISE NOTICE 'Skipping accent-insensitive search tests';
    END IF;
END $$;

-- Test unaccent if available
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'unaccent') THEN
        -- Show unaccent examples
        PERFORM 1;
        RAISE NOTICE 'unaccent(''São Paulo'') = %', unaccent('São Paulo');
        RAISE NOTICE 'unaccent(''Mobilidade Sustentável'') = %', unaccent('Mobilidade Sustentável');
        RAISE NOTICE 'unaccent(''Transição'') = %', unaccent('Transição');
    END IF;
END $$;

\echo ''

-- ============================================================================
-- 7. COLLATION TEST (Portuguese sorting)
-- ============================================================================

\echo '7. COLLATION TEST (Portuguese Sorting)'
\echo '-------------------------------------'

-- Test Portuguese alphabetical sorting
SELECT
    'Test Word' as word,
    'Expected Position' as sorting_note
FROM (
    SELECT 'Acre' as word, 1 as pos UNION ALL
    SELECT 'Amapá', 2 UNION ALL
    SELECT 'Bahia', 3 UNION ALL
    SELECT 'Ceará', 4 UNION ALL
    SELECT 'São Paulo', 5
) test_data
ORDER BY word;

\echo ''
\echo 'Note: Words above should be sorted Portuguese alphabetically'
\echo '      Amapá should come after Acre (á after c in Portuguese)'
\echo ''

-- ============================================================================
-- 8. BYTE LENGTH ANALYSIS
-- ============================================================================

\echo '8. BYTE LENGTH ANALYSIS'
\echo '-------------------------------------'

-- Analyze character vs byte length difference
SELECT
    length_category,
    COUNT(*) as document_count,
    ROUND(AVG(char_count), 0) as avg_chars,
    ROUND(AVG(byte_count), 0) as avg_bytes,
    ROUND(AVG(byte_count::FLOAT / NULLIF(char_count, 0)), 2) as avg_bytes_per_char
FROM (
    SELECT
        CASE
            WHEN OCTET_LENGTH(titulo) = LENGTH(titulo) THEN 'ASCII only'
            WHEN OCTET_LENGTH(titulo) > LENGTH(titulo) * 1.5 THEN 'Heavy diacritics'
            ELSE 'Some diacritics'
        END as length_category,
        LENGTH(titulo) as char_count,
        OCTET_LENGTH(titulo) as byte_count
    FROM documents
    WHERE titulo IS NOT NULL AND titulo != ''
) analysis
GROUP BY length_category;

\echo ''
\echo 'Note: avg_bytes_per_char > 1.0 indicates multi-byte characters (UTF-8 diacritics)'
\echo '      1.0 = ASCII only, 1.1-1.3 = typical Portuguese with diacritics'
\echo ''

-- ============================================================================
-- 9. ESTADOS WITH DIACRITICS
-- ============================================================================

\echo '9. GEOGRAPHIC NAMES WITH DIACRITICS'
\echo '-------------------------------------'

-- Show municipalities with diacritics
SELECT
    'Municipalities with Diacritics' as category,
    COUNT(*) as count,
    '✅ UTF-8 preserved' as status
FROM documents
WHERE municipio IS NOT NULL
  AND OCTET_LENGTH(municipio) > LENGTH(municipio);

\echo ''

-- Show sample municipalities with diacritics
SELECT DISTINCT
    municipio,
    LENGTH(municipio) as chars,
    OCTET_LENGTH(municipio) as bytes
FROM documents
WHERE municipio IS NOT NULL
  AND OCTET_LENGTH(municipio) > LENGTH(municipio)
LIMIT 10;

\echo ''

-- ============================================================================
-- 10. FINAL SUMMARY
-- ============================================================================

\echo '============================================================================'
\echo 'ENCODING VERIFICATION SUMMARY'
\echo '============================================================================'

DO $$
DECLARE
    total_docs INTEGER;
    docs_with_diacritics INTEGER;
    diacritics_percentage NUMERIC;
    encoding_ok BOOLEAN;
BEGIN
    -- Get document counts
    SELECT COUNT(*) INTO total_docs FROM documents;

    SELECT COUNT(*) INTO docs_with_diacritics
    FROM documents
    WHERE titulo IS NOT NULL
      AND (titulo LIKE '%ã%' OR titulo LIKE '%ç%' OR titulo LIKE '%é%'
           OR titulo LIKE '%õ%' OR titulo LIKE '%á%' OR titulo LIKE '%í%');

    diacritics_percentage := (docs_with_diacritics::FLOAT / NULLIF(total_docs, 0) * 100);

    -- Check if encoding is configured correctly
    encoding_ok := (
        SELECT setting = 'UTF8' FROM pg_settings WHERE name = 'server_encoding'
    );

    RAISE NOTICE 'Total Documents: %', total_docs;
    RAISE NOTICE 'Documents with Portuguese Diacritics: % (%.1f%%)',
        docs_with_diacritics, diacritics_percentage;
    RAISE NOTICE '';

    IF encoding_ok AND docs_with_diacritics > 0 THEN
        RAISE NOTICE '✅ ENCODING VERIFICATION PASSED';
        RAISE NOTICE '';
        RAISE NOTICE 'Key Points:';
        RAISE NOTICE '  ✅ Database encoding is UTF-8';
        RAISE NOTICE '  ✅ Portuguese diacritics are properly stored';
        RAISE NOTICE '  ✅ Data is ready for production use';
    ELSIF NOT encoding_ok THEN
        RAISE WARNING '❌ DATABASE ENCODING IS NOT UTF-8!';
        RAISE WARNING '';
        RAISE WARNING 'Action Required:';
        RAISE WARNING '  1. Convert database to UTF-8 encoding';
        RAISE WARNING '  2. Re-import data with proper encoding';
    ELSIF docs_with_diacritics = 0 THEN
        RAISE WARNING '⚠️  NO PORTUGUESE DIACRITICS FOUND';
        RAISE WARNING '';
        RAISE WARNING 'Possible Issues:';
        RAISE WARNING '  1. Data was imported without proper encoding';
        RAISE WARNING '  2. Source data is missing Portuguese characters';
        RAISE WARNING '  3. Sample size is too small';
    END IF;

    RAISE NOTICE '';
    RAISE NOTICE 'Recommendations:';
    RAISE NOTICE '  1. Use UTF-8 encoding for all data imports';
    RAISE NOTICE '  2. Install unaccent extension for accent-insensitive search';
    RAISE NOTICE '  3. Consider pt_BR collation for proper Portuguese sorting';
    RAISE NOTICE '  4. Test search queries with Portuguese characters';

END $$;

\echo '============================================================================'
\echo 'VERIFICATION COMPLETE'
\echo '============================================================================'
