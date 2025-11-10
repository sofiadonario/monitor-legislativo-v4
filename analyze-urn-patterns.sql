-- Comprehensive URN Pattern Analysis for Municipal Documents
-- Purpose: Find ALL possible patterns that indicate municipal origin

-- ============================================================================
-- 1. CURRENT KNOWN PATTERNS
-- ============================================================================
SELECT
    'Current Known Patterns' as analysis_type,
    COUNT(*) as count,
    'municipal OR camara.municipal in URN' as pattern
FROM documents
WHERE urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%';

-- ============================================================================
-- 2. ANALYZE URN STRUCTURE - Find common patterns
-- ============================================================================

-- Extract the jurisdiction level (4th segment after br;state;location)
SELECT
    'Jurisdiction Level Patterns' as analysis_type,
    substring(urn from 'urn:lex:br;[^;]+;[^:]+:([^:]+):') as jurisdiction_level,
    COUNT(*) as count
FROM documents
WHERE urn IS NOT NULL
GROUP BY jurisdiction_level
ORDER BY count DESC
LIMIT 30;

-- ============================================================================
-- 3. FIND PATTERNS WITH "PREFEITURA" (CITY HALL)
-- ============================================================================
SELECT
    'Prefeitura Pattern' as analysis_type,
    COUNT(*) as count,
    'Contains prefeitura' as pattern
FROM documents
WHERE urn ILIKE '%prefeitura%';

-- Sample prefeitura URNs
SELECT
    'Sample Prefeitura URNs' as analysis_type,
    estado,
    urn,
    municipio
FROM documents
WHERE urn ILIKE '%prefeitura%'
LIMIT 10;

-- ============================================================================
-- 4. FIND PATTERNS WITH "EXECUTIVO" AT MUNICIPAL LEVEL
-- ============================================================================
SELECT
    'Executivo Municipal Pattern' as analysis_type,
    COUNT(*) as count,
    'Contains executivo' as pattern
FROM documents
WHERE urn ILIKE '%executivo%';

-- Sample executivo URNs
SELECT
    'Sample Executivo URNs' as analysis_type,
    estado,
    urn,
    municipio
FROM documents
WHERE urn ILIKE '%executivo%'
LIMIT 10;

-- ============================================================================
-- 5. FIND PATTERNS WITH "GABINETE.PREFEITO" (MAYOR'S OFFICE)
-- ============================================================================
SELECT
    'Gabinete Prefeito Pattern' as analysis_type,
    COUNT(*) as count,
    'Contains gabinete.prefeito' as pattern
FROM documents
WHERE urn ILIKE '%gabinete%prefeito%';

-- ============================================================================
-- 6. ANALYZE URN PATTERNS BY STATE FOR POTENTIAL MUNICIPAL DOCUMENTS
-- ============================================================================

-- Check URN patterns that might indicate municipal level but aren't tagged
SELECT
    'Potential Municipal by State' as analysis_type,
    estado,
    COUNT(*) as docs_with_semicolon_pattern,
    COUNT(DISTINCT substring(urn from 'urn:lex:br;[^;]+;([^:]+):')) as unique_locations
FROM documents
WHERE urn ~ 'urn:lex:br;[^;]+;[^:]+:[^:]+'
  AND estado IS NOT NULL
  AND urn NOT LIKE '%:municipal:%'
  AND urn NOT LIKE '%camara.municipal%'
GROUP BY estado
ORDER BY docs_with_semicolon_pattern DESC
LIMIT 20;

-- ============================================================================
-- 7. FIND DOCUMENTS WITH 3 LOCATION SEGMENTS (br;state;municipality)
-- ============================================================================

-- Documents with geographic hierarchy: br;state;municipality:level:type
SELECT
    'Three-Level Geographic Hierarchy' as analysis_type,
    estado,
    COUNT(*) as count,
    'Has br;state;location: pattern' as pattern
FROM documents
WHERE urn ~ 'urn:lex:br;[^;]+;[^:]+:'
  AND estado IS NOT NULL
GROUP BY estado
ORDER BY count DESC;

-- ============================================================================
-- 8. SAMPLE DIVERSE URN PATTERNS TO IDENTIFY MUNICIPAL INDICATORS
-- ============================================================================

-- Get sample URNs from different states to see patterns
SELECT
    'URN Pattern Samples' as analysis_type,
    estado,
    urn,
    municipio,
    CASE
        WHEN municipio IS NOT NULL AND municipio != '' THEN 'Has municipio'
        ELSE 'Missing municipio'
    END as municipio_status
FROM documents
WHERE urn IS NOT NULL
  AND estado IN ('SP', 'RJ', 'MG', 'RS', 'BA', 'PR', 'CE', 'PE')
ORDER BY estado, RANDOM()
LIMIT 50;

-- ============================================================================
-- 9. CHECK FOR "LEGISLATIVO" PATTERN (LEGISLATIVE BRANCH)
-- ============================================================================
SELECT
    'Legislativo Pattern' as analysis_type,
    COUNT(*) as count,
    'Contains legislativo' as pattern
FROM documents
WHERE urn ILIKE '%legislativo%';

-- ============================================================================
-- 10. FIND ALL UNIQUE 4TH SEGMENT PATTERNS (jurisdiction level)
-- ============================================================================

-- This shows all possible jurisdiction levels in the database
SELECT
    'All Jurisdiction Level Values' as analysis_type,
    substring(urn from 'urn:lex:br;[^;]+;[^:]+:([^:]+):') as jurisdiction_level,
    COUNT(*) as count,
    COUNT(DISTINCT estado) as states_using_pattern,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as has_municipio_populated
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ 'urn:lex:br;[^;]+;[^:]+:[^:]+'
GROUP BY jurisdiction_level
ORDER BY count DESC;

-- ============================================================================
-- 11. CHECK FOR DOCUMENTS WITH LOCATION BUT NO MUNICIPAL TAG
-- ============================================================================

-- These might be municipal documents that we're missing
SELECT
    'Potential Missing Municipal Docs' as analysis_type,
    estado,
    COUNT(*) as count_with_location,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as count_with_municipio,
    COUNT(*) - COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as potential_missing
FROM documents
WHERE urn ~ 'urn:lex:br;[^;]+;[^:]+:[^:]+'  -- Has 3-level geographic structure
  AND urn NOT LIKE '%:municipal:%'
  AND urn NOT LIKE '%camara.municipal%'
  AND estado IS NOT NULL
GROUP BY estado
ORDER BY potential_missing DESC;

-- ============================================================================
-- 12. SAMPLE POTENTIAL MUNICIPAL DOCUMENTS WE MIGHT BE MISSING
-- ============================================================================

SELECT
    'Sample Potentially Missed Municipal Docs' as analysis_type,
    estado,
    urn,
    municipio,
    tipo,
    substring(ementa, 1, 100) as ementa_preview
FROM documents
WHERE urn ~ 'urn:lex:br;[^;]+;[^:]+:[^:]+'
  AND urn NOT LIKE '%:municipal:%'
  AND urn NOT LIKE '%camara.municipal%'
  AND (municipio IS NULL OR municipio = '')
  AND estado IN ('SP', 'RJ', 'MG', 'BA', 'PR')
ORDER BY estado, RANDOM()
LIMIT 30;
