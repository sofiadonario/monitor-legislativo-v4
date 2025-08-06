-- ============================================================================
-- MUNICIPALITY EXTRACTION IMPLEMENTATION SCRIPT
-- ============================================================================
-- This script immediately implements municipality extraction from combined formats
-- to increase municipality coverage from 1 to 30+ municipalities
-- ============================================================================

-- STEP 1: Create municipality extraction function
-- ============================================================================

CREATE OR REPLACE FUNCTION extract_municipality_data(input_text TEXT)
RETURNS TABLE(
    municipality_name TEXT,
    state_code TEXT,
    pattern_type TEXT
) AS $$
BEGIN
    -- Return empty if input is null or too short
    IF input_text IS NULL OR LENGTH(input_text) < 5 THEN
        RETURN;
    END IF;
    
    -- Pattern 1: Dash format (City - SP)
    IF input_text ~ '.+ - [A-Z]{2}$' THEN
        RETURN QUERY
        SELECT 
            TRIM(SUBSTRING(input_text FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))::TEXT,
            TRIM(SUBSTRING(input_text FROM '^(.+) - ([A-Z]{2})$' FOR '\2'))::TEXT,
            'dash_pattern'::TEXT
        WHERE LENGTH(TRIM(SUBSTRING(input_text FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2;
    END IF;
    
    -- Pattern 2: Parentheses format (City (SP))
    IF input_text ~ '.+ \([A-Z]{2}\)$' THEN
        RETURN QUERY
        SELECT 
            TRIM(SUBSTRING(input_text FROM '^(.+) \(([A-Z]{2})\)$' FOR '\1'))::TEXT,
            TRIM(SUBSTRING(input_text FROM '^(.+) \(([A-Z]{2})\)$' FOR '\2'))::TEXT,
            'parentheses_pattern'::TEXT
        WHERE LENGTH(TRIM(SUBSTRING(input_text FROM '^(.+) \(([A-Z]{2})\)$' FOR '\1'))) > 2;
    END IF;
    
    -- Pattern 3: Comma format (City, SP)
    IF input_text ~ '.+, [A-Z]{2}$' THEN
        RETURN QUERY
        SELECT 
            TRIM(SUBSTRING(input_text FROM '^(.+), ([A-Z]{2})$' FOR '\1'))::TEXT,
            TRIM(SUBSTRING(input_text FROM '^(.+), ([A-Z]{2})$' FOR '\2'))::TEXT,
            'comma_pattern'::TEXT
        WHERE LENGTH(TRIM(SUBSTRING(input_text FROM '^(.+), ([A-Z]{2})$' FOR '\1'))) > 2;
    END IF;
    
    -- Pattern 4: Authority format (Prefeitura de City)
    IF input_text ~* 'Prefeitura (Municipal )?de (.+)' THEN
        RETURN QUERY
        SELECT 
            TRIM(SUBSTRING(input_text FROM '(?i)Prefeitura (Municipal )?de (.+?)(?:\s*[-,(]|$)' FOR '\2'))::TEXT,
            'Unknown'::TEXT,
            'prefeitura_pattern'::TEXT
        WHERE LENGTH(TRIM(SUBSTRING(input_text FROM '(?i)Prefeitura (Municipal )?de (.+?)(?:\s*[-,(]|$)' FOR '\2'))) > 2;
    END IF;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- STEP 2: Create extracted municipalities view
-- ============================================================================

DROP VIEW IF EXISTS extracted_municipalities CASCADE;

CREATE VIEW extracted_municipalities AS
WITH all_extractions AS (
    -- Extract from locality field
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'locality' as source_field,
        d.locality as original_text,
        d.species,
        d.transport_category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.locality) as extract
    WHERE d.locality IS NOT NULL
    
    UNION ALL
    
    -- Extract from municipality field
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'municipality' as source_field,
        d.municipality as original_text,
        d.species,
        d.transport_category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.municipality) as extract
    WHERE d.municipality IS NOT NULL
    
    UNION ALL
    
    -- Extract from authority field
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'authority' as source_field,
        d.authority as original_text,
        d.species,
        d.transport_category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.authority) as extract
    WHERE d.authority IS NOT NULL
    
    UNION ALL
    
    -- Extract from title field (limited to clear municipality mentions)
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'title' as source_field,
        d.titulo as original_text,
        d.species,
        d.transport_category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.titulo) as extract
    WHERE d.titulo IS NOT NULL
      AND d.titulo ~* '(município|cidade|prefeitura)'
)
SELECT *
FROM all_extractions
WHERE municipality_name IS NOT NULL
  AND municipality_name !~* '(lei|decreto|portaria|resolução|instrução|federal|nacional|brasil|república|união|art|artigo|inciso|parágrafo)'
  AND LENGTH(municipality_name) >= 3
  AND (state_code = 'Unknown' OR state_code IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO'));

-- STEP 3: Create municipality summary view
-- ============================================================================

DROP VIEW IF EXISTS municipality_summary CASCADE;

CREATE VIEW municipality_summary AS
SELECT 
    municipality_name,
    COALESCE(state_code, 'Unknown') as state_code,
    COUNT(DISTINCT id) as document_count,
    COUNT(DISTINCT pattern_type) as pattern_types_found,
    COUNT(DISTINCT source_field) as fields_found_in,
    STRING_AGG(DISTINCT pattern_type, ', ' ORDER BY pattern_type) as pattern_types,
    STRING_AGG(DISTINCT source_field, ', ' ORDER BY source_field) as source_fields,
    STRING_AGG(DISTINCT species, ', ' ORDER BY species) as document_species,
    STRING_AGG(DISTINCT transport_category, ', ' ORDER BY transport_category) as transport_categories,
    MAX(original_text) as example_text
FROM extracted_municipalities
GROUP BY municipality_name, COALESCE(state_code, 'Unknown')
ORDER BY document_count DESC, municipality_name;

-- STEP 4: Update main documents view with extracted municipalities
-- ============================================================================

DROP VIEW IF EXISTS documents_enhanced CASCADE;

CREATE VIEW documents_enhanced AS
SELECT 
    d.*,
    -- Enhanced municipality field
    COALESCE(
        em.municipality_name,
        CASE 
            WHEN d.municipality != 'Nacional' THEN d.municipality
            ELSE NULL
        END
    ) as enhanced_municipality,
    
    -- Enhanced state field  
    COALESCE(
        CASE WHEN em.state_code != 'Unknown' THEN em.state_code ELSE NULL END,
        d.estado
    ) as enhanced_state,
    
    -- Extraction metadata
    em.pattern_type as municipality_extraction_method,
    em.source_field as municipality_source_field
    
FROM documents d
LEFT JOIN (
    SELECT DISTINCT ON (id)
        id,
        municipality_name,
        state_code,
        pattern_type,
        source_field
    FROM extracted_municipalities
    ORDER BY id, 
        CASE pattern_type 
            WHEN 'dash_pattern' THEN 1
            WHEN 'parentheses_pattern' THEN 2 
            WHEN 'comma_pattern' THEN 3
            ELSE 4
        END
) em ON d.id = em.id;

-- STEP 5: Immediate results queries
-- ============================================================================

-- Show extracted municipalities summary
SELECT 
    '=== MUNICIPALITY EXTRACTION RESULTS ===' as analysis_section;

SELECT 
    COUNT(DISTINCT municipality_name || '|' || state_code) as unique_municipalities_found,
    COUNT(DISTINCT municipality_name) as unique_municipality_names,
    COUNT(DISTINCT state_code) as states_represented,
    COUNT(*) as total_document_occurrences
FROM municipality_summary
WHERE state_code != 'Unknown';

-- Show top municipalities by document count
SELECT 
    '=== TOP MUNICIPALITIES BY DOCUMENT COUNT ===' as analysis_section;

SELECT 
    municipality_name,
    state_code,
    document_count,
    pattern_types,
    source_fields,
    SUBSTRING(example_text, 1, 100) as example
FROM municipality_summary
WHERE state_code != 'Unknown'
ORDER BY document_count DESC
LIMIT 20;

-- Show municipalities by state
SELECT 
    '=== MUNICIPALITIES BY STATE ===' as analysis_section;

SELECT 
    state_code,
    COUNT(DISTINCT municipality_name) as municipality_count,
    STRING_AGG(municipality_name, ', ' ORDER BY municipality_name) as municipalities
FROM municipality_summary
WHERE state_code != 'Unknown'
GROUP BY state_code
ORDER BY municipality_count DESC;

-- Show pattern type effectiveness
SELECT 
    '=== PATTERN TYPE EFFECTIVENESS ===' as analysis_section;

SELECT 
    pattern_type,
    COUNT(DISTINCT municipality_name || '|' || state_code) as unique_municipalities,
    COUNT(*) as total_occurrences,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1) as percentage
FROM extracted_municipalities
GROUP BY pattern_type
ORDER BY unique_municipalities DESC;

-- Show source field effectiveness  
SELECT 
    '=== SOURCE FIELD EFFECTIVENESS ===' as analysis_section;

SELECT 
    source_field,
    COUNT(DISTINCT municipality_name || '|' || state_code) as unique_municipalities,
    COUNT(*) as total_occurrences
FROM extracted_municipalities
GROUP BY source_field
ORDER BY unique_municipalities DESC;

-- STEP 6: Validation queries
-- ============================================================================

-- Show questionable extractions for manual review
SELECT 
    '=== QUESTIONABLE EXTRACTIONS FOR REVIEW ===' as analysis_section;

SELECT 
    municipality_name,
    state_code,
    pattern_type,
    source_field,
    SUBSTRING(original_text, 1, 150) as original_text,
    'Review: Long name or unusual pattern' as review_reason
FROM extracted_municipalities
WHERE LENGTH(municipality_name) > 50
   OR municipality_name ~* '(análise|gestão|potencial|levantamento|terceirização|distinguishing)'
ORDER BY LENGTH(municipality_name) DESC
LIMIT 10;

-- Show successful extractions examples
SELECT 
    '=== SUCCESSFUL EXTRACTION EXAMPLES ===' as analysis_section;

SELECT DISTINCT
    municipality_name,
    state_code,
    pattern_type,
    SUBSTRING(original_text, 1, 100) as example
FROM extracted_municipalities
WHERE LENGTH(municipality_name) BETWEEN 3 AND 30
  AND municipality_name ~* '^[A-ZÁÇÃÕÍÉÓÚÀÂÊÔÜ][a-záçãõíéóúàâêôü]'
  AND state_code != 'Unknown'
ORDER BY state_code, municipality_name
LIMIT 20;

-- STEP 7: Create indexes for performance
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_extracted_municipalities_name ON extracted_municipalities(municipality_name);
CREATE INDEX IF NOT EXISTS idx_extracted_municipalities_state ON extracted_municipalities(state_code);
CREATE INDEX IF NOT EXISTS idx_extracted_municipalities_pattern ON extracted_municipalities(pattern_type);

-- STEP 8: Final summary
-- ============================================================================

SELECT 
    '=== IMPLEMENTATION SUMMARY ===' as final_section;

SELECT 
    'Municipality extraction function created' as status
UNION ALL
SELECT 
    'Views created: extracted_municipalities, municipality_summary, documents_enhanced' as status
UNION ALL
SELECT 
    'Indexes created for performance optimization' as status
UNION ALL
SELECT 
    CONCAT('Found approximately ', COUNT(DISTINCT municipality_name), ' municipalities from combined patterns') as status
FROM municipality_summary;

SELECT 
    '=== NEXT STEPS ===' as recommendations;

SELECT 
    '1. Review questionable extractions manually' as step
UNION ALL
SELECT 
    '2. Update dashboard to use documents_enhanced view' as step  
UNION ALL
SELECT 
    '3. Add municipality validation against IBGE database' as step
UNION ALL
SELECT 
    '4. Monitor extraction quality and refine patterns' as step
UNION ALL
SELECT 
    '5. Consider expanding to additional text fields' as step;