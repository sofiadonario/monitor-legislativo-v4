-- ============================================================================
-- MUNICIPALITY EXTRACTION IMPLEMENTATION SCRIPT (FIXED)
-- ============================================================================
-- This script implements municipality extraction from combined formats
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
    -- Extract from localidade field
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'localidade' as source_field,
        d.localidade as original_text,
        d.tipo as document_type,
        d.categoria_original as category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.localidade) as extract
    WHERE d.localidade IS NOT NULL
    
    UNION ALL
    
    -- Extract from municipio field
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'municipio' as source_field,
        d.municipio as original_text,
        d.tipo as document_type,
        d.categoria_original as category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.municipio) as extract
    WHERE d.municipio IS NOT NULL
    
    UNION ALL
    
    -- Extract from autoridade field
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'autoridade' as source_field,
        d.autoridade as original_text,
        d.tipo as document_type,
        d.categoria_original as category
    FROM documents d
    CROSS JOIN LATERAL extract_municipality_data(d.autoridade) as extract
    WHERE d.autoridade IS NOT NULL
    
    UNION ALL
    
    -- Extract from titulo field (limited to clear municipality mentions)
    SELECT DISTINCT
        d.id,
        extract.municipality_name,
        extract.state_code,
        extract.pattern_type,
        'titulo' as source_field,
        d.titulo as original_text,
        d.tipo as document_type,
        d.categoria_original as category
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

CREATE VIEW municipality_summary AS
SELECT 
    municipality_name,
    COALESCE(state_code, 'Unknown') as state_code,
    COUNT(DISTINCT id) as document_count,
    COUNT(DISTINCT pattern_type) as pattern_types_found,
    COUNT(DISTINCT source_field) as fields_found_in,
    STRING_AGG(DISTINCT pattern_type, ', ' ORDER BY pattern_type) as pattern_types,
    STRING_AGG(DISTINCT source_field, ', ' ORDER BY source_field) as source_fields,
    STRING_AGG(DISTINCT document_type, ', ' ORDER BY document_type) as document_types,
    STRING_AGG(DISTINCT category, ', ' ORDER BY category) as categories,
    MAX(original_text) as example_text
FROM extracted_municipalities
GROUP BY municipality_name, COALESCE(state_code, 'Unknown')
ORDER BY document_count DESC, municipality_name;

-- STEP 4: Update main documents view with extracted municipalities
-- ============================================================================

CREATE VIEW documents_enhanced AS
SELECT 
    d.*,
    -- Enhanced municipality field
    COALESCE(
        em.municipality_name,
        CASE 
            WHEN d.municipio IS NOT NULL AND d.municipio != 'Nacional' THEN d.municipio
            ELSE NULL
        END
    ) as enhanced_municipio,
    
    -- Enhanced state field  
    COALESCE(
        CASE WHEN em.state_code != 'Unknown' THEN em.state_code ELSE NULL END,
        d.estado
    ) as enhanced_estado,
    
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

-- STEP 5: Test queries to see results
-- ============================================================================

SELECT 'MUNICIPALITY EXTRACTION RESULTS' as section;

SELECT 
    COUNT(DISTINCT municipality_name || '|' || state_code) as unique_municipalities_found,
    COUNT(DISTINCT municipality_name) as unique_municipality_names,
    COUNT(DISTINCT CASE WHEN state_code != 'Unknown' THEN state_code END) as states_represented,
    COUNT(*) as total_document_occurrences
FROM extracted_municipalities
WHERE municipality_name IS NOT NULL;

SELECT 'TOP 10 MUNICIPALITIES BY DOCUMENT COUNT' as section;

SELECT 
    municipality_name,
    state_code,
    document_count,
    pattern_types,
    source_fields,
    SUBSTRING(example_text, 1, 80) as example
FROM municipality_summary
WHERE state_code != 'Unknown'
ORDER BY document_count DESC
LIMIT 10;