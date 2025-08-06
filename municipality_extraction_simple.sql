-- ============================================================================
-- SIMPLE MUNICIPALITY EXTRACTION SCRIPT
-- ============================================================================

-- STEP 1: Test simple patterns to find municipalities
SELECT 'TESTING MUNICIPALITY PATTERNS' as section;

-- Pattern 1: Dash format (City - SP)
SELECT 
    'Dash Pattern Results' as pattern_type,
    COUNT(*) as total_found
FROM documents 
WHERE (municipio ~ '.+ - [A-Z]{2}$' OR localidade ~ '.+ - [A-Z]{2}$' OR autoridade ~ '.+ - [A-Z]{2}$')
  AND (municipio IS NOT NULL OR localidade IS NOT NULL OR autoridade IS NOT NULL);

-- Show some examples of dash patterns
SELECT 
    'DASH PATTERN EXAMPLES' as section;

SELECT DISTINCT
    CASE 
        WHEN municipio ~ '.+ - [A-Z]{2}$' THEN municipio
        WHEN localidade ~ '.+ - [A-Z]{2}$' THEN localidade  
        WHEN autoridade ~ '.+ - [A-Z]{2}$' THEN autoridade
    END as example_text,
    CASE 
        WHEN municipio ~ '.+ - [A-Z]{2}$' THEN 'municipio'
        WHEN localidade ~ '.+ - [A-Z]{2}$' THEN 'localidade'
        WHEN autoridade ~ '.+ - [A-Z]{2}$' THEN 'autoridade'
    END as source_field
FROM documents 
WHERE (municipio ~ '.+ - [A-Z]{2}$' OR localidade ~ '.+ - [A-Z]{2}$' OR autoridade ~ '.+ - [A-Z]{2}$')
  AND (municipio IS NOT NULL OR localidade IS NOT NULL OR autoridade IS NOT NULL)
LIMIT 10;

-- Pattern 2: Parentheses format (City (SP))  
SELECT 
    'PARENTHESES PATTERN EXAMPLES' as section;

SELECT DISTINCT
    CASE 
        WHEN municipio ~ '.+ \([A-Z]{2}\)$' THEN municipio
        WHEN localidade ~ '.+ \([A-Z]{2}\)$' THEN localidade  
        WHEN autoridade ~ '.+ \([A-Z]{2}\)$' THEN autoridade
        WHEN titulo ~ '.+ \([A-Z]{2}\)' THEN titulo
    END as example_text,
    CASE 
        WHEN municipio ~ '.+ \([A-Z]{2}\)$' THEN 'municipio'
        WHEN localidade ~ '.+ \([A-Z]{2}\)$' THEN 'localidade'
        WHEN autoridade ~ '.+ \([A-Z]{2}\)$' THEN 'autoridade' 
        WHEN titulo ~ '.+ \([A-Z]{2}\)' THEN 'titulo'
    END as source_field
FROM documents 
WHERE (municipio ~ '.+ \([A-Z]{2}\)$' OR localidade ~ '.+ \([A-Z]{2}\)$' OR autoridade ~ '.+ \([A-Z]{2}\)$' OR titulo ~ '.+ \([A-Z]{2}\)')
  AND (municipio IS NOT NULL OR localidade IS NOT NULL OR autoridade IS NOT NULL OR titulo IS NOT NULL)
LIMIT 10;

-- Pattern 3: Authority patterns (Prefeitura de...)
SELECT 
    'AUTHORITY PATTERN EXAMPLES' as section;

SELECT DISTINCT
    CASE 
        WHEN autoridade ~* 'prefeitura' THEN autoridade
        WHEN titulo ~* 'prefeitura' THEN titulo
    END as example_text,
    CASE 
        WHEN autoridade ~* 'prefeitura' THEN 'autoridade'
        WHEN titulo ~* 'prefeitura' THEN 'titulo'
    END as source_field
FROM documents 
WHERE (autoridade ~* 'prefeitura' OR titulo ~* 'prefeitura')
  AND (autoridade IS NOT NULL OR titulo IS NOT NULL)
LIMIT 10;

-- Pattern 4: Municipality mentions in titles
SELECT 
    'MUNICIPALITY IN TITLES' as section;

SELECT DISTINCT
    titulo as example_text,
    'titulo' as source_field
FROM documents 
WHERE titulo ~* 'município de [A-ZÁ-Ü][a-zá-ü]+( [A-ZÁ-Ü][a-zá-ü]+)*'
  AND titulo IS NOT NULL
LIMIT 10;

-- STEP 2: Count potential municipalities by pattern type
SELECT 'PATTERN SUMMARY' as section;

SELECT 
    'Dash patterns' as pattern_type,
    COUNT(DISTINCT 
        CASE 
            WHEN municipio ~ '.+ - [A-Z]{2}$' THEN municipio
            WHEN localidade ~ '.+ - [A-Z]{2}$' THEN localidade  
            WHEN autoridade ~ '.+ - [A-Z]{2}$' THEN autoridade
        END
    ) as unique_values
FROM documents 
WHERE (municipio ~ '.+ - [A-Z]{2}$' OR localidade ~ '.+ - [A-Z]{2}$' OR autoridade ~ '.+ - [A-Z]{2}$')

UNION ALL

SELECT 
    'Parentheses patterns' as pattern_type,
    COUNT(DISTINCT 
        CASE 
            WHEN municipio ~ '.+ \([A-Z]{2}\)$' THEN municipio
            WHEN localidade ~ '.+ \([A-Z]{2}\)$' THEN localidade  
            WHEN autoridade ~ '.+ \([A-Z]{2}\)$' THEN autoridade
            WHEN titulo ~ '.+ \([A-Z]{2}\)' THEN titulo
        END
    ) as unique_values
FROM documents 
WHERE (municipio ~ '.+ \([A-Z]{2}\)$' OR localidade ~ '.+ \([A-Z]{2}\)$' OR autoridade ~ '.+ \([A-Z]{2}\)$' OR titulo ~ '.+ \([A-Z]{2}\)')

UNION ALL

SELECT 
    'Authority patterns' as pattern_type,
    COUNT(DISTINCT 
        CASE 
            WHEN autoridade ~* 'prefeitura' THEN autoridade
            WHEN titulo ~* 'prefeitura' THEN titulo
        END
    ) as unique_values
FROM documents 
WHERE (autoridade ~* 'prefeitura' OR titulo ~* 'prefeitura');

-- STEP 3: Simple extraction view
CREATE OR REPLACE VIEW simple_municipality_extraction AS
SELECT DISTINCT
    id,
    -- Extract municipality name before the dash or parentheses
    CASE 
        WHEN municipio ~ '.+ - [A-Z]{2}$' THEN 
            TRIM(regexp_replace(municipio, ' - [A-Z]{2}$', ''))
        WHEN localidade ~ '.+ - [A-Z]{2}$' THEN 
            TRIM(regexp_replace(localidade, ' - [A-Z]{2}$', ''))  
        WHEN autoridade ~ '.+ - [A-Z]{2}$' THEN 
            TRIM(regexp_replace(autoridade, ' - [A-Z]{2}$', ''))
        WHEN municipio ~ '.+ \([A-Z]{2}\)$' THEN 
            TRIM(regexp_replace(municipio, ' \([A-Z]{2}\)$', ''))
        WHEN localidade ~ '.+ \([A-Z]{2}\)$' THEN 
            TRIM(regexp_replace(localidade, ' \([A-Z]{2}\)$', ''))  
        WHEN autoridade ~ '.+ \([A-Z]{2}\)$' THEN 
            TRIM(regexp_replace(autoridade, ' \([A-Z]{2}\)$', ''))
    END as extracted_municipality,
    
    -- Extract state code
    CASE 
        WHEN municipio ~ '.+ - [A-Z]{2}$' THEN 
            regexp_replace(municipio, '.+ - ([A-Z]{2})$', '\1')
        WHEN localidade ~ '.+ - [A-Z]{2}$' THEN 
            regexp_replace(localidade, '.+ - ([A-Z]{2})$', '\1')  
        WHEN autoridade ~ '.+ - [A-Z]{2}$' THEN 
            regexp_replace(autoridade, '.+ - ([A-Z]{2})$', '\1')
        WHEN municipio ~ '.+ \([A-Z]{2}\)$' THEN 
            regexp_replace(municipio, '.+ \(([A-Z]{2})\)$', '\1')
        WHEN localidade ~ '.+ \([A-Z]{2}\)$' THEN 
            regexp_replace(localidade, '.+ \(([A-Z]{2})\)$', '\1')  
        WHEN autoridade ~ '.+ \([A-Z]{2}\)$' THEN 
            regexp_replace(autoridade, '.+ \(([A-Z]{2})\)$', '\1')
    END as extracted_state,
    
    -- Source field
    CASE 
        WHEN municipio ~ '.+ - [A-Z]{2}$' OR municipio ~ '.+ \([A-Z]{2}\)$' THEN 'municipio'
        WHEN localidade ~ '.+ - [A-Z]{2}$' OR localidade ~ '.+ \([A-Z]{2}\)$' THEN 'localidade'  
        WHEN autoridade ~ '.+ - [A-Z]{2}$' OR autoridade ~ '.+ \([A-Z]{2}\)$' THEN 'autoridade'
    END as source_field,
    
    -- Original text
    CASE 
        WHEN municipio ~ '.+ - [A-Z]{2}$' OR municipio ~ '.+ \([A-Z]{2}\)$' THEN municipio
        WHEN localidade ~ '.+ - [A-Z]{2}$' OR localidade ~ '.+ \([A-Z]{2}\)$' THEN localidade  
        WHEN autoridade ~ '.+ - [A-Z]{2}$' OR autoridade ~ '.+ \([A-Z]{2}\)$' THEN autoridade
    END as original_text
    
FROM documents 
WHERE (municipio ~ '.+ - [A-Z]{2}$' OR localidade ~ '.+ - [A-Z]{2}$' OR autoridade ~ '.+ - [A-Z]{2}$'
    OR municipio ~ '.+ \([A-Z]{2}\)$' OR localidade ~ '.+ \([A-Z]{2}\)$' OR autoridade ~ '.+ \([A-Z]{2}\)$')
  AND (municipio IS NOT NULL OR localidade IS NOT NULL OR autoridade IS NOT NULL);

-- STEP 4: Results from extraction
SELECT 'EXTRACTION RESULTS' as section;

SELECT 
    COUNT(DISTINCT extracted_municipality || '|' || extracted_state) as unique_municipalities,
    COUNT(DISTINCT extracted_municipality) as unique_municipality_names,
    COUNT(DISTINCT extracted_state) as states_found,
    COUNT(*) as total_documents
FROM simple_municipality_extraction
WHERE extracted_municipality IS NOT NULL 
  AND LENGTH(extracted_municipality) > 2
  AND extracted_municipality !~* '(lei|decreto|portaria|resolução|federal|brasil|união)';

-- Show the extracted municipalities
SELECT 
    'EXTRACTED MUNICIPALITIES' as section;

SELECT 
    extracted_municipality,
    extracted_state,
    COUNT(*) as document_count,
    source_field,
    MAX(original_text) as example_original
FROM simple_municipality_extraction
WHERE extracted_municipality IS NOT NULL 
  AND LENGTH(extracted_municipality) > 2
  AND extracted_municipality !~* '(lei|decreto|portaria|resolução|federal|brasil|união)'
GROUP BY extracted_municipality, extracted_state, source_field
ORDER BY document_count DESC, extracted_municipality
LIMIT 20;