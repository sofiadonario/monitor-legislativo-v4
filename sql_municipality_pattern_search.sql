-- ============================================================================
-- MUNICIPALITY PATTERN SEARCH - SQL ANALYSIS
-- ============================================================================
-- This script searches for hidden municipality patterns in combined formats
-- like "City - State", "City (State)", etc. in the database fields
-- ============================================================================

-- 1. SEARCH FOR DASH PATTERNS WITH STATE ABBREVIATIONS (City - SP, City - RJ, etc.)
-- ============================================================================

SELECT 'DASH_PATTERNS_STATE_ABBREVIATIONS' as pattern_type, COUNT(*) as total_found FROM (
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as extracted_state,
        'municipality' as source_field
    FROM documents 
    WHERE municipality ~ '.+ - [A-Z]{2}$'
    
    UNION ALL
    
    SELECT DISTINCT
        locality as original_text,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as extracted_state,
        'locality' as source_field
    FROM documents 
    WHERE locality ~ '.+ - [A-Z]{2}$'
    
    UNION ALL
    
    SELECT DISTINCT
        authority as original_text,
        TRIM(SUBSTRING(authority FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(authority FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as extracted_state,
        'authority' as source_field
    FROM documents 
    WHERE authority ~ '.+ - [A-Z]{2}$'
) dash_patterns;

-- 2. DETAILED DASH PATTERNS RESULTS WITH EXAMPLES
-- ============================================================================

WITH dash_patterns AS (
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as extracted_state,
        'municipality' as source_field
    FROM documents 
    WHERE municipality ~ '.+ - [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        locality as original_text,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as extracted_state,
        'locality' as source_field
    FROM documents 
    WHERE locality ~ '.+ - [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        authority as original_text,
        TRIM(SUBSTRING(authority FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(authority FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as extracted_state,
        'authority' as source_field
    FROM documents 
    WHERE authority ~ '.+ - [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(authority FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
)
SELECT 
    extracted_city,
    extracted_state,
    COUNT(*) as occurrences,
    STRING_AGG(DISTINCT source_field, ', ') as found_in_fields,
    STRING_AGG(DISTINCT LEFT(original_text, 100), ' | ' ORDER BY original_text LIMIT 3) as examples
FROM dash_patterns
WHERE extracted_state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
GROUP BY extracted_city, extracted_state
ORDER BY occurrences DESC
LIMIT 50;

-- 3. SEARCH FOR PARENTHESES PATTERNS (City (SP), City (RJ), etc.)
-- ============================================================================

WITH parentheses_patterns AS (
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\2')) as extracted_state,
        'municipality' as source_field
    FROM documents 
    WHERE municipality ~ '.+ \([A-Z]{2}\)'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        locality as original_text,
        TRIM(SUBSTRING(locality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(locality FROM '^(.+) \(([A-Z]{2})\)' FOR '\2')) as extracted_state,
        'locality' as source_field
    FROM documents 
    WHERE locality ~ '.+ \([A-Z]{2}\)'
      AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        titulo as original_text,
        TRIM(SUBSTRING(titulo FROM '^.+?([A-Z][a-záçãõíéóúàâêôü]+) \(([A-Z]{2})\)' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(titulo FROM '^.+?([A-Z][a-záçãõíéóúàâêôü]+) \(([A-Z]{2})\)' FOR '\2')) as extracted_state,
        'title' as source_field
    FROM documents 
    WHERE titulo ~ '[A-Z][a-záçãõíéóúàâêôü]+ \([A-Z]{2}\)'
      AND LENGTH(TRIM(SUBSTRING(titulo FROM '^.+?([A-Z][a-záçãõíéóúàâêôü]+) \(([A-Z]{2})\)' FOR '\1'))) > 2
)
SELECT 
    'PARENTHESES_PATTERNS' as pattern_type,
    extracted_city,
    extracted_state,
    COUNT(*) as occurrences,
    STRING_AGG(DISTINCT source_field, ', ') as found_in_fields,
    STRING_AGG(DISTINCT LEFT(original_text, 100), ' | ' ORDER BY original_text LIMIT 3) as examples
FROM parentheses_patterns
WHERE extracted_state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
GROUP BY extracted_city, extracted_state
ORDER BY occurrences DESC
LIMIT 30;

-- 4. SEARCH FOR COMMA PATTERNS (City, SP - City, RJ, etc.)
-- ============================================================================

WITH comma_patterns AS (
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\2')) as extracted_state,
        'municipality' as source_field
    FROM documents 
    WHERE municipality ~ '.+, [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        locality as original_text,
        TRIM(SUBSTRING(locality FROM '^(.+), ([A-Z]{2})' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(locality FROM '^(.+), ([A-Z]{2})' FOR '\2')) as extracted_state,
        'locality' as source_field
    FROM documents 
    WHERE locality ~ '.+, [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+), ([A-Z]{2})' FOR '\1'))) > 2
)
SELECT 
    'COMMA_PATTERNS' as pattern_type,
    extracted_city,
    extracted_state,
    COUNT(*) as occurrences,
    STRING_AGG(DISTINCT source_field, ', ') as found_in_fields,
    STRING_AGG(DISTINCT LEFT(original_text, 100), ' | ' ORDER BY original_text LIMIT 3) as examples
FROM comma_patterns
WHERE extracted_state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
GROUP BY extracted_city, extracted_state
ORDER BY occurrences DESC
LIMIT 30;

-- 5. SEARCH FOR AUTHORITY PATTERNS (Prefeitura de City, Câmara de City, etc.)
-- ============================================================================

WITH authority_patterns AS (
    SELECT DISTINCT
        authority as original_text,
        CASE 
            WHEN authority ~* 'Prefeitura (Municipal )?de (.+)' THEN 
                TRIM(SUBSTRING(authority FROM 'Prefeitura (Municipal )?de (.+)' FOR '\2'))
            WHEN authority ~* 'Câmara Municipal de (.+)' THEN 
                TRIM(SUBSTRING(authority FROM 'Câmara Municipal de (.+)' FOR '\1'))
            WHEN authority ~* 'Prefeitura da Cidade de (.+)' THEN 
                TRIM(SUBSTRING(authority FROM 'Prefeitura da Cidade de (.+)' FOR '\1'))
            WHEN authority ~* 'Poder Municipal de (.+)' THEN 
                TRIM(SUBSTRING(authority FROM 'Poder Municipal de (.+)' FOR '\1'))
        END as extracted_city,
        'authority' as source_field
    FROM documents 
    WHERE authority ~* '(Prefeitura|Câmara|Poder) (Municipal )?(de|da) .+'
      AND authority NOT ~* '(Federal|Estadual|Nacional|Brasil|República)'
)
SELECT 
    'AUTHORITY_PATTERNS' as pattern_type,
    extracted_city,
    COUNT(*) as occurrences,
    STRING_AGG(DISTINCT LEFT(original_text, 150), ' | ' ORDER BY original_text LIMIT 3) as examples
FROM authority_patterns
WHERE LENGTH(extracted_city) > 2
  AND extracted_city NOT ~* '(Lei|Decreto|Portaria|Resolução|Instrução|Federal|Nacional)'
GROUP BY extracted_city
ORDER BY occurrences DESC
LIMIT 30;

-- 6. SEARCH IN DOCUMENT TITLES FOR CITY MENTIONS
-- ============================================================================

WITH title_city_patterns AS (
    SELECT DISTINCT
        titulo as original_text,
        TRIM(SUBSTRING(titulo FROM '\b([A-Z][a-záçãõíéóúàâêôü]{3,}(?:\s+[A-Za-z][a-záçãõíéóúàâêôü]*)*)\s*[-,/]\s*([A-Z]{2})\b' FOR '\1')) as extracted_city,
        TRIM(SUBSTRING(titulo FROM '\b([A-Z][a-záçãõíéóúàâêôü]{3,}(?:\s+[A-Za-z][a-záçãõíéóúàâêôü]*)*)\s*[-,/]\s*([A-Z]{2})\b' FOR '\2')) as extracted_state,
        'title' as source_field
    FROM documents 
    WHERE titulo ~ '\b[A-Z][a-záçãõíéóúàâêôü]{3,}(\s+[A-Za-z][a-záçãõíéóúàâêôü]*)*\s*[-,/]\s*[A-Z]{2}\b'
      AND titulo NOT ~* '(art|lei|decreto|§|caput|inciso|alínea)'
)
SELECT 
    'TITLE_CITY_PATTERNS' as pattern_type,
    extracted_city,
    extracted_state,
    COUNT(*) as occurrences,
    STRING_AGG(DISTINCT LEFT(original_text, 200), ' | ' ORDER BY original_text LIMIT 2) as examples
FROM title_city_patterns
WHERE extracted_state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
  AND LENGTH(extracted_city) > 2
  AND extracted_city NOT ~* '(Lei|Decreto|Portaria|Art|Artigo|§|Inciso|Federal|Nacional|República|Brasil|União)'
GROUP BY extracted_city, extracted_state
ORDER BY occurrences DESC
LIMIT 30;

-- 7. COMPREHENSIVE SUMMARY OF ALL PATTERNS FOUND
-- ============================================================================

WITH all_municipality_patterns AS (
    -- Dash patterns
    SELECT DISTINCT
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state,
        'dash_municipality' as pattern_source
    FROM documents 
    WHERE municipality ~ '.+ - [A-Z]{2}$' 
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state,
        'dash_locality' as pattern_source
    FROM documents 
    WHERE locality ~ '.+ - [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    -- Parentheses patterns
    SELECT DISTINCT
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\2')) as state,
        'parentheses_municipality' as pattern_source
    FROM documents 
    WHERE municipality ~ '.+ \([A-Z]{2}\)'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1'))) > 2
    
    UNION ALL
    
    -- Comma patterns
    SELECT DISTINCT
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\2')) as state,
        'comma_municipality' as pattern_source
    FROM documents 
    WHERE municipality ~ '.+, [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1'))) > 2
)
SELECT 
    'COMPREHENSIVE_SUMMARY' as analysis_type,
    COUNT(DISTINCT city || '|' || state) as unique_city_state_combinations,
    COUNT(DISTINCT city) as unique_cities_found,
    COUNT(DISTINCT state) as states_with_municipalities,
    STRING_AGG(DISTINCT pattern_source, ', ') as pattern_sources_used
FROM all_municipality_patterns
WHERE state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO');

-- 8. TOP CITIES BY OCCURRENCE ACROSS ALL PATTERNS
-- ============================================================================

WITH all_found_cities AS (
    SELECT DISTINCT
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state,
        1 as occurrence_count
    FROM documents 
    WHERE municipality ~ '.+ - [A-Z]{2}$' 
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state,
        1 as occurrence_count
    FROM documents 
    WHERE locality ~ '.+ - [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    SELECT DISTINCT
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\2')) as state,
        1 as occurrence_count
    FROM documents 
    WHERE municipality ~ '.+ \([A-Z]{2}\)'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1'))) > 2
      
    UNION ALL
    
    SELECT DISTINCT
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\2')) as state,
        1 as occurrence_count
    FROM documents 
    WHERE municipality ~ '.+, [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1'))) > 2
)
SELECT 
    city,
    state,
    SUM(occurrence_count) as total_occurrences
FROM all_found_cities
WHERE state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
  AND city NOT ~* '(Lei|Decreto|Portaria|Art|Artigo|§|Inciso|Federal|Nacional|República|Brasil|União|Resolução|Instrução)'
GROUP BY city, state
ORDER BY total_occurrences DESC, city
LIMIT 100;

-- 9. STATES WITH MOST MUNICIPALITY PATTERNS FOUND
-- ============================================================================

WITH state_municipality_counts AS (
    SELECT state, COUNT(DISTINCT city) as unique_municipalities FROM (
        SELECT 
            TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
            TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state
        FROM documents 
        WHERE municipality ~ '.+ - [A-Z]{2}$' 
          AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
        
        UNION 
        
        SELECT 
            TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
            TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state
        FROM documents 
        WHERE locality ~ '.+ - [A-Z]{2}$'
          AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    ) combined_cities
    WHERE state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
      AND city NOT ~* '(Lei|Decreto|Portaria|Art|Artigo|§|Inciso|Federal|Nacional|República|Brasil|União)'
    GROUP BY state
)
SELECT 
    state,
    unique_municipalities,
    CASE state
        WHEN 'SP' THEN 'São Paulo'
        WHEN 'RJ' THEN 'Rio de Janeiro'
        WHEN 'MG' THEN 'Minas Gerais'
        WHEN 'RS' THEN 'Rio Grande do Sul'
        WHEN 'PR' THEN 'Paraná'
        WHEN 'SC' THEN 'Santa Catarina'
        WHEN 'GO' THEN 'Goiás'
        WHEN 'CE' THEN 'Ceará'
        WHEN 'BA' THEN 'Bahia'
        WHEN 'PE' THEN 'Pernambuco'
        ELSE state
    END as state_full_name
FROM state_municipality_counts
ORDER BY unique_municipalities DESC;

-- 10. SAVE RESULTS TO TEMP TABLE FOR EXPORT
-- ============================================================================

-- Create a table with all found municipalities for export
DROP TABLE IF EXISTS found_municipalities_patterns;

CREATE TEMP TABLE found_municipalities_patterns AS
WITH all_municipality_findings AS (
    -- Dash patterns from municipality field
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state,
        'municipality' as source_field,
        'dash_pattern' as pattern_type
    FROM documents 
    WHERE municipality ~ '.+ - [A-Z]{2}$' 
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    -- Dash patterns from locality field
    SELECT DISTINCT
        locality as original_text,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1')) as city,
        TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\2')) as state,
        'locality' as source_field,
        'dash_pattern' as pattern_type
    FROM documents 
    WHERE locality ~ '.+ - [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(locality FROM '^(.+) - ([A-Z]{2})$' FOR '\1'))) > 2
    
    UNION ALL
    
    -- Parentheses patterns
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\2')) as state,
        'municipality' as source_field,
        'parentheses_pattern' as pattern_type
    FROM documents 
    WHERE municipality ~ '.+ \([A-Z]{2}\)'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+) \(([A-Z]{2})\)' FOR '\1'))) > 2
    
    UNION ALL
    
    -- Comma patterns
    SELECT DISTINCT
        municipality as original_text,
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1')) as city,
        TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\2')) as state,
        'municipality' as source_field,
        'comma_pattern' as pattern_type
    FROM documents 
    WHERE municipality ~ '.+, [A-Z]{2}$'
      AND LENGTH(TRIM(SUBSTRING(municipality FROM '^(.+), ([A-Z]{2})' FOR '\1'))) > 2
)
SELECT 
    city,
    state,
    pattern_type,
    source_field,
    COUNT(*) as occurrences,
    STRING_AGG(DISTINCT LEFT(original_text, 200), ' | ' ORDER BY original_text LIMIT 3) as examples,
    NOW() as analysis_date
FROM all_municipality_findings
WHERE state IN ('SP','RJ','MG','RS','PR','SC','GO','CE','BA','PE','AM','PA','MT','MS','DF','ES','PB','RN','AL','SE','PI','AC','RO','RR','AP','TO')
  AND city NOT ~* '(Lei|Decreto|Portaria|Art|Artigo|§|Inciso|Federal|Nacional|República|Brasil|União|Resolução|Instrução|Medida|Provisória)'
  AND LENGTH(city) >= 3
GROUP BY city, state, pattern_type, source_field
ORDER BY occurrences DESC, city;

-- Show summary of temp table
SELECT 
    'FINAL RESULTS SUMMARY' as summary_type,
    COUNT(DISTINCT city) as unique_cities,
    COUNT(DISTINCT state) as states_covered,
    COUNT(DISTINCT pattern_type) as pattern_types_found,
    SUM(occurrences) as total_occurrences
FROM found_municipalities_patterns;