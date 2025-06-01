-- Final LexML import script - handles all 1949 records
-- Creates synthetic URNs for records without them

BEGIN;

-- Clear existing data
DELETE FROM documents;
ALTER SEQUENCE documents_id_seq RESTART WITH 1;

-- Create temporary table
CREATE TEMP TABLE temp_lexml_import (
    row_id SERIAL,
    search_term TEXT,
    date_searched TEXT,
    url TEXT,
    title TEXT,
    urn TEXT,
    urn_type TEXT,
    country TEXT,
    state TEXT,
    municipality TEXT,
    justice TEXT,
    region TEXT,
    court_class TEXT,
    document_type_full TEXT,
    enacting_date TEXT,
    document_description TEXT,
    document_summary TEXT
);

-- Import CSV data
\copy temp_lexml_import(search_term, date_searched, url, title, urn, urn_type, country, state, municipality, justice, region, court_class, document_type_full, enacting_date, document_description, document_summary) FROM 'lexml_overview/data/processed/lexml_latest_results.csv' WITH CSV HEADER;

-- Show import statistics
DO $$
DECLARE 
    total_csv INTEGER;
    empty_urns INTEGER;
    valid_urns INTEGER;
BEGIN
    SELECT COUNT(*) INTO total_csv FROM temp_lexml_import;
    SELECT COUNT(*) INTO empty_urns FROM temp_lexml_import WHERE urn IS NULL OR urn = '';
    SELECT COUNT(*) INTO valid_urns FROM temp_lexml_import WHERE urn IS NOT NULL AND urn != '';
    
    RAISE NOTICE 'CSV records loaded: %', total_csv;
    RAISE NOTICE 'Records with empty URNs: %', empty_urns;
    RAISE NOTICE 'Records with valid URNs: %', valid_urns;
END $$;

-- Update empty URNs with synthetic ones
UPDATE temp_lexml_import 
SET urn = 'urn:lex:br:synthetic:' || row_id || ':' || 
    COALESCE(REPLACE(LOWER(search_term), ' ', '.'), 'unknown') || ':' ||
    COALESCE(REPLACE(REGEXP_REPLACE(LOWER(title), '[^a-z0-9]', '', 'g'), ' ', ''), 'untitled')
WHERE urn IS NULL OR urn = '';

-- Insert all data into documents table
INSERT INTO documents (
    urn, titulo, url, data_publicacao, estado, tipo, 
    document_type_full, document_description, document_summary,
    search_term, municipality, justice, region, court_class,
    fonte, transport_category, created_at, updated_at
)
SELECT 
    urn,
    COALESCE(NULLIF(title, ''), 'Untitled Document') as titulo,
    NULLIF(url, '') as url,
    -- Convert date from various formats
    CASE 
        WHEN enacting_date ~ '^\d{4}-\d{2}-\d{2}$' THEN enacting_date::date
        WHEN enacting_date ~ '^\d{2}/\d{2}/\d{4}$' THEN TO_DATE(enacting_date, 'DD/MM/YYYY')
        WHEN enacting_date ~ '^\d{1,2}/\d{1,2}/\d{4}$' THEN TO_DATE(enacting_date, 'DD/MM/YYYY')
        WHEN enacting_date ~ '^\d{4}$' THEN (enacting_date || '-01-01')::date
        ELSE NULL
    END as data_publicacao,
    CASE 
        WHEN state IS NOT NULL AND LENGTH(TRIM(state)) = 2 THEN UPPER(TRIM(state))
        WHEN state IS NOT NULL AND LENGTH(TRIM(state)) > 2 THEN UPPER(TRIM(state))
        ELSE NULL
    END as estado,
    -- Map document types
    CASE 
        WHEN urn_type = 'legislation' THEN 'lei'
        WHEN urn_type = 'jurisprudence' THEN 'jurisprudencia'
        WHEN urn_type = 'doutrina' THEN 'doutrina'
        ELSE 'outro'
    END as tipo,
    NULLIF(document_type_full, '') as document_type_full,
    NULLIF(document_description, '') as document_description,
    NULLIF(document_summary, '') as document_summary,
    NULLIF(search_term, '') as search_term,
    NULLIF(municipality, '') as municipality,
    NULLIF(justice, '') as justice,
    NULLIF(region, '') as region,
    NULLIF(court_class, '') as court_class,
    'LexML' as fonte,
    'transport_energy' as transport_category,
    CURRENT_TIMESTAMP as created_at,
    CURRENT_TIMESTAMP as updated_at
FROM temp_lexml_import
ON CONFLICT (urn) DO UPDATE SET
    titulo = EXCLUDED.titulo,
    url = EXCLUDED.url,
    data_publicacao = EXCLUDED.data_publicacao,
    estado = EXCLUDED.estado,
    updated_at = CURRENT_TIMESTAMP;

-- Update statistics
ANALYZE documents;

-- Report final results
DO $$
DECLARE 
    final_count INTEGER;
    type_counts TEXT;
    state_counts TEXT;
    date_range TEXT;
    search_term_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO final_count FROM documents;
    RAISE NOTICE 'Final documents in database: %', final_count;
    
    -- Show type distribution
    SELECT string_agg(tipo || ': ' || count::text, ', ') INTO type_counts
    FROM (SELECT tipo, COUNT(*) FROM documents GROUP BY tipo ORDER BY count DESC) t;
    RAISE NOTICE 'Documents by type: %', type_counts;
    
    -- Count unique search terms
    SELECT COUNT(DISTINCT search_term) INTO search_term_count FROM documents WHERE search_term IS NOT NULL;
    RAISE NOTICE 'Unique search terms: %', search_term_count;
    
    -- Show state distribution (top 5)
    SELECT string_agg(estado || ': ' || count::text, ', ') INTO state_counts
    FROM (SELECT COALESCE(estado, 'NULL') as estado, COUNT(*) FROM documents GROUP BY estado ORDER BY count DESC LIMIT 5) t;
    RAISE NOTICE 'Top 5 states: %', state_counts;
    
    -- Show date range
    SELECT MIN(data_publicacao) || ' to ' || MAX(data_publicacao) INTO date_range FROM documents WHERE data_publicacao IS NOT NULL;
    RAISE NOTICE 'Date range: %', COALESCE(date_range, 'No valid dates');
END $$;

COMMIT;

-- Show sample of imported data
SELECT 'Final sample of imported documents:' as info;
SELECT LEFT(titulo, 50) as titulo_short, tipo, estado, data_publicacao, search_term, 
       CASE WHEN urn LIKE 'urn:lex:br:synthetic:%' THEN 'SYNTHETIC' ELSE 'ORIGINAL' END as urn_type
FROM documents 
ORDER BY created_at DESC 
LIMIT 15;