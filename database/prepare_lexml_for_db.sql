-- Clear existing data and import LexML dataset
-- This script replaces the current documents with the latest LexML data

BEGIN;

-- Backup current data count
DO $$
DECLARE 
    current_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO current_count FROM documents;
    RAISE NOTICE 'Current documents in database: %', current_count;
END $$;

-- Clear existing documents
DELETE FROM documents;
ALTER SEQUENCE documents_id_seq RESTART WITH 1;

-- Create temporary table for CSV import
CREATE TEMP TABLE temp_lexml_import (
    search_term TEXT,
    date_searched DATE,
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
\copy temp_lexml_import FROM 'lexml_overview/data/processed/lexml_latest_results.csv' WITH CSV HEADER;

-- Insert into documents table with proper type mapping and date conversion
INSERT INTO documents (
    urn, titulo, url, data_publicacao, estado, tipo, 
    document_type_full, document_description, document_summary,
    search_term, municipality, justice, region, court_class,
    fonte, transport_category, created_at, updated_at
)
SELECT 
    urn,
    title as titulo,
    url,
    -- Convert date from various formats
    CASE 
        WHEN enacting_date ~ '^\d{4}-\d{2}-\d{2}$' THEN enacting_date::date
        WHEN enacting_date ~ '^\d{2}/\d{2}/\d{4}$' THEN TO_DATE(enacting_date, 'DD/MM/YYYY')
        WHEN enacting_date ~ '^\d{1,2}/\d{1,2}/\d{4}$' THEN TO_DATE(enacting_date, 'DD/MM/YYYY')
        ELSE NULL
    END as data_publicacao,
    UPPER(state) as estado,
    -- Map document types
    CASE 
        WHEN urn_type = 'legislation' THEN 'lei'
        WHEN urn_type = 'jurisprudence' THEN 'jurisprudencia'
        WHEN urn_type = 'doutrina' THEN 'doutrina'
        ELSE 'outro'
    END as tipo,
    document_type_full,
    document_description,
    document_summary,
    search_term,
    municipality,
    justice,
    region,
    court_class,
    'LexML' as fonte,
    'transport_energy' as transport_category,
    CURRENT_TIMESTAMP as created_at,
    CURRENT_TIMESTAMP as updated_at
FROM temp_lexml_import
WHERE urn IS NOT NULL AND urn != '';

-- Update statistics
ANALYZE documents;

-- Report results
DO $$
DECLARE 
    new_count INTEGER;
    type_counts TEXT;
    source_counts TEXT;
BEGIN
    SELECT COUNT(*) INTO new_count FROM documents;
    RAISE NOTICE 'New documents in database: %', new_count;
    
    -- Show type distribution
    SELECT string_agg(tipo || ': ' || count::text, ', ') INTO type_counts
    FROM (SELECT tipo, COUNT(*) FROM documents GROUP BY tipo ORDER BY count DESC) t;
    RAISE NOTICE 'Documents by type: %', type_counts;
    
    -- Show source distribution  
    SELECT string_agg(fonte || ': ' || count::text, ', ') INTO source_counts
    FROM (SELECT fonte, COUNT(*) FROM documents GROUP BY fonte) t;
    RAISE NOTICE 'Documents by source: %', source_counts;
END $$;

COMMIT;

-- Show sample of imported data
SELECT 'Sample of imported documents:' as info;
SELECT titulo, tipo, estado, data_publicacao, search_term 
FROM documents 
ORDER BY created_at DESC 
LIMIT 5;