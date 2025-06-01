-- Replace old data with corrected data in production
-- Update documents table to use corrected LexML data

-- First, backup the old data (just in case)
CREATE TABLE IF NOT EXISTS documents_backup_889 AS SELECT * FROM documents;
CREATE TABLE IF NOT EXISTS lexml_parsed_enhanced_backup_889 AS SELECT * FROM lexml_parsed_enhanced;

-- Clear old data from documents table
DELETE FROM documents;

-- Insert corrected data into documents table (R Shiny format)
INSERT INTO documents (
    urn, titulo, conteudo, tipo, data_publicacao, estado, autor, fonte, url, metadata
)
SELECT 
    urn,
    title as titulo,
    COALESCE(document_summary, document_description) as conteudo,
    urn_type as tipo,
    enacting_date as data_publicacao,
    state as estado,
    document_type_full as autor,
    'LexML' as fonte,
    url,
    jsonb_build_object(
        'search_term', search_term,
        'country', country,
        'municipality', municipality,
        'justice', justice,
        'region', region,
        'court_class', court_class,
        'source_type', 'corrected_lexml'
    ) as metadata
FROM lexml_documents_corrected
WHERE title IS NOT NULL;

-- Clear old data from lexml_parsed_enhanced table  
DELETE FROM lexml_parsed_enhanced;

-- Insert corrected data into lexml_parsed_enhanced table
INSERT INTO lexml_parsed_enhanced (
    search_term, date_searched, url, title, urn, urn_type, country, state, municipality,
    justice, region, court_class, document_type_full, promulgation_date, document_description
)
SELECT 
    search_term, date_searched, url, title, urn, urn_type, country, state, municipality,
    justice, region, court_class, document_type_full, enacting_date as promulgation_date, document_description
FROM lexml_documents_corrected;

-- Verification queries
SELECT 'Updated documents table' as status, COUNT(*) as records FROM documents;
SELECT 'Updated lexml_parsed_enhanced table' as status, COUNT(*) as records FROM lexml_parsed_enhanced;
SELECT 'Corrected table (source)' as status, COUNT(*) as records FROM lexml_documents_corrected;
SELECT 'View accessibility' as status, COUNT(*) as records FROM lexml_parsed_enhanced_fixed;

-- Check date extraction rates
SELECT 
    'documents table date rate' as metric,
    ROUND((COUNT(CASE WHEN data_publicacao IS NOT NULL THEN 1 END) * 100.0 / COUNT(*)), 1) || '%' as value
FROM documents;

SELECT 
    'lexml_parsed_enhanced date rate' as metric,
    ROUND((COUNT(CASE WHEN promulgation_date IS NOT NULL THEN 1 END) * 100.0 / COUNT(*)), 1) || '%' as value
FROM lexml_parsed_enhanced;

COMMIT;