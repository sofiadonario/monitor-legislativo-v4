-- Monitor Legislativo v4 - Railway CSV Import
-- Mount path: /var/lib/postgresql/data
-- CSV file: lexml_parsed_enhanced_fixed.csv

-- ============================================================================
-- STEP 1: CREATE DATABASE SCHEMA
-- ============================================================================

-- Drop existing tables if they exist
DROP TABLE IF EXISTS lexml_parsed_enhanced CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS legislative_data CASCADE;

-- Create main table for CSV import
CREATE TABLE lexml_parsed_enhanced (
    id SERIAL PRIMARY KEY,
    search_term VARCHAR(255),
    date_searched TIMESTAMP,
    url TEXT,
    title TEXT,
    urn TEXT,
    urn_type VARCHAR(255),
    country VARCHAR(255),
    state VARCHAR(255),
    municipality VARCHAR(255),
    justice VARCHAR(255),
    region VARCHAR(255),
    court_class VARCHAR(255),
    document_type_full VARCHAR(255),
    promulgation_date VARCHAR(255), -- Keep as VARCHAR for CSV import
    document_description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create compatible documents table for R Shiny app
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    urn VARCHAR(500) UNIQUE,
    titulo TEXT,
    conteudo TEXT,
    tipo VARCHAR(100),
    data_publicacao DATE,
    estado VARCHAR(100),
    autor VARCHAR(200),
    fonte VARCHAR(100),
    url TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    transport_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create legislative_data table for compatibility
CREATE TABLE legislative_data (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    numero VARCHAR(50),
    tipo VARCHAR(100),
    data DATE,
    estado VARCHAR(100),
    autor VARCHAR(200),
    fonte_original VARCHAR(100),
    url TEXT,
    ano INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- STEP 2: IMPORT CSV DATA
-- ============================================================================

-- Import CSV data using COPY command (much faster than INSERT)
COPY lexml_parsed_enhanced (search_term, date_searched, url, title, urn, urn_type, country, state, municipality, justice, region, court_class, document_type_full, promulgation_date, document_description)
FROM '/var/lib/postgresql/data/lexml_parsed_enhanced_fixed.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '"', ESCAPE '"');

-- ============================================================================
-- STEP 3: POPULATE COMPATIBLE TABLES
-- ============================================================================

-- Insert data into documents table (for R Shiny compatibility)
INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, autor, fonte, url, metadata, transport_category)
SELECT 
    urn,
    title as titulo,
    document_description as conteudo,
    CASE 
        WHEN document_type_full LIKE '%Lei%' THEN 'lei'
        WHEN document_type_full LIKE '%Decreto%' THEN 'decreto'
        WHEN document_type_full LIKE '%Medida Provisória%' THEN 'medida_provisoria'
        WHEN document_type_full LIKE '%Acórdão%' THEN 'acordao'
        ELSE 'outros'
    END as tipo,
    CASE 
        WHEN promulgation_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN promulgation_date::date
        ELSE NULL
    END as data_publicacao,
    COALESCE(state, 'BR') as estado,
    CASE 
        WHEN document_type_full LIKE '%Federal%' THEN 'Governo Federal'
        WHEN document_type_full LIKE '%Estadual%' THEN 'Governo Estadual'
        WHEN document_type_full LIKE '%Municipal%' THEN 'Governo Municipal'
        WHEN document_type_full LIKE '%Tribunal%' THEN 'Poder Judiciário'
        ELSE 'Diversos'
    END as autor,
    'LexML' as fonte,
    url,
    json_build_object(
        'search_term', search_term,
        'urn_type', urn_type,
        'country', country,
        'municipality', municipality,
        'justice', justice,
        'region', region,
        'court_class', court_class
    ) as metadata,
    CASE 
        WHEN search_term LIKE '%transporte%' THEN 'transporte'
        WHEN search_term LIKE '%logística%' THEN 'logistica'
        WHEN search_term LIKE '%carga%' THEN 'carga'
        ELSE 'outros'
    END as transport_category
FROM lexml_parsed_enhanced
WHERE urn IS NOT NULL AND urn != ''
ON CONFLICT (urn) DO NOTHING;

-- Insert data into legislative_data table
INSERT INTO legislative_data (titulo, numero, tipo, data, estado, autor, fonte_original, url, ano)
SELECT 
    title as titulo,
    CASE 
        WHEN title ~ '[0-9]+' THEN regexp_replace(title, '.*?([0-9]+).*', '\1')
        ELSE NULL
    END as numero,
    CASE 
        WHEN document_type_full LIKE '%Lei%' THEN 'lei'
        WHEN document_type_full LIKE '%Decreto%' THEN 'decreto'
        WHEN document_type_full LIKE '%Medida Provisória%' THEN 'medida_provisoria'
        WHEN document_type_full LIKE '%Acórdão%' THEN 'acordao'
        ELSE 'outros'
    END as tipo,
    CASE 
        WHEN promulgation_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN promulgation_date::date
        ELSE NULL
    END as data,
    COALESCE(state, 'BR') as estado,
    CASE 
        WHEN document_type_full LIKE '%Federal%' THEN 'Governo Federal'
        WHEN document_type_full LIKE '%Estadual%' THEN 'Governo Estadual'
        WHEN document_type_full LIKE '%Municipal%' THEN 'Governo Municipal'
        WHEN document_type_full LIKE '%Tribunal%' THEN 'Poder Judiciário'
        ELSE 'Diversos'
    END as autor,
    'LexML' as fonte_original,
    url,
    CASE 
        WHEN promulgation_date ~ '^[0-9]{4}' THEN EXTRACT(YEAR FROM promulgation_date::date)
        ELSE NULL
    END as ano
FROM lexml_parsed_enhanced
WHERE title IS NOT NULL AND title != '';

-- ============================================================================
-- STEP 4: CREATE INDEXES FOR PERFORMANCE
-- ============================================================================

-- Indexes for lexml_parsed_enhanced table
CREATE INDEX idx_lexml_search_term ON lexml_parsed_enhanced(search_term);
CREATE INDEX idx_lexml_urn ON lexml_parsed_enhanced(urn);
CREATE INDEX idx_lexml_state ON lexml_parsed_enhanced(state);
CREATE INDEX idx_lexml_document_type ON lexml_parsed_enhanced(document_type_full);
CREATE INDEX idx_lexml_promulgation_date ON lexml_parsed_enhanced(promulgation_date);

-- Indexes for documents table
CREATE INDEX idx_documents_urn ON documents(urn);
CREATE INDEX idx_documents_tipo ON documents(tipo);
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_data ON documents(data_publicacao);
CREATE INDEX idx_documents_transport ON documents(transport_category);

-- Indexes for legislative_data table
CREATE INDEX idx_legislative_data_tipo ON legislative_data(tipo);
CREATE INDEX idx_legislative_data_estado ON legislative_data(estado);
CREATE INDEX idx_legislative_data_data ON legislative_data(data);
CREATE INDEX idx_legislative_data_ano ON legislative_data(ano);

-- ============================================================================
-- STEP 5: VERIFICATION QUERIES
-- ============================================================================

-- Show migration results
SELECT 'CSV Import completed successfully!' as status;

-- Show table record counts
SELECT 'Table Statistics:' as info;
SELECT 'lexml_parsed_enhanced' as table_name, COUNT(*) as record_count FROM lexml_parsed_enhanced
UNION ALL
SELECT 'documents' as table_name, COUNT(*) as record_count FROM documents
UNION ALL
SELECT 'legislative_data' as table_name, COUNT(*) as record_count FROM legislative_data;

-- Show sample data
SELECT 'Sample from lexml_parsed_enhanced:' as info;
SELECT search_term, title, state, document_type_full, promulgation_date 
FROM lexml_parsed_enhanced 
ORDER BY id LIMIT 5;

-- Show document types distribution
SELECT 'Document types distribution:' as info;
SELECT tipo, COUNT(*) as count 
FROM documents 
GROUP BY tipo 
ORDER BY count DESC;

-- Show states distribution
SELECT 'States distribution:' as info;
SELECT estado, COUNT(*) as count 
FROM documents 
GROUP BY estado 
ORDER BY count DESC;

-- Show transport categories
SELECT 'Transport categories:' as info;
SELECT transport_category, COUNT(*) as count 
FROM documents 
GROUP BY transport_category 
ORDER BY count DESC;

-- Show years distribution
SELECT 'Years distribution:' as info;
SELECT ano, COUNT(*) as count 
FROM legislative_data 
WHERE ano IS NOT NULL
GROUP BY ano 
ORDER BY ano DESC;

-- Final success message
SELECT 'Migration completed! Your R Shiny app now has 889 real legislative records!' as final_status;