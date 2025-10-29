-- Import CSV data into documents table
-- File: lexml_unified_dataset.csv
-- Target: monitor_legislativo.documents

-- ============================================================================
-- STEP 1: Create staging table to hold raw CSV data
-- ============================================================================

DROP TABLE IF EXISTS csv_staging CASCADE;

CREATE TABLE csv_staging (
    titulo TEXT,
    tipo TEXT,
    data TEXT,  -- Import as TEXT first, then convert to DATE
    urn TEXT,
    autor TEXT,
    assuntos TEXT,
    classificacao TEXT,
    jurisdicao TEXT,
    autoridade TEXT,
    ementa TEXT,
    url TEXT,
    localidade TEXT,
    numero TEXT,
    ano TEXT,
    termo_busca TEXT,
    data_coleta TEXT,
    origem TEXT,
    categoria TEXT,
    modal TEXT,
    pais TEXT,
    estado TEXT,
    municipio TEXT,
    fontes_localizacao TEXT,
    _source_file TEXT,
    _extracted_category TEXT,
    _extracted_transport_mode TEXT,
    _deduplication_source TEXT,
    _original_count TEXT,
    _merged_categories TEXT,
    _merged_transport TEXT
);

-- ============================================================================
-- STEP 2: Load CSV data into staging table
-- ============================================================================
-- Note: This will be executed via psql \copy command from the client side
-- \copy csv_staging FROM '/path/to/lexml_unified_dataset.csv' WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '"', ESCAPE '"', NULL '', ENCODING 'UTF8');

-- ============================================================================
-- STEP 3: Transform and insert into documents table
-- ============================================================================

-- Clear existing data if needed (commented out for safety)
-- TRUNCATE TABLE documents CASCADE;

INSERT INTO documents (
    urn,
    titulo,
    conteudo,
    tipo,
    data_publicacao,
    estado,
    autor,
    fonte,
    url,
    metadata,
    transport_category,
    created_at,
    updated_at
)
SELECT
    NULLIF(TRIM(s.urn), ''),
    NULLIF(TRIM(s.titulo), ''),
    NULLIF(TRIM(s.ementa), ''),  -- Use ementa as content
    NULLIF(TRIM(s.tipo), ''),
    -- Convert date string to DATE, handle empty/null values
    CASE
        WHEN TRIM(s.data) = '' OR s.data IS NULL THEN NULL
        ELSE CAST(s.data AS DATE)
    END,
    NULLIF(TRIM(s.estado), ''),
    NULLIF(TRIM(s.autor), ''),
    NULLIF(TRIM(s.origem), ''),  -- Map origem to fonte
    NULLIF(TRIM(s.url), ''),
    -- Create JSONB metadata from additional fields
    jsonb_build_object(
        'assuntos', NULLIF(TRIM(s.assuntos), ''),
        'classificacao', NULLIF(TRIM(s.classificacao), ''),
        'jurisdicao', NULLIF(TRIM(s.jurisdicao), ''),
        'autoridade', NULLIF(TRIM(s.autoridade), ''),
        'localidade', NULLIF(TRIM(s.localidade), ''),
        'numero', NULLIF(TRIM(s.numero), ''),
        'ano', NULLIF(TRIM(s.ano), ''),
        'termo_busca', NULLIF(TRIM(s.termo_busca), ''),
        'data_coleta', NULLIF(TRIM(s.data_coleta), ''),
        'categoria', NULLIF(TRIM(s.categoria), ''),
        'modal', NULLIF(TRIM(s.modal), ''),
        'pais', NULLIF(TRIM(s.pais), ''),
        'municipio', NULLIF(TRIM(s.municipio), ''),
        'fontes_localizacao', NULLIF(TRIM(s.fontes_localizacao), ''),
        '_extracted_category', NULLIF(TRIM(s._extracted_category), ''),
        '_extracted_transport_mode', NULLIF(TRIM(s._extracted_transport_mode), ''),
        '_deduplication_source', NULLIF(TRIM(s._deduplication_source), ''),
        '_original_count', NULLIF(TRIM(s._original_count), ''),
        '_merged_categories', NULLIF(TRIM(s._merged_categories), ''),
        '_merged_transport', NULLIF(TRIM(s._merged_transport), '')
    ),
    NULLIF(TRIM(s.modal), ''),  -- transport_category
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM csv_staging s
-- Handle duplicate URNs - keep first occurrence
ON CONFLICT (urn) DO NOTHING;

-- ============================================================================
-- STEP 4: Verification queries
-- ============================================================================

-- Count rows in staging
SELECT COUNT(*) AS staging_count FROM csv_staging;

-- Count rows in documents
SELECT COUNT(*) AS documents_count FROM documents;

-- Check for any NULL dates
SELECT COUNT(*) AS null_dates FROM documents WHERE data_publicacao IS NULL;

-- Sample of imported data
SELECT id, titulo, tipo, data_publicacao AS data, fonte AS origem
FROM documents
ORDER BY id DESC
LIMIT 10;

-- Check distribution by tipo
SELECT tipo, COUNT(*) as count
FROM documents
GROUP BY tipo
ORDER BY count DESC;

-- Check distribution by estado
SELECT estado, COUNT(*) as count
FROM documents
WHERE estado IS NOT NULL
GROUP BY estado
ORDER BY count DESC
LIMIT 10;
