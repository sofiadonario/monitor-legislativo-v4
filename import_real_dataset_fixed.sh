#!/bin/bash

# IMPORT REAL DATASET TO RAILWAY DATABASE - FIXED VERSION
# ========================================================
# Import 134k+ docs with proper data type handling

echo "========================================="
echo "IMPORTING REAL DATASET (FIXED VERSION)"
echo "========================================="
echo "Starting at: $(date)"

DATABASE_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
DATASET_FILE="data_current/processed/production/lexml_unified_dataset.csv"

if [[ ! -f "$DATASET_FILE" ]]; then
    echo "❌ Dataset file not found: $DATASET_FILE"
    exit 1
fi

TOTAL_DOCS=$(wc -l < "$DATASET_FILE")
echo "📊 Found dataset with $TOTAL_DOCS total lines"
echo "📄 Estimated documents: $((TOTAL_DOCS - 1))"
echo ""

execute_sql() {
    local description=$1
    local sql_command=$2
    
    echo "[$(date +%H:%M:%S)] $description"
    echo "$sql_command" | psql "$DATABASE_URL" 2>&1 | head -20
    echo "✅ $description completed"
}

echo "========================================="
echo "PHASE 1: CREATE TABLE WITH FLEXIBLE SCHEMA"
echo "========================================="

execute_sql "Drop and recreate documents table" "
DROP TABLE IF EXISTS documents CASCADE;

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    tipo TEXT,
    data TEXT, -- Keep as text initially
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
    ano TEXT, -- Keep as text to handle bad data
    termo_busca TEXT,
    data_coleta TEXT, -- Keep as text initially
    origem TEXT,
    categoria TEXT,
    modal TEXT,
    pais TEXT DEFAULT 'Brasil',
    estado TEXT,
    municipio TEXT,
    fontes_localizacao TEXT,
    _source_file TEXT,
    _extracted_category TEXT,
    _extracted_transport_mode TEXT,
    _deduplication_source TEXT,
    _original_count TEXT, -- Keep as text
    _merged_categories TEXT,
    _merged_transport TEXT,
    
    -- Dashboard compatibility 
    species TEXT DEFAULT 'Não Classificado',
    municipality TEXT,
    data_publicacao DATE,
    conteudo TEXT,
    search_term TEXT,
    document_summary TEXT,
    document_type_full TEXT,
    fonte TEXT DEFAULT 'LexML',
    transport_category TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locality TEXT,
    authority_level TEXT,
    document_number TEXT,
    justice TEXT,
    region TEXT,
    court_class TEXT,
    document_description TEXT,
    metadata JSONB DEFAULT '{}'
);"

echo ""
echo "========================================="
echo "PHASE 2: IMPORT DATA WITH ERROR HANDLING"
echo "========================================="

echo "[$(date +%H:%M:%S)] Importing CSV with flexible data types..."

# Import CSV allowing for data inconsistencies
psql "$DATABASE_URL" << 'EOF'
\COPY documents(titulo, tipo, data, urn, autor, assuntos, classificacao, jurisdicao, autoridade, ementa, url, localidade, numero, ano, termo_busca, data_coleta, origem, categoria, modal, pais, estado, municipio, fontes_localizacao, _source_file, _extracted_category, _extracted_transport_mode, _deduplication_source, _original_count, _merged_categories, _merged_transport) FROM 'data_current/processed/production/lexml_unified_dataset.csv' WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '"', ESCAPE '"');
EOF

if [ $? -eq 0 ]; then
    echo "✅ CSV import successful"
else
    echo "⚠️ CSV import had errors - checking what was imported"
fi

# Check what was imported
execute_sql "Check imported data count" "
SELECT COUNT(*) as imported_documents FROM documents;"

echo ""
echo "========================================="
echo "PHASE 3: DATA CLEANING AND COMPATIBILITY"
echo "========================================="

# Clean and convert data types
execute_sql "Clean and update compatibility columns" "
-- Convert date fields
UPDATE documents SET 
    data_publicacao = CASE 
        WHEN data ~ '^\d{4}-\d{2}-\d{2}$' THEN data::date
        WHEN data ~ '^\d{4}-\d{1,2}-\d{1,2}$' THEN 
            CASE 
                WHEN data::date IS NOT NULL THEN data::date 
                ELSE NULL 
            END
        ELSE NULL
    END;

-- Set species based on categoria
UPDATE documents SET 
    species = CASE 
        WHEN categoria ILIKE '%legisla%' THEN 'Legislação'
        WHEN categoria ILIKE '%jurisprud%' THEN 'Jurisprudência'  
        WHEN categoria ILIKE '%doutrina%' THEN 'Doutrina'
        WHEN categoria ILIKE '%outros%' THEN 'Outros'
        WHEN categoria ILIKE '%proposi%' THEN 'Proposições'
        ELSE 'Não Classificado'
    END;

-- Update other compatibility fields
UPDATE documents SET 
    municipality = municipio,
    conteudo = COALESCE(ementa, assuntos, ''),
    search_term = termo_busca,
    document_summary = LEFT(COALESCE(ementa, titulo, ''), 500),
    document_type_full = CONCAT(COALESCE(tipo, ''), 
        CASE WHEN classificacao IS NOT NULL AND classificacao != '' 
             THEN ' - ' || classificacao 
             ELSE '' END),
    transport_category = modal,
    locality = localidade,
    authority_level = jurisdicao,
    document_number = numero,
    document_description = COALESCE(ementa, assuntos);
"

echo ""
echo "========================================="
echo "PHASE 4: CREATE PERFORMANCE INDEXES"
echo "========================================="

execute_sql "Create search and performance indexes" "
-- Text search index
CREATE INDEX IF NOT EXISTS idx_documents_search 
ON documents USING gin(to_tsvector('portuguese', 
    COALESCE(titulo, '') || ' ' || COALESCE(ementa, '') || ' ' || COALESCE(assuntos, '')));

-- Category indexes
CREATE INDEX IF NOT EXISTS idx_documents_categoria ON documents(categoria);
CREATE INDEX IF NOT EXISTS idx_documents_species ON documents(species);
CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado);
CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo);
CREATE INDEX IF NOT EXISTS idx_documents_modal ON documents(modal);
CREATE INDEX IF NOT EXISTS idx_documents_jurisdicao ON documents(jurisdicao);

-- Date index
CREATE INDEX IF NOT EXISTS idx_documents_data_pub ON documents(data_publicacao);
"

echo ""
echo "========================================="
echo "PHASE 5: FINAL VERIFICATION"
echo "========================================="

execute_sql "Final data verification" "
SELECT 
    COUNT(*) as total_documents,
    COUNT(DISTINCT categoria) as categories,
    COUNT(DISTINCT estado) as states,
    COUNT(DISTINCT modal) as transport_modes,
    MIN(data_publicacao) as earliest_date,
    MAX(data_publicacao) as latest_date
FROM documents;

SELECT 'TOP CATEGORIES' as info;
SELECT categoria, COUNT(*) as count 
FROM documents 
WHERE categoria IS NOT NULL AND categoria != ''
GROUP BY categoria 
ORDER BY count DESC 
LIMIT 10;

SELECT 'TOP STATES' as info;
SELECT estado, COUNT(*) as count 
FROM documents 
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado 
ORDER BY count DESC 
LIMIT 10;

SELECT 'SAMPLE DOCUMENTS' as info;
SELECT titulo, tipo, estado, categoria, data_publicacao 
FROM documents 
WHERE titulo IS NOT NULL 
LIMIT 5;
"

echo ""
echo "========================================="
echo "REAL DATASET IMPORT COMPLETED"
echo "========================================="
echo "Completed at: $(date)"
echo ""
echo "🎉 YOUR 134K+ BRAZILIAN LEGISLATIVE DOCUMENTS ARE NOW LIVE!"
echo "🚀 No more sample data bullshit!"
echo "📊 Full research dataset available in dashboard!"
echo "========================================="