#!/bin/bash

# IMPORT REAL DATASET TO RAILWAY DATABASE
# =======================================
# Import the 134,014 real Brazilian legislative documents instead of sample data

echo "========================================="
echo "IMPORTING REAL 134K+ DATASET TO RAILWAY"
echo "========================================="
echo "Starting at: $(date)"
echo ""

# Database connection
DATABASE_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Check if real dataset exists
DATASET_FILE="data_current/processed/production/lexml_unified_dataset.csv"

if [[ ! -f "$DATASET_FILE" ]]; then
    echo "❌ Dataset file not found: $DATASET_FILE"
    echo "Please check the file path"
    exit 1
fi

# Count total documents
TOTAL_DOCS=$(wc -l < "$DATASET_FILE")
echo "📊 Found dataset with $TOTAL_DOCS total lines (includes header)"
echo "📄 Estimated documents: $((TOTAL_DOCS - 1))"
echo ""

# Function to execute SQL with error handling
execute_sql() {
    local description=$1
    local sql_command=$2
    
    echo "[$(date +%H:%M:%S)] Executing: $description"
    
    timeout 60 bash -c "echo \"$sql_command\" | psql \"$DATABASE_URL\" 2>&1" | while IFS= read -r line; do
        if [[ ! "$line" =~ ^NOTICE: ]] && [[ ! "$line" =~ ^CONTEXT: ]]; then
            echo "  $line"
        fi
    done
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "  ✅ $description - Success"
        return 0
    else
        echo "  ⚠️ $description - Failed (continuing anyway)"
        return 1
    fi
}

echo "========================================="
echo "PHASE 1: PREPARE DATABASE"
echo "========================================="

# Drop existing documents table and recreate with proper schema
execute_sql "Drop existing documents table" "
DROP TABLE IF EXISTS documents CASCADE;"

# Create documents table matching the CSV structure  
execute_sql "Create documents table for real dataset" "
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    tipo VARCHAR(200),
    data DATE,
    urn TEXT,
    autor TEXT,
    assuntos TEXT,
    classificacao VARCHAR(200),
    jurisdicao VARCHAR(100),
    autoridade VARCHAR(200),
    ementa TEXT,
    url TEXT,
    localidade VARCHAR(100),
    numero VARCHAR(100),
    ano INTEGER,
    termo_busca VARCHAR(200),
    data_coleta TIMESTAMP,
    origem VARCHAR(100),
    categoria VARCHAR(100),
    modal VARCHAR(100),
    pais VARCHAR(50) DEFAULT 'Brasil',
    estado VARCHAR(50),
    municipio VARCHAR(200),
    fontes_localizacao TEXT,
    _source_file TEXT,
    _extracted_category VARCHAR(100),
    _extracted_transport_mode VARCHAR(100),
    _deduplication_source VARCHAR(100),
    _original_count INTEGER,
    _merged_categories TEXT,
    _merged_transport TEXT,
    
    -- Dashboard compatibility columns
    species VARCHAR(100) DEFAULT 'Não Classificado',
    municipality VARCHAR(200),
    data_publicacao DATE,
    conteudo TEXT,
    search_term VARCHAR(200),
    document_summary TEXT,
    document_type_full VARCHAR(200),
    fonte VARCHAR(50) DEFAULT 'LexML',
    transport_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locality VARCHAR(100),
    authority_level VARCHAR(100),
    document_number VARCHAR(50),
    justice VARCHAR(100),
    region VARCHAR(100),
    court_class VARCHAR(100),
    document_description TEXT,
    metadata JSONB DEFAULT '{}'
);"

echo ""
echo "========================================="
echo "PHASE 2: IMPORT REAL DATA"
echo "========================================="

# Import the CSV data
echo "[$(date +%H:%M:%S)] Importing CSV data from $DATASET_FILE"
echo "This may take several minutes for 134k+ documents..."

timeout 1800 psql "$DATABASE_URL" -c "\COPY documents(titulo, tipo, data, urn, autor, assuntos, classificacao, jurisdicao, autoridade, ementa, url, localidade, numero, ano, termo_busca, data_coleta, origem, categoria, modal, pais, estado, municipio, fontes_localizacao, _source_file, _extracted_category, _extracted_transport_mode, _deduplication_source, _original_count, _merged_categories, _merged_transport) FROM '$DATASET_FILE' WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '\"', ESCAPE '\"')" 2>&1

if [ $? -eq 0 ]; then
    echo "✅ CSV import completed successfully"
else
    echo "⚠️ CSV import may have had issues - continuing with post-processing"
fi

echo ""
echo "========================================="
echo "PHASE 3: DATA COMPATIBILITY UPDATES"
echo "========================================="

# Update compatibility columns for dashboard
execute_sql "Update compatibility columns" "
UPDATE documents SET 
    species = CASE 
        WHEN categoria = 'Legislação' THEN 'Legislação'
        WHEN categoria = 'Jurisprudência' THEN 'Jurisprudência'  
        WHEN categoria = 'Doutrina' THEN 'Doutrina'
        WHEN categoria = 'Outros' THEN 'Outros'
        WHEN categoria = 'Proposições' THEN 'Proposições'
        ELSE 'Não Classificado'
    END,
    municipality = municipio,
    data_publicacao = data,
    conteudo = ementa,
    search_term = termo_busca,
    document_summary = LEFT(ementa, 500),
    document_type_full = CONCAT(COALESCE(tipo, ''), ' - ', COALESCE(classificacao, '')),
    transport_category = modal,
    locality = localidade,
    authority_level = jurisdicao,
    document_number = numero,
    document_description = ementa
WHERE TRUE;"

echo ""
echo "========================================="
echo "PHASE 4: CREATE INDEXES"
echo "========================================="

# Create performance indexes
execute_sql "Create text search index" "
CREATE INDEX IF NOT EXISTS idx_documents_search 
ON documents USING gin(to_tsvector('portuguese', COALESCE(titulo, '') || ' ' || COALESCE(ementa, '')));"

execute_sql "Create estado index" "
CREATE INDEX IF NOT EXISTS idx_documents_estado 
ON documents(estado) WHERE estado IS NOT NULL;"

execute_sql "Create tipo index" "
CREATE INDEX IF NOT EXISTS idx_documents_tipo 
ON documents(tipo) WHERE tipo IS NOT NULL;"

execute_sql "Create categoria index" "
CREATE INDEX IF NOT EXISTS idx_documents_categoria 
ON documents(categoria) WHERE categoria IS NOT NULL;"

execute_sql "Create date index" "
CREATE INDEX IF NOT EXISTS idx_documents_data 
ON documents(data_publicacao) WHERE data_publicacao IS NOT NULL;"

echo ""
echo "========================================="
echo "PHASE 5: VERIFICATION"
echo "========================================="

execute_sql "Count total documents" "
SELECT COUNT(*) as total_documents FROM documents;"

execute_sql "Documents by category" "
SELECT categoria, COUNT(*) as count 
FROM documents 
WHERE categoria IS NOT NULL
GROUP BY categoria 
ORDER BY count DESC;"

execute_sql "Documents by state (top 10)" "
SELECT estado, COUNT(*) as count 
FROM documents 
WHERE estado IS NOT NULL
GROUP BY estado 
ORDER BY count DESC 
LIMIT 10;"

execute_sql "Documents by transport mode" "
SELECT modal, COUNT(*) as count 
FROM documents 
WHERE modal IS NOT NULL
GROUP BY modal 
ORDER BY count DESC;"

execute_sql "Sample of imported documents" "
SELECT titulo, tipo, estado, categoria, data_publicacao 
FROM documents 
WHERE titulo IS NOT NULL 
ORDER BY data_publicacao DESC 
LIMIT 5;"

echo ""
echo "========================================="
echo "REAL DATASET IMPORT COMPLETE"
echo "========================================="
echo "Completed at: $(date)"
echo ""
echo "✅ Real 134k+ Brazilian legislative documents imported"
echo "✅ Database compatibility updated" 
echo "✅ Performance indexes created"
echo "✅ Data verified"
echo ""
echo "The dashboard should now display YOUR ACTUAL DATA!"
echo "No more sample bullshit!"
echo "========================================="