#!/bin/bash

# Import CSV data into Cloud SQL PostgreSQL database
# Database: monitor_legislativo on mackmonitor-db

set -e  # Exit on error

# Configuration
PROJECT_ID="mackmonitor"
INSTANCE_CONNECTION="mackmonitor:southamerica-east1:mackmonitor-db"
DB_NAME="monitor_legislativo"
DB_USER="monitor_user"
DB_PASSWORD="Sdonario1"

# Paths (absolute)
SCRIPT_DIR="/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/database"
CSV_FILE="/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/production/lexml_unified_dataset.csv"
SQL_FILE="$SCRIPT_DIR/import_csv_to_documents.sql"

# Check if CSV file exists
if [ ! -f "$CSV_FILE" ]; then
    echo "ERROR: CSV file not found: $CSV_FILE"
    exit 1
fi

echo "========================================"
echo "Cloud SQL Import Process"
echo "========================================"
echo "Project: $PROJECT_ID"
echo "Instance: $INSTANCE_CONNECTION"
echo "Database: $DB_NAME"
echo "CSV File: $CSV_FILE"
echo "CSV Size: $(wc -l < "$CSV_FILE") lines"
echo "========================================"
echo ""

# Create directory for unix socket
PROXY_DIR="/tmp/cloudsql"
mkdir -p "$PROXY_DIR"

# Start Cloud SQL Proxy in background using TCP port instead
echo "Starting Cloud SQL Proxy on TCP port 5433..."
cloud_sql_proxy -instances="${INSTANCE_CONNECTION}=tcp:5433" &
PROXY_PID=$!

# Wait for proxy to be ready
echo "Waiting for Cloud SQL Proxy to be ready..."
sleep 8

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$PROXY_PID" ]; then
        echo "Stopping Cloud SQL Proxy (PID: $PROXY_PID)..."
        kill $PROXY_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Set PGPASSWORD for psql
export PGPASSWORD="$DB_PASSWORD"

echo ""
echo "========================================"
echo "STEP 1: Creating staging table..."
echo "========================================"

psql -h 127.0.0.1 -p 5433 -U "$DB_USER" -d "$DB_NAME" <<EOF
DROP TABLE IF EXISTS csv_staging CASCADE;

CREATE TABLE csv_staging (
    titulo TEXT,
    tipo TEXT,
    data TEXT,
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

SELECT 'Staging table created successfully.' AS status;
EOF

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create staging table"
    exit 1
fi

echo ""
echo "========================================"
echo "STEP 2: Loading CSV data..."
echo "========================================"
echo "This may take several minutes for 134,014 rows..."

psql -h 127.0.0.1 -p 5433 -U "$DB_USER" -d "$DB_NAME" <<EOF
\copy csv_staging FROM '$CSV_FILE' WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '"', ESCAPE '"', NULL '', ENCODING 'UTF8');

SELECT COUNT(*) AS rows_loaded FROM csv_staging;
EOF

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to load CSV data"
    exit 1
fi

echo ""
echo "========================================"
echo "STEP 3: Transforming and inserting into documents table..."
echo "========================================"

psql -h 127.0.0.1 -p 5433 -U "$DB_USER" -d "$DB_NAME" <<EOF
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
    NULLIF(TRIM(s.ementa), ''),
    NULLIF(TRIM(s.tipo), ''),
    CASE
        WHEN TRIM(s.data) = '' OR s.data IS NULL THEN NULL
        ELSE CAST(s.data AS DATE)
    END,
    NULLIF(TRIM(s.estado), ''),
    NULLIF(TRIM(s.autor), ''),
    NULLIF(TRIM(s.origem), ''),
    NULLIF(TRIM(s.url), ''),
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
    NULLIF(TRIM(s.modal), ''),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM csv_staging s
ON CONFLICT (urn) DO NOTHING;

SELECT 'Data transformation complete.' AS status;
EOF

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to insert data into documents table"
    exit 1
fi

echo ""
echo "========================================"
echo "STEP 4: Verification"
echo "========================================"

psql -h 127.0.0.1 -p 5433 -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Row counts
SELECT 'Staging table:' AS table_name, COUNT(*) AS row_count FROM csv_staging
UNION ALL
SELECT 'Documents table:', COUNT(*) FROM documents;

-- Check for NULL dates
SELECT COUNT(*) AS documents_with_null_dates FROM documents WHERE data_publicacao IS NULL;

-- Sample of imported data
SELECT id, titulo, tipo, data_publicacao AS data, fonte AS origem
FROM documents
ORDER BY id DESC
LIMIT 5;

-- Distribution by tipo
SELECT tipo, COUNT(*) as count
FROM documents
GROUP BY tipo
ORDER BY count DESC;

-- Distribution by estado
SELECT estado, COUNT(*) as count
FROM documents
WHERE estado IS NOT NULL
GROUP BY estado
ORDER BY count DESC
LIMIT 10;
EOF

echo ""
echo "========================================"
echo "Import Complete!"
echo "========================================"
echo ""
echo "To verify the import in your R Shiny app, it queries:"
echo "  SELECT id, titulo, tipo, data, origem FROM documents"
echo ""
echo "Note: The app uses 'data' column but the table has 'data_publicacao'"
echo "      You may need to update either the app or create a view."
echo ""
