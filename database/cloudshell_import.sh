#!/bin/bash
# ==============================================================================
# CLOUD SHELL IMPORT SCRIPT - Execute this in Google Cloud Shell
# ==============================================================================
# This script imports the CSV data directly from Cloud Storage into Cloud SQL
# No local network connectivity required!
# ==============================================================================

set -e  # Exit on error

echo "=========================================="
echo "Monitor Legislativo - Database Import"
echo "=========================================="
echo ""

# Configuration
PROJECT_ID="mackmonitor"
INSTANCE_NAME="mackmonitor-db"
DATABASE_NAME="monitor_legislativo"
DB_USER="monitor_user"
CSV_GCS_PATH="gs://mackmonitor-data/imports/lexml_unified_dataset.csv"
TABLE_NAME="documents"

echo "📋 Configuration:"
echo "   Project: $PROJECT_ID"
echo "   Instance: $INSTANCE_NAME"
echo "   Database: $DATABASE_NAME"
echo "   CSV: $CSV_GCS_PATH"
echo ""

# Step 1: Create temporary import table
echo "🔧 Step 1: Creating temporary import table..."
gcloud sql connect "$INSTANCE_NAME" --user="$DB_USER" --database="$DATABASE_NAME" --project="$PROJECT_ID" <<'SQL'
-- Drop temp table if it exists
DROP TABLE IF EXISTS temp_import;

-- Create temp table matching CSV structure
CREATE TABLE temp_import (
  titulo TEXT,
  tipo TEXT,
  data TEXT,  -- Will convert to DATE later
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
  source_file TEXT,
  extracted_category TEXT,
  extracted_transport_mode TEXT,
  deduplication_source TEXT,
  original_count TEXT,
  merged_categories TEXT,
  merged_transport TEXT
);

\q
SQL

echo "✅ Temporary table created"
echo ""

# Step 2: Import CSV from Cloud Storage
echo "🚀 Step 2: Importing CSV data from Cloud Storage..."
echo "   This may take several minutes for 134,014 documents..."
echo ""

gcloud sql import csv "$INSTANCE_NAME" \
  "$CSV_GCS_PATH" \
  --database="$DATABASE_NAME" \
  --table="temp_import" \
  --project="$PROJECT_ID" \
  --quiet

echo "✅ CSV data imported to temp_import table"
echo ""

# Step 3: Transform and insert into documents table
echo "🔄 Step 3: Transforming data and inserting into documents table..."
gcloud sql connect "$INSTANCE_NAME" --user="$DB_USER" --database="$DATABASE_NAME" --project="$PROJECT_ID" <<'SQL'
-- Insert transformed data into documents table
INSERT INTO documents (
  titulo,
  tipo,
  data_publicacao,
  urn,
  autor,
  assuntos,
  classificacao,
  jurisdicao,
  autoridade,
  ementa,
  url,
  localidade,
  numero,
  ano,
  termo_busca,
  data_coleta,
  fonte,
  categoria,
  modal,
  pais,
  estado,
  municipio,
  fontes_localizacao,
  metadata
)
SELECT
  titulo,
  tipo,
  -- Convert data string to DATE (handle various formats)
  CASE
    WHEN data ~ '^\d{4}-\d{2}-\d{2}$' THEN data::DATE
    ELSE NULL
  END as data_publicacao,
  urn,
  autor,
  assuntos,
  classificacao,
  jurisdicao,
  autoridade,
  ementa,
  url,
  localidade,
  numero,
  ano,
  termo_busca,
  -- Convert data_coleta to TIMESTAMP
  CASE
    WHEN data_coleta ~ '^\d{4}-\d{2}-\d{2}' THEN data_coleta::TIMESTAMP
    ELSE NULL
  END as data_coleta,
  origem as fonte,
  categoria,
  modal,
  pais,
  estado,
  municipio,
  fontes_localizacao,
  -- Store additional fields in JSONB metadata
  jsonb_build_object(
    'source_file', source_file,
    'extracted_category', extracted_category,
    'extracted_transport_mode', extracted_transport_mode,
    'deduplication_source', deduplication_source,
    'original_count', original_count,
    'merged_categories', merged_categories,
    'merged_transport', merged_transport
  ) as metadata
FROM temp_import
WHERE titulo IS NOT NULL;  -- Skip any rows without a title

-- Get the count of imported documents
SELECT COUNT(*) as "Documents Imported" FROM documents;

-- Drop the temporary table
DROP TABLE temp_import;

\q
SQL

echo "✅ Data transformation complete"
echo ""

# Step 4: Create view for backward compatibility
echo "🔧 Step 4: Creating compatibility view..."
gcloud sql connect "$INSTANCE_NAME" --user="$DB_USER" --database="$DATABASE_NAME" --project="$PROJECT_ID" <<'SQL'
-- Drop view if exists
DROP VIEW IF EXISTS documents_app_view;

-- Create view that maps column names for app compatibility
CREATE VIEW documents_app_view AS
SELECT
  id,
  titulo,
  tipo,
  data_publicacao as data,  -- App expects 'data'
  urn,
  autor,
  assuntos,
  classificacao,
  jurisdicao,
  autoridade,
  ementa,
  url,
  localidade,
  numero,
  ano,
  termo_busca,
  data_coleta,
  fonte as origem,  -- App expects 'origem'
  categoria,
  modal,
  pais,
  estado,
  municipio,
  fontes_localizacao,
  metadata
FROM documents;

\q
SQL

echo "✅ Compatibility view created"
echo ""

# Step 5: Verify the import
echo "✅ Step 5: Verifying import..."
gcloud sql connect "$INSTANCE_NAME" --user="$DB_USER" --database="$DATABASE_NAME" --project="$PROJECT_ID" <<'SQL'
-- Show table statistics
SELECT
  'documents' as table_name,
  COUNT(*) as total_rows,
  COUNT(DISTINCT tipo) as unique_types,
  MIN(data_publicacao) as earliest_date,
  MAX(data_publicacao) as latest_date
FROM documents;

-- Sample recent documents
SELECT id, titulo, tipo, data_publicacao, fonte
FROM documents
ORDER BY data_publicacao DESC NULLS LAST
LIMIT 5;

\q
SQL

echo ""
echo "=========================================="
echo "✅ IMPORT COMPLETE!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Test the app search at: https://mackmonitor-667999538255.southamerica-east1.run.app/"
echo "2. Try searching for: 'transporte' or 'lei'"
echo ""
