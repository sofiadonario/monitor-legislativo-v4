#!/usr/bin/env python3
"""
Local CSV Import to Cloud SQL via Cloud SQL Proxy
This script uses the Cloud SQL Proxy to connect and import data
"""

import csv
import sys
import subprocess
import time
from datetime import datetime

print("=" * 60)
print("Monitor Legislativo - Local CSV Import")
print("=" * 60)
print()

# Configuration
PROJECT_ID = "mackmonitor"
INSTANCE_CONNECTION_NAME = "mackmonitor:southamerica-east1:mackmonitor-db"
CSV_FILE = "data_current/processed/production/lexml_unified_dataset.csv"
DB_NAME = "monitor_legislativo"
DB_USER = "monitor_user"
DB_PASSWORD = "Sdonario1"  # Your password

print("📋 Configuration:")
print(f"   Instance: {INSTANCE_CONNECTION_NAME}")
print(f"   Database: {DB_NAME}")
print(f"   CSV File: {CSV_FILE}")
print()

# Step 1: Start Cloud SQL Proxy in background
print("🔧 Step 1: Starting Cloud SQL Proxy...")
proxy_cmd = [
    "cloud-sql-proxy",
    f"{INSTANCE_CONNECTION_NAME}",
    "--port=5433"  # Use different port to avoid conflicts
]

try:
    proxy_process = subprocess.Popen(
        proxy_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print("   Waiting for proxy to start...")
    time.sleep(3)  # Give proxy time to start
    print("✅ Cloud SQL Proxy started on port 5433")
    print()
except Exception as e:
    print(f"❌ Failed to start proxy: {e}")
    print("\nPlease install Cloud SQL Proxy:")
    print("  brew install cloud-sql-proxy")
    sys.exit(1)

# Step 2: Import using psql
print("🚀 Step 2: Importing CSV data...")
print("   This will take 3-5 minutes for 134,014 documents...")
print()

try:
    # Create the import SQL script
    import_sql = f"""
-- Drop temp table if exists
DROP TABLE IF EXISTS temp_import;

-- Create temp table
CREATE TABLE temp_import (
  titulo TEXT, tipo TEXT, data TEXT, urn TEXT, autor TEXT,
  assuntos TEXT, classificacao TEXT, jurisdicao TEXT, autoridade TEXT,
  ementa TEXT, url TEXT, localidade TEXT, numero TEXT, ano TEXT,
  termo_busca TEXT, data_coleta TEXT, origem TEXT, categoria TEXT,
  modal TEXT, pais TEXT, estado TEXT, municipio TEXT,
  fontes_localizacao TEXT, source_file TEXT, extracted_category TEXT,
  extracted_transport_mode TEXT, deduplication_source TEXT,
  original_count TEXT, merged_categories TEXT, merged_transport TEXT
);

-- Import CSV
\\copy temp_import FROM '{CSV_FILE}' WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '"', ESCAPE '"');

-- Transform and insert into documents table
INSERT INTO documents (
  titulo, tipo, data_publicacao, urn, autor, assuntos, classificacao,
  jurisdicao, autoridade, ementa, url, localidade, numero, ano,
  termo_busca, data_coleta, fonte, categoria, modal, pais, estado,
  municipio, fontes_localizacao, metadata
)
SELECT
  titulo, tipo,
  CASE WHEN data ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}$' THEN data::DATE ELSE NULL END,
  urn, autor, assuntos, classificacao, jurisdicao, autoridade, ementa,
  url, localidade, numero, ano, termo_busca,
  CASE WHEN data_coleta ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN data_coleta::TIMESTAMP ELSE NULL END,
  origem, categoria, modal, pais, estado, municipio, fontes_localizacao,
  jsonb_build_object(
    'source_file', source_file,
    'extracted_category', extracted_category,
    'extracted_transport_mode', extracted_transport_mode,
    'deduplication_source', deduplication_source,
    'original_count', original_count,
    'merged_categories', merged_categories,
    'merged_transport', merged_transport
  )
FROM temp_import
WHERE titulo IS NOT NULL;

-- Show results
SELECT COUNT(*) as "Documents Imported" FROM documents;

-- Clean up
DROP TABLE temp_import;

-- Create compatibility view
DROP VIEW IF EXISTS documents_app_view;
CREATE VIEW documents_app_view AS
SELECT id, titulo, tipo, data_publicacao as data, urn, autor, assuntos,
       classificacao, jurisdicao, autoridade, ementa, url, localidade,
       numero, ano, termo_busca, data_coleta, fonte as origem,
       categoria, modal, pais, estado, municipio, fontes_localizacao, metadata
FROM documents;
"""

    # Write SQL to temp file
    with open('/tmp/import_script.sql', 'w') as f:
        f.write(import_sql)

    # Execute via psql
    psql_cmd = [
        "psql",
        f"host=127.0.0.1 port=5433 dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} sslmode=disable",
        "-f", "/tmp/import_script.sql"
    ]

    result = subprocess.run(
        psql_cmd,
        capture_output=True,
        text=True,
        env={"PGPASSWORD": DB_PASSWORD}
    )

    print(result.stdout)
    if result.returncode != 0:
        print("❌ Import failed:")
        print(result.stderr)
        sys.exit(1)

    print("✅ Import completed successfully!")
    print()

except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)
finally:
    # Stop the proxy
    print("🔧 Stopping Cloud SQL Proxy...")
    proxy_process.terminate()
    proxy_process.wait()
    print("✅ Proxy stopped")

print()
print("=" * 60)
print("✅ ALL DONE!")
print("=" * 60)
print()
print("Test the app at:")
print("https://mackmonitor-667999538255.southamerica-east1.run.app/")
print()
