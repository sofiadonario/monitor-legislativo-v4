#!/usr/bin/env python3
"""
Import CSV data into Cloud SQL PostgreSQL database using Python
"""

import psycopg2
import csv
import sys
from datetime import datetime
import json

# Database configuration
DB_CONFIG = {
    'host': '34.39.228.246',  # Direct public IP connection
    'port': 5432,
    'database': 'monitor_legislativo',
    'user': 'monitor_user',
    'password': 'Sdonario1',
    'sslmode': 'require'  # Require SSL for Cloud SQL
}

CSV_FILE = '/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/production/lexml_unified_dataset.csv'

def create_staging_table(cursor):
    """Create staging table for raw CSV data"""
    print("Creating staging table...")
    cursor.execute("""
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
    """)
    print("Staging table created successfully.")

def import_csv_data(cursor, csv_file):
    """Import CSV data into staging table"""
    print(f"Importing CSV data from {csv_file}...")

    with open(csv_file, 'r', encoding='utf-8') as f:
        # Use COPY command with cursor
        cursor.copy_expert("""
            COPY csv_staging FROM STDIN WITH (
                FORMAT csv,
                HEADER true,
                DELIMITER ',',
                QUOTE '"',
                ESCAPE '"',
                NULL '',
                ENCODING 'UTF8'
            )
        """, f)

    cursor.execute("SELECT COUNT(*) FROM csv_staging;")
    count = cursor.fetchone()[0]
    print(f"Loaded {count:,} rows into staging table.")
    return count

def transform_and_insert(cursor):
    """Transform staging data and insert into documents table"""
    print("Transforming and inserting data into documents table...")

    cursor.execute("""
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
    """)

    cursor.execute("SELECT COUNT(*) FROM documents;")
    count = cursor.fetchone()[0]
    print(f"Documents table now has {count:,} rows.")
    return count

def verify_import(cursor):
    """Run verification queries"""
    print("\n" + "="*60)
    print("VERIFICATION")
    print("="*60)

    # Row counts
    cursor.execute("SELECT COUNT(*) FROM csv_staging;")
    staging_count = cursor.fetchone()[0]
    print(f"Staging table: {staging_count:,} rows")

    cursor.execute("SELECT COUNT(*) FROM documents;")
    documents_count = cursor.fetchone()[0]
    print(f"Documents table: {documents_count:,} rows")

    # Check for NULL dates
    cursor.execute("SELECT COUNT(*) FROM documents WHERE data_publicacao IS NULL;")
    null_dates = cursor.fetchone()[0]
    print(f"Documents with NULL dates: {null_dates:,}")

    # Sample data
    print("\nSample of imported data:")
    cursor.execute("""
        SELECT id, titulo, tipo, data_publicacao, fonte
        FROM documents
        ORDER BY id DESC
        LIMIT 5;
    """)
    for row in cursor.fetchall():
        print(f"  ID {row[0]}: {row[1][:50]}... | {row[2]} | {row[3]} | {row[4]}")

    # Distribution by tipo
    print("\nDistribution by tipo:")
    cursor.execute("""
        SELECT tipo, COUNT(*) as count
        FROM documents
        GROUP BY tipo
        ORDER BY count DESC;
    """)
    for row in cursor.fetchall():
        print(f"  {row[0] or '(NULL)'}: {row[1]:,}")

    # Distribution by estado (top 10)
    print("\nTop 10 states by document count:")
    cursor.execute("""
        SELECT estado, COUNT(*) as count
        FROM documents
        WHERE estado IS NOT NULL
        GROUP BY estado
        ORDER BY count DESC
        LIMIT 10;
    """)
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]:,}")

def main():
    """Main import process"""
    print("="*60)
    print("CSV Import to Cloud SQL PostgreSQL")
    print("="*60)
    print(f"Database: {DB_CONFIG['database']}")
    print(f"Host: {DB_CONFIG['host']}:{DB_CONFIG['port']}")
    print(f"CSV File: {CSV_FILE}")
    print("="*60)
    print()

    try:
        # Connect to database
        print("Connecting to database...")
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        cursor = conn.cursor()
        print("Connected successfully!")
        print()

        # Step 1: Create staging table
        create_staging_table(cursor)
        conn.commit()
        print()

        # Step 2: Import CSV data
        staging_count = import_csv_data(cursor, CSV_FILE)
        conn.commit()
        print()

        # Step 3: Transform and insert
        documents_count = transform_and_insert(cursor)
        conn.commit()
        print()

        # Step 4: Verification
        verify_import(cursor)
        print()

        # Close connection
        cursor.close()
        conn.close()

        print("="*60)
        print("IMPORT COMPLETE!")
        print("="*60)
        print(f"Total rows imported: {documents_count:,}")
        print()

        return 0

    except Exception as e:
        print(f"\nERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
