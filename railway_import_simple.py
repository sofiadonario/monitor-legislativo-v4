#!/usr/bin/env python3
"""
Simplified Railway PostgreSQL Import Script
===========================================

This script provides a simplified approach to import CSV data into Railway PostgreSQL.
Designed to work with local execution where network connectivity to Railway is available.

Usage:
1. Ensure you have psycopg2 installed: pip install psycopg2-binary
2. Run: python railway_import_simple.py
"""

import csv
import psycopg2
import os
from pathlib import Path

def main():
    print("🔄 Railway PostgreSQL CSV Import Script")
    print("=" * 50)
    
    # Railway connection parameters
    connection_params = {
        'host': 'nozomi.proxy.rlwy.net',
        'port': 44844,
        'database': 'railway',
        'user': 'postgres',
        'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY',
        'sslmode': 'prefer'
    }
    
    # Find CSV file
    csv_candidates = [
        'data_current/processed/production/lexml_sample_for_railway.csv',
        'railway_data_10k.csv',
        'railway_medium_dataset.csv'
    ]
    
    csv_file = None
    for candidate in csv_candidates:
        if Path(candidate).exists():
            csv_file = candidate
            break
    
    if not csv_file:
        print("❌ No CSV file found!")
        print("Available candidates:")
        for candidate in csv_candidates:
            print(f"   - {candidate}")
        return 1
    
    print(f"📁 Using CSV file: {csv_file}")
    
    try:
        # Connect to database
        print("🔄 Connecting to Railway PostgreSQL...")
        conn = psycopg2.connect(**connection_params)
        cursor = conn.cursor()
        
        print("✅ Connected successfully!")
        
        # Create table
        print("🔄 Creating documents table...")
        
        # Drop existing table
        cursor.execute("DROP TABLE IF EXISTS documents CASCADE;")
        
        # Create new table
        create_table_sql = """
        CREATE TABLE documents (
            id SERIAL PRIMARY KEY,
            titulo TEXT NOT NULL,
            tipo VARCHAR(200),
            data DATE,
            urn TEXT,
            autor TEXT,
            assuntos TEXT,
            classificacao TEXT,
            jurisdicao VARCHAR(100),
            autoridade TEXT,
            ementa TEXT,
            url TEXT,
            localidade VARCHAR(300),
            numero VARCHAR(100),
            ano INTEGER,
            termo_busca VARCHAR(500),
            data_coleta TIMESTAMP,
            origem VARCHAR(200),
            categoria VARCHAR(100),
            modal VARCHAR(100),
            pais VARCHAR(100),
            estado VARCHAR(50),
            municipio VARCHAR(300),
            fontes_localizacao VARCHAR(500),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        cursor.execute(create_table_sql)
        conn.commit()
        print("✅ Table created successfully!")
        
        # Import CSV data
        print(f"🔄 Importing data from {csv_file}...")
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            
            for row in reader:
                # Skip rows without title
                if not row.get('titulo') or row['titulo'].strip() == '':
                    continue
                
                # Clean and convert data
                data = {
                    'titulo': row.get('titulo', ''),
                    'tipo': row.get('tipo') or None,
                    'data': row.get('data') or None,
                    'urn': row.get('urn') or None,
                    'autor': row.get('autor') or None,
                    'assuntos': row.get('assuntos') or None,
                    'classificacao': row.get('classificacao') or None,
                    'jurisdicao': row.get('jurisdicao') or None,
                    'autoridade': row.get('autoridade') or None,
                    'ementa': row.get('ementa') or None,
                    'url': row.get('url') or None,
                    'localidade': row.get('localidade') or None,
                    'numero': row.get('numero') or None,
                    'ano': None,
                    'termo_busca': row.get('termo_busca') or None,
                    'data_coleta': row.get('data_coleta') or None,
                    'origem': row.get('origem') or None,
                    'categoria': row.get('categoria') or None,
                    'modal': row.get('modal') or None,
                    'pais': row.get('pais') or None,
                    'estado': row.get('estado') or None,
                    'municipio': row.get('municipio') or None,
                    'fontes_localizacao': row.get('fontes_localizacao') or None
                }
                
                # Convert ano to integer
                if row.get('ano'):
                    try:
                        data['ano'] = int(row['ano'])
                    except:
                        pass
                
                # Fix date format
                if data['data'] and len(data['data']) == 4:  # Just year
                    data['data'] = f"{data['data']}-01-01"
                elif data['data'] == '':
                    data['data'] = None
                
                # Insert row
                insert_sql = """
                INSERT INTO documents (
                    titulo, tipo, data, urn, autor, assuntos, classificacao,
                    jurisdicao, autoridade, ementa, url, localidade, numero,
                    ano, termo_busca, data_coleta, origem, categoria, modal,
                    pais, estado, municipio, fontes_localizacao
                ) VALUES (
                    %(titulo)s, %(tipo)s, %(data)s, %(urn)s, %(autor)s, %(assuntos)s, %(classificacao)s,
                    %(jurisdicao)s, %(autoridade)s, %(ementa)s, %(url)s, %(localidade)s, %(numero)s,
                    %(ano)s, %(termo_busca)s, %(data_coleta)s, %(origem)s, %(categoria)s, %(modal)s,
                    %(pais)s, %(estado)s, %(municipio)s, %(fontes_localizacao)s
                );
                """
                
                try:
                    cursor.execute(insert_sql, data)
                    count += 1
                    
                    if count % 100 == 0:
                        conn.commit()
                        print(f"   📊 Imported {count} records...")
                        
                except Exception as e:
                    print(f"⚠️ Error importing row {count}: {e}")
                    conn.rollback()
                    continue
        
        # Final commit
        conn.commit()
        
        # Create indexes
        print("🔄 Creating indexes for performance...")
        indexes = [
            "CREATE INDEX idx_documents_titulo ON documents(titulo);",
            "CREATE INDEX idx_documents_categoria ON documents(categoria);",
            "CREATE INDEX idx_documents_estado ON documents(estado);",
            "CREATE INDEX idx_documents_data ON documents(data);"
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
                print(f"✅ Created index")
            except Exception as e:
                print(f"⚠️ Index creation failed: {e}")
        
        conn.commit()
        
        # Get final count
        cursor.execute("SELECT COUNT(*) FROM documents;")
        final_count = cursor.fetchone()[0]
        
        print(f"✅ Import completed successfully!")
        print(f"📊 Total documents in database: {final_count:,}")
        
        # Show sample data
        cursor.execute("SELECT titulo, categoria, estado FROM documents LIMIT 5;")
        sample_data = cursor.fetchall()
        
        print("\n📋 Sample data:")
        for row in sample_data:
            print(f"   - {row[0][:60]}... | {row[1]} | {row[2]}")
        
        cursor.close()
        conn.close()
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())