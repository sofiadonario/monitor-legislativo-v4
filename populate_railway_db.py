#!/usr/bin/env python3
"""
Populate Railway PostgreSQL database with legislative data
"""

import os
import sys
import psycopg2
import pandas as pd
from datetime import datetime
import glob

# Database connection parameters
DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def connect_db():
    """Connect to Railway PostgreSQL database"""
    try:
        conn = psycopg2.connect(DB_URL)
        print("✅ Connected to Railway database")
        return conn
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        sys.exit(1)

def check_existing_data(conn):
    """Check existing data in database"""
    cur = conn.cursor()
    
    # Check for existing tables
    cur.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    tables = cur.fetchall()
    
    print("\n📊 Existing tables:")
    for table in tables:
        table_name = table[0]
        cur.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cur.fetchone()[0]
        print(f"   - {table_name}: {count:,} rows")
    
    return tables

def find_data_files():
    """Find CSV files to import"""
    patterns = [
        "data_current/processed/*.csv",
        "data_current/*.csv",
        "data/*.csv",
        "*.csv"
    ]
    
    csv_files = []
    for pattern in patterns:
        files = glob.glob(pattern)
        csv_files.extend(files)
    
    # Filter to only legislative data files
    legislative_files = [f for f in csv_files if any(keyword in f.lower() for keyword in 
                        ['legislat', 'lexml', 'camara', 'senado', 'document', 'projeto'])]
    
    if legislative_files:
        print(f"\n📁 Found {len(legislative_files)} legislative data files:")
        for f in legislative_files[:5]:  # Show first 5
            size = os.path.getsize(f) / (1024*1024)  # MB
            print(f"   - {f} ({size:.1f} MB)")
        if len(legislative_files) > 5:
            print(f"   ... and {len(legislative_files)-5} more")
    
    return legislative_files

def create_main_table(conn):
    """Create main documents table if it doesn't exist"""
    cur = conn.cursor()
    
    # Create comprehensive documents table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id SERIAL PRIMARY KEY,
            titulo TEXT,
            tipo VARCHAR(100),
            species VARCHAR(100) DEFAULT 'Não Classificado',
            estado VARCHAR(10),
            estado_codigo VARCHAR(10),
            municipality VARCHAR(255),
            data_publicacao DATE,
            url TEXT,
            urn TEXT UNIQUE,
            conteudo TEXT,
            document_summary TEXT,
            document_type_full VARCHAR(255),
            search_term VARCHAR(255),
            autor TEXT,
            fonte VARCHAR(50) DEFAULT 'LexML',
            transport_category VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locality VARCHAR(255),
            authority VARCHAR(255),
            authority_level VARCHAR(50),
            document_number VARCHAR(50),
            justice VARCHAR(100),
            region VARCHAR(100),
            court_class VARCHAR(100),
            document_description TEXT,
            metadata JSONB
        )
    """)
    
    # Create indexes for better performance
    cur.execute("CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data_publicacao)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_documents_urn ON documents(urn)")
    
    conn.commit()
    print("✅ Main table structure created/verified")

def import_csv_to_db(conn, csv_file, batch_size=1000):
    """Import CSV file to database"""
    print(f"\n📥 Importing {csv_file}...")
    
    try:
        # Read CSV with proper encoding
        df = pd.read_csv(csv_file, encoding='utf-8', low_memory=False)
        print(f"   Loaded {len(df):,} rows")
        
        # Map columns to database schema
        column_mapping = {
            'titulo': 'titulo',
            'title': 'titulo',
            'tipo': 'tipo',
            'type': 'tipo',
            'document_type': 'tipo',
            'estado': 'estado',
            'state': 'estado',
            'uf': 'estado',
            'data': 'data_publicacao',
            'date': 'data_publicacao',
            'data_publicacao': 'data_publicacao',
            'url': 'url',
            'link': 'url',
            'urn': 'urn',
            'id_documento': 'urn',
            'ementa': 'conteudo',
            'content': 'conteudo',
            'texto': 'conteudo',
            'autor': 'autor',
            'author': 'autor',
            'localidade': 'locality',
            'locality': 'locality',
            'jurisdicao': 'authority_level',
            'jurisdiction': 'authority_level',
            'numero': 'document_number',
            'number': 'document_number'
        }
        
        # Rename columns based on mapping
        df.rename(columns=column_mapping, inplace=True)
        
        # Ensure required columns exist
        if 'titulo' not in df.columns and 'conteudo' not in df.columns:
            print("   ⚠️  No title or content column found, skipping")
            return 0
        
        # Fill missing values
        df['titulo'] = df.get('titulo', '').fillna('')
        df['tipo'] = df.get('tipo', 'Documento').fillna('Documento')
        df['conteudo'] = df.get('conteudo', '').fillna('')
        df['urn'] = df.get('urn', pd.Series(range(len(df)))).fillna(pd.Series(range(len(df))))
        
        # Convert date column if exists
        if 'data_publicacao' in df.columns:
            try:
                df['data_publicacao'] = pd.to_datetime(df['data_publicacao'], errors='coerce')
            except:
                df['data_publicacao'] = None
        
        # Insert data in batches
        cur = conn.cursor()
        inserted = 0
        
        for i in range(0, len(df), batch_size):
            batch = df.iloc[i:i+batch_size]
            
            for _, row in batch.iterrows():
                try:
                    cur.execute("""
                        INSERT INTO documents (
                            titulo, tipo, conteudo, urn, data_publicacao,
                            estado, url, autor, locality, authority_level, document_number
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (urn) DO UPDATE SET
                            titulo = EXCLUDED.titulo,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        str(row.get('titulo', ''))[:500],
                        str(row.get('tipo', 'Documento'))[:100],
                        str(row.get('conteudo', ''))[:5000],
                        str(row.get('urn', f'doc_{i}_{inserted}'))[:255],
                        row.get('data_publicacao') if pd.notna(row.get('data_publicacao')) else None,
                        str(row.get('estado', ''))[:10],
                        str(row.get('url', ''))[:500],
                        str(row.get('autor', ''))[:255],
                        str(row.get('locality', ''))[:255],
                        str(row.get('authority_level', ''))[:50],
                        str(row.get('document_number', ''))[:50]
                    ))
                    inserted += 1
                except Exception as e:
                    if 'duplicate key' not in str(e):
                        print(f"   ⚠️  Error inserting row: {e}")
                    continue
            
            if inserted % 5000 == 0:
                conn.commit()
                print(f"   Progress: {inserted:,} / {len(df):,} rows")
        
        conn.commit()
        print(f"   ✅ Imported {inserted:,} rows")
        return inserted
        
    except Exception as e:
        print(f"   ❌ Error importing file: {e}")
        return 0

def main():
    print("\n🚀 RAILWAY DATABASE POPULATION SCRIPT")
    print("=" * 50)
    
    # Connect to database
    conn = connect_db()
    
    # Check existing data
    check_existing_data(conn)
    
    # Create main table structure
    create_main_table(conn)
    
    # Find data files
    csv_files = find_data_files()
    
    if not csv_files:
        print("\n⚠️  No CSV files found to import")
        print("   Please ensure data files are in the correct location")
        conn.close()
        return
    
    # Import each file
    total_imported = 0
    for csv_file in csv_files:
        imported = import_csv_to_db(conn, csv_file)
        total_imported += imported
    
    # Final check
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM documents")
    final_count = cur.fetchone()[0]
    
    print(f"\n✅ POPULATION COMPLETE")
    print(f"   Total documents in database: {final_count:,}")
    print(f"   Newly imported: {total_imported:,}")
    
    conn.close()

if __name__ == "__main__":
    main()