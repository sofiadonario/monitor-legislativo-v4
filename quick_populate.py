#!/usr/bin/env python3
"""Quick database population with main dataset"""

import psycopg2
import pandas as pd
import sys

# Use Railway internal URL for better performance
DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"
# Fallback to external URL if internal doesn't work
DB_URL_EXTERNAL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def populate_database():
    """Quick population of Railway database"""
    
    # Try internal URL first, fallback to external
    try:
        print("Connecting to Railway database (internal)...")
        conn = psycopg2.connect(DB_URL)
    except:
        print("Internal URL failed, trying external...")
        conn = psycopg2.connect(DB_URL_EXTERNAL)
    
    print("✅ Connected to database")
    cur = conn.cursor()
    
    # Create main table if not exists
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
            fonte VARCHAR(50) DEFAULT 'LexML',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Check current count
    cur.execute("SELECT COUNT(*) FROM documents")
    before_count = cur.fetchone()[0]
    print(f"Current documents: {before_count:,}")
    
    if before_count >= 100000:
        print("✅ Database already populated with sufficient data")
        conn.close()
        return
    
    # Load main dataset
    csv_file = "./data_current/processed/production/lexml_unified_dataset.csv"
    print(f"\nLoading {csv_file}...")
    
    try:
        df = pd.read_csv(csv_file, encoding='utf-8', low_memory=False, nrows=150000)
        print(f"Loaded {len(df):,} rows")
        
        # Basic column mapping
        if 'titulo' not in df.columns:
            if 'title' in df.columns:
                df['titulo'] = df['title']
            elif 'Titulo' in df.columns:
                df['titulo'] = df['Titulo']
        
        if 'tipo' not in df.columns:
            if 'Tipo' in df.columns:
                df['tipo'] = df['Tipo']
            elif 'type' in df.columns:
                df['tipo'] = df['type']
        
        # Fill missing values
        df['titulo'] = df.get('titulo', '').fillna('Documento')
        df['tipo'] = df.get('tipo', '').fillna('Legislação')
        df['conteudo'] = df.get('ementa', df.get('conteudo', '')).fillna('')
        
        # Generate unique URNs
        df['urn'] = ['doc_' + str(i) for i in range(len(df))]
        
        # Insert in batches
        batch_size = 1000
        inserted = 0
        
        for i in range(0, min(len(df), 150000), batch_size):
            batch = df.iloc[i:i+batch_size]
            
            for _, row in batch.iterrows():
                try:
                    cur.execute("""
                        INSERT INTO documents (titulo, tipo, conteudo, urn)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (urn) DO NOTHING
                    """, (
                        str(row.get('titulo', ''))[:500],
                        str(row.get('tipo', 'Documento'))[:100],
                        str(row.get('conteudo', ''))[:2000],
                        row['urn']
                    ))
                    inserted += 1
                except Exception as e:
                    continue
            
            if i % 10000 == 0:
                conn.commit()
                print(f"Progress: {inserted:,} rows inserted")
        
        conn.commit()
        
        # Final count
        cur.execute("SELECT COUNT(*) FROM documents")
        final_count = cur.fetchone()[0]
        
        print(f"\n✅ COMPLETE!")
        print(f"   Documents in database: {final_count:,}")
        print(f"   Newly added: {final_count - before_count:,}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    conn.close()

if __name__ == "__main__":
    populate_database()