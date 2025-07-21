#!/usr/bin/env python3
"""
Reload CSV files from data_current/processed/ to PostgreSQL database
After municipality-state parsing fix
"""

import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import glob
from datetime import datetime
import sys
import json

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def connect_to_database():
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        print("✅ Connected to database successfully")
        return conn
    except Exception as e:
        print(f"❌ Error connecting to database: {e}")
        return None

def load_csv_files():
    """Load all CSV files from data_current/processed/"""
    csv_pattern = "data_current/processed/*.csv"
    csv_files = glob.glob(csv_pattern)
    
    if not csv_files:
        print(f"❌ No CSV files found in data_current/processed/")
        return None
    
    print(f"✅ Found {len(csv_files)} CSV files to process")
    
    all_data = []
    
    for csv_file in csv_files:
        print(f"🔄 Loading {os.path.basename(csv_file)}")
        try:
            df = pd.read_csv(csv_file, encoding='utf-8')
            if not df.empty:
                df['source_file'] = os.path.basename(csv_file)
                all_data.append(df)
                print(f"   ✅ Loaded {len(df)} records from {os.path.basename(csv_file)}")
            else:
                print(f"   ⚠️ Empty file: {os.path.basename(csv_file)}")
        except Exception as e:
            print(f"   ❌ Error loading {csv_file}: {e}")
    
    if all_data:
        combined_df = pd.concat(all_data, ignore_index=True)
        print(f"✅ Combined dataset: {len(combined_df)} total records")
        return combined_df
    else:
        print("❌ No data loaded from any CSV files")
        return None

def clean_and_prepare_data(df):
    """Clean and prepare data for database insertion"""
    print("🔄 Cleaning and preparing data...")
    
    # Create a copy to avoid modifying original
    data = df.copy()
    
    # Ensure required columns exist
    required_cols = ['Search_term', 'Url', 'Title', 'Urn', 'Urn_type', 'State', 'Municipality', 
                     'Enacting_date', 'Document_description', 'Document_summary']
    
    for col in required_cols:
        if col not in data.columns:
            data[col] = ''
    
    # Clean and prepare the data
    prepared_data = data.assign(
        # Core fields
        urn=data['Urn'].fillna(''),
        titulo=data['Title'].fillna(''),
        url=data['Url'].fillna(''),
        estado=data['State'].fillna(''),  # This now contains the fixed state data
        municipality=data['Municipality'].fillna(''),  # This now contains the fixed municipality data
        
        # Type mapping
        tipo=data['Urn_type'].map({
            'legislation': 'lei',
            'jurisprudence': 'jurisprudencia', 
            'doutrina': 'doutrina',
            'library': 'doutrina'
        }).fillna('outro'),
        
        # Content fields
        conteudo=data['Document_summary'].fillna(''),
        document_type_full=data.get('Document_type_full', '').fillna(''),
        document_description=data.get('Document_description', '').fillna(''),
        document_summary=data.get('Document_summary', '').fillna(''),
        search_term=data.get('Search_term', '').fillna(''),
        
        # Location fields
        justice=data.get('Justice', '').fillna(''),
        region=data.get('Region', '').fillna(''),
        court_class=data.get('Court_class', '').fillna(''),
        
        # Metadata and other fields
        autor='',
        fonte='LexML',
        transport_category='transport_energy',
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    # Handle date conversion
    def parse_date(date_str):
        if pd.isna(date_str) or date_str == '':
            return None
        try:
            if isinstance(date_str, str):
                if ' ' in date_str:
                    date_str = date_str.split(' ')[0]
                if '/' in date_str:
                    return datetime.strptime(date_str, '%d/%m/%Y').date()
                elif '-' in date_str:
                    return datetime.strptime(date_str, '%Y-%m-%d').date()
            return None
        except:
            return None
    
    prepared_data['data_publicacao'] = data['Enacting_date'].apply(parse_date)
    
    # Create metadata JSON
    def create_metadata(row):
        return json.dumps({
            'search_term': str(row.get('Search_term', '')),
            'urn_type': str(row.get('Urn_type', '')),
            'country': str(row.get('Country', '')),
            'source_file': str(row.get('source_file', ''))
        })
    
    prepared_data['metadata'] = data.apply(create_metadata, axis=1)
    
    # Select final columns
    final_columns = [
        'urn', 'titulo', 'url', 'data_publicacao', 'estado', 'municipality',
        'tipo', 'conteudo', 'autor', 'fonte', 'transport_category',
        'document_type_full', 'document_description', 'document_summary',
        'search_term', 'justice', 'region', 'court_class', 'metadata',
        'created_at', 'updated_at'
    ]
    
    final_data = prepared_data[final_columns]
    
    print(f"✅ Data prepared: {len(final_data)} records ready for insertion")
    return final_data

def clear_existing_data(conn):
    """Clear existing LexML documents"""
    try:
        cursor = conn.cursor()
        
        # Get count before deletion
        cursor.execute("SELECT COUNT(*) FROM documents WHERE fonte = 'LexML'")
        before_count = cursor.fetchone()[0]
        print(f"📊 LexML documents before deletion: {before_count}")
        
        # Clear only LexML documents
        cursor.execute("DELETE FROM documents WHERE fonte = 'LexML'")
        
        conn.commit()
        print("✅ Existing LexML documents cleared successfully")
        
    except Exception as e:
        print(f"❌ Error clearing existing data: {e}")
        conn.rollback()
        raise

def insert_data_batch(conn, data, batch_size=100):
    """Insert data in batches with proper conflict handling"""
    try:
        cursor = conn.cursor()
        
        # Prepare the INSERT statement
        columns = [
            'urn', 'titulo', 'url', 'data_publicacao', 'estado', 'municipality',
            'tipo', 'conteudo', 'autor', 'fonte', 'transport_category',
            'document_type_full', 'document_description', 'document_summary',
            'search_term', 'justice', 'region', 'court_class', 'metadata',
            'created_at', 'updated_at'
        ]
        
        placeholders = ', '.join(['%s'] * len(columns))
        insert_sql = f"""
            INSERT INTO documents ({', '.join(columns)})
            VALUES ({placeholders})
            ON CONFLICT (urn) DO UPDATE SET
                titulo = EXCLUDED.titulo,
                url = EXCLUDED.url,
                data_publicacao = EXCLUDED.data_publicacao,
                estado = EXCLUDED.estado,
                municipality = EXCLUDED.municipality,
                tipo = EXCLUDED.tipo,
                conteudo = EXCLUDED.conteudo,
                document_type_full = EXCLUDED.document_type_full,
                document_description = EXCLUDED.document_description,
                document_summary = EXCLUDED.document_summary,
                search_term = EXCLUDED.search_term,
                justice = EXCLUDED.justice,
                region = EXCLUDED.region,
                court_class = EXCLUDED.court_class,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at
        """
        
        # Insert in batches
        total_rows = len(data)
        inserted_count = 0
        
        for i in range(0, total_rows, batch_size):
            batch = data.iloc[i:i + batch_size]
            
            # Prepare batch data
            batch_values = []
            for _, row in batch.iterrows():
                values = [
                    row.get('urn', ''),
                    row.get('titulo', ''),
                    row.get('url', ''),
                    row.get('data_publicacao'),
                    row.get('estado', ''),
                    row.get('municipality', ''),
                    row.get('tipo', ''),
                    row.get('conteudo', ''),
                    row.get('autor', ''),
                    row.get('fonte', ''),
                    row.get('transport_category', ''),
                    row.get('document_type_full', ''),
                    row.get('document_description', ''),
                    row.get('document_summary', ''),
                    row.get('search_term', ''),
                    row.get('justice', ''),
                    row.get('region', ''),
                    row.get('court_class', ''),
                    row.get('metadata', '{}'),
                    row.get('created_at', datetime.now()),
                    row.get('updated_at', datetime.now())
                ]
                batch_values.append(values)
            
            # Execute batch insert
            cursor.executemany(insert_sql, batch_values)
            inserted_count += len(batch_values)
            
            print(f"🔄 Inserted batch {i//batch_size + 1}: {inserted_count}/{total_rows} records")
        
        conn.commit()
        print(f"✅ Successfully inserted {inserted_count} records")
        
    except Exception as e:
        print(f"❌ Error inserting data: {e}")
        conn.rollback()
        raise

def verify_municipality_state_fix(conn):
    """Verify the municipality-state parsing fix is applied in the database"""
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        print("🔍 Verifying municipality-state parsing fix...")
        
        # Check for properly separated municipality and state data
        cursor.execute("""
            SELECT estado, municipality, COUNT(*) as count
            FROM documents 
            WHERE fonte = 'LexML' AND estado != '' AND municipality != ''
            GROUP BY estado, municipality
            ORDER BY count DESC
            LIMIT 10
        """)
        
        results = cursor.fetchall()
        print("📊 Sample of properly separated municipality-state data:")
        for row in results:
            print(f"   Estado: {row['estado']}, Municipality: {row['municipality']} - {row['count']} documents")
        
        # Check for Catanduva specifically
        cursor.execute("""
            SELECT estado, municipality, titulo
            FROM documents 
            WHERE fonte = 'LexML' AND municipality ILIKE '%catanduva%'
            LIMIT 3
        """)
        
        catanduva_results = cursor.fetchall()
        print("🔍 Catanduva examples (should show Estado='SP', Municipality='Catanduva'):")
        for row in catanduva_results:
            print(f"   Estado: '{row['estado']}', Municipality: '{row['municipality']}' - {row['titulo'][:50]}...")
        
        # Count total documents
        cursor.execute("SELECT COUNT(*) as total FROM documents WHERE fonte = 'LexML'")
        total = cursor.fetchone()['total']
        print(f"📊 Total LexML documents in database: {total}")
        
    except Exception as e:
        print(f"❌ Error verifying data: {e}")

def main():
    print("🚀 Starting CSV data reload to PostgreSQL database")
    print("📋 Loading fixed CSV files from data_current/processed/")
    print("=" * 60)
    
    # Load CSV data
    df = load_csv_files()
    if df is None:
        return False
    
    # Clean and prepare data
    prepared_data = clean_and_prepare_data(df)
    if prepared_data is None:
        return False
    
    # Connect to database
    conn = connect_to_database()
    if conn is None:
        return False
    
    try:
        # Clear existing LexML data
        clear_existing_data(conn)
        
        # Insert new data
        insert_data_batch(conn, prepared_data)
        
        # Verify the municipality-state fix
        verify_municipality_state_fix(conn)
        
        print("\n✅ CSV data reload completed successfully!")
        print("✅ Municipality-state parsing fix has been applied to the database!")
        return True
        
    except Exception as e:
        print(f"\n❌ Reload failed: {e}")
        return False
        
    finally:
        conn.close()
        print("🔐 Database connection closed")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)