#!/usr/bin/env python3
"""
Import LexML CSV data to PostgreSQL database
Replaces existing documents with the latest LexML dataset
"""

import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from datetime import datetime
import sys

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

def load_csv_data():
    """Load LexML CSV data"""
    csv_path = "lexml_overview/data/processed/lexml_latest_results.csv"
    
    if not os.path.exists(csv_path):
        print(f"❌ CSV file not found: {csv_path}")
        return None
    
    try:
        df = pd.read_csv(csv_path)
        print(f"✅ Loaded CSV with {len(df)} records")
        return df
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return None

def clean_and_prepare_data(df):
    """Clean and prepare data for database insertion"""
    print("🔄 Cleaning and preparing data...")
    
    # Create a copy to avoid modifying original
    data = df.copy()
    
    # Map CSV columns to database columns
    column_mapping = {
        'title': 'titulo',
        'urn': 'urn',
        'url': 'url',
        'enacting_date': 'data_publicacao',
        'state': 'estado',
        'urn_type': 'tipo',
        'document_type_full': 'document_type_full',
        'document_description': 'document_description',
        'document_summary': 'document_summary',
        'search_term': 'search_term',
        'municipality': 'municipality',
        'justice': 'justice',
        'region': 'region',
        'court_class': 'court_class'
    }
    
    # Rename columns
    data = data.rename(columns=column_mapping)
    
    # Convert date format
    def parse_date(date_str):
        if pd.isna(date_str) or date_str == '':
            return None
        try:
            # Try different date formats
            if '/' in str(date_str):
                return datetime.strptime(str(date_str), '%d/%m/%Y').date()
            elif '-' in str(date_str):
                return datetime.strptime(str(date_str), '%Y-%m-%d').date()
            else:
                return None
        except:
            return None
    
    data['data_publicacao'] = data['data_publicacao'].apply(parse_date)
    
    # Map document types
    def map_document_type(urn_type):
        type_mapping = {
            'legislation': 'lei',
            'jurisprudence': 'jurisprudencia',
            'doutrina': 'doutrina'
        }
        return type_mapping.get(urn_type, 'outro')
    
    data['tipo'] = data['tipo'].apply(map_document_type)
    
    # Add metadata
    data['fonte'] = 'LexML'
    data['transport_category'] = 'transport_energy'
    data['created_at'] = datetime.now()
    data['updated_at'] = datetime.now()
    
    # Fill missing values
    data = data.fillna('')
    
    print(f"✅ Data prepared: {len(data)} records ready for insertion")
    return data

def clear_existing_data(conn):
    """Clear existing documents to replace with new data"""
    try:
        cursor = conn.cursor()
        
        # Get count before deletion
        cursor.execute("SELECT COUNT(*) FROM documents")
        before_count = cursor.fetchone()[0]
        print(f"📊 Documents before deletion: {before_count}")
        
        # Clear the table
        cursor.execute("DELETE FROM documents")
        cursor.execute("ALTER SEQUENCE documents_id_seq RESTART WITH 1")
        
        conn.commit()
        print("✅ Existing documents cleared successfully")
        
    except Exception as e:
        print(f"❌ Error clearing existing data: {e}")
        conn.rollback()
        raise

def insert_data_batch(conn, data, batch_size=100):
    """Insert data in batches"""
    try:
        cursor = conn.cursor()
        
        # Prepare the INSERT statement
        columns = [
            'urn', 'titulo', 'url', 'data_publicacao', 'estado', 'tipo',
            'document_type_full', 'document_description', 'document_summary',
            'search_term', 'municipality', 'justice', 'region', 'court_class',
            'fonte', 'transport_category', 'created_at', 'updated_at'
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
                tipo = EXCLUDED.tipo,
                document_type_full = EXCLUDED.document_type_full,
                document_description = EXCLUDED.document_description,
                document_summary = EXCLUDED.document_summary,
                search_term = EXCLUDED.search_term,
                municipality = EXCLUDED.municipality,
                justice = EXCLUDED.justice,
                region = EXCLUDED.region,
                court_class = EXCLUDED.court_class,
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
                    row.get('tipo', ''),
                    row.get('document_type_full', ''),
                    row.get('document_description', ''),
                    row.get('document_summary', ''),
                    row.get('search_term', ''),
                    row.get('municipality', ''),
                    row.get('justice', ''),
                    row.get('region', ''),
                    row.get('court_class', ''),
                    'LexML',
                    'transport_energy',
                    datetime.now(),
                    datetime.now()
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

def verify_insertion(conn):
    """Verify the data was inserted correctly"""
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Count total documents
        cursor.execute("SELECT COUNT(*) as total FROM documents")
        total = cursor.fetchone()['total']
        print(f"📊 Total documents in database: {total}")
        
        # Count by type
        cursor.execute("SELECT tipo, COUNT(*) as count FROM documents GROUP BY tipo ORDER BY count DESC")
        types = cursor.fetchall()
        print("📊 Documents by type:")
        for type_info in types:
            print(f"   {type_info['tipo']}: {type_info['count']}")
        
        # Count by source
        cursor.execute("SELECT fonte, COUNT(*) as count FROM documents GROUP BY fonte")
        sources = cursor.fetchall()
        print("📊 Documents by source:")
        for source_info in sources:
            print(f"   {source_info['fonte']}: {source_info['count']}")
        
        # Sample of recent documents
        cursor.execute("SELECT titulo, tipo, estado, data_publicacao FROM documents ORDER BY created_at DESC LIMIT 5")
        samples = cursor.fetchall()
        print("📊 Sample of recent documents:")
        for doc in samples:
            print(f"   {doc['titulo'][:50]}... | {doc['tipo']} | {doc['estado']} | {doc['data_publicacao']}")
        
    except Exception as e:
        print(f"❌ Error verifying data: {e}")

def main():
    print("🚀 Starting LexML data import to PostgreSQL database")
    print("=" * 60)
    
    # Load CSV data
    df = load_csv_data()
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
        # Clear existing data
        clear_existing_data(conn)
        
        # Insert new data
        insert_data_batch(conn, prepared_data)
        
        # Verify insertion
        verify_insertion(conn)
        
        print("\n✅ LexML data import completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Import failed: {e}")
        return False
        
    finally:
        conn.close()
        print("🔐 Database connection closed")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)