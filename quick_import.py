#!/usr/bin/env python3
"""
Quick import script to populate Railway database with full dataset
"""
import psycopg2
import csv
import sys
from datetime import datetime

# Database connection
DB_CONFIG = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY',
    'sslmode': 'prefer'
}

def main():
    print("=== Railway Database Import ===")
    
    # Check CSV file
    csv_file = "data_current/processed/production/lexml_unified_dataset.csv"
    try:
        with open(csv_file, 'r') as f:
            # Count lines
            line_count = sum(1 for _ in f) - 1  # exclude header
            print(f"✅ Found CSV: {csv_file} ({line_count:,} documents)")
    except FileNotFoundError:
        print(f"❌ CSV not found: {csv_file}")
        return
    
    # Connect to database
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("✅ Connected to Railway database")
        
        # Check current count
        cursor.execute("SELECT COUNT(*) FROM documents")
        current_count = cursor.fetchone()[0]
        print(f"Current documents in database: {current_count:,}")
        
        if current_count >= 100000:
            print("✅ Database already has sufficient documents")
            return
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return
    
    # Import data in batches
    try:
        print("Starting import process...")
        
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            batch = []
            batch_size = 1000
            total_imported = 0
            
            for row in reader:
                # Clean and prepare data
                clean_row = {
                    'titulo': row.get('titulo', '')[:500] if row.get('titulo') else '',
                    'tipo': row.get('tipo', '')[:200] if row.get('tipo') else '',
                    'data_publicacao': None,  # Will handle date parsing
                    'urn': row.get('urn', '')[:500] if row.get('urn') else '',
                    'autor': row.get('autor', ''),
                    'ementa': row.get('ementa', ''),
                    'url': row.get('url', ''),
                    'estado': row.get('estado', '')[:10] if row.get('estado') else '',
                    'categoria': row.get('categoria', '')[:100] if row.get('categoria') else '',
                }
                
                # Handle date
                date_str = row.get('data', '')
                if date_str and len(date_str) >= 10:
                    try:
                        clean_row['data_publicacao'] = date_str[:10]  # YYYY-MM-DD format
                    except:
                        clean_row['data_publicacao'] = None
                
                batch.append(clean_row)
                
                # Insert batch
                if len(batch) >= batch_size:
                    insert_batch(cursor, batch)
                    total_imported += len(batch)
                    print(f"Imported {total_imported:,} documents...")
                    batch = []
            
            # Insert remaining batch
            if batch:
                insert_batch(cursor, batch)
                total_imported += len(batch)
        
        conn.commit()
        print(f"✅ Import complete! Total imported: {total_imported:,} documents")
        
        # Verify final count
        cursor.execute("SELECT COUNT(*) FROM documents")
        final_count = cursor.fetchone()[0]
        print(f"Final database count: {final_count:,} documents")
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def insert_batch(cursor, batch):
    """Insert a batch of documents"""
    for row in batch:
        try:
            cursor.execute("""
                INSERT INTO documents 
                (titulo, tipo, data_publicacao, urn, autor, ementa, url, estado, categoria)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (urn) DO NOTHING
            """, (
                row['titulo'], row['tipo'], row['data_publicacao'], 
                row['urn'], row['autor'], row['ementa'], 
                row['url'], row['estado'], row['categoria']
            ))
        except Exception as e:
            # Skip problematic rows
            continue

if __name__ == '__main__':
    main()