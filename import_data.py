#!/usr/bin/env python3
import psycopg2
import csv
import os
import sys
from datetime import datetime

# Increase CSV field size limit
csv.field_size_limit(sys.maxsize)

# Database connection parameters
DB_PARAMS = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def import_csv_to_postgres():
    """Import CSV data to PostgreSQL database"""
    
    # Connect to database
    conn = psycopg2.connect(**DB_PARAMS)
    cur = conn.cursor()
    
    # CSV file path
    csv_path = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_final_completo/lexml_dataset_limpo_classificado_20250722_102507.csv"
    
    print(f"Starting import from: {csv_path}")
    
    # Get unique terms for lookup table
    print("Collecting unique terms...")
    unique_terms = set()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['termo_busca']:
                unique_terms.add(row['termo_busca'])
    
    # Insert unique terms
    print(f"Inserting {len(unique_terms)} unique terms...")
    for term in unique_terms:
        try:
            cur.execute("INSERT INTO termos_busca (termo) VALUES (%s) ON CONFLICT DO NOTHING", (term,))
        except Exception as e:
            print(f"Error inserting term {term}: {e}")
    
    conn.commit()
    
    # Import main data
    print("Importing main dataset...")
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        count = 0
        batch = []
        batch_size = 1000
        
        for row in reader:
            # Handle empty values
            for key in row:
                if row[key] == '':
                    row[key] = None
            
            # Handle date format
            if row['data']:
                try:
                    # Parse date
                    row['data'] = datetime.strptime(row['data'], '%Y-%m-%d').date()
                except:
                    row['data'] = None
            
            # Handle timestamp
            if row['data_coleta']:
                try:
                    row['data_coleta'] = datetime.strptime(row['data_coleta'], '%Y-%m-%d %H:%M:%S')
                except:
                    row['data_coleta'] = None
            
            # Handle integer fields
            if row['numero']:
                try:
                    row['numero'] = int(row['numero'])
                except:
                    row['numero'] = None
                    
            if row['ano']:
                try:
                    row['ano'] = int(row['ano'])
                except:
                    row['ano'] = None
            
            # Handle empty URN by generating a unique identifier
            if not row['urn']:
                # Generate a unique URN based on other fields
                unique_id = f"generated:{row['categoria']}:{row['modal']}:{count}"
                row['urn'] = unique_id
            
            # Prepare values tuple
            values = (
                row['titulo'],
                row['tipo'],
                row['data'],
                row['urn'],
                row['autor'],
                row['assuntos'],
                row['classificacao'],
                row['jurisdicao'],
                row['autoridade'],
                row['ementa'],
                row['url'],
                row['localidade'],
                row['numero'],
                row['ano'],
                row['termo_busca'],
                row['data_coleta'],
                row['origem'],
                row['categoria'],
                row['modal']
            )
            
            batch.append(values)
            count += 1
            
            # Insert batch
            if len(batch) >= batch_size:
                insert_query = """
                    INSERT INTO lexml_documents 
                    (titulo, tipo, data, urn, autor, assuntos, classificacao, 
                     jurisdicao, autoridade, ementa, url, localidade, numero, 
                     ano, termo_busca, data_coleta, origem, categoria, modal)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (urn) DO NOTHING
                """
                
                try:
                    cur.executemany(insert_query, batch)
                    conn.commit()
                    print(f"Inserted batch: {count} records processed")
                except Exception as e:
                    print(f"Error in batch: {e}")
                    conn.rollback()
                    # Try inserting one by one for this batch
                    for val in batch:
                        try:
                            cur.execute(insert_query, val)
                            conn.commit()
                        except Exception as e2:
                            print(f"Error inserting record: {e2}")
                            conn.rollback()
                
                batch = []
        
        # Insert remaining records
        if batch:
            try:
                cur.executemany(insert_query, batch)
                conn.commit()
                print(f"Inserted final batch: {count} records processed")
            except Exception as e:
                print(f"Error in final batch: {e}")
                conn.rollback()
    
    print(f"Import completed. Total records processed: {count}")
    
    # Verify count
    cur.execute("SELECT COUNT(*) FROM lexml_documents")
    db_count = cur.fetchone()[0]
    print(f"Records in database: {db_count}")
    
    # Close connection
    cur.close()
    conn.close()

if __name__ == "__main__":
    import_csv_to_postgres()