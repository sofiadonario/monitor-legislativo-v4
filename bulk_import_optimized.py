#!/usr/bin/env python3
import psycopg2
import psycopg2.extras
import csv
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

def bulk_import():
    """Optimized bulk import"""
    
    # Connect to database
    conn = psycopg2.connect(**DB_PARAMS)
    cur = conn.cursor()
    
    # Get current count
    cur.execute("SELECT MAX(id) FROM lexml_documents")
    max_id = cur.fetchone()[0] or 0
    print(f"Starting from ID: {max_id}")
    
    # CSV file path
    csv_path = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_final_completo/lexml_dataset_limpo_classificado_20250722_102507.csv"
    
    print(f"Starting optimized bulk import...")
    
    count = 0
    batch = []
    batch_size = 5000  # Larger batch size
    start_time = datetime.now()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            count += 1
            
            # Skip already imported records
            if count <= max_id:
                continue
            
            # Handle empty values
            for key in row:
                if row[key] == '':
                    row[key] = None
            
            # Handle empty URN
            if not row['urn']:
                row['urn'] = f"generated:{row['categoria']}:{row['modal']}:{count}"
            
            # Handle date
            if row['data']:
                try:
                    row['data'] = datetime.strptime(row['data'], '%Y-%m-%d').date()
                except:
                    row['data'] = None
            
            # Handle timestamp
            if row['data_coleta']:
                try:
                    row['data_coleta'] = datetime.strptime(row['data_coleta'], '%Y-%m-%d %H:%M:%S')
                except:
                    row['data_coleta'] = None
            
            # Handle integers
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
            
            # Add to batch
            batch.append((
                row['titulo'], row['tipo'], row['data'], row['urn'],
                row['autor'], row['assuntos'], row['classificacao'],
                row['jurisdicao'], row['autoridade'], row['ementa'],
                row['url'], row['localidade'], row['numero'], row['ano'],
                row['termo_busca'], row['data_coleta'], row['origem'],
                row['categoria'], row['modal']
            ))
            
            # Insert batch
            if len(batch) >= batch_size:
                try:
                    psycopg2.extras.execute_batch(
                        cur,
                        """INSERT INTO lexml_documents 
                           (titulo, tipo, data, urn, autor, assuntos, classificacao, 
                            jurisdicao, autoridade, ementa, url, localidade, numero, 
                            ano, termo_busca, data_coleta, origem, categoria, modal)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (urn) DO NOTHING""",
                        batch,
                        page_size=1000
                    )
                    conn.commit()
                    
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = (count - max_id) / elapsed if elapsed > 0 else 0
                    eta = (134014 - count) / rate if rate > 0 else 0
                    
                    print(f"Progress: {count:,}/134,014 ({(count/134014)*100:.1f}%) - "
                          f"Rate: {rate:.0f} rec/sec - ETA: {eta/60:.1f} min")
                except Exception as e:
                    print(f"Error in batch: {e}")
                    conn.rollback()
                
                batch = []
    
    # Insert final batch
    if batch:
        try:
            psycopg2.extras.execute_batch(
                cur,
                """INSERT INTO lexml_documents 
                   (titulo, tipo, data, urn, autor, assuntos, classificacao, 
                    jurisdicao, autoridade, ementa, url, localidade, numero, 
                    ano, termo_busca, data_coleta, origem, categoria, modal)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (urn) DO NOTHING""",
                batch,
                page_size=1000
            )
            conn.commit()
            print(f"Final progress: {count:,}/134,014 ({(count/134014)*100:.1f}%)")
        except Exception as e:
            print(f"Error in final batch: {e}")
            conn.rollback()
    
    # Final count
    cur.execute("SELECT COUNT(*) FROM lexml_documents")
    final_count = cur.fetchone()[0]
    print(f"\nImport completed! Total records: {final_count:,}")
    
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"Total time: {elapsed/60:.1f} minutes")
    
    cur.close()
    conn.close()

if __name__ == "__main__":
    bulk_import()