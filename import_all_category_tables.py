#!/usr/bin/env python3
import psycopg2
import psycopg2.extras
import csv
import sys
import os
from datetime import datetime
import glob

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

def import_csv_to_table(csv_path, table_name, conn):
    """Import a single CSV file to its corresponding table"""
    cur = conn.cursor()
    
    print(f"\nImporting {os.path.basename(csv_path)} to {table_name}...")
    
    count = 0
    batch = []
    batch_size = 5000
    start_time = datetime.now()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            count += 1
            
            # Handle empty values
            for key in row:
                if row[key] == '':
                    row[key] = None
            
            # Handle empty URN
            if not row['urn']:
                row['urn'] = f"generated:{table_name}:{count}"
            
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
                        f"""INSERT INTO {table_name} 
                           (titulo, tipo, data, urn, autor, assuntos, classificacao, 
                            jurisdicao, autoridade, ementa, url, localidade, numero, 
                            ano, termo_busca, data_coleta, origem, categoria, modal)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (urn) DO NOTHING""",
                        batch,
                        page_size=1000
                    )
                    conn.commit()
                except Exception as e:
                    print(f"Error in batch: {e}")
                    conn.rollback()
                
                batch = []
    
    # Insert final batch
    if batch:
        try:
            psycopg2.extras.execute_batch(
                cur,
                f"""INSERT INTO {table_name} 
                   (titulo, tipo, data, urn, autor, assuntos, classificacao, 
                    jurisdicao, autoridade, ementa, url, localidade, numero, 
                    ano, termo_busca, data_coleta, origem, categoria, modal)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (urn) DO NOTHING""",
                batch,
                page_size=1000
            )
            conn.commit()
        except Exception as e:
            print(f"Error in final batch: {e}")
            conn.rollback()
    
    # Get final count
    cur.execute(f"SELECT COUNT(*) FROM {table_name}")
    final_count = cur.fetchone()[0]
    
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"  Imported {final_count} records in {elapsed:.1f} seconds")
    
    cur.close()
    return final_count

def main():
    """Import all category CSV files"""
    
    # Connect to database
    conn = psycopg2.connect(**DB_PARAMS)
    
    # Base directory
    base_dir = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_final_completo"
    
    # Mapping of CSV files to table names
    csv_to_table = {
        'lexml_doutrina_aereo_*.csv': 'lexml_doutrina_aereo',
        'lexml_doutrina_geral_*.csv': 'lexml_doutrina_geral',
        'lexml_doutrina_maritimo_*.csv': 'lexml_doutrina_maritimo',
        'lexml_doutrina_rodoviario_*.csv': 'lexml_doutrina_rodoviario',
        'lexml_jurisprudencia_aereo_*.csv': 'lexml_jurisprudencia_aereo',
        'lexml_jurisprudencia_geral_*.csv': 'lexml_jurisprudencia_geral',
        'lexml_jurisprudencia_maritimo_*.csv': 'lexml_jurisprudencia_maritimo',
        'lexml_jurisprudencia_rodoviario_*.csv': 'lexml_jurisprudencia_rodoviario',
        'lexml_legislacao_aereo_*.csv': 'lexml_legislacao_aereo',
        'lexml_legislacao_geral_*.csv': 'lexml_legislacao_geral',
        'lexml_legislacao_maritimo_*.csv': 'lexml_legislacao_maritimo',
        'lexml_legislacao_rodoviario_*.csv': 'lexml_legislacao_rodoviario',
        'lexml_outros_aereo_*.csv': 'lexml_outros_aereo',
        'lexml_outros_geral_*.csv': 'lexml_outros_geral',
        'lexml_outros_maritimo_*.csv': 'lexml_outros_maritimo',
        'lexml_outros_rodoviario_*.csv': 'lexml_outros_rodoviario',
        'lexml_proposicoes_aereo_*.csv': 'lexml_proposicoes_aereo',
        'lexml_proposicoes_geral_*.csv': 'lexml_proposicoes_geral',
        'lexml_proposicoes_maritimo_*.csv': 'lexml_proposicoes_maritimo',
        'lexml_proposicoes_rodoviario_*.csv': 'lexml_proposicoes_rodoviario'
    }
    
    total_records = 0
    start_time = datetime.now()
    
    print("Starting import of all category-specific CSV files...")
    
    # Import each CSV file
    for pattern, table_name in csv_to_table.items():
        csv_files = glob.glob(os.path.join(base_dir, pattern))
        if csv_files:
            csv_path = csv_files[0]  # Should only be one file per pattern
            records = import_csv_to_table(csv_path, table_name, conn)
            total_records += records
        else:
            print(f"Warning: No file found for pattern {pattern}")
    
    # Summary
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n=== IMPORT COMPLETE ===")
    print(f"Total records imported: {total_records:,}")
    print(f"Total time: {elapsed/60:.1f} minutes")
    
    # Show summary by category
    cur = conn.cursor()
    print("\n=== RECORDS BY CATEGORY ===")
    categories = ['doutrina', 'jurisprudencia', 'legislacao', 'outros', 'proposicoes']
    for cat in categories:
        total = 0
        for modal in ['aereo', 'geral', 'maritimo', 'rodoviario']:
            table = f"lexml_{cat}_{modal}"
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = cur.fetchone()[0]
            if count > 0:
                print(f"  {table}: {count:,}")
                total += count
        print(f"  {cat.upper()} TOTAL: {total:,}")
    
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()