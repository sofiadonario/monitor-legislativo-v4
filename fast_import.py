#!/usr/bin/env python3
import psycopg2
import csv
import sys
from io import StringIO
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

def fast_import():
    """Fast import using COPY command"""
    
    # Connect to database
    conn = psycopg2.connect(**DB_PARAMS)
    cur = conn.cursor()
    
    # CSV file path
    csv_path = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_final_completo/lexml_dataset_limpo_classificado_20250722_102507.csv"
    
    print(f"Starting fast import from: {csv_path}")
    
    # First, collect unique terms
    print("Collecting unique terms...")
    unique_terms = set()
    
    # Create a StringIO buffer for COPY
    buffer = StringIO()
    count = 0
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            count += 1
            
            # Handle empty values
            for key in row:
                if row[key] == '':
                    row[key] = '\\N'  # PostgreSQL NULL
            
            # Handle empty URN
            if row['urn'] == '\\N':
                row['urn'] = f"generated:{row['categoria']}:{row['modal']}:{count}"
            
            # Handle date
            if row['data'] != '\\N':
                try:
                    datetime.strptime(row['data'], '%Y-%m-%d')
                except:
                    row['data'] = '\\N'
            
            # Handle timestamp
            if row['data_coleta'] != '\\N':
                try:
                    datetime.strptime(row['data_coleta'], '%Y-%m-%d %H:%M:%S')
                except:
                    row['data_coleta'] = '\\N'
            
            # Collect unique terms
            if row['termo_busca'] != '\\N':
                unique_terms.add(row['termo_busca'])
            
            # Write to buffer
            line = '\t'.join([
                row['titulo'].replace('\t', ' ').replace('\n', ' ').replace('\r', ' '),
                row['tipo'],
                row['data'],
                row['urn'],
                row['autor'],
                row['assuntos'].replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') if row['assuntos'] != '\\N' else '\\N',
                row['classificacao'].replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') if row['classificacao'] != '\\N' else '\\N',
                row['jurisdicao'],
                row['autoridade'],
                row['ementa'].replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') if row['ementa'] != '\\N' else '\\N',
                row['url'],
                row['localidade'],
                row['numero'],
                row['ano'],
                row['termo_busca'],
                row['data_coleta'],
                row['origem'],
                row['categoria'],
                row['modal']
            ])
            buffer.write(line + '\n')
            
            if count % 10000 == 0:
                print(f"Processed {count} records...")
    
    print(f"Total records to import: {count}")
    
    # Insert unique terms
    print(f"Inserting {len(unique_terms)} unique terms...")
    for term in unique_terms:
        try:
            cur.execute("INSERT INTO termos_busca (termo) VALUES (%s) ON CONFLICT DO NOTHING", (term,))
        except:
            pass
    conn.commit()
    
    # Use COPY to insert data
    print("Performing bulk import...")
    buffer.seek(0)
    
    try:
        cur.copy_expert(
            """COPY lexml_documents (titulo, tipo, data, urn, autor, assuntos, classificacao, 
                                   jurisdicao, autoridade, ementa, url, localidade, numero, 
                                   ano, termo_busca, data_coleta, origem, categoria, modal)
               FROM STDIN WITH (FORMAT text, NULL '\\N', DELIMITER E'\\t')""",
            buffer
        )
        conn.commit()
        print("Bulk import completed successfully!")
    except Exception as e:
        print(f"Error during bulk import: {e}")
        conn.rollback()
    
    # Verify count
    cur.execute("SELECT COUNT(*) FROM lexml_documents")
    db_count = cur.fetchone()[0]
    print(f"Records in database: {db_count}")
    
    # Close connection
    cur.close()
    conn.close()

if __name__ == "__main__":
    fast_import()