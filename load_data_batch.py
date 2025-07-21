#!/usr/bin/env python3
"""
Load data from CSV files to Railway PostgreSQL in batches with progress tracking
"""

import os
import csv
import psycopg2
import psycopg2.extras
import json
from datetime import datetime
import re
import sys

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def parse_municipality_state(state_value, municipality_value):
    """Parse municipality and state values"""
    if municipality_value and municipality_value.strip():
        return state_value, municipality_value
    
    if state_value and ' - ' in state_value:
        pattern = r'^(.+)\s*-\s*([A-Z]{2})$'
        match = re.match(pattern, state_value.strip())
        if match:
            return match.group(2).strip(), match.group(1).strip()
    
    return state_value, municipality_value

def get_document_type(urn_type):
    """Map URN type to document tipo"""
    urn_type_lower = urn_type.lower() if urn_type else ""
    if "legislation" in urn_type_lower:
        return "legislation"
    elif "jurisprudence" in urn_type_lower:
        return "jurisprudence"
    elif "doutrina" in urn_type_lower:
        return "library"
    else:
        return "other"

def get_transport_category(search_term):
    """Determine transport category"""
    search_term_lower = search_term.lower() if search_term else ""
    if any(term in search_term_lower for term in ["aereo", "aéreo"]):
        return "aereo"
    elif any(term in search_term_lower for term in ["rodoviario", "rodoviário"]):
        return "rodoviario"
    elif any(term in search_term_lower for term in ["maritimo", "marítimo"]):
        return "maritimo"
    else:
        return "geral"

def parse_date(date_str):
    """Parse date string"""
    if not date_str or date_str.strip() == "":
        return None
    
    # Try just year first
    if re.match(r'^\d{4}$', date_str.strip()):
        try:
            return datetime(int(date_str.strip()), 1, 1).date()
        except:
            pass
    
    # Try other formats
    for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%d-%m-%Y"]:
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    
    return None

def process_batch(batch_data, cursor):
    """Process a batch of records"""
    if not batch_data:
        return 0
    
    # Use execute_values for batch insert
    query = """
        INSERT INTO documents (
            urn, titulo, url, data_publicacao, estado, municipality,
            tipo, fonte, metadata, transport_category,
            conteudo, search_term, justice, region, court_class,
            document_type_full, document_description, document_summary,
            created_at, updated_at
        ) VALUES %s
        ON CONFLICT (urn) DO UPDATE SET
            titulo = EXCLUDED.titulo,
            estado = EXCLUDED.estado,
            municipality = EXCLUDED.municipality,
            metadata = EXCLUDED.metadata,
            updated_at = EXCLUDED.updated_at
    """
    
    try:
        psycopg2.extras.execute_values(
            cursor, query, batch_data,
            template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            page_size=100
        )
        return len(batch_data)
    except Exception as e:
        print(f"  ⚠️ Batch error: {e}")
        return 0

def load_csv_file(csv_path, conn):
    """Load a single CSV file using batch processing"""
    filename = os.path.basename(csv_path)
    print(f"\n📄 Processing {filename}...")
    
    cursor = conn.cursor()
    batch_size = 100
    batch_data = []
    total_processed = 0
    total_skipped = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            
            for row_num, row in enumerate(reader, 1):
                # Show progress every 500 rows
                if row_num % 500 == 0:
                    print(f"  Processing row {row_num}...")
                    sys.stdout.flush()
                
                urn = row.get('Urn', '')
                titulo = row.get('Title', '')
                
                if not urn or not titulo:
                    total_skipped += 1
                    continue
                
                # Parse municipality and state
                state, municipality = parse_municipality_state(
                    row.get('State', ''),
                    row.get('Municipality', '')
                )
                
                # Prepare record
                metadata = {
                    'search_term': row.get('Search_term', ''),
                    'date_searched': row.get('Date_searched', ''),
                    'urn_type': row.get('Urn_type', ''),
                    'country': row.get('Country', ''),
                    'justice': row.get('Justice', ''),
                    'region': row.get('Region', ''),
                    'court_class': row.get('Court_class', ''),
                    'document_type_full': row.get('Document_type_full', ''),
                    'document_description': row.get('Document_description', ''),
                    'original_state': row.get('State', ''),
                    'original_municipality': row.get('Municipality', '')
                }
                
                record = (
                    urn,
                    titulo,
                    row.get('Url', ''),
                    parse_date(row.get('Enacting_date', '')),
                    state,
                    municipality,
                    get_document_type(row.get('Urn_type', '')),
                    'LexML',
                    json.dumps(metadata),
                    get_transport_category(row.get('Search_term', '')),
                    row.get('Document_summary', ''),
                    row.get('Search_term', ''),
                    row.get('Justice', ''),
                    row.get('Region', ''),
                    row.get('Court_class', ''),
                    row.get('Document_type_full', ''),
                    row.get('Document_description', ''),
                    row.get('Document_summary', ''),
                    datetime.now(),
                    datetime.now()
                )
                
                batch_data.append(record)
                
                # Process batch when it reaches batch_size
                if len(batch_data) >= batch_size:
                    processed = process_batch(batch_data, cursor)
                    total_processed += processed
                    conn.commit()
                    batch_data = []
            
            # Process remaining records
            if batch_data:
                processed = process_batch(batch_data, cursor)
                total_processed += processed
                conn.commit()
        
        print(f"  ✅ Completed: {total_processed} processed, {total_skipped} skipped")
        return total_processed, total_skipped
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        conn.rollback()
        return 0, 0

def main():
    """Main function"""
    print("🚀 Batch Loading Data to Railway PostgreSQL")
    print("=" * 60)
    
    try:
        # Connect
        print("🔄 Connecting to database...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        print("✅ Connected!")
        
        # Clear existing data (optional - comment out to append)
        print("🗑️ Clearing existing data...")
        cursor.execute("TRUNCATE TABLE documents RESTART IDENTITY")
        conn.commit()
        
        # Get CSV files
        csv_dir = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed"
        csv_files = sorted([f for f in os.listdir(csv_dir) if f.endswith('.csv')])
        
        print(f"📁 Found {len(csv_files)} CSV files")
        
        total_processed = 0
        total_skipped = 0
        
        # Process each file
        for i, csv_file in enumerate(csv_files, 1):
            print(f"\n[{i}/{len(csv_files)}] ", end="")
            csv_path = os.path.join(csv_dir, csv_file)
            processed, skipped = load_csv_file(csv_path, conn)
            total_processed += processed
            total_skipped += skipped
        
        # Final verification
        cursor.execute("SELECT COUNT(*) FROM documents")
        final_count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE municipality IS NOT NULL AND municipality != ''
        """)
        municipality_count = cursor.fetchone()[0]
        
        print("\n" + "=" * 60)
        print("📊 FINAL SUMMARY:")
        print(f"  Total records processed: {total_processed}")
        print(f"  Total records in database: {final_count}")
        print(f"  Records with municipality: {municipality_count}")
        
        conn.close()
        print("\n✅ Data loading completed!")
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    main()