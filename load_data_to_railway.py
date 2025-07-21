#!/usr/bin/env python3
"""
Load data from CSV files to Railway PostgreSQL with proper municipality/state parsing
"""

import os
import csv
import psycopg2
import json
from datetime import datetime
import re

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def parse_municipality_state(state_value, municipality_value):
    """
    Parse municipality and state values, handling cases where they might be combined
    
    Returns: (state, municipality) tuple
    """
    # If municipality is already filled, return as is
    if municipality_value and municipality_value.strip():
        return state_value, municipality_value
    
    # Check if state contains municipality-state pattern
    if state_value and ' - ' in state_value:
        # Pattern to match "Municipality - ST" format
        pattern = r'^(.+)\s*-\s*([A-Z]{2})$'
        match = re.match(pattern, state_value.strip())
        
        if match:
            municipality = match.group(1).strip()
            state = match.group(2).strip()
            return state, municipality
    
    # Return original values if no parsing needed
    return state_value, municipality_value

def get_document_type(urn_type):
    """Map URN type to document tipo"""
    urn_type_lower = urn_type.lower() if urn_type else ""
    
    if "legislation" in urn_type_lower or "legislacao" in urn_type_lower:
        return "legislation"
    elif "jurisprudence" in urn_type_lower or "jurisprudencia" in urn_type_lower:
        return "jurisprudence"
    elif "doutrina" in urn_type_lower or "library" in urn_type_lower:
        return "library"
    else:
        return "other"

def get_transport_category(search_term):
    """Determine transport category from search term"""
    search_term_lower = search_term.lower() if search_term else ""
    
    if any(term in search_term_lower for term in ["aereo", "aéreo", "aeronautico", "aeronáutico"]):
        return "aereo"
    elif any(term in search_term_lower for term in ["rodoviario", "rodoviário"]):
        return "rodoviario"
    elif any(term in search_term_lower for term in ["maritimo", "marítimo", "naval", "portuario", "portuário"]):
        return "maritimo"
    else:
        return "geral"

def parse_date(date_str):
    """Parse date string to date object"""
    if not date_str or date_str.strip() == "":
        return None
    
    # Try different date formats
    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%Y"  # Just year
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    
    # If just a year (4 digits), create January 1st of that year
    if re.match(r'^\d{4}$', date_str.strip()):
        try:
            year = int(date_str.strip())
            return datetime(year, 1, 1).date()
        except:
            pass
    
    return None

def load_csv_to_database(csv_file_path, conn):
    """Load a single CSV file to the database"""
    filename = os.path.basename(csv_file_path)
    print(f"\n📄 Processing {filename}...")
    
    cursor = conn.cursor()
    records_inserted = 0
    records_updated = 0
    records_skipped = 0
    
    try:
        with open(csv_file_path, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            
            for row_num, row in enumerate(reader, 1):
                try:
                    # Parse municipality and state
                    state, municipality = parse_municipality_state(
                        row.get('State', ''),
                        row.get('Municipality', '')
                    )
                    
                    # Prepare data
                    urn = row.get('Urn', '')
                    titulo = row.get('Title', '')
                    
                    # Skip if no URN or title
                    if not urn or not titulo:
                        records_skipped += 1
                        continue
                    
                    # Parse date
                    data_publicacao = parse_date(row.get('Enacting_date', ''))
                    
                    # Create metadata JSON
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
                        'original_state': row.get('State', ''),  # Keep original for reference
                        'original_municipality': row.get('Municipality', '')
                    }
                    
                    # Get document type and transport category
                    tipo = get_document_type(row.get('Urn_type', ''))
                    transport_category = get_transport_category(row.get('Search_term', ''))
                    
                    # Insert or update record
                    insert_query = """
                        INSERT INTO documents (
                            urn, titulo, url, data_publicacao, estado, municipality,
                            tipo, fonte, metadata, transport_category,
                            conteudo, search_term, justice, region, court_class,
                            document_type_full, document_description, document_summary,
                            created_at, updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT (urn) DO UPDATE SET
                            titulo = EXCLUDED.titulo,
                            estado = EXCLUDED.estado,
                            municipality = EXCLUDED.municipality,
                            metadata = EXCLUDED.metadata,
                            updated_at = EXCLUDED.updated_at
                    """
                    
                    cursor.execute(insert_query, (
                        urn,
                        titulo,
                        row.get('Url', ''),
                        data_publicacao,
                        state,
                        municipality,
                        tipo,
                        'LexML',
                        json.dumps(metadata),
                        transport_category,
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
                    ))
                    
                    if cursor.rowcount > 0:
                        records_inserted += 1
                    
                except Exception as e:
                    print(f"  ⚠️ Error on row {row_num}: {e}")
                    records_skipped += 1
                    continue
        
        # Commit after each file
        conn.commit()
        print(f"  ✅ Processed: {records_inserted} inserted/updated, {records_skipped} skipped")
        
    except Exception as e:
        print(f"  ❌ Error processing file: {e}")
        conn.rollback()
    
    return records_inserted, records_skipped

def main():
    """Main function to load all CSV files"""
    print("🚀 Loading data to Railway PostgreSQL")
    print("=" * 60)
    
    # Connect to database
    try:
        print("🔄 Connecting to database...")
        conn = psycopg2.connect(DATABASE_URL)
        print("✅ Connected successfully!")
        
        # Get initial count
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM documents")
        initial_count = cursor.fetchone()[0]
        print(f"📊 Initial document count: {initial_count}")
        
        # Process all CSV files
        csv_dir = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed"
        csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]
        
        print(f"\n📁 Found {len(csv_files)} CSV files to process")
        
        total_inserted = 0
        total_skipped = 0
        
        for csv_file in csv_files:
            csv_path = os.path.join(csv_dir, csv_file)
            inserted, skipped = load_csv_to_database(csv_path, conn)
            total_inserted += inserted
            total_skipped += skipped
        
        # Get final count and verify
        cursor.execute("SELECT COUNT(*) FROM documents")
        final_count = cursor.fetchone()[0]
        
        # Check municipality/state parsing
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE municipality IS NOT NULL AND municipality != ''
        """)
        municipality_count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE estado LIKE '%-%'
        """)
        problematic_count = cursor.fetchone()[0]
        
        print("\n" + "=" * 60)
        print("📊 SUMMARY:")
        print(f"  Total files processed: {len(csv_files)}")
        print(f"  Total records inserted/updated: {total_inserted}")
        print(f"  Total records skipped: {total_skipped}")
        print(f"  Final document count: {final_count}")
        print(f"  Documents with municipality: {municipality_count}")
        print(f"  Problematic estado values: {problematic_count}")
        
        # Show sample of properly parsed data
        if municipality_count > 0:
            print("\n📋 Sample of properly parsed records:")
            cursor.execute("""
                SELECT estado, municipality, titulo 
                FROM documents 
                WHERE municipality IS NOT NULL AND municipality != ''
                LIMIT 5
            """)
            for row in cursor.fetchall():
                print(f"  Estado: '{row[0]}', Municipality: '{row[1]}', Title: {row[2][:50]}...")
        
        conn.close()
        print("\n✅ Data loading completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()