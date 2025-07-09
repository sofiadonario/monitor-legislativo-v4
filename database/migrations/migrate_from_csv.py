#!/usr/bin/env python3
"""
Migrate data from lexml_parsed_enhanced_fixed.csv to Railway PostgreSQL
This is the cleanest approach using the fixed CSV data directly.
"""

import asyncio
import asyncpg
import csv
from datetime import datetime
from pathlib import Path

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
CSV_FILE = "data/processed/lexml_parsed_enhanced_fixed.csv"

def parse_date(date_str):
    """Parse various date formats"""
    if not date_str or date_str == 'nan' or date_str == '':
        return None
    
    try:
        # Try different date formats
        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y']:
            try:
                return datetime.strptime(date_str, fmt)
            except:
                continue
        return None
    except:
        return None

async def migrate_from_csv():
    print("🚀 Starting migration from lexml_parsed_enhanced_fixed.csv...")
    
    # Check if CSV exists
    csv_path = Path(CSV_FILE)
    if not csv_path.exists():
        print(f"❌ CSV file not found: {CSV_FILE}")
        return
    
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        # Step 1: Clear existing data
        print("🧹 Clearing existing tables...")
        await conn.execute("TRUNCATE TABLE lexml_parsed_enhanced CASCADE")
        await conn.execute("TRUNCATE TABLE documents CASCADE")
        await conn.execute("TRUNCATE TABLE legislative_data CASCADE")
        
        # Step 2: Read CSV and insert data
        print("📄 Reading CSV file...")
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        print(f"📊 Found {len(rows)} rows in CSV")
        
        # Step 3: Insert into lexml_parsed_enhanced
        print("⚡ Inserting into lexml_parsed_enhanced...")
        
        insert_count = 0
        for i, row in enumerate(rows):
            if i % 100 == 0:
                print(f"  Progress: {i}/{len(rows)}...")
            
            try:
                # Parse dates
                date_searched = parse_date(row.get('date_searched'))
                promulgation_date = parse_date(row.get('promulgation_date'))
                
                # Insert into lexml_parsed_enhanced
                await conn.execute("""
                    INSERT INTO lexml_parsed_enhanced (
                        search_term, date_searched, url, title, urn, urn_type,
                        country, state, municipality, justice, region, court_class,
                        document_type_full, promulgation_date, document_description
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                """, 
                    row.get('search_term', ''),
                    date_searched,
                    row.get('url', ''),
                    row.get('title', ''),
                    row.get('urn', ''),
                    row.get('urn_type', ''),
                    row.get('country', ''),
                    row.get('state', ''),
                    row.get('municipality', ''),
                    row.get('justice', ''),
                    row.get('region', ''),
                    row.get('court_class', ''),
                    row.get('document_type_full', ''),
                    promulgation_date,
                    row.get('document_description', '')
                )
                insert_count += 1
                
            except Exception as e:
                print(f"⚠️ Warning: Failed to insert row {i}: {str(e)[:100]}")
                continue
        
        print(f"✅ Inserted {insert_count} rows into lexml_parsed_enhanced")
        
        # Step 4: Populate documents table
        print("📄 Populating documents table...")
        await conn.execute("""
            INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, fonte, url)
            SELECT 
                urn,
                title AS titulo,
                document_description AS conteudo,
                COALESCE(
                    CASE 
                        WHEN urn_type = 'legislation' THEN 'lei'
                        WHEN urn_type = 'decree' THEN 'decreto'
                        WHEN urn_type = 'resolution' THEN 'resolucao'
                        WHEN document_type_full ILIKE '%lei%' THEN 'lei'
                        WHEN document_type_full ILIKE '%decreto%' THEN 'decreto'
                        WHEN document_type_full ILIKE '%portaria%' THEN 'portaria'
                        WHEN document_type_full ILIKE '%resolução%' THEN 'resolucao'
                        ELSE COALESCE(document_type_full, 'outro')
                    END, 
                    'outro'
                ) AS tipo,
                promulgation_date::date AS data_publicacao,
                COALESCE(state, country, 'BR') AS estado,
                'LexML' AS fonte,
                url
            FROM lexml_parsed_enhanced
            WHERE urn IS NOT NULL AND urn != ''
            ON CONFLICT (urn) DO NOTHING
        """)
        
        # Step 5: Populate legislative_data table
        print("📄 Populating legislative_data table...")
        await conn.execute("""
            INSERT INTO legislative_data (titulo, numero, tipo, data, estado, autor, fonte_original, url, ano)
            SELECT 
                title AS titulo,
                SUBSTRING(urn FROM '\\d+') AS numero,
                COALESCE(
                    CASE 
                        WHEN urn_type = 'legislation' THEN 'lei'
                        WHEN urn_type = 'decree' THEN 'decreto'
                        WHEN urn_type = 'resolution' THEN 'resolucao'
                        WHEN document_type_full ILIKE '%lei%' THEN 'lei'
                        WHEN document_type_full ILIKE '%decreto%' THEN 'decreto'
                        WHEN document_type_full ILIKE '%portaria%' THEN 'portaria'
                        WHEN document_type_full ILIKE '%resolução%' THEN 'resolucao'
                        ELSE COALESCE(document_type_full, 'outro')
                    END, 
                    'outro'
                ) AS tipo,
                promulgation_date::date AS data,
                COALESCE(state, country, 'BR') AS estado,
                search_term AS autor,
                'LexML' AS fonte_original,
                url,
                EXTRACT(YEAR FROM promulgation_date)::integer AS ano
            FROM lexml_parsed_enhanced
            WHERE promulgation_date IS NOT NULL
        """)
        
        # Step 6: Verify results
        print("\n✅ Verifying migration...")
        
        tables = ['lexml_parsed_enhanced', 'documents', 'legislative_data']
        for table in tables:
            count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
            print(f"📊 {table}: {count} rows")
        
        # Show sample data
        print("\n📋 Sample migrated data:")
        rows = await conn.fetch("""
            SELECT title, urn_type, state, promulgation_date 
            FROM lexml_parsed_enhanced 
            WHERE promulgation_date IS NOT NULL
            ORDER BY promulgation_date DESC 
            LIMIT 5
        """)
        
        for row in rows:
            print(f"  - {row['title'][:60]}...")
            print(f"    Type: {row['urn_type']}, State: {row['state']}, Date: {row['promulgation_date']}")
        
        print("\n🎉 Migration from CSV completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(migrate_from_csv())