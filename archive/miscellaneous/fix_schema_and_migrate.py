#!/usr/bin/env python3
"""
Fix schema and migrate data from CSV
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
        # Handle duplicate timestamps
        if ' ' in date_str and date_str.count(':') > 2:
            date_str = date_str.split(' ')[0] + ' ' + date_str.split(' ')[1]
        
        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d/%m/%Y']:
            try:
                return datetime.strptime(date_str, fmt)
            except:
                continue
        return None
    except:
        return None

async def fix_and_migrate():
    print("🚀 Fixing schema and migrating data...")
    
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        # Step 1: Fix column types in documents table
        print("🔧 Updating schema to accommodate actual data lengths...")
        
        # Alter documents table columns
        await conn.execute("ALTER TABLE documents ALTER COLUMN tipo TYPE VARCHAR(200)")
        await conn.execute("ALTER TABLE documents ALTER COLUMN estado TYPE VARCHAR(200)")
        
        # Alter legislative_data table columns  
        await conn.execute("ALTER TABLE legislative_data ALTER COLUMN tipo TYPE VARCHAR(200)")
        await conn.execute("ALTER TABLE legislative_data ALTER COLUMN estado TYPE VARCHAR(200)")
        
        print("✅ Schema updated")
        
        # Step 2: Clear tables
        print("🧹 Clearing tables...")
        await conn.execute("TRUNCATE TABLE lexml_parsed_enhanced, documents, legislative_data CASCADE")
        
        # Step 3: Read CSV
        print("📄 Reading CSV...")
        with open(CSV_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        print(f"📊 Processing {len(rows)} rows...")
        
        # Step 4: Batch insert into lexml_parsed_enhanced
        print("⚡ Inserting data...")
        
        batch_data = []
        for row in rows:
            batch_data.append((
                row.get('search_term', ''),
                parse_date(row.get('date_searched')),
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
                parse_date(row.get('promulgation_date')),
                row.get('document_description', '')
            ))
        
        await conn.executemany("""
            INSERT INTO lexml_parsed_enhanced (
                search_term, date_searched, url, title, urn, urn_type,
                country, state, municipality, justice, region, court_class,
                document_type_full, promulgation_date, document_description
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """, batch_data)
        
        # Step 5: Populate documents table
        print("📄 Populating documents table...")
        await conn.execute("""
            INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, fonte, url)
            SELECT 
                urn, 
                title, 
                document_description,
                COALESCE(
                    CASE 
                        WHEN document_type_full ILIKE '%lei%' THEN 'lei'
                        WHEN document_type_full ILIKE '%decreto%' THEN 'decreto'
                        WHEN document_type_full ILIKE '%portaria%' THEN 'portaria'
                        WHEN document_type_full ILIKE '%resolução%' OR document_type_full ILIKE '%resolucao%' THEN 'resolucao'
                        WHEN document_type_full ILIKE '%medida provisória%' OR document_type_full ILIKE '%mpv%' THEN 'medida_provisoria'
                        ELSE LEFT(COALESCE(document_type_full, urn_type, 'outro'), 200)
                    END,
                    'outro'
                ),
                promulgation_date::date,
                LEFT(COALESCE(state, country, 'BR'), 200),
                'LexML',
                url
            FROM lexml_parsed_enhanced
            WHERE urn IS NOT NULL AND urn != ''
            ON CONFLICT (urn) DO NOTHING
        """)
        
        # Step 6: Populate legislative_data table
        print("📄 Populating legislative_data table...")
        await conn.execute("""
            INSERT INTO legislative_data (titulo, tipo, data, estado, fonte_original, url, ano)
            SELECT 
                title,
                COALESCE(
                    CASE 
                        WHEN document_type_full ILIKE '%lei%' THEN 'lei'
                        WHEN document_type_full ILIKE '%decreto%' THEN 'decreto'
                        WHEN document_type_full ILIKE '%portaria%' THEN 'portaria'
                        WHEN document_type_full ILIKE '%resolução%' OR document_type_full ILIKE '%resolucao%' THEN 'resolucao'
                        WHEN document_type_full ILIKE '%medida provisória%' OR document_type_full ILIKE '%mpv%' THEN 'medida_provisoria'
                        ELSE LEFT(COALESCE(document_type_full, urn_type, 'outro'), 200)
                    END,
                    'outro'
                ),
                promulgation_date::date,
                LEFT(COALESCE(state, country, 'BR'), 200),
                'LexML',
                url,
                EXTRACT(YEAR FROM promulgation_date)::integer
            FROM lexml_parsed_enhanced
            WHERE promulgation_date IS NOT NULL
        """)
        
        # Step 7: Verify results
        print("\n✅ Migration completed! Verifying...")
        
        for table in ['lexml_parsed_enhanced', 'documents', 'legislative_data']:
            count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
            print(f"  📊 {table}: {count} rows")
        
        # Show transport-related count
        transport_count = await conn.fetchval("""
            SELECT COUNT(*) 
            FROM documents 
            WHERE titulo ILIKE '%transport%' 
               OR conteudo ILIKE '%transport%'
        """)
        print(f"\n  🚗 Transport-related documents: {transport_count}")
        
        print("\n🎉 Migration from lexml_parsed_enhanced_fixed.csv completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(fix_and_migrate())