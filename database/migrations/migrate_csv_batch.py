#!/usr/bin/env python3
"""
Batch migration from CSV - much faster approach
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
        # Handle the duplicate timestamp issue
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

async def migrate_batch():
    print("🚀 Starting batch migration from CSV...")
    
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        # Clear tables
        print("🧹 Clearing tables...")
        await conn.execute("TRUNCATE TABLE lexml_parsed_enhanced, documents, legislative_data CASCADE")
        
        # Read CSV
        print("📄 Reading CSV...")
        with open(CSV_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        print(f"📊 Processing {len(rows)} rows...")
        
        # Prepare data for batch insert
        lexml_data = []
        for row in rows:
            lexml_data.append((
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
        
        # Batch insert into lexml_parsed_enhanced
        print("⚡ Batch inserting into lexml_parsed_enhanced...")
        await conn.executemany("""
            INSERT INTO lexml_parsed_enhanced (
                search_term, date_searched, url, title, urn, urn_type,
                country, state, municipality, justice, region, court_class,
                document_type_full, promulgation_date, document_description
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """, lexml_data)
        
        # Populate other tables using SQL
        print("📄 Populating documents and legislative_data...")
        
        await conn.execute("""
            INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, fonte, url)
            SELECT 
                urn, title, document_description,
                CASE 
                    WHEN document_type_full ILIKE '%lei%' THEN 'lei'
                    WHEN document_type_full ILIKE '%decreto%' THEN 'decreto'
                    ELSE COALESCE(document_type_full, 'outro')
                END,
                promulgation_date::date,
                COALESCE(state, country, 'BR'),
                'LexML',
                url
            FROM lexml_parsed_enhanced
            WHERE urn IS NOT NULL AND urn != ''
            ON CONFLICT (urn) DO NOTHING
        """)
        
        await conn.execute("""
            INSERT INTO legislative_data (titulo, tipo, data, estado, fonte_original, url, ano)
            SELECT 
                title,
                CASE 
                    WHEN document_type_full ILIKE '%lei%' THEN 'lei'
                    WHEN document_type_full ILIKE '%decreto%' THEN 'decreto'
                    ELSE COALESCE(document_type_full, 'outro')
                END,
                promulgation_date::date,
                COALESCE(state, country, 'BR'),
                'LexML',
                url,
                EXTRACT(YEAR FROM promulgation_date)::integer
            FROM lexml_parsed_enhanced
            WHERE promulgation_date IS NOT NULL
        """)
        
        # Verify
        print("\n✅ Verification:")
        for table in ['lexml_parsed_enhanced', 'documents', 'legislative_data']:
            count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
            print(f"  {table}: {count} rows")
        
        print("\n🎉 Batch migration completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(migrate_batch())