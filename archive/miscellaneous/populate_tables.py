#!/usr/bin/env python3
"""
Populate documents and legislative_data tables from lexml_parsed_enhanced
"""

import asyncio
import asyncpg
from datetime import datetime

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

async def populate_tables():
    print("🚀 Populating documents and legislative_data tables...")
    
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        # First, clear the tables
        print("🧹 Clearing target tables...")
        await conn.execute("TRUNCATE TABLE documents CASCADE")
        await conn.execute("TRUNCATE TABLE legislative_data CASCADE")
        
        # Populate documents table from lexml_parsed_enhanced
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
                        ELSE document_type_full
                    END, 
                    'outro'
                ) AS tipo,
                promulgation_date::date AS data_publicacao,
                COALESCE(state, country, 'BR') AS estado,
                'LexML' AS fonte,
                url
            FROM lexml_parsed_enhanced
            WHERE urn IS NOT NULL
            ON CONFLICT (urn) DO NOTHING
        """)
        
        docs_count = await conn.fetchval("SELECT COUNT(*) FROM documents")
        print(f"✅ Documents table: {docs_count} rows")
        
        # Populate legislative_data table
        print("📄 Populating legislative_data table...")
        await conn.execute("""
            INSERT INTO legislative_data (titulo, numero, tipo, data, estado, autor, fonte_original, url, ano)
            SELECT 
                title AS titulo,
                SUBSTRING(urn FROM '\d+') AS numero,
                COALESCE(
                    CASE 
                        WHEN urn_type = 'legislation' THEN 'lei'
                        WHEN urn_type = 'decree' THEN 'decreto'
                        WHEN urn_type = 'resolution' THEN 'resolucao'
                        ELSE document_type_full
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
        
        leg_count = await conn.fetchval("SELECT COUNT(*) FROM legislative_data")
        print(f"✅ Legislative_data table: {leg_count} rows")
        
        # Create indexes for better performance
        print("🔧 Creating indexes...")
        
        # Documents indexes
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data_publicacao)")
        
        # Legislative data indexes
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_legislative_tipo ON legislative_data(tipo)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_legislative_estado ON legislative_data(estado)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_legislative_ano ON legislative_data(ano)")
        
        # Show sample data
        print("\n📋 Sample data from documents:")
        rows = await conn.fetch("""
            SELECT titulo, tipo, estado, data_publicacao 
            FROM documents 
            ORDER BY data_publicacao DESC 
            LIMIT 5
        """)
        
        for row in rows:
            print(f"  - {row['titulo'][:60]}...")
            print(f"    Type: {row['tipo']}, State: {row['estado']}, Date: {row['data_publicacao']}")
        
        print("\n🎉 All tables populated successfully!")
        print(f"\nSummary:")
        print(f"  - lexml_parsed_enhanced: 889 rows")
        print(f"  - documents: {docs_count} rows")
        print(f"  - legislative_data: {leg_count} rows")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(populate_tables())