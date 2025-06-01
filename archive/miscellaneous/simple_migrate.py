#!/usr/bin/env python3
"""
Simple Railway PostgreSQL Migration
Executes migration in chunks to avoid complex SQL issues
"""

import asyncio
import asyncpg
import re

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

async def migrate():
    print("🚀 Starting simple migration...")
    
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        # Step 1: Drop existing tables
        print("📦 Dropping existing tables...")
        await conn.execute("DROP TABLE IF EXISTS lexml_parsed_enhanced CASCADE")
        await conn.execute("DROP TABLE IF EXISTS documents CASCADE")
        await conn.execute("DROP TABLE IF EXISTS legislative_data CASCADE")
        
        # Step 2: Create tables
        print("🏗️ Creating tables...")
        await conn.execute("""
            CREATE TABLE lexml_parsed_enhanced (
                id SERIAL PRIMARY KEY,
                search_term VARCHAR(255),
                date_searched TIMESTAMP,
                url TEXT,
                title TEXT,
                urn TEXT,
                urn_type VARCHAR(255),
                country VARCHAR(255),
                state VARCHAR(255),
                municipality VARCHAR(255),
                justice VARCHAR(255),
                region VARCHAR(255),
                court_class VARCHAR(255),
                document_type_full VARCHAR(255),
                promulgation_date TIMESTAMP,
                document_description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await conn.execute("""
            CREATE TABLE documents (
                id SERIAL PRIMARY KEY,
                urn VARCHAR(500) UNIQUE,
                titulo TEXT,
                conteudo TEXT,
                tipo VARCHAR(100),
                data_publicacao DATE,
                estado VARCHAR(100),
                autor VARCHAR(200),
                fonte VARCHAR(100),
                url TEXT,
                metadata JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await conn.execute("""
            CREATE TABLE legislative_data (
                id SERIAL PRIMARY KEY,
                titulo TEXT,
                numero VARCHAR(50),
                tipo VARCHAR(100),
                data DATE,
                estado VARCHAR(100),
                autor VARCHAR(200),
                fonte_original VARCHAR(100),
                url TEXT,
                ano INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Step 3: Read and process insert statements
        print("📄 Reading migration data...")
        with open('REAL_DATA_MIGRATION_FIXED.sql', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract INSERT statements
        insert_pattern = r"INSERT INTO \w+ .*?;(?=\n|$)"
        inserts = re.findall(insert_pattern, content, re.DOTALL)
        
        print(f"📊 Found {len(inserts)} INSERT statements")
        
        # Execute inserts
        for i, insert_stmt in enumerate(inserts):
            if i % 100 == 0:
                print(f"⚡ Progress: {i}/{len(inserts)} statements...")
            
            try:
                await conn.execute(insert_stmt)
            except Exception as e:
                print(f"⚠️ Warning: Failed to insert row {i}: {str(e)[:100]}")
                continue
        
        # Step 4: Verify
        print("\n✅ Verifying migration...")
        
        tables = ['lexml_parsed_enhanced', 'documents', 'legislative_data']
        for table in tables:
            count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
            print(f"📊 {table}: {count} rows")
        
        print("\n🎉 Migration completed!")
        
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(migrate())