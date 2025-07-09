#!/usr/bin/env python3
"""
Automatic Railway PostgreSQL Migration Script
"""

import asyncio
import asyncpg
from pathlib import Path

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

async def migrate():
    print("🚀 Starting automatic migration...")
    
    # Read migration file
    with open("REAL_DATA_MIGRATION_FIXED.sql", 'r', encoding='utf-8') as f:
        migration_sql = f.read()
    
    # Connect and execute
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute(migration_sql)
        
        # Verify
        count = await conn.fetchval("SELECT COUNT(*) FROM lexml_parsed_enhanced")
        print(f"✅ Migration successful! Inserted {count} rows")
        
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(migrate())