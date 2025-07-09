#!/usr/bin/env python3
"""
Railway PostgreSQL Migration Script
Migrates real legislative data from REAL_DATA_MIGRATION.sql to Railway PostgreSQL
"""

import asyncio
import asyncpg
import sys
from pathlib import Path

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
MIGRATION_FILE = "REAL_DATA_MIGRATION.sql"

async def execute_migration():
    """Execute the migration SQL file on Railway PostgreSQL"""
    print("🚀 Starting Railway PostgreSQL migration...")
    
    try:
        # Read the migration SQL file
        migration_path = Path(MIGRATION_FILE)
        if not migration_path.exists():
            print(f"❌ Migration file not found: {MIGRATION_FILE}")
            return False
            
        with open(migration_path, 'r', encoding='utf-8') as f:
            migration_sql = f.read()
        
        print(f"📄 Read migration file: {len(migration_sql)} characters")
        
        # Connect to Railway PostgreSQL
        print("🔌 Connecting to Railway PostgreSQL...")
        conn = await asyncpg.connect(DATABASE_URL)
        
        try:
            # Execute the migration
            print("⚡ Executing migration...")
            await conn.execute(migration_sql)
            
            # Verify the migration
            print("\n✅ Migration completed! Verifying data...")
            
            # Check row counts
            tables = ['lexml_parsed_enhanced', 'documents', 'legislative_data']
            for table in tables:
                count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
                print(f"  📊 {table}: {count} rows")
            
            # Show sample data
            print("\n📋 Sample data from lexml_parsed_enhanced:")
            rows = await conn.fetch("""
                SELECT title, urn_type, state, promulgation_date 
                FROM lexml_parsed_enhanced 
                ORDER BY promulgation_date DESC
                LIMIT 5
            """)
            
            for row in rows:
                print(f"  - {row['title'][:60]}...")
                print(f"    Type: {row['urn_type']}, State: {row['state']}, Date: {row['promulgation_date']}")
            
            print("\n🎉 Migration successful! Your Railway PostgreSQL now contains 889 real legislative documents.")
            return True
            
        finally:
            await conn.close()
            
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        print("\nTroubleshooting tips:")
        print("1. Check if the database URL is correct")
        print("2. Ensure the database is accessible from your network")
        print("3. Verify that tables don't already exist (you may need to drop them first)")
        return False

async def check_connection():
    """Test the database connection"""
    print("🔍 Testing database connection...")
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        version = await conn.fetchval("SELECT version()")
        print(f"✅ Connected successfully!")
        print(f"📊 PostgreSQL version: {version}")
        
        # Check existing tables
        tables = await conn.fetch("""
            SELECT tablename 
            FROM pg_tables 
            WHERE schemaname = 'public'
            ORDER BY tablename
        """)
        
        if tables:
            print(f"\n📋 Existing tables:")
            for table in tables:
                count = await conn.fetchval(f"SELECT COUNT(*) FROM {table['tablename']}")
                print(f"  - {table['tablename']}: {count} rows")
        else:
            print("\n📋 No existing tables found.")
            
        await conn.close()
        return True
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")
        return False

async def main():
    """Main execution function"""
    print("=" * 60)
    print("Railway PostgreSQL Migration Tool")
    print("=" * 60)
    
    # First check connection
    if not await check_connection():
        print("\n⚠️  Cannot connect to database. Please check your connection details.")
        return
    
    # Ask for confirmation
    print("\n⚠️  This will:")
    print("  1. DROP existing tables (lexml_parsed_enhanced, documents, legislative_data)")
    print("  2. CREATE new tables with proper schema")
    print("  3. INSERT 889 rows of real legislative data")
    
    response = input("\n❓ Do you want to proceed? (yes/no): ").strip().lower()
    
    if response == 'yes':
        await execute_migration()
    else:
        print("❌ Migration cancelled.")

if __name__ == "__main__":
    asyncio.run(main())