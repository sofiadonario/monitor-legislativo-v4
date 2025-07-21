#!/usr/bin/env python3
"""
Check Railway PostgreSQL table structure for municipality/state separation
"""

import psycopg2
import sys

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def check_tables():
    """Check table structure and data"""
    try:
        print("🔄 Connecting to Railway PostgreSQL...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("✅ Connection successful!\n")
        
        # Check documents table structure
        print("📊 Checking documents table structure:")
        cursor.execute("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'documents' 
            ORDER BY ordinal_position
        """)
        
        columns = cursor.fetchall()
        print(f"\nFound {len(columns)} columns in documents table:")
        for col in columns:
            print(f"  - {col[0]}: {col[1]} {'(nullable)' if col[2] == 'YES' else '(not null)'}")
        
        # Check if municipality column exists
        municipality_exists = any(col[0] == 'municipality' for col in columns)
        print(f"\n{'✅' if municipality_exists else '❌'} Municipality column exists: {municipality_exists}")
        
        # Check for data with combined municipality-state in estado column
        print("\n📊 Checking for problematic data (municipality-state in estado column):")
        cursor.execute("""
            SELECT COUNT(*) 
            FROM documents 
            WHERE estado LIKE '%-%' 
            AND estado NOT LIKE '%--%'
        """)
        problematic_count = cursor.fetchone()[0]
        print(f"  Records with '-' in estado column: {problematic_count}")
        
        # Check for properly separated data
        if municipality_exists:
            cursor.execute("""
                SELECT COUNT(*) 
                FROM documents 
                WHERE municipality IS NOT NULL 
                AND municipality != ''
            """)
            separated_count = cursor.fetchone()[0]
            print(f"  Records with separated municipality: {separated_count}")
        
        # Get total record count
        cursor.execute("SELECT COUNT(*) FROM documents")
        total_count = cursor.fetchone()[0]
        print(f"  Total records: {total_count}")
        
        # Sample problematic records
        if problematic_count > 0:
            print("\n📋 Sample problematic records:")
            cursor.execute("""
                SELECT id, estado, municipality, titulo 
                FROM documents 
                WHERE estado LIKE '%-%' 
                LIMIT 5
            """)
            samples = cursor.fetchall()
            for row in samples:
                print(f"  ID: {row[0]}, Estado: '{row[1]}', Municipality: '{row[2]}', Title: {row[3][:50]}...")
        
        # Sample properly parsed records
        if municipality_exists:
            print("\n📋 Sample properly parsed records:")
            cursor.execute("""
                SELECT id, estado, municipality, titulo 
                FROM documents 
                WHERE municipality IS NOT NULL 
                AND municipality != ''
                AND estado NOT LIKE '%-%'
                LIMIT 5
            """)
            samples = cursor.fetchall()
            for row in samples:
                print(f"  ID: {row[0]}, Estado: '{row[1]}', Municipality: '{row[2]}', Title: {row[3][:50]}...")
        
        # Check other relevant tables
        print("\n📊 Checking other tables:")
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        print(f"Found {len(tables)} tables:")
        for table in tables:
            print(f"  - {table[0]}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Railway PostgreSQL Table Structure Check")
    print("=" * 60)
    success = check_tables()
    sys.exit(0 if success else 1)