#!/usr/bin/env python3
"""
Quick database verification script
"""

import sys

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def verify_database():
    """Quick database verification"""
    
    try:
        import psycopg2
        
        # Connect to database
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("✅ Database connection successful")
        
        # Check total documents
        cursor.execute("SELECT COUNT(*) FROM documents")
        total_count = cursor.fetchone()[0]
        print(f"📊 Total documents in database: {total_count}")
        
        # Check LexML documents
        cursor.execute("SELECT COUNT(*) FROM documents WHERE fonte = 'LexML'")
        lexml_count = cursor.fetchone()[0]
        print(f"📊 LexML documents: {lexml_count}")
        
        # Check for municipality-state issues
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE fonte = 'LexML' AND estado LIKE '%-%'
        """)
        problematic_count = cursor.fetchone()[0]
        print(f"📊 Documents with problematic state format (contains '-'): {problematic_count}")
        
        # Check for properly separated data
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE fonte = 'LexML' AND estado != '' AND municipality != ''
        """)
        fixed_count = cursor.fetchone()[0]
        print(f"📊 Documents with properly separated municipality-state: {fixed_count}")
        
        # Sample some data
        cursor.execute("""
            SELECT estado, municipality, titulo 
            FROM documents 
            WHERE fonte = 'LexML' AND municipality != '' 
            LIMIT 5
        """)
        
        samples = cursor.fetchall()
        print("📋 Sample records:")
        for row in samples:
            print(f"   Estado: '{row[0]}', Municipality: '{row[1]}' - {row[2][:40]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Verifying database status...")
    success = verify_database()
    sys.exit(0 if success else 1)