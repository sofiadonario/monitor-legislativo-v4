#!/usr/bin/env python3
"""
Apply data fixes to Railway PostgreSQL database
"""

import psycopg2

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def apply_fixes():
    """Apply SQL fixes to the database"""
    try:
        print("🔧 Applying data fixes to Railway PostgreSQL...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Read SQL file
        with open('fix_data_issues.sql', 'r') as f:
            sql_content = f.read()
        
        # Split into individual statements (simple split by semicolon)
        statements = [s.strip() for s in sql_content.split(';') if s.strip() and not s.strip().startswith('--')]
        
        print(f"📝 Found {len(statements)} SQL statements to execute")
        
        # Execute each statement
        for i, statement in enumerate(statements, 1):
            if statement.strip():
                print(f"\n🔄 Executing statement {i}...")
                try:
                    cursor.execute(statement)
                    if cursor.description:
                        # This is a SELECT statement, show results
                        results = cursor.fetchall()
                        for row in results:
                            print(f"   {row}")
                    else:
                        # This is an UPDATE statement
                        print(f"   ✅ Updated {cursor.rowcount} rows")
                except Exception as e:
                    print(f"   ⚠️ Error: {e}")
                    conn.rollback()
                    continue
        
        # Commit all changes
        conn.commit()
        print("\n✅ All fixes applied successfully!")
        
        # Show final statistics
        print("\n📊 Final Database Statistics:")
        
        cursor.execute("SELECT COUNT(*) FROM documents")
        total = cursor.fetchone()[0]
        print(f"   Total documents: {total}")
        
        cursor.execute("SELECT COUNT(*) FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado !~ '-'")
        good_estado = cursor.fetchone()[0]
        print(f"   Documents with clean estado: {good_estado}")
        
        cursor.execute("SELECT COUNT(*) FROM documents WHERE municipality IS NOT NULL AND municipality != ''")
        with_municipality = cursor.fetchone()[0]
        print(f"   Documents with municipality: {with_municipality}")
        
        cursor.execute("SELECT COUNT(*) FROM documents WHERE estado LIKE '%-%'")
        problematic = cursor.fetchone()[0]
        print(f"   Remaining problematic estados: {problematic}")
        
        # Show sample of fixed records
        print("\n📋 Sample of fixed records:")
        cursor.execute("""
            SELECT id, estado, municipality, titulo
            FROM documents 
            WHERE metadata->>'data_fixes_applied' = '2025-07-21_municipality_state_parsing'
            AND estado IS NOT NULL AND estado != ''
            LIMIT 5
        """)
        samples = cursor.fetchall()
        for sample in samples:
            print(f"   ID {sample[0]}: Estado='{sample[1]}', Municipality='{sample[2]}'")
            print(f"      Title: {sample[3][:60]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    apply_fixes()