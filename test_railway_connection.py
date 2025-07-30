#!/usr/bin/env python3

import psycopg2
import sys

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def test_connection():
    """Test Railway database connection and list tables"""
    try:
        print("🔗 Testing Railway database connection...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Test basic connectivity
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        print(f"✅ Connected to PostgreSQL: {version[0][:50]}...")
        
        # List all tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        tables = cursor.fetchall()
        print(f"📊 Found {len(tables)} tables:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # Test document tables specifically
        document_tables = []
        for table in tables:
            table_name = table[0]
            if 'document' in table_name.lower() or 'lexml' in table_name.lower():
                document_tables.append(table_name)
        
        if document_tables:
            print(f"\n📄 Document tables found: {len(document_tables)}")
            for doc_table in document_tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {doc_table};")
                    count = cursor.fetchone()[0]
                    print(f"  - {doc_table}: {count:,} rows")
                    
                    # Get sample data from the largest table
                    if count > 10000:
                        cursor.execute(f"""
                            SELECT column_name 
                            FROM information_schema.columns 
                            WHERE table_name = '{doc_table}'
                            ORDER BY ordinal_position
                            LIMIT 10;
                        """)
                        columns = [col[0] for col in cursor.fetchall()]
                        print(f"    Columns: {', '.join(columns)}")
                        
                        # Get sample data
                        cursor.execute(f"SELECT * FROM {doc_table} LIMIT 3;")
                        sample_data = cursor.fetchall()
                        print(f"    Sample rows: {len(sample_data)}")
                        
                except Exception as e:
                    print(f"    ❌ Error accessing {doc_table}: {e}")
        else:
            print("❌ No document tables found!")
        
        cursor.close()
        conn.close()
        print("✅ Connection test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)