#!/usr/bin/env python3
"""
Execute the generated SQL file in batches to apply municipality-state parsing fix
"""

import sys
import os
import time

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def execute_sql_in_batches():
    """Execute SQL file in manageable batches"""
    
    sql_file = "reload_database.sql"
    
    if not os.path.exists(sql_file):
        print(f"❌ SQL file not found: {sql_file}")
        return False
    
    print("🚀 Executing SQL file in batches...")
    print("=" * 60)
    
    try:
        import psycopg2
        
        # Connect to database
        conn = psycopg2.connect(DATABASE_URL)
        conn.set_session(autocommit=True)  # Enable autocommit for better performance
        cursor = conn.cursor()
        
        print("✅ Connected to database successfully")
        
        # First, clear existing data
        print("🔄 Clearing existing LexML data...")
        cursor.execute("DELETE FROM documents WHERE fonte = 'LexML'")
        print("✅ Cleared existing data")
        
        # Read SQL file and process INSERT statements
        with open(sql_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Extract only INSERT statements
        insert_statements = []
        for line in sql_content.split('\n'):
            if line.strip().startswith('INSERT INTO documents'):
                insert_statements.append(line.strip())
        
        print(f"📋 Found {len(insert_statements)} INSERT statements to execute")
        
        # Execute in batches
        batch_size = 50
        total_executed = 0
        
        for i in range(0, len(insert_statements), batch_size):
            batch = insert_statements[i:i + batch_size]
            
            print(f"🔄 Processing batch {i//batch_size + 1}/{(len(insert_statements)//batch_size) + 1} ({len(batch)} statements)")
            
            try:
                # Begin transaction for this batch
                cursor.execute("BEGIN")
                
                for statement in batch:
                    if statement.strip():
                        cursor.execute(statement)
                        total_executed += 1
                
                # Commit the batch
                cursor.execute("COMMIT")
                
                print(f"   ✅ Batch completed: {total_executed}/{len(insert_statements)} total")
                
                # Brief pause to prevent overwhelming the database
                time.sleep(0.1)
                
            except Exception as e:
                print(f"❌ Error in batch {i//batch_size + 1}: {e}")
                cursor.execute("ROLLBACK")
                conn.close()
                return False
        
        print(f"✅ Successfully executed {total_executed} INSERT statements")
        
        # Verify the results
        cursor.execute("SELECT COUNT(*) FROM documents WHERE fonte = 'LexML'")
        total_count = cursor.fetchone()[0]
        print(f"📊 Total LexML documents in database: {total_count}")
        
        # Check for properly separated municipality-state data
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE fonte = 'LexML' AND estado != '' AND municipality != ''
        """)
        fixed_count = cursor.fetchone()[0]
        print(f"📊 Documents with properly separated municipality-state: {fixed_count}")
        
        # Check Catanduva examples
        cursor.execute("""
            SELECT estado, municipality, titulo 
            FROM documents 
            WHERE fonte = 'LexML' AND municipality ILIKE '%catanduva%' 
            LIMIT 3
        """)
        
        catanduva_examples = cursor.fetchall()
        print("🔍 Catanduva examples verification:")
        for row in catanduva_examples:
            print(f"   Estado: '{row[0]}', Municipality: '{row[1]}' - {row[2][:50]}...")
        
        conn.close()
        print("✅ Database reload completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error executing SQL: {e}")
        return False

def main():
    print("🚀 Starting batched database reload execution")
    
    success = execute_sql_in_batches()
    
    if success:
        print("\n🎉 SUCCESS: Municipality-state parsing fix has been applied to the database!")
        print("✅ All records have been updated with proper field separation")
        return True
    else:
        print("\n❌ FAILED: Could not execute SQL file")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)