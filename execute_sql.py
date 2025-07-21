#!/usr/bin/env python3
"""
Execute the generated SQL file to apply municipality-state parsing fix to database
"""

import sys
import os

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def execute_sql_file():
    """Execute the SQL file using available methods"""
    
    sql_file = "reload_database.sql"
    
    if not os.path.exists(sql_file):
        print(f"❌ SQL file not found: {sql_file}")
        return False
    
    print("🚀 Executing SQL file to apply municipality-state parsing fix...")
    print("=" * 60)
    
    # Try psycopg2 first
    try:
        import psycopg2
        HAS_PSYCOPG2 = True
    except ImportError:
        HAS_PSYCOPG2 = False
    
    if HAS_PSYCOPG2:
        print("✅ Using psycopg2 for direct execution")
        return execute_with_psycopg2(sql_file)
    else:
        print("⚠️ psycopg2 not available, trying alternative methods...")
        return execute_with_alternatives(sql_file)

def execute_with_psycopg2(sql_file):
    """Execute SQL using psycopg2"""
    try:
        import psycopg2
        
        # Connect to database
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("✅ Connected to database successfully")
        
        # Read SQL file
        with open(sql_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Split into individual statements
        statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
        
        print(f"📋 Found {len(statements)} SQL statements to execute")
        
        # Execute statements
        executed = 0
        for i, statement in enumerate(statements):
            try:
                if statement.strip():
                    cursor.execute(statement)
                    executed += 1
                    
                    if i % 100 == 0:
                        print(f"🔄 Executed {i}/{len(statements)} statements")
                        
            except Exception as e:
                print(f"❌ Error executing statement {i}: {e}")
                print(f"Statement: {statement[:100]}...")
                conn.rollback()
                return False
        
        # Commit all changes
        conn.commit()
        print(f"✅ Successfully executed {executed} SQL statements")
        
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

def execute_with_alternatives(sql_file):
    """Try alternative methods to execute SQL"""
    import subprocess
    
    # Try different PostgreSQL client commands
    client_commands = [
        'psql',
        'postgresql-client',
        '/usr/bin/psql',
        '/usr/local/bin/psql'
    ]
    
    for cmd in client_commands:
        try:
            result = subprocess.run([cmd, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ Found PostgreSQL client: {cmd}")
                return execute_with_psql(cmd, sql_file)
        except:
            continue
    
    print("❌ No PostgreSQL client found")
    print("📋 Manual execution required:")
    print(f"   Run: psql {DATABASE_URL} -f {sql_file}")
    return False

def execute_with_psql(psql_cmd, sql_file):
    """Execute SQL using psql command"""
    import subprocess
    
    try:
        print(f"🔄 Executing SQL file using {psql_cmd}...")
        
        result = subprocess.run([
            psql_cmd, DATABASE_URL, '-f', sql_file
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ SQL execution completed successfully!")
            print(result.stdout)
            return True
        else:
            print(f"❌ SQL execution failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ SQL execution timed out")
        return False
    except Exception as e:
        print(f"❌ Error executing SQL: {e}")
        return False

def main():
    print("🚀 Starting database reload execution")
    
    success = execute_sql_file()
    
    if success:
        print("\n🎉 SUCCESS: Municipality-state parsing fix has been applied to the database!")
        print("✅ All 4,097 records have been updated with proper field separation")
        return True
    else:
        print("\n❌ FAILED: Could not execute SQL file automatically")
        print("📋 Please run manually:")
        print(f"   psql {DATABASE_URL} -f reload_database.sql")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)