#!/usr/bin/env python3
"""
Direct PostgreSQL query to find all tables in Supabase
Monitor Legislativo v4 - PostgreSQL Direct Connection
"""

import subprocess
import json
import os
from datetime import datetime

# Database configuration
DB_URL = "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres"

def run_psql_query(query, description):
    """Run a PostgreSQL query using psql command"""
    print(f"\n📋 {description}")
    print(f"🔍 Query: {query}")
    
    # Create the psql command
    cmd = ['psql', DB_URL, '-c', query]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Query executed successfully")
            print("📊 Result:")
            print(result.stdout)
            return result.stdout
        else:
            print(f"❌ Query failed: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print("❌ Query timeout")
        return None
    except FileNotFoundError:
        print("❌ psql command not found. Please install PostgreSQL client tools.")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def find_all_tables():
    """Find all tables in the database"""
    print("🔍 Searching for ALL tables in Supabase database...")
    
    # Query to get all tables with row counts
    query = """
    SELECT 
        schemaname,
        tablename,
        n_tup_ins as total_inserts,
        n_tup_upd as total_updates,
        n_tup_del as total_deletes,
        n_live_tup as live_rows,
        n_dead_tup as dead_rows
    FROM pg_stat_user_tables 
    ORDER BY n_live_tup DESC;
    """
    
    result = run_psql_query(query, "Getting all tables with row counts")
    
    if result:
        print("\n🎯 Looking for table with 889 rows...")
        lines = result.strip().split('\n')
        
        for line in lines:
            if '889' in line:
                print(f"🎯 FOUND POTENTIAL MATCH: {line}")
    
    return result

def get_table_structure(table_name):
    """Get the structure of a specific table"""
    print(f"\n📊 Getting structure for table: {table_name}")
    
    query = f"""
    SELECT 
        column_name,
        data_type,
        is_nullable,
        column_default
    FROM information_schema.columns 
    WHERE table_name = '{table_name}' AND table_schema = 'public'
    ORDER BY ordinal_position;
    """
    
    return run_psql_query(query, f"Getting structure for table {table_name}")

def export_table_data(table_name, limit=None):
    """Export data from a specific table"""
    print(f"\n📥 Exporting data from table: {table_name}")
    
    if limit:
        query = f"SELECT * FROM {table_name} LIMIT {limit};"
    else:
        query = f"SELECT * FROM {table_name};"
    
    return run_psql_query(query, f"Exporting data from {table_name}")

def create_migration_from_table(table_name):
    """Create migration SQL for a specific table"""
    print(f"\n🔧 Creating migration for table: {table_name}")
    
    # Get table structure
    structure = get_table_structure(table_name)
    
    if not structure:
        print("❌ Could not get table structure")
        return False
    
    # Export the data using pg_dump
    dump_cmd = f'pg_dump "{DB_URL}" --table={table_name} --data-only --inserts'
    
    try:
        result = subprocess.run(dump_cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            # Create migration file
            migration_sql = f"""
-- Monitor Legislativo v4 - REAL DATA Migration
-- Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
-- From: Supabase PostgreSQL table '{table_name}'
-- To: Railway PostgreSQL

-- ============================================================================
-- TABLE STRUCTURE
-- ============================================================================

{structure}

-- ============================================================================
-- REAL DATA FROM {table_name.upper()}
-- ============================================================================

{result.stdout}

-- ============================================================================
-- VERIFICATION
-- ============================================================================

SELECT 'Real data migration completed!' as status;
SELECT COUNT(*) as total_records FROM {table_name};
"""
            
            filename = f"real_migration_{table_name}.sql"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(migration_sql)
            
            print(f"✅ Migration created: {filename}")
            return True
        else:
            print(f"❌ pg_dump failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error creating migration: {e}")
        return False

def main():
    """Main function to discover and migrate real data"""
    print("🚀 Starting Direct PostgreSQL Database Discovery")
    print("=" * 60)
    
    # Step 1: Find all tables
    tables_result = find_all_tables()
    
    if not tables_result:
        print("❌ Could not get table list")
        return False
    
    # Step 2: Ask user to identify the table with 889 rows
    print("\n🎯 Based on the output above, which table has 889 rows?")
    print("📝 Please identify the table name and I'll create the migration.")
    
    # For now, let's try some common table names that might have data
    potential_tables = [
        'documents', 'processed_documents', 'search_results',
        'lexml_documents', 'collection_logs', 'export_logs',
        'data_export_logs', 'periodic_collection_logs'
    ]
    
    print("\n🔍 Testing potential table names...")
    for table in potential_tables:
        query = f"SELECT COUNT(*) FROM {table};"
        result = run_psql_query(query, f"Checking row count for {table}")
        
        if result and '889' in result:
            print(f"🎯 FOUND IT! Table '{table}' has 889 rows!")
            
            # Create migration for this table
            if create_migration_from_table(table):
                print(f"\n✅ SUCCESS! Real data migration created for table: {table}")
                print("🎯 Next steps:")
                print(f"1. Execute the migration SQL file in Railway PostgreSQL")
                print(f"2. Your app will now have 889 real records from {table}")
                return True
    
    print("\n❌ Could not automatically find the table with 889 rows")
    print("🔍 Please check the table list above and manually identify the correct table")
    
    return False

if __name__ == "__main__":
    main()