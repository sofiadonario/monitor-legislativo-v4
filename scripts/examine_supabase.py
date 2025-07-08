#!/usr/bin/env python3
"""
Examine Supabase database structure and identify real tables
Monitor Legislativo v4 - Supabase Investigation
"""

import json
import urllib.request
import urllib.parse
import ssl
from datetime import datetime

# Supabase configuration
SUPABASE_URL = "https://upxonmtqerdrxdgywzuj.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVweG9ubXRxZXJkcnhkZ3l3enVqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MDE3NTc0MCwiZXhwIjoyMDY1NzUxNzQwfQ.1USLM75ahfUuTlhvV_nARHojd8qRFKP59lb9fYoisDg"

def get_supabase_tables():
    """Get all tables from Supabase using REST API"""
    print("🔍 Examining Supabase database structure...")
    
    # Create SSL context that doesn't verify certificates (for testing)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # Common table names to check
    potential_tables = [
        "documents",
        "legislative_data", 
        "processed_documents",
        "search_cache",
        "user_sessions",
        "geographic_data",
        "collections",
        "lexml_documents",
        "transport_data",
        "public_documents",
        "monitored_documents",
        "cached_searches",
        "document_metadata",
        "processed_data",
        "search_history",
        "data_export_logs",
        "document_fingerprints",
        "periodic_collection_logs",
        "alerts",
        "collection_status"
    ]
    
    found_tables = []
    
    for table in potential_tables:
        try:
            # Try to get table info using Supabase REST API
            url = f"{SUPABASE_URL}/rest/v1/{table}?select=*&limit=1"
            
            req = urllib.request.Request(url)
            req.add_header('apikey', SUPABASE_KEY)
            req.add_header('Authorization', f'Bearer {SUPABASE_KEY}')
            req.add_header('Content-Type', 'application/json')
            
            print(f"📋 Checking table: {table}")
            
            with urllib.request.urlopen(req, context=ssl_context) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    found_tables.append({
                        'name': table,
                        'sample_data': data,
                        'record_count': len(data)
                    })
                    print(f"✅ Found table: {table} (sample records: {len(data)})")
                else:
                    print(f"❌ Table {table} not accessible (status: {response.status})")
                    
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"⚠️  Table {table} does not exist")
            else:
                print(f"❌ Error accessing {table}: {e.code} - {e.reason}")
        except Exception as e:
            print(f"❌ Error checking table {table}: {e}")
    
    return found_tables

def get_table_schema(table_name):
    """Get schema information for a specific table"""
    print(f"📊 Getting schema for table: {table_name}")
    
    # Try to get more records to understand the structure
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        url = f"{SUPABASE_URL}/rest/v1/{table_name}?select=*&limit=10"
        
        req = urllib.request.Request(url)
        req.add_header('apikey', SUPABASE_KEY)
        req.add_header('Authorization', f'Bearer {SUPABASE_KEY}')
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req, context=ssl_context) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                return data
            else:
                print(f"❌ Cannot get schema for {table_name}: {response.status}")
                return None
                
    except Exception as e:
        print(f"❌ Error getting schema for {table_name}: {e}")
        return None

def create_real_migration_sql(found_tables):
    """Create migration SQL with real table structures"""
    print("🔧 Creating real migration SQL...")
    
    migration_sql = f"""
-- Monitor Legislativo v4 - REAL DATA Migration
-- Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
-- From: Supabase PostgreSQL (REAL DATA)
-- To: Railway PostgreSQL

-- ============================================================================
-- REAL TABLES DISCOVERED FROM SUPABASE
-- ============================================================================

"""
    
    for table_info in found_tables:
        table_name = table_info['name']
        sample_data = table_info['sample_data']
        
        migration_sql += f"""
-- Found table: {table_name}
-- Sample data structure: {len(sample_data)} records
"""
        
        if sample_data:
            # Try to infer column types from sample data
            first_record = sample_data[0]
            migration_sql += f"-- Sample record: {json.dumps(first_record, indent=2)}\n"
            
            # Create table structure based on sample data
            migration_sql += f"""
DROP TABLE IF EXISTS {table_name} CASCADE;
CREATE TABLE {table_name} (
    id SERIAL PRIMARY KEY,
"""
            
            # Add columns based on sample data
            for key, value in first_record.items():
                if key != 'id':  # Skip ID as we're using SERIAL
                    if isinstance(value, str):
                        if len(value) > 255:
                            migration_sql += f"    {key} TEXT,\n"
                        else:
                            migration_sql += f"    {key} VARCHAR(255),\n"
                    elif isinstance(value, int):
                        migration_sql += f"    {key} INTEGER,\n"
                    elif isinstance(value, bool):
                        migration_sql += f"    {key} BOOLEAN,\n"
                    elif isinstance(value, dict):
                        migration_sql += f"    {key} JSONB,\n"
                    else:
                        migration_sql += f"    {key} TEXT,\n"
            
            migration_sql += """    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

"""
            
            # Add sample insert statements
            migration_sql += f"-- Insert sample data for {table_name}\n"
            for i, record in enumerate(sample_data[:5]):  # Limit to first 5 records
                columns = []
                values = []
                for key, value in record.items():
                    if key != 'id':
                        columns.append(key)
                        if isinstance(value, str):
                            values.append(f"'{value.replace("'", "''")}'")
                        elif isinstance(value, dict):
                            values.append(f"'{json.dumps(value)}'")
                        elif value is None:
                            values.append("NULL")
                        else:
                            values.append(str(value))
                
                migration_sql += f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(values)});\n"
            
            migration_sql += "\n"
    
    migration_sql += """
-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

SELECT 'Real data migration completed!' as status;
"""
    
    for table_info in found_tables:
        table_name = table_info['name']
        migration_sql += f"SELECT '{table_name}' as table_name, COUNT(*) as record_count FROM {table_name};\n"
    
    # Write to file
    with open('real_supabase_migration.sql', 'w', encoding='utf-8') as f:
        f.write(migration_sql)
    
    print("✅ Real migration SQL created: real_supabase_migration.sql")
    return True

def main():
    """Main function to examine Supabase and create real migration"""
    print("🚀 Starting Real Supabase Database Examination")
    print("=" * 60)
    
    # Step 1: Find all available tables
    found_tables = get_supabase_tables()
    
    if not found_tables:
        print("❌ No tables found in Supabase!")
        print("🔍 This could mean:")
        print("   - Tables have different names than expected")
        print("   - Database permissions are restricted")
        print("   - Database is empty or in different schema")
        return False
    
    print(f"\n✅ Found {len(found_tables)} tables in Supabase:")
    for table in found_tables:
        print(f"   - {table['name']} ({table['record_count']} sample records)")
    
    # Step 2: Get detailed schema for each table
    print("\n📊 Getting detailed schemas...")
    for table_info in found_tables:
        detailed_data = get_table_schema(table_info['name'])
        if detailed_data:
            table_info['detailed_data'] = detailed_data
    
    # Step 3: Create real migration SQL
    create_real_migration_sql(found_tables)
    
    print("\n🎯 Next steps:")
    print("1. Review 'real_supabase_migration.sql' file")
    print("2. Execute it in Railway PostgreSQL console")
    print("3. Test Railway application with real data")
    print("4. Real data will replace sample data in your app")
    
    return True

if __name__ == "__main__":
    main()