#!/usr/bin/env python3
"""
Discover ALL tables in Supabase database using proper schema queries
Monitor Legislativo v4 - Complete Database Discovery
"""

import json
import urllib.request
import urllib.parse
import ssl
from datetime import datetime

# Supabase configuration
SUPABASE_URL = "https://upxonmtqerdrxdgywzuj.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVweG9ubXRxZXJkcnhkZ3l3enVqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MDE3NTc0MCwiZXhwIjoyMDY1NzUxNzQwfQ.1USLM75ahfUuTlhvV_nARHojd8qRFKP59lb9fYoisDg"

def make_supabase_request(endpoint, params=None):
    """Make authenticated request to Supabase"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    url = f"{SUPABASE_URL}/rest/v1/{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    
    req = urllib.request.Request(url)
    req.add_header('apikey', SUPABASE_KEY)
    req.add_header('Authorization', f'Bearer {SUPABASE_KEY}')
    req.add_header('Content-Type', 'application/json')
    
    try:
        with urllib.request.urlopen(req, context=ssl_context) as response:
            if response.status == 200:
                return json.loads(response.read().decode())
            else:
                print(f"❌ Error: {response.status} - {response.reason}")
                return None
    except Exception as e:
        print(f"❌ Request failed: {e}")
        return None

def get_all_tables_from_schema():
    """Get all tables using information_schema query"""
    print("🔍 Discovering ALL tables in Supabase database...")
    
    # First, let's try to get table list using PostgREST metadata
    print("📋 Getting table metadata from PostgREST...")
    
    # Use the root endpoint to get OpenAPI spec which lists all tables
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # Try to get the OpenAPI spec
    try:
        req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/")
        req.add_header('apikey', SUPABASE_KEY)
        req.add_header('Authorization', f'Bearer {SUPABASE_KEY}')
        req.add_header('Accept', 'application/openapi+json')
        
        with urllib.request.urlopen(req, context=ssl_context) as response:
            if response.status == 200:
                openapi_data = json.loads(response.read().decode())
                
                # Extract table names from OpenAPI paths
                tables = []
                if 'paths' in openapi_data:
                    for path in openapi_data['paths']:
                        if path.startswith('/'):
                            table_name = path.strip('/')
                            if table_name and '/' not in table_name:
                                tables.append(table_name)
                
                print(f"✅ Found {len(tables)} tables from OpenAPI spec:")
                for table in sorted(tables):
                    print(f"   - {table}")
                
                return tables
                
    except Exception as e:
        print(f"❌ Failed to get OpenAPI spec: {e}")
    
    # Fallback: try common table names that might exist
    print("\n🔍 Fallback: Testing common table patterns...")
    
    common_patterns = [
        # Document-related tables
        'documents', 'doc', 'document', 'docs',
        'legislative_documents', 'legislation', 'laws', 'bills',
        'processed_documents', 'processed_data', 'processing_results',
        
        # Search and cache tables
        'search_results', 'search_cache', 'cached_results',
        'search_history', 'search_queries', 'queries',
        
        # Collection tables
        'collections', 'collection_logs', 'collection_status',
        'periodic_collections', 'data_collections',
        
        # Export and processing
        'export_logs', 'data_export_logs', 'exports',
        'processing_logs', 'batch_processing', 'jobs',
        
        # Metadata and fingerprints
        'document_fingerprints', 'fingerprints', 'metadata',
        'document_metadata', 'file_metadata',
        
        # Geographic and transport
        'transport_data', 'geographic_data', 'spatial_data',
        'municipalities', 'states', 'regions',
        
        # LexML specific
        'lexml_documents', 'lexml_data', 'lexml_cache',
        'lexml_results', 'lexml_search',
        
        # User and session management
        'users', 'user_sessions', 'sessions',
        'alerts', 'notifications',
        
        # Analysis and monitoring
        'analysis_results', 'monitoring_data', 'statistics',
        'performance_metrics', 'system_logs'
    ]
    
    found_tables = []
    
    for table_name in common_patterns:
        print(f"📋 Testing table: {table_name}")
        
        # Try to get count of records
        try:
            data = make_supabase_request(table_name, {'select': 'count', 'head': 'true'})
            if data is not None:
                # If we get here, the table exists
                found_tables.append(table_name)
                print(f"✅ Found table: {table_name}")
                
                # Get a sample of records to see the structure
                sample_data = make_supabase_request(table_name, {'select': '*', 'limit': '3'})
                if sample_data:
                    print(f"   📊 Sample records: {len(sample_data)}")
                    if sample_data:
                        print(f"   🔍 First record keys: {list(sample_data[0].keys())}")
                
        except Exception as e:
            print(f"   ❌ Not found: {table_name}")
    
    return found_tables

def get_table_with_889_rows():
    """Try to find the table with 889 rows"""
    print("\n🎯 Searching for table with 889 rows...")
    
    # Get all tables first
    all_tables = get_all_tables_from_schema()
    
    if not all_tables:
        print("❌ No tables found!")
        return None
    
    # Check each table for row count
    for table_name in all_tables:
        try:
            print(f"📊 Checking row count for: {table_name}")
            
            # Get all records to count them
            data = make_supabase_request(table_name, {'select': '*'})
            if data:
                row_count = len(data)
                print(f"   📈 {table_name}: {row_count} rows")
                
                if row_count == 889:
                    print(f"🎯 FOUND IT! Table '{table_name}' has exactly 889 rows!")
                    return table_name, data
                elif row_count > 0:
                    print(f"   ℹ️  Table '{table_name}' has {row_count} rows")
                    
        except Exception as e:
            print(f"   ❌ Error checking {table_name}: {e}")
    
    return None

def create_comprehensive_migration(table_name, data):
    """Create migration SQL with the real data"""
    print(f"\n🔧 Creating comprehensive migration for table: {table_name}")
    
    if not data:
        print("❌ No data to migrate!")
        return False
    
    # Analyze the data structure
    first_record = data[0]
    columns = list(first_record.keys())
    
    print(f"📊 Table structure: {len(columns)} columns")
    print(f"📋 Columns: {columns}")
    
    # Create migration SQL
    migration_sql = f"""
-- Monitor Legislativo v4 - REAL DATA Migration
-- Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
-- From: Supabase PostgreSQL table '{table_name}' ({len(data)} rows)
-- To: Railway PostgreSQL

-- ============================================================================
-- REAL TABLE: {table_name}
-- ============================================================================

-- Drop existing table if it exists
DROP TABLE IF EXISTS {table_name} CASCADE;

-- Create table structure based on real data
CREATE TABLE {table_name} (
    id SERIAL PRIMARY KEY,
"""
    
    # Generate column definitions based on sample data
    for col in columns:
        if col == 'id':
            continue  # Skip ID as we're using SERIAL
        
        # Analyze column type from sample data
        sample_values = [record.get(col) for record in data[:10] if record.get(col) is not None]
        
        if not sample_values:
            migration_sql += f"    {col} TEXT,\n"
        elif all(isinstance(v, str) for v in sample_values):
            max_length = max(len(v) for v in sample_values)
            if max_length > 255:
                migration_sql += f"    {col} TEXT,\n"
            else:
                migration_sql += f"    {col} VARCHAR({max(max_length * 2, 255)}),\n"
        elif all(isinstance(v, int) for v in sample_values):
            migration_sql += f"    {col} INTEGER,\n"
        elif all(isinstance(v, bool) for v in sample_values):
            migration_sql += f"    {col} BOOLEAN,\n"
        elif all(isinstance(v, dict) for v in sample_values):
            migration_sql += f"    {col} JSONB,\n"
        else:
            migration_sql += f"    {col} TEXT,\n"
    
    migration_sql += """    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert real data
"""
    
    # Insert all the real data
    for i, record in enumerate(data):
        if i % 100 == 0:
            migration_sql += f"-- Inserting records {i}-{min(i+99, len(data))}\n"
        
        columns_list = []
        values_list = []
        
        for col in columns:
            if col == 'id':
                continue
            
            value = record.get(col)
            columns_list.append(col)
            
            if value is None:
                values_list.append('NULL')
            elif isinstance(value, str):
                # Escape single quotes
                escaped_value = value.replace("'", "''")
                values_list.append(f"'{escaped_value}'")
            elif isinstance(value, dict):
                json_value = json.dumps(value).replace("'", "''")
                values_list.append(f"'{json_value}'")
            elif isinstance(value, bool):
                values_list.append('TRUE' if value else 'FALSE')
            else:
                values_list.append(str(value))
        
        migration_sql += f"INSERT INTO {table_name} ({', '.join(columns_list)}) VALUES ({', '.join(values_list)});\n"
    
    migration_sql += f"""
-- Create indexes for performance
CREATE INDEX idx_{table_name}_id ON {table_name}(id);
"""
    
    # Add indexes based on common column patterns
    for col in columns:
        if col in ['urn', 'url', 'titulo', 'tipo', 'estado', 'data', 'created_at']:
            migration_sql += f"CREATE INDEX idx_{table_name}_{col} ON {table_name}({col});\n"
    
    migration_sql += f"""
-- Verification
SELECT 'Real data migration completed!' as status;
SELECT COUNT(*) as total_records FROM {table_name};
SELECT 'Table: {table_name}' as table_info;
"""
    
    # Write to file
    filename = f"real_data_migration_{table_name}.sql"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(migration_sql)
    
    print(f"✅ Real data migration created: {filename}")
    print(f"📊 Migrated {len(data)} real records from {table_name}")
    
    return True

def main():
    """Main function to discover all tables and find the one with 889 rows"""
    print("🚀 Starting Complete Supabase Database Discovery")
    print("=" * 60)
    
    # Find the table with 889 rows
    result = get_table_with_889_rows()
    
    if result:
        table_name, data = result
        print(f"\n🎯 SUCCESS! Found table '{table_name}' with {len(data)} rows")
        
        # Create comprehensive migration
        create_comprehensive_migration(table_name, data)
        
        print("\n✅ Next steps:")
        print(f"1. Execute the migration SQL in Railway PostgreSQL")
        print(f"2. Real data from '{table_name}' will be available in your app")
        print(f"3. {len(data)} real records will replace sample data")
        
    else:
        print("❌ Could not find table with 889 rows")
        print("🔍 Please check the table names and try again")
    
    return result is not None

if __name__ == "__main__":
    main()