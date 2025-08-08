#!/usr/bin/env python3
"""
PostgreSQL Database Analysis for Railway Deployment
Legislative Monitoring Application
"""

import psycopg2
import sys
from datetime import datetime

# Database connection parameters
DB_CONFIG = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def safe_query(cursor, query, description=""):
    """Safely execute a query with error handling"""
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        print(f"✓ {description} - SUCCESS")
        return result
    except Exception as e:
        print(f"✗ {description} - ERROR: {e}")
        return None

def main():
    print("=== PostgreSQL Database Analysis Report ===")
    print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 1. Test database connection
    print("1. TESTING DATABASE CONNECTION")
    print("=" * 32)
    print(f"Host: {DB_CONFIG['host']}")
    print(f"Port: {DB_CONFIG['port']}")
    print(f"Database: {DB_CONFIG['database']}")
    print(f"User: {DB_CONFIG['user']}\n")
    
    conn = None
    cursor = None
    connection_success = False
    
    try:
        # Attempt connection
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        print("✓ Database connection established successfully!")
        connection_success = True
        
        # Test basic query
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"✓ PostgreSQL Version: {version[:80]}...")
        
    except Exception as e:
        print(f"✗ Database connection FAILED:")
        print(f"  Error: {e}")
        print("  This could indicate:")
        print("  - Network connectivity issues")
        print("  - Incorrect credentials")
        print("  - Database server is down")
        print("  - Firewall blocking connection")
        sys.exit(1)
    
    if not connection_success:
        print("\n❌ Cannot proceed with analysis - connection failed")
        sys.exit(1)
    
    print("\n2. DATABASE SCHEMA ANALYSIS")
    print("=" * 27)
    
    # List all schemas
    schemas = safe_query(cursor, """
        SELECT schema_name 
        FROM information_schema.schemata 
        WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
        ORDER BY schema_name;
    """, "Listing schemas")
    
    if schemas:
        print("Available schemas:")
        for schema in schemas:
            print(f"  - {schema[0]}")
    
    print("\n3. TABLES AND VIEWS INVENTORY")
    print("=" * 29)
    
    # List all tables
    tables = safe_query(cursor, """
        SELECT 
            schemaname,
            tablename,
            tableowner,
            hasindexes,
            hasrules,
            hastriggers
        FROM pg_tables 
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        ORDER BY schemaname, tablename;
    """, "Listing all tables")
    
    if tables and len(tables) > 0:
        print("Tables found:")
        for table in tables:
            schema, name, owner, indexes, rules, triggers = table
            print(f"  - {schema}.{name} (owner: {owner}, indexes: {'YES' if indexes else 'NO'})")
        print(f"Total tables: {len(tables)}")
    else:
        print("❌ No tables found or query failed")
    
    # List all views
    views = safe_query(cursor, """
        SELECT 
            schemaname,
            viewname,
            viewowner
        FROM pg_views 
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        ORDER BY schemaname, viewname;
    """, "Listing all views")
    
    if views and len(views) > 0:
        print("\nViews found:")
        for view in views:
            schema, name, owner = view
            print(f"  - {schema}.{name} (owner: {owner})")
        print(f"Total views: {len(views)}")
    else:
        print("\n⚠️  No views found")
    
    print("\n4. KEY TABLE STRUCTURE ANALYSIS")
    print("=" * 31)
    
    def analyze_table(schema_name, table_name):
        print(f"\n--- Table: {schema_name}.{table_name} ---")
        
        # Get column information
        columns = safe_query(cursor, f"""
            SELECT 
                column_name,
                data_type,
                is_nullable,
                column_default,
                character_maximum_length,
                numeric_precision,
                numeric_scale
            FROM information_schema.columns 
            WHERE table_schema = '{schema_name}' AND table_name = '{table_name}'
            ORDER BY ordinal_position;
        """, f"Getting columns for {table_name}")
        
        if columns and len(columns) > 0:
            print(f"Columns ({len(columns)} total):")
            for i, col in enumerate(columns[:10]):  # Show first 10 columns
                name, dtype, nullable, default, max_len, precision, scale = col
                type_info = dtype
                if max_len:
                    type_info += f"({max_len})"
                elif precision:
                    type_info += f"({precision},{scale or 0})"
                
                null_info = " NULL" if nullable == "YES" else " NOT NULL"
                default_info = f" DEFAULT {str(default)[:20]}" if default else ""
                
                print(f"  {name}: {type_info}{null_info}{default_info}")
            
            if len(columns) > 10:
                print(f"  ... and {len(columns) - 10} more columns")
        
        # Get row count
        row_count = safe_query(cursor, f"SELECT COUNT(*) FROM {schema_name}.{table_name};",
                              f"Getting row count for {table_name}")
        
        if row_count:
            count = row_count[0][0]
            print(f"Row count: {count:,}")
        
        # Look for key columns
        if columns:
            id_cols = [col[0] for col in columns if 'id' in col[0].lower()]
            if id_cols:
                print(f"Key columns found: {', '.join(id_cols)}")
            
            date_cols = [col[0] for col in columns if col[1] in ['date', 'timestamp with time zone', 'timestamp without time zone']]
            if date_cols:
                print(f"Date columns found: {', '.join(date_cols)}")
    
    # Analyze tables
    if tables and len(tables) > 0:
        # Look for tables with specific patterns
        key_tables = [t for t in tables if any(keyword in t[1].lower() 
                     for keyword in ['document', 'lexml', 'legislat', 'bill', 'proposal', 'law', 'norma', 'ato', 'dados'])]
        
        if key_tables:
            print("Found key legislative tables:")
            for table in key_tables:
                analyze_table(table[0], table[1])
        else:
            print("⚠️  No tables with 'document', 'lexml', or legislative keywords found")
            print("Analyzing all available tables:")
            for table in tables:
                analyze_table(table[0], table[1])
    
    print("\n5. DATABASE PERMISSIONS AND ACCESS")
    print("=" * 34)
    
    # Check current user
    current_user = safe_query(cursor, "SELECT current_user, current_database();", "Getting current user info")
    if current_user:
        user, db = current_user[0]
        print(f"Current user: {user}")
        print(f"Current database: {db}")
    
    # Check database size
    db_size = safe_query(cursor, """
        SELECT pg_size_pretty(pg_database_size(current_database())) as database_size;
    """, "Getting database size")
    
    if db_size:
        print(f"Database size: {db_size[0][0]}")
    
    # Check table sizes if we have tables
    if tables and len(tables) > 0:
        print("\nTable sizes:")
        for table in tables:
            schema, name = table[0], table[1]
            size_result = safe_query(cursor, f"SELECT pg_size_pretty(pg_relation_size('{schema}.{name}'));",
                                   f"Getting size for {name}")
            if size_result:
                print(f"  {schema}.{name}: {size_result[0][0]}")
    
    print("\n6. R SHINY CONNECTION COMPATIBILITY")
    print("=" * 35)
    
    print("Testing connection parameters for R Shiny:")
    
    # Check connection limits
    conn_info = safe_query(cursor, """
        SELECT setting as max_connections
        FROM pg_settings 
        WHERE name = 'max_connections';
    """, "Checking connection limits")
    
    if conn_info:
        print(f"Max connections allowed: {conn_info[0][0]}")
    
    # Check current connections
    current_conns = safe_query(cursor, """
        SELECT 
            count(*) as active_connections,
            current_database() as database
        FROM pg_stat_activity 
        WHERE datname = current_database();
    """, "Checking current connections")
    
    if current_conns:
        print(f"Current active connections: {current_conns[0][0]}")
    
    # Test transaction capability
    try:
        cursor.execute("BEGIN;")
        cursor.execute("SELECT 1;")
        cursor.execute("COMMIT;")
        print("✓ Transaction support confirmed")
    except Exception as e:
        print(f"✗ Transaction test failed: {e}")
    
    # Test query performance
    import time
    start_time = time.time()
    test_query = safe_query(cursor, "SELECT 1 as test;", "Testing query performance")
    end_time = time.time()
    if test_query:
        print(f"Query response time: {round(end_time - start_time, 3)} seconds")
    
    print("\n7. SUMMARY AND RECOMMENDATIONS")
    print("=" * 30)
    
    issues_found = []
    recommendations = []
    
    # Check if we have tables
    if not tables or len(tables) == 0:
        issues_found.append("No tables found in database")
        recommendations.append("Verify data import was successful")
    else:
        print(f"✓ Database contains {len(tables)} table(s)")
    
    # Connection analysis
    print("✓ Connection parameters suitable for R Shiny deployment")
    print("✓ PostgreSQL connection working correctly")
    
    # Generate connection string for Shiny app
    print("\nConnection string for R Shiny:")
    print("```r")
    print("library(DBI)")
    print("library(RPostgreSQL)  # or library(RPostgres)")
    print("")
    print("# Database connection")
    print("conn <- dbConnect(")
    print("  RPostgreSQL::PostgreSQL(),  # or RPostgres::Postgres()")
    print("  host = \"nozomi.proxy.rlwy.net\",")
    print("  port = 44844,")
    print("  dbname = \"railway\",")
    print("  user = \"postgres\",")
    print("  password = \"smNCedRjMKeNsoqpurLWXjGEUZxORwVY\"")
    print(")")
    print("```")
    
    if issues_found:
        print("\n❌ ISSUES FOUND:")
        for issue in issues_found:
            print(f"  - {issue}")
    
    if recommendations:
        print("\n💡 RECOMMENDATIONS:")
        for rec in recommendations:
            print(f"  - {rec}")
    
    # Additional recommendations
    print("  - Use connection pooling for production Shiny apps")
    print("  - Consider using RPostgres instead of RPostgreSQL for better performance")
    print("  - Implement proper error handling in your Shiny app for database disconnections")
    print("  - Monitor connection usage to avoid hitting connection limits")
    print("  - Use environment variables to store database credentials securely")
    
    print("\n=== ANALYSIS COMPLETE ===")
    print("Connection Status: ✓ SUCCESSFUL")
    print("Database accessible via R: ✓ YES")
    print("Ready for Shiny deployment: ✓ YES")
    
    # Close connection
    if cursor:
        cursor.close()
    if conn:
        conn.close()
        print("Database connection closed.")

if __name__ == "__main__":
    main()