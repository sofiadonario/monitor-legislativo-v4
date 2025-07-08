#!/usr/bin/env python3
"""
Direct PostgreSQL connection to Supabase
Monitor Legislativo v4 - Direct Database Access
"""

import json
import socket
import re
from datetime import datetime

def test_connection():
    """Test direct connection to Supabase PostgreSQL"""
    print("🔍 Testing direct PostgreSQL connection to Supabase...")
    
    # Parse connection details
    host = "db.upxonmtqerdrxdgywzuj.supabase.co"
    port = 5432
    database = "postgres"
    username = "postgres"
    password = "MonitorTransporte25*"
    
    print(f"🔗 Connecting to: {host}:{port}/{database}")
    print(f"👤 Username: {username}")
    
    # Test basic network connectivity
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print("✅ Network connectivity to PostgreSQL server successful")
        else:
            print(f"❌ Cannot connect to PostgreSQL server: {result}")
            return False
    except Exception as e:
        print(f"❌ Network error: {e}")
        return False
    
    # Try to create a simple connection test
    print("\n🔍 Testing PostgreSQL connection with basic commands...")
    
    # Create a simple SQL command to test
    test_queries = [
        "SELECT version();",
        "SELECT current_database();",
        "SELECT current_user;",
        "\\dt",  # List tables
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';",
        "SELECT COUNT(*) FROM pg_stat_user_tables;",
        "SELECT schemaname, tablename FROM pg_tables WHERE schemaname = 'public';"
    ]
    
    # For each query, create a psql command
    for query in test_queries:
        print(f"\n📋 Testing query: {query}")
        
        # We'll create a simple test that shows what the command would be
        # Since we don't have psql installed, we'll show what needs to be run
        
        if query.startswith("\\"):
            # Meta commands
            print(f"   Command: psql 'postgresql://{username}:{password}@{host}:{port}/{database}' -c '{query}'")
        else:
            # Regular SQL
            print(f"   Command: psql 'postgresql://{username}:{password}@{host}:{port}/{database}' -c \"{query}\"")
    
    print("\n🎯 Manual Testing Required:")
    print("Since psql is not available in this environment, you need to:")
    print("1. Install PostgreSQL client tools (psql)")
    print("2. Run the commands above manually")
    print("3. Or use a GUI tool like pgAdmin, DBeaver, or Supabase Dashboard")
    
    return True

def create_connection_guide():
    """Create a guide for connecting to Supabase"""
    print("\n📝 Creating connection guide...")
    
    guide = f"""
# Supabase PostgreSQL Connection Guide

## Connection Details
- **Host**: db.upxonmtqerdrxdgywzuj.supabase.co
- **Port**: 5432
- **Database**: postgres
- **Username**: postgres
- **Password**: MonitorTransporte25*

## Connection String
```
postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres
```

## Manual Commands to Test Connection

### 1. Check PostgreSQL Version
```bash
psql "postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres" -c "SELECT version();"
```

### 2. List All Tables
```bash
psql "postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres" -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
```

### 3. Check Table Sizes
```bash
psql "postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres" -c "SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del FROM pg_stat_user_tables;"
```

### 4. List Tables with Meta Command
```bash
psql "postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres" -c "\\dt"
```

### 5. Export Table Data (if tables exist)
```bash
# Replace 'documents' with actual table name
pg_dump "postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres" --table=documents --data-only --inserts > documents_real_data.sql
```

## Alternative Tools
1. **pgAdmin**: GUI PostgreSQL administration tool
2. **DBeaver**: Universal database tool
3. **Supabase Dashboard**: Web-based interface at https://app.supabase.com
4. **TablePlus**: Modern database GUI

## Next Steps
1. Install PostgreSQL client tools
2. Run the manual commands above
3. Identify which tables actually exist
4. Export real data from existing tables
5. Create proper migration SQL for Railway

Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    
    with open('supabase_connection_guide.md', 'w', encoding='utf-8') as f:
        f.write(guide)
    
    print("✅ Connection guide created: supabase_connection_guide.md")
    return True

def main():
    """Main function"""
    print("🚀 Starting Direct PostgreSQL Connection Test")
    print("=" * 60)
    
    # Test basic connectivity
    if test_connection():
        print("✅ Basic connectivity test passed")
    else:
        print("❌ Basic connectivity test failed")
        return False
    
    # Create connection guide
    create_connection_guide()
    
    print("\n🎯 Summary:")
    print("✅ Network connectivity to Supabase PostgreSQL works")
    print("✅ Connection guide created for manual testing")
    print("⚠️  Manual database exploration required")
    print("🔧 Need to install PostgreSQL client tools for data extraction")
    
    return True

if __name__ == "__main__":
    main()