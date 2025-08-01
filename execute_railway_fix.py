#!/usr/bin/env python3
"""
Automated Railway Database Fix Script
Connects to Railway PostgreSQL and executes the database fix
"""

import os
import psycopg2
from urllib.parse import urlparse

def execute_railway_fix():
    """Execute the database fix on Railway PostgreSQL"""
    
    # Get DATABASE_URL from environment
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        print("❌ DATABASE_URL environment variable not found")
        print("Please set it from your Railway PostgreSQL service")
        return False
    
    try:
        # Parse the database URL
        parsed = urlparse(database_url)
        
        # Connect to PostgreSQL
        print("🔄 Connecting to Railway PostgreSQL...")
        conn = psycopg2.connect(
            host=parsed.hostname,
            port=parsed.port,
            database=parsed.path[1:],  # Remove leading slash
            user=parsed.username,
            password=parsed.password
        )
        
        cursor = conn.cursor()
        
        # Read the SQL fix file
        print("📄 Reading SQL fix file...")
        with open('IMMEDIATE_RAILWAY_FIX.sql', 'r', encoding='utf-8') as f:
            sql_commands = f.read()
        
        # Execute the fix
        print("🔧 Executing database fix...")
        cursor.execute(sql_commands)
        conn.commit()
        
        # Verify the fix
        print("✅ Verifying fix...")
        cursor.execute("SELECT COUNT(*) FROM documents")
        count = cursor.fetchone()[0]
        print(f"📊 Total documents now: {count:,}")
        
        if count > 100000:
            print("🎉 SUCCESS! Database fix completed successfully!")
            print("🚂 Now redeploy your Railway application")
        else:
            print("⚠️ Warning: Document count is lower than expected")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Error executing database fix: {e}")
        print("Please execute the SQL manually in Railway Query tab")
        return False

if __name__ == "__main__":
    print("🚀 Railway Database Fix - Automated Execution")
    print("=" * 50)
    
    success = execute_railway_fix()
    
    if success:
        print("\n✅ Database fix completed!")
        print("Next step: Redeploy your Railway application")
    else:
        print("\n❌ Automated fix failed")
        print("Please execute IMMEDIATE_RAILWAY_FIX.sql manually in Railway")