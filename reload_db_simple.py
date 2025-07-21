#!/usr/bin/env python3
"""
Simple script to reload database using the provided connection URL
"""

import sys
import os

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def execute_sql_file():
    """Execute the SQL file using subprocess"""
    
    sql_file = "reload_database.sql"
    
    if not os.path.exists(sql_file):
        print(f"❌ SQL file not found: {sql_file}")
        return False
    
    print("🚀 Executing SQL file to reload database...")
    print("=" * 60)
    
    # Try to use subprocess to call psql if available
    import subprocess
    
    # Try different ways to call psql
    psql_commands = [
        ['psql', DATABASE_URL, '-f', sql_file],
        ['psql', '-h', 'nozomi.proxy.rlwy.net', '-p', '44844', '-U', 'postgres', '-d', 'railway', '-f', sql_file],
    ]
    
    for cmd in psql_commands:
        try:
            print(f"🔄 Trying command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("✅ SQL execution completed successfully!")
                print("Output:", result.stdout)
                return True
            else:
                print(f"❌ Command failed: {result.stderr}")
                
        except FileNotFoundError:
            print(f"❌ Command not found: {cmd[0]}")
        except subprocess.TimeoutExpired:
            print("❌ Command timed out")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("❌ All attempts failed")
    print("📋 Manual execution required:")
    print(f"   psql {DATABASE_URL} -f {sql_file}")
    return False

def main():
    print("🚀 Starting database reload execution")
    
    success = execute_sql_file()
    
    if success:
        print("\n🎉 SUCCESS: Database has been reloaded!")
        return True
    else:
        print("\n❌ FAILED: Could not execute SQL file automatically")
        print("📋 Please run manually:")
        print(f"   psql {DATABASE_URL} -f reload_database.sql")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 