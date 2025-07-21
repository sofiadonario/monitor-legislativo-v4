#!/usr/bin/env python3
"""
Direct database connection script to reload database
"""

import sys
import os

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def try_psycopg2():
    """Try using psycopg2"""
    try:
        import psycopg2
        print("✅ psycopg2 found, attempting connection...")
        
        # Parse connection string
        # postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("✅ Connected to database successfully")
        
        # Read SQL file
        sql_file = "reload_database.sql"
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
        conn.close()
        return True
        
    except ImportError:
        print("❌ psycopg2 not available")
        return False
    except Exception as e:
        print(f"❌ Error with psycopg2: {e}")
        return False

def try_sqlalchemy():
    """Try using SQLAlchemy"""
    try:
        from sqlalchemy import create_engine, text
        print("✅ SQLAlchemy found, attempting connection...")
        
        engine = create_engine(DATABASE_URL)
        
        # Read SQL file
        sql_file = "reload_database.sql"
        with open(sql_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Split into individual statements
        statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
        
        print(f"📋 Found {len(statements)} SQL statements to execute")
        
        with engine.connect() as conn:
            # Execute statements
            executed = 0
            for i, statement in enumerate(statements):
                try:
                    if statement.strip():
                        conn.execute(text(statement))
                        executed += 1
                        
                        if i % 100 == 0:
                            print(f"🔄 Executed {i}/{len(statements)} statements")
                            
                except Exception as e:
                    print(f"❌ Error executing statement {i}: {e}")
                    print(f"Statement: {statement[:100]}...")
                    return False
            
            conn.commit()
            print(f"✅ Successfully executed {executed} SQL statements")
            return True
        
    except ImportError:
        print("❌ SQLAlchemy not available")
        return False
    except Exception as e:
        print(f"❌ Error with SQLAlchemy: {e}")
        return False

def try_asyncpg():
    """Try using asyncpg"""
    try:
        import asyncpg
        import asyncio
        print("✅ asyncpg found, attempting connection...")
        
        async def execute_sql():
            # Parse connection string
            conn = await asyncpg.connect(DATABASE_URL)
            
            # Read SQL file
            sql_file = "reload_database.sql"
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
                        await conn.execute(statement)
                        executed += 1
                        
                        if i % 100 == 0:
                            print(f"🔄 Executed {i}/{len(statements)} statements")
                            
                except Exception as e:
                    print(f"❌ Error executing statement {i}: {e}")
                    print(f"Statement: {statement[:100]}...")
                    await conn.close()
                    return False
            
            await conn.close()
            print(f"✅ Successfully executed {executed} SQL statements")
            return True
        
        return asyncio.run(execute_sql())
        
    except ImportError:
        print("❌ asyncpg not available")
        return False
    except Exception as e:
        print(f"❌ Error with asyncpg: {e}")
        return False

def main():
    print("🚀 Starting database reload execution")
    print("=" * 60)
    
    # Try different database libraries
    methods = [
        ("psycopg2", try_psycopg2),
        ("SQLAlchemy", try_sqlalchemy),
        ("asyncpg", try_asyncpg)
    ]
    
    for name, method in methods:
        print(f"\n🔄 Trying {name}...")
        if method():
            print(f"\n🎉 SUCCESS: Database reloaded using {name}!")
            return True
        print(f"❌ {name} failed")
    
    print("\n❌ All methods failed")
    print("📋 Please install a PostgreSQL client or run manually:")
    print(f"   psql {DATABASE_URL} -f reload_database.sql")
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 