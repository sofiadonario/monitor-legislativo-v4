#!/usr/bin/env python3
"""
Deploy schema to Railway PostgreSQL using Railway's internal network
This script runs inside Railway's environment via 'railway run'
"""

import os
import sys

try:
    import psycopg2
except ImportError:
    print("❌ psycopg2 not found. Installing...")
    os.system("pip install psycopg2-binary")
    import psycopg2

# Get DATABASE_URL from Railway environment
database_url = os.getenv("DATABASE_URL")
if not database_url:
    print("❌ DATABASE_URL not set by Railway")
    sys.exit(1)

print("=" * 80)
print("DEPLOYING TO RAILWAY POSTGRESQL")
print("=" * 80)
print(f"Database URL: {database_url[:40]}...")
print()

# Read SQL file
sql_file = "high_performance_search_schema.sql"
print(f"Reading {sql_file}...")

try:
    with open(sql_file, 'r') as f:
        sql = f.read()
    print(f"✓ Loaded {len(sql)} bytes")
except FileNotFoundError:
    print(f"❌ {sql_file} not found")
    print("Current directory:", os.getcwd())
    print("Files:", os.listdir('.'))
    sys.exit(1)

# Connect and execute
print("\nConnecting to database...")
try:
    conn = psycopg2.connect(database_url)
    conn.autocommit = True
    cur = conn.cursor()

    print("✓ Connected")
    print("\nExecuting SQL (this may take 30-60 seconds)...")

    cur.execute(sql)

    print("✓ Schema deployed successfully!")

    # Verify
    print("\nVerifying...")
    cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('legis_docs', 'ingest_control')")
    print(f"✓ Tables: {cur.fetchone()[0]}/2")

    cur.execute("SELECT COUNT(*) FROM pg_matviews WHERE schemaname = 'public'")
    print(f"✓ Materialized views: {cur.fetchone()[0]}")

    print("\n" + "=" * 80)
    print("DEPLOYMENT COMPLETE!")
    print("=" * 80)

    cur.close()
    conn.close()

except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
