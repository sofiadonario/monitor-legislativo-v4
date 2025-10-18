#!/usr/bin/env python3
"""
Simplest possible deployment script for Railway
Uses DATABASE_PUBLIC_URL explicitly
"""
import os
import sys

try:
    import psycopg2
except ImportError:
    print("Installing psycopg2-binary...")
    os.system("pip3 install psycopg2-binary")
    import psycopg2

# Use public URL explicitly
database_url = os.getenv("DATABASE_PUBLIC_URL")
if not database_url:
    database_url = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

print("Connecting to:", database_url[:60] + "...")

# Read SQL
with open("high_performance_search_schema.sql", "r") as f:
    sql = f.read()

print(f"SQL loaded: {len(sql)} bytes")

# Connect and execute
try:
    conn = psycopg2.connect(database_url, connect_timeout=30)
    conn.autocommit = True
    cur = conn.cursor()

    print("Connected! Executing SQL...")
    cur.execute(sql)

    print("✓ Success!")

    # Verify
    cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'legis_docs'")
    print(f"Tables created: {cur.fetchone()[0]}")

    cur.close()
    conn.close()

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
