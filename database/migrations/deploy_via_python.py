#!/usr/bin/env python3
"""
Deploy High-Performance Schema to Railway PostgreSQL using Python
Alternative to psql for environments without PostgreSQL client tools
"""

import os
import sys
from datetime import datetime

try:
    import psycopg2
    from psycopg2 import sql
except ImportError:
    print("❌ ERROR: psycopg2 not installed")
    print("Install with: pip install psycopg2-binary")
    sys.exit(1)


def main():
    print("=" * 80)
    print("RAILWAY POSTGRESQL SCHEMA DEPLOYMENT (Python)")
    print("=" * 80)
    print()

    # Get DATABASE_URL from environment (Railway sets this automatically)
    database_url = os.getenv("DATABASE_URL")

    # If not set, try DATABASE_PUBLIC_URL
    if not database_url:
        database_url = os.getenv("DATABASE_PUBLIC_URL")

    if not database_url:
        print("❌ ERROR: DATABASE_URL environment variable not set")
        print()
        print("Railway CLI should set this automatically when using 'railway run'")
        print("If running locally, set DATABASE_PUBLIC_URL instead")
        sys.exit(1)

    # Parse connection string
    print("📋 Connecting to Railway PostgreSQL...")

    try:
        # Connect to database
        conn = psycopg2.connect(database_url)
        conn.autocommit = True
        cur = conn.cursor()

        # Test connection
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        print(f"✓ Connected: {version[:80]}")
        print()

        # Read SQL file
        sql_file = "high_performance_search_schema.sql"
        print(f"📂 Reading schema file: {sql_file}")

        if not os.path.exists(sql_file):
            print(f"❌ ERROR: {sql_file} not found in current directory")
            sys.exit(1)

        with open(sql_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()

        print(f"✓ Schema file loaded ({len(sql_content)} bytes)")
        print()

        # Confirm deployment
        response = input("⚠️  Deploy schema to Railway? This will create new tables. (y/N): ")
        if response.lower() != 'y':
            print("Deployment cancelled.")
            sys.exit(0)

        print()
        print("=" * 80)
        print("DEPLOYING SCHEMA...")
        print("=" * 80)

        # Execute SQL
        cur.execute(sql_content)

        print("✓ Schema deployed successfully")
        print()

        # Verify installation
        print("=" * 80)
        print("VERIFYING INSTALLATION")
        print("=" * 80)

        # Check tables
        cur.execute("""
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name IN ('legis_docs', 'ingest_control')
        """)
        table_count = cur.fetchone()[0]
        print(f"✓ Tables created: {table_count}/2")

        # Check materialized views
        cur.execute("""
            SELECT COUNT(*) FROM pg_matviews
            WHERE schemaname = 'public'
        """)
        mv_count = cur.fetchone()[0]
        print(f"✓ Materialized views: {mv_count}")

        # Check extensions
        cur.execute("""
            SELECT COUNT(*) FROM pg_extension
            WHERE extname IN ('postgis', 'unaccent', 'pg_trgm', 'btree_gin', 'pg_stat_statements')
        """)
        ext_count = cur.fetchone()[0]
        print(f"✓ Extensions installed: {ext_count}/5")

        # Check indexes
        cur.execute("""
            SELECT COUNT(*) FROM pg_indexes
            WHERE schemaname = 'public'
            AND tablename = 'legis_docs'
        """)
        idx_count = cur.fetchone()[0]
        print(f"✓ Indexes on legis_docs: {idx_count}")

        print()
        print("=" * 80)
        print("DEPLOYMENT COMPLETE")
        print("=" * 80)
        print()
        print("Next Steps:")
        print()
        print("1. Insert test document:")
        print("   INSERT INTO legis_docs (id, title, full_text, jurisdiction, state, date)")
        print("   VALUES ('test-001', 'Lei de Mobilidade', 'Texto...', 'federal', 'SP', CURRENT_DATE);")
        print()
        print("2. Test full-text search:")
        print("   SELECT * FROM legis_docs")
        print("   WHERE search_vector @@ to_tsquery('portuguese', 'mobilidade');")
        print()
        print("3. Monitor performance:")
        print("   SELECT * FROM v_slow_queries;")
        print()

        cur.close()
        conn.close()

    except psycopg2.Error as e:
        print(f"❌ Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
