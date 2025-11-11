#!/usr/bin/env python3
"""
Populate estado field from URN for all documents in the database.
This script extracts geographic information from LexML URNs.
"""

import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor

# Database connection parameters
DB_CONFIG = {
    'host': '/cloudsql/mackmonitor:southamerica-east1:mackmonitor-db',
    'database': 'monitor_legislativo',
    'user': 'monitor_user',
    'password': 'Sdonario1'
}

def connect_db():
    """Connect to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("✅ Connected to database successfully")
        return conn
    except Exception as e:
        print(f"❌ Error connecting to database: {e}")
        sys.exit(1)

def run_sql_file(conn, sql_file_path):
    """Run SQL commands from a file."""
    try:
        with open(sql_file_path, 'r', encoding='utf-8') as f:
            sql = f.read()

        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Execute SQL
        print(f"\n📝 Executing SQL from {sql_file_path}...")
        cursor.execute(sql)

        # Fetch and print all results
        while True:
            try:
                results = cursor.fetchall()
                if results:
                    print("\n" + "="*80)
                    for row in results:
                        print(dict(row))
            except psycopg2.ProgrammingError:
                # No more results
                break

        conn.commit()
        cursor.close()

        print("\n✅ SQL execution completed successfully!")
        return True

    except Exception as e:
        print(f"\n❌ Error executing SQL: {e}")
        conn.rollback()
        return False

def main():
    """Main execution function."""
    print("="*80)
    print("POPULATE GEOGRAPHIC DATA FROM URNs")
    print("="*80)

    # Connect to database
    conn = connect_db()

    # Get SQL file path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    sql_file = os.path.join(project_root, 'database', 'populate_estado_from_urn.sql')

    if not os.path.exists(sql_file):
        print(f"❌ SQL file not found: {sql_file}")
        sys.exit(1)

    print(f"📂 Using SQL file: {sql_file}")

    # Run the SQL update
    success = run_sql_file(conn, sql_file)

    # Close connection
    conn.close()
    print("\n🔌 Database connection closed")

    if success:
        print("\n" + "="*80)
        print("✅ SUCCESS: Geographic data populated from URNs!")
        print("="*80)
        print("\nNext steps:")
        print("1. Redeploy the application")
        print("2. Refresh the geographic visualization")
        print("3. Verify all 134k+ documents appear on the map")
        sys.exit(0)
    else:
        print("\n❌ FAILED: Could not populate geographic data")
        sys.exit(1)

if __name__ == "__main__":
    main()
