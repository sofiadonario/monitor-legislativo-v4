#!/usr/bin/env python3
"""
Quick test of database connection and data verification
"""

import psycopg2
from psycopg2.extras import RealDictCursor

DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def test_database():
    """Test database connection and verify data"""
    print("🔍 TESTING DATABASE CONNECTION AND DATA...")
    
    try:
        conn = psycopg2.connect(DB_URL)
        print("✅ Connected to database")
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check total documents
            cur.execute("SELECT COUNT(*) as count FROM documents")
            total = cur.fetchone()['count']
            print(f"📊 Total documents in database: {total:,}")
            
            # Check categories
            cur.execute("""
                SELECT dc.name, COUNT(*) as count
                FROM documents d
                LEFT JOIN document_categories dc ON d.category_id = dc.id
                WHERE dc.name IS NOT NULL
                GROUP BY dc.name
                ORDER BY count DESC
            """)
            categories = cur.fetchall()
            
            print("📋 Category distribution:")
            for cat in categories:
                percentage = (cat['count'] / total) * 100
                print(f"   {cat['name']}: {cat['count']:,} ({percentage:.1f}%)")
            
            # Check states
            cur.execute("""
                SELECT estado, COUNT(*) as count
                FROM documents
                WHERE estado IS NOT NULL AND estado != ''
                GROUP BY estado
                ORDER BY count DESC
                LIMIT 5
            """)
            states = cur.fetchall()
            
            print("🗺️ Top 5 states:")
            for state in states:
                print(f"   {state['estado']}: {state['count']:,}")
            
            # Test dashboard view
            cur.execute("SELECT COUNT(*) as count FROM lexml_dashboard_view")
            view_count = cur.fetchone()['count']
            print(f"🎯 Dashboard view working: {view_count:,} rows")
            
        conn.close()
        print("✅ Database test completed successfully!")
        print("🚀 Database is ready for dashboard integration!")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

if __name__ == "__main__":
    test_database()