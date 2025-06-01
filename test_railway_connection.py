#!/usr/bin/env python3
"""
Quick test for Railway PostgreSQL connection
"""

import psycopg2
import os

def test_connection():
    """Test Railway PostgreSQL connection with timeout."""
    try:
        print("🔄 Testing Railway PostgreSQL connection...")
        
        # Railway connection parameters
        conn = psycopg2.connect(
            host='nozomi.proxy.rlwy.net',
            port=44844,
            database='railway',
            user='postgres',
            password='smNCedRjMKeNsoqpurLWXjGEUZxORwVY',
            sslmode='prefer',
            connect_timeout=10  # 10 second timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version(), current_database();")
        result = cursor.fetchone()
        
        print("✅ Connection successful!")
        print(f"📊 PostgreSQL Version: {result[0][:50]}...")
        print(f"🗄️ Database: {result[1]}")
        
        # Check if documents table exists
        cursor.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = 'documents';
        """)
        
        table_exists = cursor.fetchone()
        print(f"📋 Documents table exists: {'Yes' if table_exists else 'No'}")
        
        if table_exists:
            cursor.execute("SELECT COUNT(*) FROM documents;")
            count = cursor.fetchone()[0]
            print(f"📊 Current document count: {count:,}")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    success = test_connection()
    exit(0 if success else 1)