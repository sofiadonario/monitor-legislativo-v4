#!/usr/bin/env python3
"""Test Supabase connection and table access"""

import os
from supabase import create_client, Client

# Supabase credentials
SUPABASE_URL = "https://upxonmtqerdrxdgywzuj.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVweG9ubXRxZXJkcnhkZ3l3enVqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAxNzU3NDAsImV4cCI6MjA2NTc1MTc0MH0.5KeIVpddEXKJL9SSVzgrYBAXWmJTSTv4aZKJPOnnRQM"

def test_connection():
    try:
        # Create client
        print("Creating Supabase client...")
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        print("✓ Client created successfully")
        
        # Test table access
        print("\nTesting table access...")
        response = supabase.table('legislative_documents').select('*').limit(5).execute()
        
        print(f"✓ Table access successful")
        print(f"Found {len(response.data)} documents")
        
        if response.data:
            print("\nFirst document:")
            doc = response.data[0]
            for key, value in doc.items():
                if value:
                    print(f"  {key}: {str(value)[:100]}...")
        else:
            print("\nNo documents found in table")
            
        # Test count
        count_response = supabase.table('legislative_documents').select('*', count='exact').execute()
        print(f"\nTotal documents in table: {count_response.count}")
        
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    print("Testing Supabase connection for Monitor Legislativo v4")
    print("=" * 50)
    test_connection()