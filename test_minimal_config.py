#!/usr/bin/env python3
"""
Minimal test for DATABASE_URL configuration
"""
import os

def test_minimal():
    """Test basic DATABASE_URL handling"""
    print("Testing minimal DATABASE_URL configuration...")
    
    # Ensure DATABASE_URL is not set
    if 'DATABASE_URL' in os.environ:
        del os.environ['DATABASE_URL']
    print("✓ DATABASE_URL removed from environment")
    
    # Test basic environment variable reading
    db_url = os.getenv('DATABASE_URL', '')
    print(f"os.getenv('DATABASE_URL', ''): {repr(db_url)}")
    
    if db_url == '':
        print("✓ DATABASE_URL is empty string as expected")
    else:
        print(f"❌ DATABASE_URL should be empty, got: {repr(db_url)}")
        return False
    
    # Test None handling
    db_url_none = os.getenv('DATABASE_URL')
    print(f"os.getenv('DATABASE_URL'): {repr(db_url_none)}")
    
    if db_url_none is None:
        print("✓ DATABASE_URL is None when not set")
    else:
        print(f"❌ DATABASE_URL should be None, got: {repr(db_url_none)}")
        return False
    
    # Test conditional handling
    database_configured = bool(db_url)
    print(f"bool(DATABASE_URL): {database_configured}")
    
    if not database_configured:
        print("✓ Database correctly detected as not configured")
    else:
        print("❌ Database should be detected as not configured")
        return False
    
    print("\n🎉 MINIMAL CONFIGURATION TEST PASSED!")
    return True

if __name__ == "__main__":
    success = test_minimal()
    exit(0 if success else 1)