#!/usr/bin/env python3
"""
Simple test for configuration without external dependencies
"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, '.')

def test_simple_config():
    """Test basic configuration without external dependencies"""
    print("Testing basic configuration...")
    
    # Ensure DATABASE_URL is not set
    if 'DATABASE_URL' in os.environ:
        del os.environ['DATABASE_URL']
    print("✓ DATABASE_URL removed from environment")
    
    try:
        # Test environment configuration - just the class, not validation
        from core.config.env_loader import EnvironmentConfig
        
        print(f"DATABASE_URL value: {repr(EnvironmentConfig.DATABASE_URL)}")
        
        if EnvironmentConfig.DATABASE_URL == '':
            print("✓ EnvironmentConfig.DATABASE_URL is empty string as expected")
        else:
            print(f"❌ EnvironmentConfig.DATABASE_URL should be empty, got: {repr(EnvironmentConfig.DATABASE_URL)}")
            return False
        
    except Exception as e:
        print(f"❌ Environment configuration failed: {e}")
        return False
    
    try:
        # Test database configuration - just the class
        from core.database.supabase_config import SupabaseConfig
        
        print(f"SupabaseConfig.DATABASE_URL: {repr(SupabaseConfig.DATABASE_URL)}")
        
        if SupabaseConfig.DATABASE_URL is None:
            print("✓ SupabaseConfig.DATABASE_URL is None as expected")
        else:
            print(f"❌ SupabaseConfig.DATABASE_URL should be None, got: {repr(SupabaseConfig.DATABASE_URL)}")
            return False
        
        # Test fix_database_url method
        fixed_url = SupabaseConfig.fix_database_url()
        if fixed_url is None:
            print("✓ fix_database_url returns None when DATABASE_URL is None")
        else:
            print(f"❌ fix_database_url should return None, got: {repr(fixed_url)}")
            return False
        
        # Test get_async_engine method
        engine = SupabaseConfig.get_async_engine()
        if engine is None:
            print("✓ get_async_engine returns None when DATABASE_URL is None")
        else:
            print(f"❌ get_async_engine should return None, got: {repr(engine)}")
            return False
        
        # Test get_session_factory method
        session_factory = SupabaseConfig.get_session_factory()
        if session_factory is None:
            print("✓ get_session_factory returns None when DATABASE_URL is None")
        else:
            print(f"❌ get_session_factory should return None, got: {repr(session_factory)}")
            return False
        
        print("✓ Database configuration works correctly without DATABASE_URL")
        
    except Exception as e:
        print(f"❌ Database configuration failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n🎉 BASIC CONFIGURATION TESTS PASSED!")
    return True

if __name__ == "__main__":
    success = test_simple_config()
    sys.exit(0 if success else 1)