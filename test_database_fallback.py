#!/usr/bin/env python3
"""
Test script to verify database fallback mode works correctly
"""
import os
import sys
import asyncio

# Add parent directory to path
sys.path.insert(0, '.')

async def test_database_fallback():
    """Test database initialization without DATABASE_URL"""
    print("Testing database fallback mode...")
    
    # Ensure DATABASE_URL is not set
    if 'DATABASE_URL' in os.environ:
        del os.environ['DATABASE_URL']
    print("✓ DATABASE_URL removed from environment")
    
    try:
        # Test environment configuration
        from core.config.env_loader import EnvironmentConfig, validate_environment
        
        print(f"DATABASE_URL value: {repr(EnvironmentConfig.DATABASE_URL)}")
        
        # Validate environment
        validation = validate_environment()
        print(f"Environment validation: {'PASSED' if validation['valid'] else 'FAILED'}")
        
        if validation['errors']:
            print("Errors:")
            for error in validation['errors']:
                print(f"  - {error}")
        
        if validation['warnings']:
            print("Warnings:")
            for warning in validation['warnings']:
                print(f"  - {warning}")
        
        print("✓ Environment configuration works without DATABASE_URL")
        
    except Exception as e:
        print(f"❌ Environment configuration failed: {e}")
        return False
    
    try:
        # Test database configuration
        from core.database.supabase_config import SupabaseConfig, DatabaseManager
        
        print(f"SupabaseConfig.DATABASE_URL: {repr(SupabaseConfig.DATABASE_URL)}")
        
        # Create database manager
        db_manager = DatabaseManager()
        print(f"Database available: {db_manager.database_available}")
        
        if not db_manager.database_available:
            print("✓ Database manager correctly detects no database configuration")
        else:
            print("❌ Database manager should detect no database configuration")
            return False
        
        print("✓ Database configuration works in fallback mode")
        
    except Exception as e:
        print(f"❌ Database configuration failed: {e}")
        return False
    
    try:
        # Test database cache service
        from main_app.services.database_cache_service import DatabaseCacheService
        
        cache_service = DatabaseCacheService()
        await cache_service.initialize()
        
        if not cache_service.db_available:
            print("✓ Database cache service correctly works in fallback mode")
        else:
            print("❌ Database cache service should be in fallback mode")
            return False
        
        # Test health status
        health = await cache_service.get_health_status()
        print(f"Cache service health: {health}")
        
        print("✓ Database cache service works in fallback mode")
        
    except Exception as e:
        print(f"❌ Database cache service failed: {e}")
        return False
    
    try:
        # Test alternative database manager
        from core.database.alternative_config import AlternativeDatabaseManager
        
        alt_manager = AlternativeDatabaseManager()
        success = await alt_manager.initialize_with_fallback()
        
        if not success:
            print("✓ Alternative database manager correctly skips when no DATABASE_URL")
        else:
            print("❌ Alternative database manager should skip when no DATABASE_URL")
            return False
        
        print("✓ Alternative database manager works correctly without DATABASE_URL")
        
    except Exception as e:
        print(f"❌ Alternative database manager failed: {e}")
        return False
    
    print("\n🎉 ALL TESTS PASSED! Database fallback mode works correctly.")
    return True

if __name__ == "__main__":
    success = asyncio.run(test_database_fallback())
    sys.exit(0 if success else 1)