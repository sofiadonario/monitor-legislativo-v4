#!/usr/bin/env python3
"""
Database Initialization Script
Initializes the Supabase database schema for Monitor Legislativo v4
"""

import asyncio
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


async def initialize_database():
    """Initialize database schema and verify setup"""
    print("\n" + "="*60)
    print("Monitor Legislativo v4 - Database Initialization")
    print("="*60)
    
    # Check dependencies first
    print("\n1. Checking dependencies...")
    try:
        import sqlalchemy
        import asyncpg
        print("✅ All dependencies installed")
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("\nPlease install required dependencies:")
        print("pip install sqlalchemy[asyncio]==2.0.23 asyncpg==0.29.0")
        return False
    
    # Initialize database
    print("\n2. Connecting to database...")
    try:
        from core.database.supabase_config import get_database_manager
        
        db_manager = await get_database_manager()
        if not db_manager:
            print("❌ Could not create database manager")
            return False
        
        print("✅ Connected to database")
        
        # Initialize schema
        print("\n3. Initializing database schema...")
        print("   Creating tables:")
        print("   - cache_entries (for search result caching)")
        print("   - export_cache (for export file caching)")
        print("   - search_history (for analytics tracking)")
        
        success = await db_manager.initialize_schema()
        if success:
            print("✅ Database schema initialized successfully!")
        else:
            print("❌ Schema initialization failed")
            print("   Check logs for details")
            return False
        
        # Verify tables exist
        print("\n4. Verifying database tables...")
        stats = await db_manager.get_cache_stats()
        if stats:
            print("✅ All tables verified and accessible")
            print(f"   Current cache entries: {stats.get('cache', {}).get('total_entries', 0)}")
            print(f"   Current export cache: {stats.get('exports', {}).get('total_cached', 0)}")
            print(f"   Search history entries: {stats.get('searches', {}).get('total_24h', 0)}")
        else:
            print("⚠️  Could not verify tables")
        
        # Test cache service
        print("\n5. Testing cache service integration...")
        from main_app.services.database_cache_service import get_database_cache_service
        
        cache_service = await get_database_cache_service()
        
        # Test caching a search result
        test_result = await cache_service.cache_search_result(
            query="test initialization",
            filters={},
            result_data={"test": True, "documents": []},
            cache_duration_minutes=5
        )
        
        if test_result:
            print("✅ Cache service working correctly")
            
            # Retrieve the cached result
            cached = await cache_service.get_cached_search_result("test initialization", {})
            if cached:
                print("✅ Cache retrieval working correctly")
            else:
                print("⚠️  Cache retrieval test failed")
        else:
            print("⚠️  Cache service test failed")
        
        # Clean up test data
        print("\n6. Cleaning up test data...")
        cleaned = await db_manager.cleanup_expired_cache()
        print(f"✅ Cleanup complete (removed {cleaned} expired entries)")
        
        print("\n" + "="*60)
        print("✅ Database initialization complete!")
        print("="*60)
        print("\nYour database is ready for use with Monitor Legislativo v4")
        print("\nNext steps:")
        print("1. Start the application: python main_app/main.py")
        print("2. Check health status: http://localhost:8000/api/lexml/health")
        print("3. Monitor performance: http://localhost:8000/api/lexml/analytics")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error during initialization: {e}")
        print(f"   Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


async def check_existing_data():
    """Check if database already has data"""
    print("\n7. Checking for existing data...")
    
    try:
        from core.database.supabase_config import get_database_manager
        
        db_manager = await get_database_manager()
        stats = await db_manager.get_cache_stats()
        
        total_entries = (
            stats.get('cache', {}).get('total_entries', 0) +
            stats.get('exports', {}).get('total_cached', 0)
        )
        
        if total_entries > 0:
            print(f"ℹ️  Found {total_entries} existing cache entries")
            print("   The system will use these cached results for better performance")
        else:
            print("ℹ️  No existing cache data found")
            print("   Cache will be populated as you use the system")
            
    except Exception as e:
        print(f"⚠️  Could not check existing data: {e}")


async def main():
    """Main initialization execution"""
    print("\n🚀 Starting database initialization...")
    
    # Run initialization
    success = await initialize_database()
    
    if success:
        # Check for existing data
        await check_existing_data()
        
        print("\n✨ Initialization complete!")
        print("\n📝 Configuration summary:")
        print(f"   Database URL: {os.getenv('DATABASE_URL', 'Not configured').split('@')[1] if '@' in os.getenv('DATABASE_URL', '') else 'Not configured'}")
        print(f"   Supabase Project: upxonmtqerdrxdgywzuj")
        print(f"   Connection Pool: 5 connections (optimized for free tier)")
        print(f"   Cache TTL: 30 minutes for searches, 24 hours for exports")
    else:
        print("\n❌ Initialization failed. Please check the errors above.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())