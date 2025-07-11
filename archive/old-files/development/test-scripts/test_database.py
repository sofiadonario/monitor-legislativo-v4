#!/usr/bin/env python3
"""
Database Connection Test Script
Tests AsyncPG and SQLAlchemy configuration for Supabase
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


async def test_database_connection():
    """Test database connection and configuration"""
    print("\n" + "="*60)
    print("Monitor Legislativo v4 - Database Connection Test")
    print("="*60)
    
    # Check environment variables
    print("\n1. Checking environment variables...")
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        # Hide password in output
        safe_url = db_url.split('@')[0].rsplit(':', 1)[0] + ':****@' + db_url.split('@')[1]
        print(f"✅ DATABASE_URL found: {safe_url}")
    else:
        print("❌ DATABASE_URL not found in environment")
        return False
    
    # Check if dependencies are installed
    print("\n2. Checking dependencies...")
    try:
        import sqlalchemy
        print(f"✅ SQLAlchemy installed: {sqlalchemy.__version__}")
    except ImportError:
        print("❌ SQLAlchemy not installed")
        print("   Run: pip install sqlalchemy[asyncio]==2.0.23")
        return False
    
    try:
        import asyncpg
        print(f"✅ AsyncPG installed: {asyncpg.__version__}")
    except ImportError:
        print("❌ AsyncPG not installed")
        print("   Run: pip install asyncpg==0.29.0")
        return False
    
    # Test database connection
    print("\n3. Testing database connection...")
    try:
        from core.database.supabase_config import get_database_manager
        
        db_manager = await get_database_manager()
        print("✅ Database manager created successfully")
        
        # Test connection
        connected = await db_manager.test_connection()
        if connected:
            print("✅ Database connection successful!")
        else:
            print("❌ Database connection failed")
            print("   Check logs above for detailed error information")
            return False
        
        # Get cache statistics
        print("\n4. Testing database operations...")
        stats = await db_manager.get_cache_stats()
        if stats:
            print("✅ Database operations working")
            print(f"   Cache entries: {stats.get('cache', {}).get('total_entries', 0)}")
            print(f"   Export cache: {stats.get('exports', {}).get('total_cached', 0)}")
            print(f"   Search history (24h): {stats.get('searches', {}).get('total_24h', 0)}")
        else:
            print("⚠️  Could not retrieve cache statistics")
        
        print("\n5. Testing cache service integration...")
        from main_app.services.database_cache_service import get_database_cache_service
        
        cache_service = await get_database_cache_service()
        health = await cache_service.get_health_status()
        
        if health.get('database_available'):
            print("✅ Cache service integrated with database")
            print(f"   Features available: {', '.join(health.get('features_available', []))}")
        else:
            print("⚠️  Cache service in fallback mode")
            print(f"   Reason: {health.get('fallback_mode', 'Unknown')}")
        
        print("\n" + "="*60)
        print("✅ All tests passed! Database is ready for use.")
        print("="*60)
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        print(f"   Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


async def test_api_endpoints():
    """Test API endpoints to verify integration"""
    print("\n6. Testing API endpoints...")
    
    try:
        import httpx
        
        # Assuming local development
        base_url = "http://localhost:8000"
        
        async with httpx.AsyncClient() as client:
            # Test health endpoint
            response = await client.get(f"{base_url}/api/lexml/health")
            if response.status_code == 200:
                health_data = response.json()
                print("✅ Health endpoint working")
                print(f"   Database available: {health_data.get('database_available', False)}")
                print(f"   Cache service: {health_data.get('cache_service_status', 'Unknown')}")
            else:
                print(f"⚠️  Health endpoint returned status {response.status_code}")
                
    except Exception as e:
        print(f"⚠️  Could not test API endpoints: {e}")
        print("   Make sure the server is running: python main_app/main.py")


async def main():
    """Main test execution"""
    # Run database tests
    db_success = await test_database_connection()
    
    if db_success:
        # Optionally test API endpoints
        print("\nWould you like to test API endpoints? (requires server running)")
        print("Press Enter to skip, or type 'yes' to test: ", end='')
        response = input().strip().lower()
        
        if response == 'yes':
            await test_api_endpoints()
    
    print("\n✨ Test complete!")
    
    if not db_success:
        print("\n⚠️  Some issues were found. Please address them and run the test again.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())