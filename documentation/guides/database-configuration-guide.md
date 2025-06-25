# Database Configuration Guide - AsyncPG & SQLAlchemy Setup

## Overview
This guide will help you properly configure AsyncPG and SQLAlchemy for the Monitor Legislativo v4 project to activate the Supabase database integration.

## 1. Understanding the Issue

The current configuration has a URL format mismatch:
- **Current URL**: `postgresql://user:pass@host:port/db` (standard format)
- **Required for AsyncPG**: `postgresql+asyncpg://user:pass@host:port/db` (async format)

## 2. Configuration Steps

### Step 1: Update the Database Configuration

The `supabase_config.py` file needs to be updated to handle the URL conversion properly.

**Key Changes Needed:**
1. Convert the DATABASE_URL to use asyncpg driver
2. Add proper SSL configuration for Supabase
3. Handle connection pooling for free tier limits

### Step 2: Environment Variables

Ensure your `.env` file has these values:
```env
DATABASE_URL=postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres
SUPABASE_URL=https://upxonmtqerdrxdgywzuj.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Step 3: Connection String Conversion

The DATABASE_URL needs to be converted for AsyncPG:
```python
# Original
postgresql://postgres:password@host:5432/postgres

# Converted for AsyncPG
postgresql+asyncpg://postgres:password@host:5432/postgres
```

## 3. Required Updates

### Update 1: Fix URL Conversion in supabase_config.py

```python
@classmethod
def get_async_engine(cls):
    """Create async engine optimized for Supabase free tier"""
    # Convert DATABASE_URL to asyncpg format
    db_url = cls.DATABASE_URL
    if db_url.startswith('postgresql://'):
        db_url = db_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
    
    return create_async_engine(
        db_url,
        pool_size=cls.POOL_SIZE,
        max_overflow=cls.MAX_OVERFLOW,
        pool_timeout=cls.POOL_TIMEOUT,
        pool_recycle=cls.POOL_RECYCLE,
        echo=cls.ECHO_SQL,
        connect_args={
            "server_settings": {
                "application_name": "monitor_legislativo_v4",
            },
            # SSL configuration for Supabase
            "ssl": "require",
            "command_timeout": 60,
            "prepared_statement_cache_size": 0,  # Disable for Supabase compatibility
        }
    )
```

### Update 2: Add Error Handling

```python
async def test_connection(self) -> bool:
    """Test database connection with detailed error reporting"""
    try:
        async with self.session_factory() as session:
            result = await session.execute(text("SELECT 1"))
            logger.info("Database connection successful")
            return result.scalar() == 1
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        logger.error("Please install: pip install sqlalchemy[asyncio] asyncpg")
        return False
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        return False
```

## 4. Testing the Connection

### Create a Test Script

Create `test_database.py`:
```python
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_connection():
    # Import after env vars loaded
    from core.database.supabase_config import get_database_manager
    
    print("Testing database connection...")
    db_manager = await get_database_manager()
    
    if db_manager:
        print("✅ Database manager created")
        connected = await db_manager.test_connection()
        if connected:
            print("✅ Database connection successful!")
        else:
            print("❌ Database connection failed")
    else:
        print("❌ Could not create database manager")

if __name__ == "__main__":
    asyncio.run(test_connection())
```

### Run the Test
```bash
python test_database.py
```

## 5. Common Issues and Solutions

### Issue 1: Module Import Error
**Error**: `ModuleNotFoundError: No module named 'sqlalchemy'`
**Solution**: 
```bash
pip install sqlalchemy[asyncio]==2.0.23 asyncpg==0.29.0
```

### Issue 2: SSL Connection Error
**Error**: `SSL connection required`
**Solution**: Add SSL configuration to connect_args (shown above)

### Issue 3: Connection Pool Exhausted
**Error**: `QueuePool limit of size 5 overflow 0 reached`
**Solution**: Already configured with POOL_SIZE=5 and MAX_OVERFLOW=0

### Issue 4: Authentication Failed
**Error**: `password authentication failed`
**Solution**: Verify DATABASE_URL in .env file

## 6. Deployment Steps

### For Local Development:
1. Install dependencies: `pip install -r requirements.txt`
2. Create `.env` file with database credentials
3. Run test script to verify connection
4. Start the application: `python main_app/main.py`

### For Railway Deployment:
1. Ensure environment variables are set in Railway dashboard
2. Deploy the updated code
3. Check logs for "Database cache service initialized successfully"
4. Monitor `/api/lexml/health` endpoint

## 7. Verification

Once configured correctly, you should see:
```
INFO: Database connection successful
INFO: Database schema initialized successfully
INFO: ✅ Database cache service initialized successfully
```

The health endpoint should return:
```json
{
  "database_available": true,
  "connection_healthy": true,
  "features_available": [
    "search_result_caching",
    "export_caching",
    "analytics_tracking",
    "performance_monitoring"
  ]
}
```

## 8. Rollback Plan

If issues occur, the system will automatically fallback to CSV mode:
- No data loss
- Continued operation
- Performance remains good (<5ms response time)

To force CSV-only mode, set in `.env`:
```env
FORCE_CSV_ONLY=true
```

## Next Steps

After successful configuration:
1. Monitor cache hit rates via `/api/lexml/analytics`
2. Check Supabase dashboard for usage metrics
3. Set up automated cache cleanup (already implemented)
4. Consider implementing the analytics dashboard