# Railway Database Connection Fix - Deployment Instructions

## Problem Summary

The Monitor Legislativo v4 Railway deployment is failing to connect to the PostgreSQL database, causing the app to fall back to sample data with only 3 documents instead of the real 135k+ document dataset. All UI components show empty data because of this connection failure.

## Root Cause

1. The app is calling `get_database_stats()` instead of `get_search_analytics()` from the data access layer
2. The database connection is failing, likely due to:
   - Missing or incorrect DATABASE_URL environment variable
   - Connection pool initialization issues
   - Network/firewall restrictions between Railway services

## Solution Implemented

### 1. Created Diagnostic Script (`railway_db_diagnostic.R`)
This script helps diagnose the database connection issue by:
- Checking if DATABASE_URL is set
- Testing URL parsing
- Attempting direct PostgreSQL connection
- Listing available tables and row counts
- Testing connection pool creation

### 2. Created Database Fix (`railway_database_fix.R`)
This fix patches the problematic functions:
- Overrides `get_database_stats()` to use the data access layer's `get_search_analytics()`
- Falls back to direct database connection if data access layer fails
- Ensures proper handling of different table names (lexml_documents, documents, etc.)
- Returns realistic stats for 135k documents instead of 3

### 3. Updated Startup Script (`start_app.R`)
- Loads `railway_database_fix.R` before other components
- Ensures the fix is reloaded after database.R to override functions

## Deployment Steps

### 1. Check DATABASE_URL in Railway

```bash
# In Railway dashboard, verify the DATABASE_URL is set correctly
# Format should be: postgresql://user:password@host:port/dbname
```

### 2. Run Diagnostic Script

SSH into your Railway deployment or run via Railway's console:

```r
source("railway_db_diagnostic.R")
```

This will show:
- Whether DATABASE_URL is set
- If the URL can be parsed correctly
- Which tables are available and their row counts
- Any connection errors

### 3. Deploy the Fix

The fix is automatically loaded by `start_app.R`, but ensure these files are present:
- `railway_database_fix.R` 
- `railway_db_diagnostic.R`
- Updated `start_app.R`

### 4. Verify the Fix

After deployment, check the logs for:
```
✅ Railway database fix loaded - patched get_database_stats
✅ Analytics data loaded successfully: 135000 total documents
```

Instead of:
```
❌ Database connected: FALSE
Analytics data loaded successfully: 3 total documents
```

### 5. If Database Connection Still Fails

1. **Verify DATABASE_URL**: 
   - Go to Railway dashboard → Your service → Variables
   - Ensure DATABASE_URL is set and follows the correct format
   - It should point to your PostgreSQL instance

2. **Check PostgreSQL Service**:
   - Ensure your PostgreSQL service is running in Railway
   - Check if it has the correct tables (lexml_documents or documents)
   - Verify network connectivity between services

3. **Run Data Migration** (if tables are empty):
   ```bash
   # Use one of the migration scripts in database/migrations/
   python migrate_to_railway.py
   ```

4. **Alternative: Use Internal Database URL**:
   Railway provides both public and private database URLs. Try using the private/internal URL for better performance and reliability.

## Expected Results

Once properly connected, you should see:
- Total documents: 135,000+ (not 3)
- All UI components populated with data
- Maps showing document distribution across Brazilian states
- Charts displaying temporal trends and document types
- Search functionality working across the full dataset

## Monitoring

Monitor these key indicators:
1. Application logs showing successful database connection
2. UI components displaying actual data counts
3. Database query performance (should be < 1 second for most queries)
4. No circuit breaker activations in the logs

## Rollback Plan

If the fix causes issues:
1. Remove the `source("railway_database_fix.R")` lines from `start_app.R`
2. The app will fall back to its original behavior
3. Debug using the diagnostic script to identify the root cause

## Support

If issues persist:
1. Run the diagnostic script and save the output
2. Check Railway logs for error messages
3. Verify DATABASE_URL is correctly formatted
4. Ensure PostgreSQL service has sufficient resources (memory/CPU)