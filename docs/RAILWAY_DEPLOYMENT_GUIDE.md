# Railway Database Fix - Immediate Deployment Guide

## Problem Analysis

The error `COALESCE types text and date cannot be matched` was occurring because:

1. **Root Cause**: The `documents` view was created with inconsistent date types
2. **Specific Issue**: `data_publicacao` (DATE) vs `created_at` (TIMESTAMP cast to date)
3. **Impact**: Application showing only "3 total documents" instead of 144,138

## Immediate Fix Steps

### Step 1: Execute SQL Fix on Railway

1. Go to Railway Dashboard → PostgreSQL Service → Query tab
2. Copy and paste the entire content of `IMMEDIATE_RAILWAY_FIX.sql`
3. Execute the script

### Step 2: Verify Fix Success

The script will output verification messages. You should see:
- "Testing the fixed query..." with year/count results
- "Verifying data types..." showing both fields as `date` type
- "total_document_count" showing 144,138 (or similar large number)

### Step 3: Redeploy Application

After SQL fix is applied:
1. In Railway Dashboard → Your App Service
2. Click "Deploy" or trigger a redeploy
3. Wait for deployment to complete

## Expected Results After Fix

- **Document Count**: 144,138 total documents (instead of 3)
- **Error Resolution**: No more "COALESCE types" errors
- **Dashboard**: All analytics charts should populate with real data
- **Performance**: Proper indexing maintained

## Files Modified

1. **`IMMEDIATE_RAILWAY_FIX.sql`** - Database schema fix
2. **`missing_functions.R`** - R code fixes for type casting
3. **`database/fix_date_type_mismatch.sql`** - Complete view recreation script

## Technical Details

### What Was Fixed

```sql
-- BEFORE (problematic)
data as data_publicacao,           -- DATE type
data_coleta as created_at,         -- TIMESTAMP type

-- Query that failed:
COALESCE(data_publicacao, created_at::date)  -- Type mismatch

-- AFTER (fixed)
data::date as data_publicacao,     -- DATE type  
data_coleta::date as created_at,   -- DATE type (explicitly cast)

-- Query that works:
COALESCE(data_publicacao, created_at)        -- Both DATE type
```

### R Code Fixes

Removed all `::date` casting in COALESCE operations:
- `COALESCE(data_publicacao, created_at::date)` → `COALESCE(data_publicacao, created_at)`

## Monitoring & Prevention

### Post-Deployment Verification

1. Check application logs for any remaining errors
2. Verify document count in dashboard shows 144k+ documents
3. Test analytics charts load properly

### Future Prevention

- Always ensure consistent data types in views
- Test COALESCE operations with explicit type casting
- Use development environment to test schema changes

## Rollback Plan (if needed)

If issues occur, restore the original view:
```sql
-- Emergency rollback (run only if needed)
DROP VIEW IF EXISTS documents CASCADE;
CREATE VIEW documents AS SELECT * FROM lexml_documents;
```

## Contact

If deployment issues persist:
1. Check Railway logs for specific error messages
2. Verify all `lexml_*` tables exist and have data
3. Ensure PostgreSQL version compatibility (should be 13+)

---

**Status**: Ready for immediate Railway deployment
**Estimated Fix Time**: 2-3 minutes
**Expected Downtime**: None (view recreation is instantaneous)