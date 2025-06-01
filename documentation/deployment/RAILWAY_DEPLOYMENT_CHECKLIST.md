# Railway Deployment Checklist - Database Activation

## Pre-Deployment Checklist

### 1. Verify Local Setup ✓
- [ ] Run `python test_database.py` locally
- [ ] Confirm "Database connection successful" message
- [ ] Run `python initialize_database.py` if first time
- [ ] Test the application locally with database active

### 2. Check Dependencies ✓
Verify `requirements.txt` contains:
```
sqlalchemy[asyncio]==2.0.23
asyncpg==0.29.0
```
✅ **Already present in your requirements.txt**

### 3. Environment Variables in Railway ✓

Login to Railway dashboard and set these variables:

```bash
# Database (Required)
DATABASE_URL=postgresql://postgres:MonitorTransporte25*@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres

# Supabase (Required)
SUPABASE_URL=https://upxonmtqerdrxdgywzuj.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVweG9ubXRxZXJkcnhkZ3l3enVqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAxNzU3NDAsImV4cCI6MjA2NTc1MTc0MH0.5KeIVpddEXKJL9SSVzgrYBAXWmJTSTv4aZKJPOnnRQM

# Redis (Optional but recommended)
REDIS_URL=rediss://default:ATHqAAIjcDFhODQ3OTFlMDViMTI0ZTRlYWZhMjgwMWU0NWQ4NmRlZXAxMA@tight-guinea-12778.upstash.io:6379

# Optional
LOG_LEVEL=info
DEBUG=false
```

## Deployment Steps

### 1. Commit Changes
```bash
git add .
git commit -m "🚀 Activate Supabase database integration with AsyncPG/SQLAlchemy"
git push origin main
```

### 2. Monitor Railway Deployment

Watch the deployment logs for these key messages:

**Expected Success Messages:**
```
✅ Database connection successful
✅ Database schema initialized successfully
✅ Database cache service initialized successfully
```

**Possible Warning (OK):**
```
⚠️ Database cache service running in fallback mode
```
This means dependencies aren't loaded yet. Redeploy if this persists.

### 3. Verify Deployment

After deployment completes, check these endpoints:

#### a) Health Check
```
https://monitor-legislativo-v4-production.up.railway.app/api/lexml/health
```

Expected response:
```json
{
  "database_available": true,
  "connection_healthy": true,
  "cache_service_status": "active",
  "features_available": [
    "search_result_caching",
    "export_caching",
    "analytics_tracking",
    "performance_monitoring"
  ]
}
```

#### b) Analytics Check
```
https://monitor-legislativo-v4-production.up.railway.app/api/lexml/analytics
```

Expected: Should return analytics data structure

#### c) Search Test
```
https://monitor-legislativo-v4-production.up.railway.app/api/lexml/search?q=transporte
```

Look for `"cache_hit": false` on first request, then `"cache_hit": true` on repeat

## Troubleshooting

### Issue: "Database cache service running in fallback mode"

**Solution 1:** Force rebuild
```bash
git commit --allow-empty -m "Force Railway rebuild for database activation"
git push origin main
```

**Solution 2:** Check Railway logs for specific errors

### Issue: "Database connection failed"

**Check:**
1. DATABASE_URL is correctly set in Railway
2. Supabase project is active (not paused)
3. Password doesn't have special characters that need escaping

### Issue: "ModuleNotFoundError: No module named 'sqlalchemy'"

**Solution:** Railway might be caching old dependencies
1. In Railway dashboard, go to Settings
2. Clear build cache
3. Redeploy

## Post-Deployment Verification

### 1. Performance Check
- First search: ~100-500ms (fetching from API)
- Repeated search: <50ms (cache hit)

### 2. Database Monitoring
- Login to Supabase dashboard
- Check Database > Tables
- Verify tables exist: cache_entries, export_cache, search_history

### 3. Cache Statistics
After some usage, check:
```
https://monitor-legislativo-v4-production.up.railway.app/api/lexml/stats
```

## Rollback Plan

If issues occur, system automatically falls back to CSV mode:

1. No action needed - system continues working
2. To force CSV-only mode, set in Railway:
   ```
   FORCE_CSV_ONLY=true
   ```

## Success Indicators

✅ Health endpoint shows `database_available: true`  
✅ Search results include cache statistics  
✅ No errors in Railway logs  
✅ Supabase dashboard shows active connections  
✅ Response times improve on repeated queries  

## Notes

- Database features activate automatically when dependencies are available
- First deployment might take longer due to dependency installation
- System maintains 100% uptime even if database fails (CSV fallback)
- Monitor Supabase free tier limits (500MB storage, 2GB bandwidth/month)