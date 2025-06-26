# Alternative DATABASE_URL for Railway

## Current Issue
Authentication error: `'NoneType' object has no attribute 'group'`

This suggests the username format `postgres.upxonmtqerdrxdgywzuj` is causing asyncpg parsing issues.

## Alternative URL Format

**Try this DATABASE_URL in Railway:**
```
DATABASE_URL=postgresql://postgres:MonitorTransporte25%2A@aws-0-sa-east-1.pooler.supabase.com:5432/postgres
```

**Key change:** Using standard `postgres` username instead of `postgres.upxonmtqerdrxdgywzuj`

## Other Options to Try

### Option 1: Direct Connection (non-pooler)
```
DATABASE_URL=postgresql://postgres:MonitorTransporte25%2A@db.upxonmtqerdrxdgywzuj.supabase.co:5432/postgres
```

### Option 2: Transaction Pooler (port 6543)
```
DATABASE_URL=postgresql://postgres:MonitorTransporte25%2A@db.upxonmtqerdrxdgywzuj.supabase.co:6543/postgres
```

### Option 3: Different Connection Pooler Format
```
DATABASE_URL=postgresql://postgres:MonitorTransporte25%2A@aws-0-sa-east-1.pooler.supabase.com:6543/postgres
```

## Testing Steps

1. Update Railway DATABASE_URL with Alternative URL above
2. Wait for auto-deploy (2-3 minutes)
3. Test: `curl https://monitor-legislativo-v4-production.up.railway.app/api/v1/health/database`
4. If still fails, try Option 1, then Option 2, then Option 3

## Expected Success
Once working, you should see:
- ✅ Database connection successful
- ✅ No authentication errors
- ✅ Cache service operational