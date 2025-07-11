# Redis Setup Guide for Railway

## Current Status
- ✅ Redis caching enabled in `railway.toml` (`ENABLE_CACHE = "true"`)
- ✅ Backend Redis client configured with fallback handling
- ⚠️ Railway Redis service needs to be added

## Required Actions

### 1. Add Redis Service in Railway Dashboard

1. Go to your Railway project dashboard
2. Click "Add Service" 
3. Select "Redis"
4. Deploy the Redis service

### 2. Configure Environment Variables

Railway will automatically provide `REDIS_URL` environment variable once Redis service is deployed.

**Alternative Redis Providers (if needed):**
- **Upstash Redis**: Set `UPSTASH_REDIS_URL` environment variable
- **External Redis**: Set `REDIS_URL` environment variable

### 3. Environment Variables Reference

```bash
# Primary Redis configuration
REDIS_URL=redis://default:password@redis-host:6379

# Alternative configurations
UPSTASH_REDIS_URL=redis://default:password@upstash-host:6379
REDIS_HOST=redis-host
REDIS_PORT=6379
REDIS_PASSWORD=password

# Cache configuration
ENABLE_CACHE=true
REDIS_MAX_CONNECTIONS=10
REDIS_TIMEOUT=5
```

## Verification Steps

1. **Check Redis Health**:
   ```bash
   curl https://backend-api-production-2392.up.railway.app/health
   ```

2. **Test Cache Performance**:
   The application will automatically use Redis for:
   - API response caching
   - Search result caching
   - Export data caching
   - Session management

## Fallback Behavior

The application is designed to work with or without Redis:
- **With Redis**: Enhanced performance through caching
- **Without Redis**: Graceful degradation to database-only operations

## Current Configuration

- **Cache TTL**: Configured in `backend/src/cache/redis_config.py`
- **Connection Pool**: Max 50 connections, 10 minimum idle
- **Memory Policy**: `allkeys-lru` with 256MB max memory
- **Health Checks**: Integrated into main application health endpoint

## Troubleshooting

If Redis connection fails:
1. Check Railway Redis service status
2. Verify `REDIS_URL` environment variable
3. Check application logs for Redis connection errors
4. Application will continue without Redis (database-only mode)

## Next Steps

1. **Add Redis service in Railway dashboard**
2. **Verify Redis connection in application logs**
3. **Test improved performance with caching enabled**