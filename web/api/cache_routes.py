"""
Cache Management Routes for Monitor Legislativo v4
API endpoints for cache monitoring and control

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
from pydantic import BaseModel

from core.cache.cache_strategy import cache_strategy, CacheWarmer
from core.cache import redis_manager, cdn_manager
from core.auth.decorators import require_admin

router = APIRouter(tags=["cache"])

class CacheConfig(BaseModel):
    """Cache configuration model"""
    redis: Optional[Dict[str, Any]] = None
    cdn: Optional[Dict[str, Any]] = None

class CacheInvalidation(BaseModel):
    """Cache invalidation request"""
    pattern: str
    layers: Optional[list] = None

@router.get("/cache/stats")
async def get_cache_statistics():
    """
    Get cache statistics across all layers
    """
    try:
        stats = cache_strategy.get_stats()
        
        # Add Redis info if available
        redis_cache = await redis_manager.get_cache()
        if redis_cache and redis_cache._connected:
            stats["layers"]["redis"]["info"] = await redis_cache.info()
        
        # Add CDN analytics if available
        if cache_strategy.cdn_enabled:
            stats["layers"]["cdn"]["analytics"] = await cdn_manager.get_analytics()
        
        return stats
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/initialize")
async def initialize_cache(
    config: CacheConfig,
    _admin = Depends(require_admin)
):
    """
    Initialize cache layers with configuration (requires admin)
    """
    try:
        await cache_strategy.initialize(
            redis_config=config.redis,
            cdn_config=config.cdn
        )
        
        return {"message": "Cache layers initialized successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/invalidate")
async def invalidate_cache(
    request: CacheInvalidation,
    _admin = Depends(require_admin)
):
    """
    Invalidate cache entries matching pattern (requires admin)
    """
    try:
        count = await cache_strategy.invalidate_pattern(request.pattern)
        
        return {
            "message": f"Invalidated {count} cache entries",
            "pattern": request.pattern
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/warm/{category}")
async def warm_cache(
    category: str,
    _admin = Depends(require_admin)
):
    """
    Warm cache for specific category (requires admin)
    
    Categories:
    - search: Popular search queries
    - static: Static assets to CDN
    - all: All categories
    """
    try:
        warmer = CacheWarmer(cache_strategy)
        
        if category == "search":
            await warmer.warm_search_results([
                "política pública",
                "saúde",
                "educação", 
                "meio ambiente",
                "reforma tributária",
                "segurança pública"
            ])
            message = "Search cache warmed"
            
        elif category == "static":
            await warmer.warm_static_content()
            message = "Static content cache warmed"
            
        elif category == "all":
            await warmer.warm_search_results([
                "política pública",
                "saúde",
                "educação"
            ])
            await warmer.warm_static_content()
            message = "All cache categories warmed"
            
        else:
            raise HTTPException(status_code=400, detail=f"Unknown category: {category}")
        
        return {"message": message}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cache/redis/info")
async def get_redis_info(_admin = Depends(require_admin)):
    """
    Get Redis server information (requires admin)
    """
    redis_cache = await redis_manager.get_cache()
    if not redis_cache or not redis_cache._connected:
        raise HTTPException(status_code=503, detail="Redis not connected")
    
    try:
        info = await redis_cache.info()
        return info
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/redis/flush")
async def flush_redis_cache(_admin = Depends(require_admin)):
    """
    Flush Redis cache (requires admin) - USE WITH CAUTION!
    """
    redis_cache = await redis_manager.get_cache()
    if not redis_cache or not redis_cache._connected:
        raise HTTPException(status_code=503, detail="Redis not connected")
    
    try:
        success = await redis_cache.flush_db()
        if success:
            return {"message": "Redis cache flushed successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to flush Redis cache")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cache/cdn/analytics")
async def get_cdn_analytics():
    """
    Get CDN analytics and performance metrics
    """
    if not cache_strategy.cdn_enabled:
        raise HTTPException(status_code=503, detail="CDN not enabled")
    
    try:
        analytics = await cdn_manager.get_analytics()
        optimization = await cdn_manager.optimize_cache()
        
        return {
            "analytics": analytics,
            "optimization": optimization
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/cdn/purge")
async def purge_cdn_cache(
    url: str,
    _admin = Depends(require_admin)
):
    """
    Purge specific URL from CDN cache (requires admin)
    """
    if not cache_strategy.cdn_enabled:
        raise HTTPException(status_code=503, detail="CDN not enabled")
    
    try:
        success = await cdn_manager.purge_url(url)
        if success:
            return {"message": f"Purged {url} from CDN cache"}
        else:
            raise HTTPException(status_code=500, detail="Failed to purge CDN cache")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cache/memory/stats")
async def get_memory_cache_stats():
    """
    Get in-memory cache statistics
    """
    try:
        stats = cache_strategy.memory_cache.get_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cache/health")
async def cache_health_check():
    """
    Check health of all cache layers
    """
    health = {
        "status": "healthy",
        "layers": {
            "memory": {"status": "healthy"},
            "redis": {"status": "unknown"},
            "cdn": {"status": "unknown"}
        }
    }
    
    # Check Redis
    redis_cache = await redis_manager.get_cache()
    if redis_cache:
        try:
            await redis_cache.get("health_check")
            health["layers"]["redis"]["status"] = "healthy"
        except:
            health["layers"]["redis"]["status"] = "unhealthy"
            health["status"] = "degraded"
    else:
        health["layers"]["redis"]["status"] = "disabled"
    
    # Check CDN
    if cache_strategy.cdn_enabled:
        try:
            analytics = await cdn_manager.get_analytics()
            if analytics:
                health["layers"]["cdn"]["status"] = "healthy"
            else:
                health["layers"]["cdn"]["status"] = "unhealthy"
                health["status"] = "degraded"
        except:
            health["layers"]["cdn"]["status"] = "unhealthy"
            health["status"] = "degraded"
    else:
        health["layers"]["cdn"]["status"] = "disabled"
    
    return health