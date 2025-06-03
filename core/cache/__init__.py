"""
Advanced Caching System for Monitor Legislativo v4
Combines Redis and CDN for optimal performance

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .redis_cache import (
    RedisCache,
    RedisCacheManager,
    redis_manager,
    get_redis_cache,
    init_redis_cache
)

from .cdn_cache import (
    CDNProvider,
    CloudflareCDN,
    FastlyCDN,
    CDNCacheManager,
    CacheKeyGenerator,
    cdn_manager,
    cache_static_content,
    purge_cdn_cache,
    get_cdn_analytics
)

__all__ = [
    # Redis
    "RedisCache",
    "RedisCacheManager",
    "redis_manager",
    "get_redis_cache",
    "init_redis_cache",
    
    # CDN
    "CDNProvider",
    "CloudflareCDN",
    "FastlyCDN",
    "CDNCacheManager",
    "CacheKeyGenerator",
    "cdn_manager",
    "cache_static_content",
    "purge_cdn_cache",
    "get_cdn_analytics"
]