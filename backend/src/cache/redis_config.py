"""
Redis Cache Configuration for Monitor Legislativo
Implements intelligent caching strategies for different data types
"""

import os
from typing import Dict, Any
from dataclasses import dataclass, field


@dataclass
class CacheTTLConfig:
    """TTL configuration for different cache patterns"""
    default: int = 3600  # 1 hour
    api_camara: int = 7200  # 2 hours
    api_senado: int = 7200  # 2 hours
    api_planalto: int = 86400  # 24 hours
    api_regulatory: int = 14400  # 4 hours
    geography: int = 2592000  # 30 days
    export: int = 1800  # 30 minutes
    search_results: int = 900  # 15 minutes
    statistics: int = 3600  # 1 hour
    user_session: int = 86400  # 24 hours


@dataclass
class RedisPoolConfig:
    """Redis connection pool configuration"""
    max_connections: int = 50
    min_idle_connections: int = 10
    connection_timeout: int = 20
    socket_keepalive: bool = True
    socket_keepalive_options: Dict[int, int] = field(default_factory=lambda: {
        1: 1,  # TCP_KEEPIDLE
        2: 60,  # TCP_KEEPINTVL
        3: 3,  # TCP_KEEPCNT
    })


class RedisConfig:
    """Main Redis configuration class"""
    
    # Redis instance configuration
    HOST = os.getenv('REDIS_HOST', 'localhost')
    PORT = int(os.getenv('REDIS_PORT', '6379'))
    DB = int(os.getenv('REDIS_DB', '0'))
    PASSWORD = os.getenv('REDIS_PASSWORD', None)  # Set via environment variable
    
    # For Upstash Redis (production)
    REDIS_URL = os.getenv('REDIS_URL', None)
    
    # Memory management
    MAX_MEMORY = '256mb'
    EVICTION_POLICY = 'allkeys-lru'
    
    # Performance settings
    MAX_CLIENTS = 10000
    TCP_KEEPALIVE = 300
    TIMEOUT = 300
    
    # TTL configurations
    TTL = CacheTTLConfig()
    
    # Connection pool
    POOL = RedisPoolConfig()
    
    # Cache key patterns with specific TTLs
    CACHE_PATTERNS = {
        # Government APIs
        'api:camara:*': {'ttl': TTL.api_camara, 'priority': 'high'},
        'api:senado:*': {'ttl': TTL.api_senado, 'priority': 'high'},
        'api:planalto:*': {'ttl': TTL.api_planalto, 'priority': 'medium'},
        
        # Regulatory agencies
        'api:antt:*': {'ttl': TTL.api_regulatory, 'priority': 'medium'},
        'api:anac:*': {'ttl': TTL.api_regulatory, 'priority': 'medium'},
        'api:antaq:*': {'ttl': TTL.api_regulatory, 'priority': 'medium'},
        'api:aneel:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:anatel:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:anvisa:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:ans:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:ana:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:ancine:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:anp:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        'api:anm:*': {'ttl': TTL.api_regulatory, 'priority': 'low'},
        
        # Static data
        'geography:*': {'ttl': TTL.geography, 'priority': 'low'},
        'document_types:*': {'ttl': TTL.geography, 'priority': 'low'},
        'brazil_states:*': {'ttl': TTL.geography, 'priority': 'low'},
        
        # Dynamic data
        'search:*': {'ttl': TTL.search_results, 'priority': 'high'},
        'export:*': {'ttl': TTL.export, 'priority': 'medium'},
        'stats:*': {'ttl': TTL.statistics, 'priority': 'medium'},
        
        # User data
        'session:*': {'ttl': TTL.user_session, 'priority': 'high'},
        'user_prefs:*': {'ttl': TTL.user_session, 'priority': 'medium'},
    }
    
    # Cache warming patterns - pre-load these on startup
    CACHE_WARMING_PATTERNS = [
        'geography:brazil_states',
        'geography:regions',
        'document_types:all',
        'api:sources:list',
    ]
    
    # Batch operation settings
    BATCH_SIZE = 100
    PIPELINE_SIZE = 1000
    
    # Monitoring and metrics
    ENABLE_METRICS = True
    METRICS_INTERVAL = 60  # seconds
    
    @classmethod
    def get_redis_url(cls, password: str = None) -> str:
        """Generate Redis connection URL"""
        # Use REDIS_URL if available (for Upstash/external Redis)
        if cls.REDIS_URL:
            return cls.REDIS_URL
            
        # Fallback to manual construction
        pwd = password or cls.PASSWORD
        if pwd:
            return f"redis://:{pwd}@{cls.HOST}:{cls.PORT}/{cls.DB}"
        return f"redis://{cls.HOST}:{cls.PORT}/{cls.DB}"
    
    @classmethod
    def get_ttl_for_key(cls, key: str) -> int:
        """Get TTL for a specific cache key based on pattern"""
        for pattern, config in cls.CACHE_PATTERNS.items():
            if cls._match_pattern(key, pattern):
                return config['ttl']
        return cls.TTL.default
    
    @classmethod
    def get_priority_for_key(cls, key: str) -> str:
        """Get priority for a specific cache key based on pattern"""
        for pattern, config in cls.CACHE_PATTERNS.items():
            if cls._match_pattern(key, pattern):
                return config['priority']
        return 'medium'
    
    @staticmethod
    def _match_pattern(key: str, pattern: str) -> bool:
        """Check if key matches pattern with wildcards"""
        import fnmatch
        return fnmatch.fnmatch(key, pattern)
    
    @classmethod
    def get_memory_config(cls) -> Dict[str, Any]:
        """Get Redis memory configuration commands"""
        return {
            'maxmemory': cls.MAX_MEMORY,
            'maxmemory-policy': cls.EVICTION_POLICY,
            'maxclients': cls.MAX_CLIENTS,
            'timeout': cls.TIMEOUT,
            'tcp-keepalive': cls.TCP_KEEPALIVE,
        }
    
    @classmethod
    def get_cache_stats_keys(cls) -> list:
        """Get keys for cache statistics tracking"""
        return [
            'stats:cache_hits',
            'stats:cache_misses',
            'stats:api_calls_saved',
            'stats:bandwidth_saved',
            'stats:avg_response_time',
            'stats:cache_size',
        ]


# Export configuration instance
redis_config = RedisConfig()