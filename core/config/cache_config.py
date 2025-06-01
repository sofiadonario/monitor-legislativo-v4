"""
Cache Configuration
Implements adaptive caching strategies from recommendations
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class CacheStrategy:
    """Cache strategy configuration"""
    ttl: int  # Time to live in seconds
    strategy: str  # 'time-based', 'adaptive', 'access-based'
    min_ttl: Optional[int] = None
    max_ttl: Optional[int] = None
    
    def get_adaptive_ttl(self, access_frequency: float = 0.0) -> int:
        """Calculate adaptive TTL based on access patterns"""
        if self.strategy != 'adaptive':
            return self.ttl
        
        # High frequency = shorter TTL (fresher data)
        # Low frequency = longer TTL (less updates needed)
        if access_frequency > 10:  # More than 10 accesses per hour
            return self.min_ttl or 1800  # 30 minutes
        elif access_frequency > 5:
            return 3600  # 1 hour
        elif access_frequency > 1:
            return 7200  # 2 hours
        else:
            return self.max_ttl or 86400  # 24 hours


# Cache configuration as recommended in analysis
CACHE_CONFIG = {
    # Legislative APIs - moderate TTL
    "camara": CacheStrategy(
        ttl=3600,  # 1 hour
        strategy="time-based"
    ),
    "senado": CacheStrategy(
        ttl=3600,  # 1 hour
        strategy="time-based"
    ),
    "planalto": CacheStrategy(
        ttl=7200,  # 2 hours (slower updates)
        strategy="time-based"
    ),
    
    # Regulatory scrapers - adaptive with longer TTL
    "aneel": CacheStrategy(
        ttl=86400,  # 24 hours default
        strategy="adaptive",
        min_ttl=3600,  # 1 hour minimum
        max_ttl=604800  # 1 week maximum
    ),
    "anatel": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "anvisa": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "ans": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "ana": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "ancine": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "antt": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "antaq": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "anac": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "anp": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    "anm": CacheStrategy(
        ttl=86400,
        strategy="adaptive",
        min_ttl=3600,
        max_ttl=604800
    ),
    
    # Special cache strategies
    "unified_search": CacheStrategy(
        ttl=3600,
        strategy="adaptive",
        min_ttl=1800,
        max_ttl=14400  # 4 hours max
    ),
    "common_queries": CacheStrategy(
        ttl=7200,  # 2 hours for common queries
        strategy="time-based"
    ),
    "fallback_cache": CacheStrategy(
        ttl=172800,  # 48 hours for fallback data
        strategy="time-based"
    )
}


def get_cache_strategy(source: str) -> CacheStrategy:
    """Get cache strategy for source"""
    return CACHE_CONFIG.get(source, CacheStrategy(ttl=3600, strategy="time-based"))