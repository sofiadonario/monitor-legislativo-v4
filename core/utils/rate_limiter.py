"""
Rate Limiting and Quota Management System
Implements token bucket and sliding window algorithms
"""

import time
import threading
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import logging

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

class RateLimitType(Enum):
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"

@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_capacity: int = 100
    algorithm: RateLimitType = RateLimitType.TOKEN_BUCKET
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 1

@dataclass
class QuotaConfig:
    """API quota configuration"""
    daily_quota: int = 10000
    monthly_quota: int = 300000
    reset_hour: int = 0  # Hour of day to reset daily quota (0-23)
    enable_overage: bool = False
    overage_multiplier: float = 1.5

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_time: int
    retry_after: Optional[int] = None
    quota_remaining: Optional[int] = None

class TokenBucket:
    """Token bucket rate limiter"""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from bucket"""
        with self._lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            time_elapsed = now - self.last_refill
            tokens_to_add = time_elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_remaining(self) -> int:
        """Get remaining tokens"""
        with self._lock:
            return int(self.tokens)

class SlidingWindowCounter:
    """Sliding window rate limiter"""
    
    def __init__(self, window_size: int, max_requests: int):
        self.window_size = window_size  # in seconds
        self.max_requests = max_requests
        self.requests: Dict[int, int] = {}  # timestamp -> count
        self._lock = threading.Lock()
    
    def is_allowed(self) -> Tuple[bool, int]:
        """Check if request is allowed and return remaining count"""
        with self._lock:
            now = int(time.time())
            window_start = now - self.window_size
            
            # Clean old entries
            self.requests = {
                timestamp: count 
                for timestamp, count in self.requests.items() 
                if timestamp > window_start
            }
            
            # Count requests in current window
            current_count = sum(self.requests.values())
            
            if current_count < self.max_requests:
                # Add current request
                self.requests[now] = self.requests.get(now, 0) + 1
                remaining = self.max_requests - current_count - 1
                return True, remaining
            
            return False, 0

class MemoryRateLimiter:
    """In-memory rate limiter"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.buckets: Dict[str, TokenBucket] = {}
        self.windows: Dict[str, SlidingWindowCounter] = {}
        self._lock = threading.Lock()
    
    def _get_bucket(self, key: str) -> TokenBucket:
        """Get or create token bucket for key"""
        if key not in self.buckets:
            with self._lock:
                if key not in self.buckets:
                    # Convert requests per minute to tokens per second
                    refill_rate = self.config.requests_per_minute / 60.0
                    self.buckets[key] = TokenBucket(
                        self.config.burst_capacity, 
                        refill_rate
                    )
        return self.buckets[key]
    
    def _get_window(self, key: str, window_size: int, max_requests: int) -> SlidingWindowCounter:
        """Get or create sliding window for key"""
        window_key = f"{key}:{window_size}"
        if window_key not in self.windows:
            with self._lock:
                if window_key not in self.windows:
                    self.windows[window_key] = SlidingWindowCounter(window_size, max_requests)
        return self.windows[window_key]
    
    def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check if request is within rate limits"""
        if self.config.algorithm == RateLimitType.TOKEN_BUCKET:
            bucket = self._get_bucket(key)
            allowed = bucket.consume()
            remaining = bucket.get_remaining()
            
            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=int(time.time() + 60),  # Next minute
                retry_after=1 if not allowed else None
            )
        
        elif self.config.algorithm == RateLimitType.SLIDING_WINDOW:
            # Check minute window
            minute_window = self._get_window(key, 60, self.config.requests_per_minute)
            minute_allowed, minute_remaining = minute_window.is_allowed()
            
            if not minute_allowed:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=int(time.time() + 60),
                    retry_after=60
                )
            
            # Check hour window
            hour_window = self._get_window(key, 3600, self.config.requests_per_hour)
            hour_allowed, hour_remaining = hour_window.is_allowed()
            
            if not hour_allowed:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=int(time.time() + 3600),
                    retry_after=3600
                )
            
            return RateLimitResult(
                allowed=True,
                remaining=min(minute_remaining, hour_remaining),
                reset_time=int(time.time() + 60)
            )
        
        # Default: allow all requests
        return RateLimitResult(
            allowed=True,
            remaining=1000,
            reset_time=int(time.time() + 60)
        )

class RedisRateLimiter:
    """Redis-based distributed rate limiter"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._redis = None
        self._connect()
    
    def _connect(self):
        """Connect to Redis"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available for rate limiting")
            return
        
        try:
            self._redis = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                decode_responses=True
            )
            self._redis.ping()
            logger.info("Connected to Redis for rate limiting")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._redis = None
    
    def _is_available(self) -> bool:
        """Check if Redis is available"""
        if not self._redis:
            return False
        try:
            self._redis.ping()
            return True
        except:
            return False
    
    def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check rate limit using Redis"""
        if not self._is_available():
            # Fallback: allow request but log warning
            logger.warning("Redis unavailable, allowing request")
            return RateLimitResult(
                allowed=True,
                remaining=0,
                reset_time=int(time.time() + 60)
            )
        
        try:
            now = int(time.time())
            pipe = self._redis.pipeline()
            
            # Sliding window implementation using sorted sets
            minute_key = f"rate_limit:{key}:minute"
            hour_key = f"rate_limit:{key}:hour"
            
            # Remove old entries and count current
            minute_start = now - 60
            hour_start = now - 3600
            
            pipe.zremrangebyscore(minute_key, 0, minute_start)
            pipe.zremrangebyscore(hour_key, 0, hour_start)
            pipe.zcard(minute_key)
            pipe.zcard(hour_key)
            
            results = pipe.execute()
            minute_count = results[2]
            hour_count = results[3]
            
            # Check limits
            if minute_count >= self.config.requests_per_minute:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=now + 60,
                    retry_after=60
                )
            
            if hour_count >= self.config.requests_per_hour:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=now + 3600,
                    retry_after=3600
                )
            
            # Add current request
            pipe = self._redis.pipeline()
            pipe.zadd(minute_key, {str(now): now})
            pipe.zadd(hour_key, {str(now): now})
            pipe.expire(minute_key, 60)
            pipe.expire(hour_key, 3600)
            pipe.execute()
            
            remaining = min(
                self.config.requests_per_minute - minute_count - 1,
                self.config.requests_per_hour - hour_count - 1
            )
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                reset_time=now + 60
            )
            
        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            # Fallback: allow request
            return RateLimitResult(
                allowed=True,
                remaining=0,
                reset_time=int(time.time() + 60)
            )

class QuotaManager:
    """Manages API quotas"""
    
    def __init__(self, config: QuotaConfig):
        self.config = config
        self.daily_usage: Dict[str, int] = {}
        self.monthly_usage: Dict[str, int] = {}
        self._lock = threading.Lock()
    
    def check_quota(self, key: str) -> Tuple[bool, int, int]:
        """Check if request is within quota limits"""
        with self._lock:
            today = datetime.now().strftime("%Y-%m-%d")
            month = datetime.now().strftime("%Y-%m")
            
            daily_key = f"{key}:{today}"
            monthly_key = f"{key}:{month}"
            
            daily_used = self.daily_usage.get(daily_key, 0)
            monthly_used = self.monthly_usage.get(monthly_key, 0)
            
            # Check limits
            if daily_used >= self.config.daily_quota:
                if not self.config.enable_overage:
                    return False, 0, 0
                elif daily_used >= self.config.daily_quota * self.config.overage_multiplier:
                    return False, 0, 0
            
            if monthly_used >= self.config.monthly_quota:
                return False, 0, 0
            
            # Update usage
            self.daily_usage[daily_key] = daily_used + 1
            self.monthly_usage[monthly_key] = monthly_used + 1
            
            daily_remaining = max(0, self.config.daily_quota - daily_used - 1)
            monthly_remaining = max(0, self.config.monthly_quota - monthly_used - 1)
            
            return True, daily_remaining, monthly_remaining
    
    def get_usage(self, key: str) -> Dict[str, int]:
        """Get usage statistics for key"""
        today = datetime.now().strftime("%Y-%m-%d")
        month = datetime.now().strftime("%Y-%m")
        
        daily_key = f"{key}:{today}"
        monthly_key = f"{key}:{month}"
        
        return {
            'daily_used': self.daily_usage.get(daily_key, 0),
            'monthly_used': self.monthly_usage.get(monthly_key, 0),
            'daily_limit': self.config.daily_quota,
            'monthly_limit': self.config.monthly_quota
        }

class RateLimitManager:
    """Main rate limiting manager"""
    
    def __init__(self, 
                 rate_config: RateLimitConfig = None,
                 quota_config: QuotaConfig = None):
        self.rate_config = rate_config or RateLimitConfig()
        self.quota_config = quota_config or QuotaConfig()
        
        # Use Redis if available, otherwise memory
        if REDIS_AVAILABLE:
            self.rate_limiter = RedisRateLimiter(self.rate_config)
        else:
            self.rate_limiter = MemoryRateLimiter(self.rate_config)
        
        self.quota_manager = QuotaManager(self.quota_config)
    
    def check_limits(self, client_id: str, endpoint: str = None) -> RateLimitResult:
        """Check both rate limits and quotas"""
        # Create composite key
        key = f"{client_id}:{endpoint}" if endpoint else client_id
        
        # Check rate limits
        rate_result = self.rate_limiter.check_rate_limit(key)
        
        if not rate_result.allowed:
            return rate_result
        
        # Check quotas
        quota_allowed, daily_remaining, monthly_remaining = self.quota_manager.check_quota(key)
        
        if not quota_allowed:
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=self._get_next_reset_time(),
                quota_remaining=0
            )
        
        # Combine results
        rate_result.quota_remaining = min(daily_remaining, monthly_remaining)
        return rate_result
    
    def _get_next_reset_time(self) -> int:
        """Get next quota reset time"""
        now = datetime.now()
        tomorrow = now.replace(hour=self.quota_config.reset_hour, minute=0, second=0, microsecond=0)
        if tomorrow <= now:
            tomorrow += timedelta(days=1)
        return int(tomorrow.timestamp())
    
    def get_stats(self, client_id: str) -> Dict[str, Any]:
        """Get comprehensive stats for client"""
        usage_stats = self.quota_manager.get_usage(client_id)
        
        return {
            'rate_limit_config': asdict(self.rate_config),
            'quota_config': asdict(self.quota_config),
            'usage': usage_stats,
            'backend': 'redis' if isinstance(self.rate_limiter, RedisRateLimiter) else 'memory'
        }

# Global rate limiter instance
_rate_limiter: Optional[RateLimitManager] = None

def get_rate_limiter() -> RateLimitManager:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimitManager()
    return _rate_limiter

def init_rate_limiter(rate_config: RateLimitConfig = None, 
                     quota_config: QuotaConfig = None) -> RateLimitManager:
    """Initialize global rate limiter"""
    global _rate_limiter
    _rate_limiter = RateLimitManager(rate_config, quota_config)
    return _rate_limiter