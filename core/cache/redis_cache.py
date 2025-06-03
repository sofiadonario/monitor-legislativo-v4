"""
Redis Cache Implementation for Monitor Legislativo v4
Distributed caching with Redis for scalability

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import json
import logging
import asyncio
from typing import Any, Optional, Dict, List, Set
from datetime import datetime, timedelta
import hashlib
import pickle

try:
    import redis.asyncio as redis
    from redis.asyncio.connection import ConnectionPool
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

logger = logging.getLogger(__name__)

class RedisCache:
    """Advanced Redis cache with clustering support"""
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 6379,
                 db: int = 0,
                 password: Optional[str] = None,
                 cluster_mode: bool = False,
                 max_connections: int = 50,
                 decode_responses: bool = False):
        
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.cluster_mode = cluster_mode
        self.max_connections = max_connections
        self.decode_responses = decode_responses
        
        self._client: Optional[redis.Redis] = None
        self._pool: Optional[ConnectionPool] = None
        self._connected = False
        
    async def connect(self) -> bool:
        """Connect to Redis server"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis module not available")
            return False
            
        try:
            # Create connection pool
            self._pool = redis.ConnectionPool(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                max_connections=self.max_connections,
                decode_responses=self.decode_responses
            )
            
            # Create Redis client
            self._client = redis.Redis(connection_pool=self._pool)
            
            # Test connection
            await self._client.ping()
            self._connected = True
            
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._connected = False
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Redis"""
        if self._client:
            await self._client.close()
            self._connected = False
            logger.info("Disconnected from Redis")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self._connected:
            return None
            
        try:
            value = await self._client.get(key)
            if value is None:
                return None
                
            # Try to deserialize as JSON first
            try:
                return json.loads(value)
            except:
                # Fall back to pickle for complex objects
                try:
                    return pickle.loads(value)
                except:
                    # Return as string if all else fails
                    return value.decode() if isinstance(value, bytes) else value
                    
        except Exception as e:
            logger.error(f"Redis get error for key {key}: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL"""
        if not self._connected:
            return False
            
        try:
            # Serialize value
            try:
                serialized = json.dumps(value, default=str)
            except:
                # Fall back to pickle for complex objects
                serialized = pickle.dumps(value)
            
            if ttl:
                result = await self._client.setex(key, ttl, serialized)
            else:
                result = await self._client.set(key, serialized)
                
            return bool(result)
            
        except Exception as e:
            logger.error(f"Redis set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self._connected:
            return False
            
        try:
            result = await self._client.delete(key)
            return bool(result)
        except Exception as e:
            logger.error(f"Redis delete error for key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self._connected:
            return False
            
        try:
            return bool(await self._client.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error for key {key}: {e}")
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key"""
        if not self._connected:
            return False
            
        try:
            return bool(await self._client.expire(key, ttl))
        except Exception as e:
            logger.error(f"Redis expire error for key {key}: {e}")
            return False
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values at once"""
        if not self._connected or not keys:
            return {}
            
        try:
            values = await self._client.mget(keys)
            result = {}
            
            for key, value in zip(keys, values):
                if value is not None:
                    try:
                        result[key] = json.loads(value)
                    except:
                        try:
                            result[key] = pickle.loads(value)
                        except:
                            result[key] = value.decode() if isinstance(value, bytes) else value
                            
            return result
            
        except Exception as e:
            logger.error(f"Redis mget error: {e}")
            return {}
    
    async def set_many(self, mapping: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set multiple values at once"""
        if not self._connected or not mapping:
            return False
            
        try:
            # Serialize all values
            serialized = {}
            for key, value in mapping.items():
                try:
                    serialized[key] = json.dumps(value, default=str)
                except:
                    serialized[key] = pickle.dumps(value)
            
            # Use pipeline for atomic operation
            async with self._client.pipeline() as pipe:
                for key, value in serialized.items():
                    if ttl:
                        pipe.setex(key, ttl, value)
                    else:
                        pipe.set(key, value)
                        
                results = await pipe.execute()
                
            return all(results)
            
        except Exception as e:
            logger.error(f"Redis mset error: {e}")
            return False
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment numeric value"""
        if not self._connected:
            return None
            
        try:
            return await self._client.incrby(key, amount)
        except Exception as e:
            logger.error(f"Redis increment error for key {key}: {e}")
            return None
    
    async def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """Decrement numeric value"""
        if not self._connected:
            return None
            
        try:
            return await self._client.decrby(key, amount)
        except Exception as e:
            logger.error(f"Redis decrement error for key {key}: {e}")
            return None
    
    # Set operations
    async def sadd(self, key: str, *members: Any) -> int:
        """Add members to set"""
        if not self._connected:
            return 0
            
        try:
            serialized = [json.dumps(m, default=str) for m in members]
            return await self._client.sadd(key, *serialized)
        except Exception as e:
            logger.error(f"Redis sadd error for key {key}: {e}")
            return 0
    
    async def srem(self, key: str, *members: Any) -> int:
        """Remove members from set"""
        if not self._connected:
            return 0
            
        try:
            serialized = [json.dumps(m, default=str) for m in members]
            return await self._client.srem(key, *serialized)
        except Exception as e:
            logger.error(f"Redis srem error for key {key}: {e}")
            return 0
    
    async def smembers(self, key: str) -> Set[Any]:
        """Get all members of set"""
        if not self._connected:
            return set()
            
        try:
            members = await self._client.smembers(key)
            result = set()
            
            for member in members:
                try:
                    result.add(json.loads(member))
                except:
                    result.add(member.decode() if isinstance(member, bytes) else member)
                    
            return result
            
        except Exception as e:
            logger.error(f"Redis smembers error for key {key}: {e}")
            return set()
    
    # Hash operations
    async def hset(self, key: str, field: str, value: Any) -> bool:
        """Set hash field"""
        if not self._connected:
            return False
            
        try:
            serialized = json.dumps(value, default=str)
            result = await self._client.hset(key, field, serialized)
            return bool(result)
        except Exception as e:
            logger.error(f"Redis hset error for key {key}: {e}")
            return False
    
    async def hget(self, key: str, field: str) -> Optional[Any]:
        """Get hash field"""
        if not self._connected:
            return None
            
        try:
            value = await self._client.hget(key, field)
            if value is None:
                return None
                
            try:
                return json.loads(value)
            except:
                return value.decode() if isinstance(value, bytes) else value
                
        except Exception as e:
            logger.error(f"Redis hget error for key {key}: {e}")
            return None
    
    async def hgetall(self, key: str) -> Dict[str, Any]:
        """Get all hash fields"""
        if not self._connected:
            return {}
            
        try:
            data = await self._client.hgetall(key)
            result = {}
            
            for field, value in data.items():
                field_str = field.decode() if isinstance(field, bytes) else field
                try:
                    result[field_str] = json.loads(value)
                except:
                    result[field_str] = value.decode() if isinstance(value, bytes) else value
                    
            return result
            
        except Exception as e:
            logger.error(f"Redis hgetall error for key {key}: {e}")
            return {}
    
    # Pattern operations
    async def keys(self, pattern: str) -> List[str]:
        """Get keys matching pattern"""
        if not self._connected:
            return []
            
        try:
            keys = await self._client.keys(pattern)
            return [k.decode() if isinstance(k, bytes) else k for k in keys]
        except Exception as e:
            logger.error(f"Redis keys error for pattern {pattern}: {e}")
            return []
    
    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        if not self._connected:
            return 0
            
        try:
            keys = await self.keys(pattern)
            if keys:
                return await self._client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Redis delete_pattern error for pattern {pattern}: {e}")
            return 0
    
    # Cache statistics
    async def info(self) -> Dict[str, Any]:
        """Get Redis server info"""
        if not self._connected:
            return {}
            
        try:
            info = await self._client.info()
            return {
                "version": info.get("redis_version"),
                "used_memory": info.get("used_memory_human"),
                "connected_clients": info.get("connected_clients"),
                "total_commands": info.get("total_commands_processed"),
                "keyspace": info.get("db0", {})
            }
        except Exception as e:
            logger.error(f"Redis info error: {e}")
            return {}
    
    async def flush_db(self) -> bool:
        """Flush current database (use with caution!)"""
        if not self._connected:
            return False
            
        try:
            await self._client.flushdb()
            return True
        except Exception as e:
            logger.error(f"Redis flushdb error: {e}")
            return False

class RedisCacheManager:
    """Manager for Redis cache with advanced features"""
    
    def __init__(self):
        self.caches: Dict[str, RedisCache] = {}
        self.default_cache: Optional[RedisCache] = None
        
    async def add_cache(self, name: str, cache: RedisCache, is_default: bool = False) -> bool:
        """Add a Redis cache instance"""
        if await cache.connect():
            self.caches[name] = cache
            if is_default or self.default_cache is None:
                self.default_cache = cache
            return True
        return False
    
    def get_cache(self, name: Optional[str] = None) -> Optional[RedisCache]:
        """Get cache by name or default"""
        if name:
            return self.caches.get(name)
        return self.default_cache
    
    async def close_all(self) -> None:
        """Close all cache connections"""
        for cache in self.caches.values():
            await cache.disconnect()
        self.caches.clear()
        self.default_cache = None

# Global cache manager
redis_manager = RedisCacheManager()

# Convenience functions
async def get_redis_cache(name: Optional[str] = None) -> Optional[RedisCache]:
    """Get Redis cache instance"""
    return redis_manager.get_cache(name)

async def init_redis_cache(host: str = "localhost", 
                          port: int = 6379,
                          **kwargs) -> bool:
    """Initialize default Redis cache"""
    cache = RedisCache(host, port, **kwargs)
    return await redis_manager.add_cache("default", cache, is_default=True)