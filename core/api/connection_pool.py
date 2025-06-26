"""
Connection Pool Manager for API Clients
======================================

Manages HTTP session pooling and connection reuse for improved performance.
Implements connection limits, timeouts, and health monitoring.

Features:
- Connection pooling with configurable limits
- Session reuse across requests
- Automatic connection health checks
- Graceful degradation on connection failures
"""

import asyncio
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass
import logging

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class PoolConfig:
    """Configuration for connection pool"""
    max_connections: int = 100
    max_connections_per_host: int = 30
    timeout_seconds: int = 30
    keepalive_timeout: int = 30
    force_close_idle_after: int = 300  # 5 minutes
    health_check_interval: int = 60  # 1 minute


class ConnectionPoolManager:
    """
    Manages HTTP connection pools for API clients
    
    Provides efficient connection reuse and health monitoring
    for high-volume API interactions.
    """
    
    def __init__(self, config: Optional[PoolConfig] = None):
        self.config = config or PoolConfig()
        self.pools: Dict[str, Any] = {}
        self.health_status: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._health_check_task: Optional[asyncio.Task] = None
        
        logger.info(f"Connection pool manager initialized with config: {self.config}")
    
    async def get_session(self, pool_name: str = "default", 
                         base_url: Optional[str] = None) -> Any:
        """
        Get or create a session from the pool
        
        Args:
            pool_name: Name of the pool
            base_url: Base URL for the session
            
        Returns:
            aiohttp.ClientSession or None if not available
        """
        if not AIOHTTP_AVAILABLE:
            logger.warning("aiohttp not available, connection pooling disabled")
            return None
        
        async with self._lock:
            if pool_name not in self.pools:
                await self._create_pool(pool_name, base_url)
            
            pool_info = self.pools.get(pool_name)
            if pool_info and not pool_info['session'].closed:
                pool_info['last_used'] = time.time()
                return pool_info['session']
            else:
                # Recreate if closed
                await self._create_pool(pool_name, base_url)
                return self.pools[pool_name]['session']
    
    async def _create_pool(self, pool_name: str, base_url: Optional[str] = None):
        """Create a new connection pool"""
        if not AIOHTTP_AVAILABLE:
            return
        
        # Close existing pool if any
        if pool_name in self.pools:
            old_session = self.pools[pool_name]['session']
            if not old_session.closed:
                await old_session.close()
        
        # Configure connector with pooling
        connector = aiohttp.TCPConnector(
            limit=self.config.max_connections,
            limit_per_host=self.config.max_connections_per_host,
            ttl_dns_cache=300,
            keepalive_timeout=self.config.keepalive_timeout,
            force_close=False
        )
        
        # Configure timeout
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout_seconds,
            connect=10,
            sock_read=self.config.timeout_seconds
        )
        
        # Create session
        headers = {
            'User-Agent': 'MonitorLegislativoV4/2.0 (Enhanced; Connection-Pooled)',
            'Accept': 'application/json, application/xml, text/xml',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'Connection': 'keep-alive'
        }
        
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            base_url=base_url
        )
        
        # Store pool info
        self.pools[pool_name] = {
            'session': session,
            'created_at': time.time(),
            'last_used': time.time(),
            'base_url': base_url,
            'request_count': 0
        }
        
        # Initialize health status
        self.health_status[pool_name] = {
            'healthy': True,
            'last_check': time.time(),
            'consecutive_failures': 0
        }
        
        logger.info(f"Created connection pool '{pool_name}' with base_url: {base_url}")
    
    async def release_session(self, pool_name: str = "default"):
        """
        Mark session as available for reuse
        
        Args:
            pool_name: Name of the pool
        """
        if pool_name in self.pools:
            self.pools[pool_name]['last_used'] = time.time()
            self.pools[pool_name]['request_count'] += 1
    
    async def close_pool(self, pool_name: str):
        """Close a specific connection pool"""
        async with self._lock:
            if pool_name in self.pools:
                session = self.pools[pool_name]['session']
                if not session.closed:
                    await session.close()
                del self.pools[pool_name]
                
                if pool_name in self.health_status:
                    del self.health_status[pool_name]
                
                logger.info(f"Closed connection pool '{pool_name}'")
    
    async def close_all(self):
        """Close all connection pools"""
        pool_names = list(self.pools.keys())
        for pool_name in pool_names:
            await self.close_pool(pool_name)
        
        # Cancel health check task
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        logger.info("All connection pools closed")
    
    async def start_health_monitoring(self):
        """Start background health monitoring"""
        if self._health_check_task and not self._health_check_task.done():
            return
        
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Started connection pool health monitoring")
    
    async def _health_check_loop(self):
        """Background task for health monitoring"""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._check_pool_health()
                await self._cleanup_idle_pools()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _check_pool_health(self):
        """Check health of all pools"""
        for pool_name, pool_info in list(self.pools.items()):
            try:
                session = pool_info['session']
                if session.closed:
                    self.health_status[pool_name]['healthy'] = False
                else:
                    # Simple health check - connector status
                    connector = session.connector
                    if hasattr(connector, '_acquired'):
                        active_connections = len(connector._acquired)
                        self.health_status[pool_name].update({
                            'healthy': True,
                            'active_connections': active_connections,
                            'last_check': time.time()
                        })
                    
            except Exception as e:
                logger.error(f"Health check failed for pool '{pool_name}': {e}")
                self.health_status[pool_name]['healthy'] = False
                self.health_status[pool_name]['consecutive_failures'] += 1
    
    async def _cleanup_idle_pools(self):
        """Clean up idle connection pools"""
        current_time = time.time()
        
        for pool_name, pool_info in list(self.pools.items()):
            idle_time = current_time - pool_info['last_used']
            
            if idle_time > self.config.force_close_idle_after:
                logger.info(f"Closing idle pool '{pool_name}' (idle for {idle_time:.0f}s)")
                await self.close_pool(pool_name)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection pool statistics"""
        stats = {
            'pools': {},
            'config': {
                'max_connections': self.config.max_connections,
                'max_connections_per_host': self.config.max_connections_per_host,
                'timeout_seconds': self.config.timeout_seconds
            }
        }
        
        for pool_name, pool_info in self.pools.items():
            stats['pools'][pool_name] = {
                'created_at': pool_info['created_at'],
                'last_used': pool_info['last_used'],
                'request_count': pool_info['request_count'],
                'base_url': pool_info['base_url'],
                'health': self.health_status.get(pool_name, {})
            }
        
        return stats


# Global instance for shared use
_global_pool_manager: Optional[ConnectionPoolManager] = None


async def get_global_pool_manager() -> ConnectionPoolManager:
    """Get or create global connection pool manager"""
    global _global_pool_manager
    
    if _global_pool_manager is None:
        _global_pool_manager = ConnectionPoolManager()
        await _global_pool_manager.start_health_monitoring()
    
    return _global_pool_manager