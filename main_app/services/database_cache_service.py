"""
Database Cache Service
=====================

Provides database-backed caching for search results, exports, and analytics.
Integrates Supabase PostgreSQL with the existing search workflow.
"""

import asyncio
import json
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import asdict

logger = logging.getLogger(__name__)

# Import database manager with error handling for missing dependencies
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / 'core'))

try:
    from database.supabase_config import get_database_manager
    from sqlalchemy import text
    DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database dependencies not available: {e}")
    DEPENDENCIES_AVAILABLE = False
    
    # Mock the functions for fallback mode
    async def get_database_manager():
        return None
    
    def text(query):
        return query


class DatabaseCacheService:
    """
    Database-backed caching service with fallback support.
    Provides search result caching, export caching, and analytics tracking.
    """
    
    def __init__(self):
        self.db_manager = None
        self.db_available = False
        self.initialization_attempted = False
    
    async def initialize(self) -> bool:
        """Initialize database connection with fallback handling"""
        if self.initialization_attempted:
            return self.db_available
        
        self.initialization_attempted = True
        
        # Check if dependencies are available
        if not DEPENDENCIES_AVAILABLE:
            logger.info("Database dependencies not available - operating in fallback mode")
            self.db_available = False
            return False
        
        try:
            self.db_manager = await get_database_manager()
            if self.db_manager:
                self.db_available = await self.db_manager.test_connection()
                
                if self.db_available:
                    logger.info("Database cache service initialized successfully")
                    return True
                else:
                    logger.warning("Database connection failed - cache service will operate in fallback mode")
                    return False
            else:
                logger.warning("Database manager not available - cache service will operate in fallback mode")
                self.db_available = False
                return False
                
        except Exception as e:
            logger.warning(f"Database cache service initialization failed: {e}")
            self.db_available = False
            return False
    
    def _generate_cache_key(self, query: str, filters: Dict = None) -> str:
        """Generate a consistent cache key for search parameters"""
        cache_data = {
            'query': query,
            'filters': filters or {}
        }
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    async def get_cached_search_result(self, query: str, filters: Dict = None) -> Optional[Dict]:
        """Retrieve cached search result if available and not expired"""
        if not self.db_available:
            return None
        
        try:
            cache_key = self._generate_cache_key(query, filters)
            
            async with self.db_manager.session_factory() as session:
                result = await session.execute(text("""
                    SELECT value FROM cache_entries 
                    WHERE key = :cache_key AND expires_at > NOW()
                """), {'cache_key': cache_key})
                
                row = result.fetchone()
                if row:
                    logger.info(f"Cache hit for query: {query[:50]}...")
                    return json.loads(row[0])
                
        except Exception as e:
            logger.warning(f"Cache retrieval failed: {e}")
        
        return None
    
    async def cache_search_result(self, query: str, filters: Dict, result_data: Dict, 
                                cache_duration_minutes: int = 30) -> bool:
        """Cache search result with expiration"""
        if not self.db_available:
            return False
        
        try:
            cache_key = self._generate_cache_key(query, filters)
            expires_at = datetime.now() + timedelta(minutes=cache_duration_minutes)
            
            async with self.db_manager.session_factory() as session:
                await session.execute(text("""
                    INSERT INTO cache_entries (key, value, expires_at)
                    VALUES (:cache_key, :value, :expires_at)
                    ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        expires_at = EXCLUDED.expires_at
                """), {
                    'cache_key': cache_key,
                    'value': json.dumps(result_data),
                    'expires_at': expires_at
                })
                
                await session.commit()
                logger.info(f"Cached search result for: {query[:50]}...")
                return True
                
        except Exception as e:
            logger.warning(f"Cache storage failed: {e}")
            return False
    
    async def track_search_analytics(self, query: str, filters: Dict, result_count: int, 
                                   execution_time_ms: float) -> bool:
        """Track search analytics for academic research insights"""
        if not self.db_available:
            return False
        
        try:
            query_params = {
                'query': query,
                'filters': filters or {}
            }
            query_hash = hashlib.md5(json.dumps(query_params, sort_keys=True).encode()).hexdigest()
            
            async with self.db_manager.session_factory() as session:
                await session.execute(text("""
                    INSERT INTO search_history (query_hash, query_params, result_count, execution_time_ms)
                    VALUES (:query_hash, :query_params, :result_count, :execution_time_ms)
                """), {
                    'query_hash': query_hash,
                    'query_params': json.dumps(query_params),
                    'result_count': result_count,
                    'execution_time_ms': int(execution_time_ms)
                })
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.warning(f"Analytics tracking failed: {e}")
            return False
    
    async def cache_export_result(self, export_format: str, content: str, 
                                metadata: Dict, cache_duration_hours: int = 24) -> Optional[str]:
        """Cache export result and return cache key"""
        if not self.db_available:
            return None
        
        try:
            cache_key = f"export_{export_format}_{hashlib.md5(content.encode()).hexdigest()[:16]}"
            expires_at = datetime.now() + timedelta(hours=cache_duration_hours)
            
            async with self.db_manager.session_factory() as session:
                await session.execute(text("""
                    INSERT INTO export_cache (cache_key, format, content, metadata, expires_at)
                    VALUES (:cache_key, :format, :content, :metadata, :expires_at)
                    ON CONFLICT (cache_key) DO UPDATE SET
                        content = EXCLUDED.content,
                        metadata = EXCLUDED.metadata,
                        expires_at = EXCLUDED.expires_at
                """), {
                    'cache_key': cache_key,
                    'format': export_format,
                    'content': content,
                    'metadata': json.dumps(metadata),
                    'expires_at': expires_at
                })
                
                await session.commit()
                return cache_key
                
        except Exception as e:
            logger.warning(f"Export cache storage failed: {e}")
            return None
    
    async def get_cached_export(self, cache_key: str) -> Optional[Dict]:
        """Retrieve cached export result"""
        if not self.db_available:
            return None
        
        try:
            async with self.db_manager.session_factory() as session:
                result = await session.execute(text("""
                    SELECT format, content, metadata FROM export_cache 
                    WHERE cache_key = :cache_key AND expires_at > NOW()
                """), {'cache_key': cache_key})
                
                row = result.fetchone()
                if row:
                    return {
                        'format': row[0],
                        'content': row[1],
                        'metadata': json.loads(row[2]) if row[2] else {}
                    }
                
        except Exception as e:
            logger.warning(f"Export cache retrieval failed: {e}")
        
        return None
    
    async def get_analytics_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get search analytics summary for academic insights"""
        if not self.db_available:
            return {
                'database_available': False,
                'message': 'Analytics unavailable - database not connected'
            }
        
        try:
            async with self.db_manager.session_factory() as session:
                # Get search statistics
                search_stats = await session.execute(text("""
                    SELECT 
                        COUNT(*) as total_searches,
                        AVG(result_count) as avg_results,
                        AVG(execution_time_ms) as avg_time_ms,
                        COUNT(DISTINCT query_hash) as unique_queries
                    FROM search_history 
                    WHERE created_at > NOW() - INTERVAL :hours HOUR
                """), {'hours': hours})
                
                # Get popular queries
                popular_queries = await session.execute(text("""
                    SELECT 
                        query_params::json->>'query' as query,
                        COUNT(*) as frequency
                    FROM search_history 
                    WHERE created_at > NOW() - INTERVAL :hours HOUR
                        AND query_params::json->>'query' IS NOT NULL
                    GROUP BY query_params::json->>'query' 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 10
                """), {'hours': hours})
                
                # Get cache statistics
                cache_stats = await self.db_manager.get_cache_stats()
                
                search_row = search_stats.fetchone()
                popular_list = popular_queries.fetchall()
                
                return {
                    'database_available': True,
                    'time_period_hours': hours,
                    'search_analytics': {
                        'total_searches': search_row[0] if search_row else 0,
                        'avg_results_per_search': float(search_row[1]) if search_row and search_row[1] else 0,
                        'avg_response_time_ms': float(search_row[2]) if search_row and search_row[2] else 0,
                        'unique_queries': search_row[3] if search_row else 0
                    },
                    'popular_queries': [
                        {'query': row[0], 'frequency': row[1]} 
                        for row in popular_list
                    ],
                    'cache_statistics': cache_stats,
                    'generated_at': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Analytics summary failed: {e}")
            return {
                'database_available': True,
                'error': str(e),
                'message': 'Analytics temporarily unavailable'
            }
    
    async def cleanup_expired_entries(self) -> Dict[str, int]:
        """Clean up expired cache entries and return counts"""
        if not self.db_available:
            return {'cache_entries': 0, 'export_cache': 0}
        
        try:
            return {
                'entries_cleaned': await self.db_manager.cleanup_expired_cache()
            }
        except Exception as e:
            logger.warning(f"Cache cleanup failed: {e}")
            return {'cache_entries': 0, 'export_cache': 0, 'error': str(e)}
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get database cache service health status"""
        health_status = {
            'service_name': 'DatabaseCacheService',
            'database_available': self.db_available,
            'initialization_attempted': self.initialization_attempted
        }
        
        if self.db_available and self.db_manager:
            try:
                connection_test = await self.db_manager.test_connection()
                cache_stats = await self.db_manager.get_cache_stats()
                
                health_status.update({
                    'connection_healthy': connection_test,
                    'cache_statistics': cache_stats,
                    'features_available': [
                        'search_result_caching',
                        'export_caching', 
                        'analytics_tracking',
                        'performance_monitoring'
                    ]
                })
            except Exception as e:
                health_status.update({
                    'connection_healthy': False,
                    'error': str(e)
                })
        else:
            health_status.update({
                'fallback_mode': True,
                'features_available': ['basic_search_only']
            })
        
        return health_status


# Global service instance
_database_cache_service: Optional[DatabaseCacheService] = None


async def get_database_cache_service() -> DatabaseCacheService:
    """Get or create global database cache service instance"""
    global _database_cache_service
    if _database_cache_service is None:
        _database_cache_service = DatabaseCacheService()
        await _database_cache_service.initialize()
    return _database_cache_service