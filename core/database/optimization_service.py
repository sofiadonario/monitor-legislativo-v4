"""
Database Optimization Service
Advanced database performance monitoring and optimization
"""

import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from contextlib import contextmanager
from sqlalchemy import create_engine, text, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
import threading
import statistics

from .models import (
    Base, Proposition, SearchLog, PerformanceMetric, 
    DatabaseOptimizer, OptimizedQueries
)

logger = logging.getLogger(__name__)

@dataclass
class QueryPerformance:
    """Query performance metrics"""
    query: str
    execution_time: float
    row_count: int
    timestamp: datetime
    cache_hit: bool = False
    
@dataclass
class DatabaseStats:
    """Database statistics"""
    total_propositions: int
    total_searches: int
    avg_search_time: float
    slow_queries_count: int
    cache_hit_rate: float
    index_usage: Dict[str, Any]
    connection_pool_stats: Dict[str, Any]

class QueryProfiler:
    """Profiles database queries for optimization"""
    
    def __init__(self):
        self.query_log: List[QueryPerformance] = []
        self._lock = threading.Lock()
        self._enabled = True
    
    def log_query(self, query: str, execution_time: float, row_count: int = 0, cache_hit: bool = False):
        """Log query performance"""
        if not self._enabled:
            return
            
        with self._lock:
            self.query_log.append(QueryPerformance(
                query=query[:500],  # Truncate long queries
                execution_time=execution_time,
                row_count=row_count,
                timestamp=datetime.utcnow(),
                cache_hit=cache_hit
            ))
            
            # Keep only recent queries (last 1000)
            if len(self.query_log) > 1000:
                self.query_log = self.query_log[-1000:]
    
    def get_slow_queries(self, threshold_ms: float = 100.0) -> List[QueryPerformance]:
        """Get queries slower than threshold"""
        with self._lock:
            return [q for q in self.query_log if q.execution_time > threshold_ms]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get profiling statistics"""
        with self._lock:
            if not self.query_log:
                return {}
            
            execution_times = [q.execution_time for q in self.query_log]
            
            return {
                'total_queries': len(self.query_log),
                'avg_execution_time': statistics.mean(execution_times),
                'median_execution_time': statistics.median(execution_times),
                'max_execution_time': max(execution_times),
                'slow_queries_count': len([q for q in self.query_log if q.execution_time > 100]),
                'cache_hits': len([q for q in self.query_log if q.cache_hit]),
                'cache_hit_rate': len([q for q in self.query_log if q.cache_hit]) / len(self.query_log) * 100
            }
    
    def enable(self):
        """Enable query profiling"""
        self._enabled = True
    
    def disable(self):
        """Disable query profiling"""
        self._enabled = False

class DatabaseOptimizationService:
    """Main database optimization service"""
    
    def __init__(self, database_url: str, pool_size: int = 100, max_overflow: int = 200):
        """
        Initialize database optimization service with production-ready settings
        
        CRITICAL FIXES:
        - Increased pool_size from 20 to 100 (handles 100+ concurrent users)
        - Increased max_overflow from 30 to 200 (prevents connection exhaustion)
        - Disabled pool_pre_ping (eliminates 50-100ms overhead per query)
        - Added connection monitoring and health checks
        """
        self.database_url = database_url
        
        # Create optimized engine with production settings
        self.engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=False,  # FIXED: Disabled for performance (was causing 50-100ms overhead)
            pool_recycle=3600,    # Recycle connections every hour
            pool_timeout=30,      # Max wait time for connection from pool
            echo=False,           # Set to True for query debugging
            connect_args={
                "connect_timeout": 10,  # Connection timeout
                "application_name": "MonitorLegislativo_v4"  # For monitoring
            }
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Initialize profiler
        self.profiler = QueryProfiler()
        
        # Setup query event listener
        self._setup_query_profiling()
        
        # Statistics cache
        self._stats_cache = {}
        self._stats_cache_time = None
        self._stats_cache_ttl = 300  # 5 minutes
        
        # Connection pool monitoring (ADDED: Track connection leaks)
        self._connection_stats = {
            'total_checkouts': 0,
            'total_checkins': 0,
            'current_checked_out': 0,
            'pool_exhausted_events': 0
        }
        
        # Setup connection pool event listeners
        self._setup_connection_monitoring()
    
    def _setup_connection_monitoring(self):
        """Setup connection pool monitoring to detect leaks"""
        from sqlalchemy import event
        
        @event.listens_for(self.engine, "checkout")
        def checkout_event(dbapi_conn, connection_record, connection_proxy):
            """Track connection checkouts"""
            self._connection_stats['total_checkouts'] += 1
            self._connection_stats['current_checked_out'] += 1
            
            # Log warning if pool is getting exhausted
            pool = self.engine.pool
            if pool.checkedout() > (pool.size() * 0.8):  # 80% threshold
                logger.warning(
                    f"Connection pool {pool.checkedout()}/{pool.size()} "
                    f"(80%+ utilized - potential leak detection)"
                )
        
        @event.listens_for(self.engine, "checkin")
        def checkin_event(dbapi_conn, connection_record):
            """Track connection checkins"""
            self._connection_stats['total_checkins'] += 1
            self._connection_stats['current_checked_out'] -= 1
            
        @event.listens_for(self.engine, "invalidate")
        def invalidate_event(dbapi_conn, connection_record, exception):
            """Track connection invalidations"""
            logger.warning(f"Database connection invalidated: {exception}")
            
    def _setup_query_profiling(self):
        """Setup SQLAlchemy event listeners for query profiling"""
        
        @event.listens_for(self.engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.time()
        
        @event.listens_for(self.engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            total_time = (time.time() - context._query_start_time) * 1000  # Convert to ms
            
            # Log significant queries
            if total_time > 10:  # Only log queries taking more than 10ms
                self.profiler.log_query(
                    query=statement,
                    execution_time=total_time,
                    row_count=cursor.rowcount if hasattr(cursor, 'rowcount') else 0
                )
    
    @contextmanager
    def get_session(self) -> Session:
        """Get database session with automatic cleanup"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def create_tables(self):
        """Create all database tables"""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created successfully")
    
    def drop_tables(self):
        """Drop all database tables (use with caution!)"""
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("All database tables dropped")
    
    def create_indexes(self):
        """Create additional performance indexes"""
        additional_indexes = [
            # Full-text search indexes (PostgreSQL specific)
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_propositions_fulltext ON propositions USING gin(to_tsvector('portuguese', title || ' ' || COALESCE(summary, '')))",
            
            # Partial indexes for active data
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_propositions_active ON propositions (publication_date DESC) WHERE status = 'ACTIVE'",
            
            # Expression indexes for common searches
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_authors_name_lower ON authors (lower(name))",
            
            # Covering indexes for frequent queries
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_propositions_search_covering ON propositions (source_id, year, type) INCLUDE (title, status, publication_date)",
        ]
        
        with self.get_session() as session:
            for index_sql in additional_indexes:
                try:
                    session.execute(text(index_sql))
                    logger.info(f"Created index: {index_sql[:50]}...")
                except Exception as e:
                    logger.warning(f"Failed to create index: {e}")
    
    def analyze_database(self) -> DatabaseStats:
        """Analyze database performance and statistics"""
        
        # Check cache first
        now = datetime.utcnow()
        if (self._stats_cache_time and 
            (now - self._stats_cache_time).seconds < self._stats_cache_ttl):
            return self._stats_cache.get('stats')
        
        with self.get_session() as session:
            optimizer = DatabaseOptimizer(session)
            
            # Basic counts
            total_propositions = session.query(Proposition).count()
            total_searches = session.query(SearchLog).count()
            
            # Performance metrics
            search_analytics = OptimizedQueries.get_search_analytics(session, days=7)
            slow_queries = optimizer.analyze_slow_queries(limit=10)
            
            # Profiler stats
            profiler_stats = self.profiler.get_stats()
            
            # Connection pool stats
            pool_stats = {
                'pool_size': self.engine.pool.size(),
                'checked_in': self.engine.pool.checkedin(),
                'checked_out': self.engine.pool.checkedout(),
                'overflow': self.engine.pool.overflow(),
                'invalid': self.engine.pool.invalid()
            }
            
            stats = DatabaseStats(
                total_propositions=total_propositions,
                total_searches=total_searches,
                avg_search_time=search_analytics.get('avg_search_time_ms', 0),
                slow_queries_count=len(slow_queries),
                cache_hit_rate=profiler_stats.get('cache_hit_rate', 0),
                index_usage=optimizer.get_index_usage_stats(),
                connection_pool_stats=pool_stats
            )
            
            # Cache results
            self._stats_cache = {'stats': stats}
            self._stats_cache_time = now
            
            return stats
    
    def optimize_search_performance(self):
        """Run optimization tasks for search performance"""
        with self.get_session() as session:
            optimizer = DatabaseOptimizer(session)
            
            logger.info("Starting search performance optimization...")
            
            # Update search vectors
            optimizer.optimize_search_vectors()
            
            # Update popularity scores
            optimizer.update_popularity_scores()
            
            # Clean up old cache entries
            optimizer.cleanup_expired_cache()
            
            logger.info("Search performance optimization completed")
    
    def vacuum_analyze(self):
        """Run database maintenance (PostgreSQL specific)"""
        try:
            with self.engine.connect() as conn:
                # For PostgreSQL
                conn.execute(text("VACUUM ANALYZE"))
                logger.info("Database vacuum and analyze completed")
        except Exception as e:
            logger.warning(f"Vacuum analyze failed (may not be supported): {e}")
    
    def get_query_execution_plan(self, query: str, parameters: Dict = None) -> str:
        """Get query execution plan for optimization"""
        try:
            with self.get_session() as session:
                explain_query = f"EXPLAIN ANALYZE {query}"
                result = session.execute(text(explain_query), parameters or {})
                return '\n'.join([str(row) for row in result.fetchall()])
        except Exception as e:
            logger.error(f"Failed to get execution plan: {e}")
            return f"Error: {e}"
    
    def monitor_slow_queries(self, threshold_ms: float = 1000.0) -> List[Dict[str, Any]]:
        """Monitor and return slow queries"""
        slow_queries = self.profiler.get_slow_queries(threshold_ms)
        
        # Group by similar queries
        query_groups = {}
        for query in slow_queries:
            # Normalize query for grouping (remove parameters)
            normalized = self._normalize_query(query.query)
            
            if normalized not in query_groups:
                query_groups[normalized] = {
                    'query': normalized,
                    'count': 0,
                    'total_time': 0,
                    'max_time': 0,
                    'avg_time': 0,
                    'last_seen': None
                }
            
            group = query_groups[normalized]
            group['count'] += 1
            group['total_time'] += query.execution_time
            group['max_time'] = max(group['max_time'], query.execution_time)
            group['avg_time'] = group['total_time'] / group['count']
            group['last_seen'] = query.timestamp
        
        # Sort by total impact (count * avg_time)
        return sorted(
            query_groups.values(),
            key=lambda x: x['count'] * x['avg_time'],
            reverse=True
        )
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query for grouping similar queries"""
        import re
        
        # Remove parameter values
        normalized = re.sub(r"'[^']*'", "'?'", query)
        normalized = re.sub(r'\b\d+\b', '?', normalized)
        
        # Remove extra whitespace
        normalized = ' '.join(normalized.split())
        
        return normalized
    
    def optimize_proposition_search(self, query: str, filters: Dict[str, Any] = None,
                                  limit: int = 25, offset: int = 0) -> Tuple[List[Proposition], float]:
        """Optimized proposition search with performance tracking"""
        start_time = time.time()
        
        with self.get_session() as session:
            # Use optimized query
            propositions = OptimizedQueries.search_propositions(
                session, query, filters, limit, offset
            )
            
            search_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Log search performance
            self._log_search_performance(
                session=session,
                query=query,
                filters=filters,
                result_count=len(propositions),
                search_time_ms=search_time
            )
            
            return propositions, search_time
    
    def _log_search_performance(self, session: Session, query: str, filters: Dict[str, Any],
                              result_count: int, search_time_ms: float):
        """Log search performance to database"""
        try:
            search_log = SearchLog(
                query=query,
                normalized_query=query.lower().strip() if query else None,
                filters=filters,
                total_results=result_count,
                search_time_ms=int(search_time_ms),
                source_used='database',
                timestamp=datetime.utcnow()
            )
            
            session.add(search_log)
            session.commit()
            
        except Exception as e:
            logger.error(f"Failed to log search performance: {e}")
            session.rollback()
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate optimization recommendations based on analysis"""
        recommendations = []
        
        # Analyze current performance
        stats = self.analyze_database()
        slow_queries = self.monitor_slow_queries(threshold_ms=500)
        
        # Check average search time
        if stats.avg_search_time > 500:  # 500ms threshold
            recommendations.append({
                'type': 'performance',
                'priority': 'high',
                'title': 'Slow Search Performance',
                'description': f'Average search time is {stats.avg_search_time:.1f}ms',
                'action': 'Consider adding more indexes or enabling query caching'
            })
        
        # Check slow queries
        if len(slow_queries) > 5:
            recommendations.append({
                'type': 'queries',
                'priority': 'medium',
                'title': 'Multiple Slow Queries Detected',
                'description': f'Found {len(slow_queries)} slow query patterns',
                'action': 'Review and optimize slow queries or add missing indexes'
            })
        
        # Check connection pool
        pool_usage = (stats.connection_pool_stats['checked_out'] / 
                     stats.connection_pool_stats['pool_size'] * 100)
        
        if pool_usage > 80:
            recommendations.append({
                'type': 'infrastructure',
                'priority': 'medium',
                'title': 'High Connection Pool Usage',
                'description': f'Connection pool is {pool_usage:.1f}% utilized',
                'action': 'Consider increasing pool size or optimizing connection usage'
            })
        
        # Check cache hit rate
        if stats.cache_hit_rate < 70:
            recommendations.append({
                'type': 'caching',
                'priority': 'low',
                'title': 'Low Cache Hit Rate',
                'description': f'Cache hit rate is {stats.cache_hit_rate:.1f}%',
                'action': 'Review caching strategy and increase cache TTL for stable data'
            })
        
        return recommendations
    
    def health_check(self) -> Dict[str, Any]:
        """Comprehensive database health check"""
        start_time = time.time()
        
        try:
            with self.get_session() as session:
                # Test basic connectivity
                session.execute(text("SELECT 1"))
                
                # Get basic stats
                stats = self.analyze_database()
                
                health_time = (time.time() - start_time) * 1000
                
                return {
                    'status': 'healthy',
                    'response_time_ms': health_time,
                    'total_propositions': stats.total_propositions,
                    'total_searches': stats.total_searches,
                    'avg_search_time_ms': stats.avg_search_time,
                    'connection_pool': stats.connection_pool_stats,
                    'recommendations_count': len(self.get_optimization_recommendations()),
                    'last_check': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': (time.time() - start_time) * 1000,
                'last_check': datetime.utcnow().isoformat()
            }

# Global database service instance
_db_service: Optional[DatabaseOptimizationService] = None

def get_database_service() -> DatabaseOptimizationService:
    """Get global database service instance"""
    global _db_service
    if _db_service is None:
        raise RuntimeError("Database service not initialized. Call init_database_service() first.")
    return _db_service

def init_database_service(database_url: str, **kwargs) -> DatabaseOptimizationService:
    """Initialize global database service"""
    global _db_service
    _db_service = DatabaseOptimizationService(database_url, **kwargs)
    return _db_service