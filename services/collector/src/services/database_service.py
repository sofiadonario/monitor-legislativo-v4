"""
Database service for collection operations
Handles all database interactions for the collector
"""

import logging
import os
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import asyncpg
from asyncpg.pool import Pool

# Add parent directory to path for core imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))))

try:
    from core.database.two_tier_manager import TwoTierDatabaseManager, get_two_tier_manager
except ImportError:
    # Fallback for when core is not available
    logger = logging.getLogger(__name__)
    logger.warning("Core module not available, using standalone database operations")
    TwoTierDatabaseManager = None
    get_two_tier_manager = None

logger = logging.getLogger(__name__)


class CollectionDatabaseService:
    """Database service for collection operations"""
    
    def __init__(self):
        self.db_manager: Optional[TwoTierDatabaseManager] = None
        self.pool: Optional[Pool] = None
        self.standalone_mode = False
    
    async def initialize(self):
        """Initialize database connection"""
        try:
            if get_two_tier_manager:
                self.db_manager = await get_two_tier_manager()
            else:
                self.standalone_mode = True
            
            # Create connection pool for high-performance operations
            db_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@postgres:5432/legislativo')
            
            # Convert to asyncpg format if needed
            if db_url.startswith('postgresql://'):
                db_url = db_url.replace('postgresql://', 'postgresql://', 1)
            
            self.pool = await asyncpg.create_pool(
                db_url, 
                min_size=5, 
                max_size=20,
                command_timeout=60,
                server_settings={
                    'application_name': 'collector_service',
                }
            )
            
            logger.info("Collection database service initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize database service: {e}")
            raise
    
    async def close(self):
        """Close database connections"""
        if self.pool:
            await self.pool.close()
    
    async def get_terms_due_for_collection(self) -> List[Dict[str, Any]]:
        """Get search terms that are due for collection"""
        if self.db_manager and not self.standalone_mode:
            return await self.db_manager.get_terms_due_for_collection()
        
        # Standalone implementation
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, term, category, cql_query, collection_frequency, priority
                    FROM search_terms 
                    WHERE active = true 
                    AND (
                        next_collection IS NULL 
                        OR next_collection <= NOW()
                    )
                    ORDER BY priority ASC, next_collection ASC NULLS FIRST
                """)
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to get terms due for collection: {e}")
            return []
    
    async def get_search_terms(self, search_term_ids: List[int]) -> List[Dict[str, Any]]:
        """Get specific search terms by IDs"""
        if self.db_manager and not self.standalone_mode:
            return await self.db_manager.get_search_terms(search_term_ids)
        
        # Standalone implementation
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT id, term, category, cql_query, collection_frequency, priority
                    FROM search_terms 
                    WHERE id = ANY($1) AND active = true
                """, search_term_ids)
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to get search terms: {e}")
            return []
    
    async def store_collected_documents(self, documents: List[Dict[str, Any]], 
                                      search_term_id: int, source_api: str) -> Dict[str, int]:
        """Store collected documents with deduplication"""
        if self.db_manager and not self.standalone_mode:
            return await self.db_manager.store_collected_documents(
                documents, search_term_id, source_api
            )
        
        # Standalone implementation with high performance
        return await self.batch_insert_documents(documents, search_term_id, source_api)
    
    async def log_collection_execution(self, log_data: Dict[str, Any]) -> int:
        """Log collection execution details"""
        if self.db_manager and not self.standalone_mode:
            return await self.db_manager.log_collection_execution(log_data)
        
        # Standalone implementation
        try:
            async with self.pool.acquire() as conn:
                log_id = await conn.fetchval("""
                    INSERT INTO collection_logs (
                        search_term_id, collection_type, status, records_collected,
                        records_new, records_updated, records_skipped,
                        execution_time_ms, error_message, error_type,
                        started_at, completed_at, api_response_time_ms
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
                    ) RETURNING id
                """, 
                log_data.get('search_term_id'),
                log_data.get('collection_type'),
                log_data.get('status'),
                log_data.get('records_collected'),
                log_data.get('records_new'),
                log_data.get('records_updated'),
                log_data.get('records_skipped'),
                log_data.get('execution_time_ms'),
                log_data.get('error_message'),
                log_data.get('error_type'),
                log_data.get('started_at'),
                log_data.get('completed_at'),
                log_data.get('api_response_time_ms')
                )
                
                return log_id
                
        except Exception as e:
            logger.error(f"Failed to log collection execution: {e}")
            return -1
    
    async def update_next_collection_time(self, search_term_id: int) -> bool:
        """Update next collection time for a search term"""
        if self.db_manager and not self.standalone_mode:
            return await self.db_manager.update_next_collection_time(search_term_id)
        
        # Standalone implementation
        try:
            async with self.pool.acquire() as conn:
                # Get current search term
                row = await conn.fetchrow("""
                    SELECT collection_frequency FROM search_terms WHERE id = $1
                """, search_term_id)
                
                if not row:
                    return False
                
                frequency = row['collection_frequency']
                
                # Calculate next collection time
                now = datetime.now()
                if frequency == 'daily':
                    next_collection = now + datetime.timedelta(days=1)
                elif frequency == 'weekly':
                    next_collection = now + datetime.timedelta(weeks=1)
                elif frequency == 'monthly':
                    next_collection = now + datetime.timedelta(days=30)
                else:  # custom or unknown
                    next_collection = now + datetime.timedelta(days=7)  # default to weekly
                
                await conn.execute("""
                    UPDATE search_terms 
                    SET next_collection = $1, updated_at = NOW()
                    WHERE id = $2
                """, next_collection, search_term_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to update next collection time: {e}")
            return False
    
    async def batch_insert_documents(self, documents: List[Dict[str, Any]], 
                                   search_term_id: int, source_api: str) -> Dict[str, int]:
        """High-performance batch insert with COPY"""
        stats = {'new': 0, 'updated': 0, 'skipped': 0}
        
        if not self.pool or not documents:
            return stats
        
        try:
            async with self.pool.acquire() as conn:
                # Create temporary table
                await conn.execute("""
                    CREATE TEMP TABLE temp_documents (
                        urn VARCHAR(500),
                        document_type VARCHAR(100),
                        title TEXT,
                        content TEXT,
                        metadata JSONB,
                        search_term_id INTEGER,
                        source_api VARCHAR(50),
                        document_date DATE,
                        content_hash VARCHAR(64)
                    )
                """)
                
                # Prepare data for COPY
                records = []
                for doc in documents:
                    # Parse document_date if it's a string
                    document_date = doc.get('document_date')
                    if isinstance(document_date, str) and document_date:
                        try:
                            # Try to parse the date
                            parsed_date = datetime.strptime(document_date, '%Y-%m-%d').date()
                        except ValueError:
                            try:
                                # Try alternative format
                                parsed_date = datetime.strptime(document_date[:10], '%Y-%m-%d').date()
                            except ValueError:
                                parsed_date = None
                    else:
                        parsed_date = document_date
                    
                    records.append((
                        doc['urn'],
                        doc.get('document_type', 'Unknown'),
                        doc['title'],
                        doc.get('content'),
                        json.dumps(doc.get('metadata', {})),
                        search_term_id,
                        source_api,
                        parsed_date,
                        doc.get('content_hash')
                    ))
                
                # Batch insert using COPY
                await conn.copy_records_to_table(
                    'temp_documents',
                    records=records,
                    columns=['urn', 'document_type', 'title', 'content', 'metadata',
                            'search_term_id', 'source_api', 'document_date', 'content_hash']
                )
                
                # Merge with main table
                rows = await conn.fetch("""
                    WITH inserted AS (
                        INSERT INTO legislative_documents 
                        (urn, document_type, title, content, metadata, 
                         search_term_id, source_api, document_date)
                        SELECT urn, document_type, title, content, metadata,
                               search_term_id, source_api, document_date
                        FROM temp_documents
                        ON CONFLICT (urn) DO UPDATE SET
                            content = EXCLUDED.content,
                            metadata = EXCLUDED.metadata,
                            updated_at = NOW()
                        RETURNING urn, (xmax = 0) as is_new
                    )
                    SELECT 
                        COUNT(*) FILTER (WHERE is_new) as new_count,
                        COUNT(*) FILTER (WHERE NOT is_new) as updated_count
                    FROM inserted
                """)
                
                if rows:
                    row = rows[0]
                    stats['new'] = row['new_count'] or 0
                    stats['updated'] = row['updated_count'] or 0
                
                # Drop temporary table
                await conn.execute("DROP TABLE temp_documents")
                
                logger.info(f"Batch inserted - New: {stats['new']}, Updated: {stats['updated']}")
                
        except Exception as e:
            logger.error(f"Batch insert failed: {e}")
            stats['skipped'] = len(documents)
            # Log the specific error for debugging
            logger.error(f"Error details: {str(e)}")
            if hasattr(e, 'args') and e.args:
                logger.error(f"Error args: {e.args}")
        
        return stats
    
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        try:
            async with self.pool.acquire() as conn:
                # Get document counts by source
                source_stats = await conn.fetch("""
                    SELECT 
                        source_api,
                        COUNT(*) as document_count,
                        COUNT(*) FILTER (WHERE collected_at >= NOW() - INTERVAL '24 hours') as last_24h,
                        COUNT(*) FILTER (WHERE collected_at >= NOW() - INTERVAL '7 days') as last_7d,
                        MAX(collected_at) as last_collection
                    FROM legislative_documents
                    GROUP BY source_api
                    ORDER BY document_count DESC
                """)
                
                # Get search term performance
                term_stats = await conn.fetch("""
                    SELECT 
                        st.term,
                        st.category,
                        COUNT(ld.*) as document_count,
                        COUNT(cl.*) as collection_runs,
                        AVG(cl.execution_time_ms) as avg_execution_time,
                        MAX(cl.completed_at) as last_run
                    FROM search_terms st
                    LEFT JOIN legislative_documents ld ON st.id = ld.search_term_id
                    LEFT JOIN collection_logs cl ON st.id = cl.search_term_id
                    WHERE st.active = true
                    GROUP BY st.id, st.term, st.category
                    ORDER BY document_count DESC
                    LIMIT 10
                """)
                
                # Get recent collection logs
                recent_logs = await conn.fetch("""
                    SELECT 
                        cl.*,
                        st.term,
                        st.category
                    FROM collection_logs cl
                    JOIN search_terms st ON cl.search_term_id = st.id
                    ORDER BY cl.started_at DESC
                    LIMIT 20
                """)
                
                return {
                    'source_stats': [dict(row) for row in source_stats],
                    'term_stats': [dict(row) for row in term_stats],
                    'recent_logs': [dict(row) for row in recent_logs]
                }
                
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        try:
            async with self.pool.acquire() as conn:
                # Test basic connectivity
                result = await conn.fetchval("SELECT 1")
                
                # Check table existence
                tables = await conn.fetch("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    AND table_name IN ('search_terms', 'legislative_documents', 'collection_logs')
                """)
                
                # Get connection pool stats
                pool_stats = {
                    'size': self.pool.get_size(),
                    'min_size': self.pool.get_min_size(),
                    'max_size': self.pool.get_max_size(),
                    'idle_size': self.pool.get_idle_size()
                }
                
                return {
                    'status': 'healthy',
                    'connectivity': result == 1,
                    'tables_found': len(tables),
                    'expected_tables': 3,
                    'pool_stats': pool_stats,
                    'standalone_mode': self.standalone_mode
                }
                
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'standalone_mode': self.standalone_mode
            }