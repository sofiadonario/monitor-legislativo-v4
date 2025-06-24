"""
Two-Tier Database Manager for Monitor Legislativo v4
Extends existing Supabase configuration with collection and analytics capabilities
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
from sqlalchemy import text, func
from sqlalchemy.ext.asyncio import AsyncSession
from .supabase_config import DatabaseManager as BaseManager, get_database_manager

logger = logging.getLogger(__name__)


class TwoTierDatabaseManager(BaseManager):
    """Extended database manager for two-tier architecture"""
    
    async def create_search_term(self, term_data: Dict[str, Any]) -> int:
        """Create a new search term for automated collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    INSERT INTO search_terms (
                        term, category, cql_query, description, 
                        collection_frequency, priority, created_by
                    ) VALUES (
                        :term, :category, :cql_query, :description,
                        :frequency, :priority, :created_by
                    ) RETURNING id
                """), term_data)
                
                search_term_id = result.scalar()
                await session.commit()
                
                logger.info(f"Created search term {search_term_id}: {term_data['term']}")
                return search_term_id
                
        except Exception as e:
            logger.error(f"Failed to create search term: {e}")
            raise
    
    async def get_active_search_terms(self) -> List[Dict[str, Any]]:
        """Get all active search terms for collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term, category, cql_query, collection_frequency, priority,
                           next_collection
                    FROM search_terms 
                    WHERE active = true 
                    ORDER BY priority ASC, next_collection ASC NULLS FIRST
                """))
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get active search terms: {e}")
            return []
    
    async def get_all_search_terms(self) -> List[Dict[str, Any]]:
        """Get all search terms regardless of status"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term, category, cql_query, description, active,
                           collection_frequency, priority, next_collection,
                           created_at, updated_at, created_by
                    FROM search_terms 
                    ORDER BY created_at DESC
                """))
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get all search terms: {e}")
            return []
    
    async def get_search_terms(self, search_term_ids: List[int]) -> List[Dict[str, Any]]:
        """Get specific search terms by IDs"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term, category, cql_query, collection_frequency, priority
                    FROM search_terms 
                    WHERE id = ANY(:ids) AND active = true
                """), {'ids': search_term_ids})
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get search terms: {e}")
            return []
    
    async def get_terms_due_for_collection(self) -> List[Dict[str, Any]]:
        """Get search terms that are due for collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term, category, cql_query, collection_frequency, priority
                    FROM search_terms 
                    WHERE active = true 
                    AND (
                        next_collection IS NULL 
                        OR next_collection <= NOW()
                    )
                    ORDER BY priority ASC, next_collection ASC NULLS FIRST
                """))
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get terms due for collection: {e}")
            return []
    
    async def store_collected_documents(self, documents: List[Dict[str, Any]], 
                                      search_term_id: int, source_api: str) -> Dict[str, int]:
        """Store collected documents with deduplication"""
        stats = {'new': 0, 'updated': 0, 'skipped': 0}
        
        try:
            async with self.session_factory() as session:
                for doc in documents:
                    result = await session.execute(text("""
                        INSERT INTO legislative_documents (
                            urn, document_type, title, content, metadata,
                            search_term_id, source_api, document_date
                        ) VALUES (
                            :urn, :document_type, :title, :content, :metadata,
                            :search_term_id, :source_api, :document_date
                        )
                        ON CONFLICT (urn) DO UPDATE SET
                            content = EXCLUDED.content,
                            metadata = EXCLUDED.metadata,
                            updated_at = NOW()
                        RETURNING (xmax = 0) as is_new
                    """), {
                        'urn': doc['urn'],
                        'document_type': doc.get('document_type', 'Unknown'),
                        'title': doc['title'],
                        'content': doc.get('content'),
                        'metadata': json.dumps(doc.get('metadata', {})),
                        'search_term_id': search_term_id,
                        'source_api': source_api,
                        'document_date': doc.get('document_date')
                    })
                    
                    is_new = result.scalar()
                    if is_new:
                        stats['new'] += 1
                    else:
                        stats['updated'] += 1
                
                await session.commit()
                logger.info(f"Stored documents - New: {stats['new']}, Updated: {stats['updated']}")
                
        except Exception as e:
            logger.error(f"Failed to store documents: {e}")
            stats['skipped'] = len(documents)
            
        return stats
    
    async def log_collection_execution(self, log_data: Dict[str, Any]) -> int:
        """Log collection execution details"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    INSERT INTO collection_logs (
                        search_term_id, collection_type, status, records_collected,
                        records_new, records_updated, records_skipped,
                        execution_time_ms, error_message, error_type,
                        started_at, completed_at, api_response_time_ms
                    ) VALUES (
                        :search_term_id, :collection_type, :status, :records_collected,
                        :records_new, :records_updated, :records_skipped,
                        :execution_time_ms, :error_message, :error_type,
                        :started_at, :completed_at, :api_response_time_ms
                    ) RETURNING id
                """), log_data)
                
                log_id = result.scalar()
                await session.commit()
                return log_id
                
        except Exception as e:
            logger.error(f"Failed to log collection execution: {e}")
            return -1
    
    async def update_search_term_schedule(self, search_term_id: int, 
                                        next_collection: datetime) -> bool:
        """Update next collection time for a search term"""
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    UPDATE search_terms 
                    SET next_collection = :next_collection, updated_at = NOW()
                    WHERE id = :id
                """), {
                    'id': search_term_id,
                    'next_collection': next_collection
                })
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update search term schedule: {e}")
            return False
    
    async def update_next_collection_time(self, search_term_id: int) -> bool:
        """Calculate and update next collection time based on frequency"""
        try:
            async with self.session_factory() as session:
                # Get current search term
                result = await session.execute(text("""
                    SELECT collection_frequency FROM search_terms WHERE id = :id
                """), {'id': search_term_id})
                
                row = result.fetchone()
                if not row:
                    return False
                
                frequency = row[0]
                
                # Calculate next collection time
                now = datetime.now()
                if frequency == 'daily':
                    next_collection = now + timedelta(days=1)
                elif frequency == 'weekly':
                    next_collection = now + timedelta(weeks=1)
                elif frequency == 'monthly':
                    next_collection = now + timedelta(days=30)
                else:  # custom or unknown
                    next_collection = now + timedelta(days=7)  # default to weekly
                
                await session.execute(text("""
                    UPDATE search_terms 
                    SET next_collection = :next_collection, updated_at = NOW()
                    WHERE id = :id
                """), {
                    'id': search_term_id,
                    'next_collection': next_collection
                })
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update next collection time: {e}")
            return False
    
    async def deactivate_search_term(self, search_term_id: int) -> bool:
        """Deactivate a search term"""
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    UPDATE search_terms 
                    SET active = false, updated_at = NOW()
                    WHERE id = :id
                """), {'id': search_term_id})
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to deactivate search term: {e}")
            return False
    
    async def get_recent_collection_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent collection logs"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT cl.*, st.term, st.category
                    FROM collection_logs cl
                    JOIN search_terms st ON cl.search_term_id = st.id
                    ORDER BY cl.started_at DESC
                    LIMIT :limit
                """), {'limit': limit})
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get recent collection logs: {e}")
            return []
    
    async def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get comprehensive dashboard summary"""
        try:
            async with self.session_factory() as session:
                # Refresh materialized view
                await session.execute(text("SELECT refresh_analytics_views()"))
                
                # Get dashboard data
                result = await session.execute(text("""
                    SELECT * FROM dashboard_summary
                """))
                
                summary = dict(result.fetchone()._mapping) if result.rowcount > 0 else {}
                
                # Get collection performance
                perf_result = await session.execute(text("""
                    SELECT * FROM collection_performance 
                    ORDER BY last_collection DESC NULLS LAST
                    LIMIT 10
                """))
                
                summary['collection_performance'] = [
                    dict(row._mapping) for row in perf_result.fetchall()
                ]
                
                # Get recent search patterns
                patterns_result = await session.execute(text("""
                    SELECT * FROM search_patterns
                    LIMIT 20
                """))
                
                summary['search_patterns'] = [
                    dict(row._mapping) for row in patterns_result.fetchall()
                ]
                
                return summary
                
        except Exception as e:
            logger.error(f"Failed to get dashboard summary: {e}")
            return {}
    
    async def track_search_analytics(self, analytics_data: Dict[str, Any]) -> bool:
        """Track search analytics for performance monitoring"""
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    INSERT INTO search_analytics (
                        query_hash, query_params, result_count, execution_time_ms,
                        cache_hit, user_session_id
                    ) VALUES (
                        :query_hash, :query_params, :result_count, :execution_time_ms,
                        :cache_hit, :user_session_id
                    )
                """), analytics_data)
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to track search analytics: {e}")
            return False


# Singleton instance for two-tier operations
_two_tier_manager: Optional[TwoTierDatabaseManager] = None


async def get_two_tier_manager() -> TwoTierDatabaseManager:
    """Get or create two-tier database manager singleton"""
    global _two_tier_manager
    if _two_tier_manager is None:
        # Get base manager first
        base_manager = await get_database_manager()
        
        # Create two-tier manager with same engine and session factory
        _two_tier_manager = TwoTierDatabaseManager()
        _two_tier_manager.engine = base_manager.engine
        _two_tier_manager.session_factory = base_manager.session_factory
        
        # Test connection and initialize schema
        if await _two_tier_manager.test_connection():
            logger.info("Two-tier database manager initialized successfully")
        else:
            logger.warning("Two-tier database manager initialized in fallback mode")
    
    return _two_tier_manager