"""
Private Database Router for Monitor Legislativo
Serves legislative data from private database instead of external APIs
"""

import asyncio
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, func

try:
    from ..services.database_cache_service import get_database_cache_service
    from core.database.supabase_config import get_database_manager
except ImportError:
    # Fallback for testing
    pass

logger = logging.getLogger(__name__)

# Router configuration
router = APIRouter(
    prefix="/api/private",
    tags=["Private Database"],
    responses={
        500: {"description": "Database Error"},
        503: {"description": "Service Temporarily Unavailable"}
    }
)


async def get_private_db_session():
    """Dependency to get private database session"""
    try:
        db_manager = await get_database_manager()
        async with db_manager.session_factory() as session:
            yield session
    except Exception as e:
        logger.error(f"Failed to get database session: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")


@router.get("/search", summary="Search Private Legislative Database")
async def search_private_database(
    query: str = Query(..., description="Search query"),
    document_type: Optional[str] = Query(None, description="Filter by document type"),
    state: Optional[str] = Query(None, description="Filter by state"),
    authority: Optional[str] = Query(None, description="Filter by authority"),
    geographic_level: Optional[str] = Query(None, description="Filter by geographic level"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    limit: int = Query(50, le=500, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Results offset"),
    session: AsyncSession = Depends(get_private_db_session)
):
    """
    Search the private legislative database
    Uses full-text search with PostgreSQL tsvector
    """
    try:
        # Build WHERE conditions
        where_conditions = ["1=1"]  # Base condition
        params = {
            'search_query': query,
            'limit': limit,
            'offset': offset
        }
        
        # Add filters
        if document_type:
            where_conditions.append("document_type ILIKE :doc_type")
            params['doc_type'] = f"%{document_type}%"
        
        if state:
            where_conditions.append("(state_code = :state OR state_name ILIKE :state_name)")
            params['state'] = state.upper()
            params['state_name'] = f"%{state}%"
        
        if authority:
            where_conditions.append("authority ILIKE :authority")
            params['authority'] = f"%{authority}%"
        
        if geographic_level:
            where_conditions.append("geographic_level = :geo_level")
            params['geo_level'] = geographic_level
        
        if start_date:
            where_conditions.append("event_date >= :start_date")
            params['start_date'] = start_date
        
        if end_date:
            where_conditions.append("event_date <= :end_date")
            params['end_date'] = end_date
        
        where_clause = " AND ".join(where_conditions)
        
        # Main search query with full-text search
        search_query = text(f"""
            SELECT 
                id, urn, title, description, document_type, authority, locality,
                event_type, event_date, publication_date, subject_keywords,
                full_text_url, source_url, state_code, state_name, municipality,
                geographic_level, word_count, collected_at,
                ts_rank(search_vector, plainto_tsquery('portuguese', :search_query)) as relevance_score
            FROM private_legislative_documents
            WHERE {where_clause}
            AND search_vector @@ plainto_tsquery('portuguese', :search_query)
            ORDER BY relevance_score DESC, event_date DESC
            LIMIT :limit OFFSET :offset
        """)
        
        # Count query for pagination
        count_query = text(f"""
            SELECT COUNT(*) as total
            FROM private_legislative_documents
            WHERE {where_clause}
            AND search_vector @@ plainto_tsquery('portuguese', :search_query)
        """)
        
        # Execute queries
        result = await session.execute(search_query, params)
        documents = [dict(row._mapping) for row in result.fetchall()]
        
        count_result = await session.execute(count_query, params)
        total_count = count_result.scalar()
        
        # Log search for analytics
        await _log_search_analytics(session, query, {
            'document_type': document_type,
            'state': state,
            'authority': authority,
            'geographic_level': geographic_level,
            'start_date': start_date,
            'end_date': end_date
        }, len(documents))
        
        return {
            "status": "success",
            "query": query,
            "total_found": total_count,
            "results_returned": len(documents),
            "offset": offset,
            "limit": limit,
            "has_more": (offset + limit) < total_count,
            "documents": documents,
            "data_source": "private_database",
            "search_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Private database search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/state-density", summary="Get Document Density by State")
async def get_state_density(
    session: AsyncSession = Depends(get_private_db_session)
):
    """
    Get document density statistics by state for map visualization
    """
    try:
        query = text("""
            SELECT 
                state_code,
                state_name,
                total_documents,
                documents_last_month,
                documents_last_year,
                last_updated,
                CASE 
                    WHEN total_documents > 1000 THEN 'high'
                    WHEN total_documents > 100 THEN 'medium'
                    ELSE 'low'
                END as density_level
            FROM state_document_density
            WHERE state_code IS NOT NULL
            ORDER BY total_documents DESC
        """)
        
        result = await session.execute(query)
        states = [dict(row._mapping) for row in result.fetchall()]
        
        # Calculate overall statistics
        total_docs = sum(state['total_documents'] for state in states)
        states_with_data = len(states)
        
        return {
            "status": "success",
            "total_documents": total_docs,
            "states_with_data": states_with_data,
            "last_updated": max((state['last_updated'] for state in states), default=None),
            "density_data": states,
            "data_source": "private_database"
        }
        
    except Exception as e:
        logger.error(f"State density query failed: {e}")
        raise HTTPException(status_code=500, detail=f"State density query failed: {str(e)}")


@router.get("/analytics", summary="Get Database Analytics")
async def get_database_analytics(
    days: int = Query(30, le=365, description="Days to analyze"),
    session: AsyncSession = Depends(get_private_db_session)
):
    """
    Get analytics about the private database content and usage
    """
    try:
        # Document collection statistics
        doc_stats_query = text("""
            SELECT 
                COUNT(*) as total_documents,
                COUNT(DISTINCT state_code) as states_covered,
                COUNT(DISTINCT document_type) as document_types,
                COUNT(DISTINCT authority) as authorities,
                COUNT(*) FILTER (WHERE collected_at >= NOW() - INTERVAL '%s days') as recent_documents,
                MIN(event_date) as oldest_document_date,
                MAX(event_date) as newest_document_date,
                AVG(word_count) as avg_word_count
            FROM private_legislative_documents
        """)
        
        # Collection execution statistics
        collection_stats_query = text("""
            SELECT 
                COUNT(*) as total_executions,
                COUNT(*) FILTER (WHERE status = 'completed') as successful_executions,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_executions,
                SUM(documents_new) as total_new_documents,
                SUM(documents_updated) as total_updated_documents,
                AVG(execution_time_seconds) as avg_execution_time,
                MAX(started_at) as last_collection
            FROM collection_executions
            WHERE started_at >= NOW() - INTERVAL '%s days'
        """)
        
        # Search analytics
        search_stats_query = text("""
            SELECT 
                COUNT(*) as total_searches,
                COUNT(DISTINCT search_query) as unique_queries,
                AVG(results_count) as avg_results_per_search,
                AVG(execution_time_ms) as avg_search_time_ms
            FROM private_search_analytics
            WHERE search_timestamp >= NOW() - INTERVAL '%s days'
        """)
        
        # Top document types
        top_types_query = text("""
            SELECT 
                document_type,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM private_legislative_documents), 2) as percentage
            FROM private_legislative_documents
            WHERE document_type IS NOT NULL
            GROUP BY document_type
            ORDER BY count DESC
            LIMIT 10
        """)
        
        # Execute all queries
        doc_result = await session.execute(doc_stats_query, (days,))
        doc_stats = dict(doc_result.fetchone()._mapping)
        
        collection_result = await session.execute(collection_stats_query, (days,))
        collection_stats = dict(collection_result.fetchone()._mapping)
        
        search_result = await session.execute(search_stats_query, (days,))
        search_stats = dict(search_result.fetchone()._mapping)
        
        types_result = await session.execute(top_types_query)
        top_types = [dict(row._mapping) for row in types_result.fetchall()]
        
        return {
            "status": "success",
            "analysis_period_days": days,
            "generated_at": datetime.now().isoformat(),
            "document_statistics": doc_stats,
            "collection_statistics": collection_stats,
            "search_statistics": search_stats,
            "top_document_types": top_types,
            "data_source": "private_database"
        }
        
    except Exception as e:
        logger.error(f"Analytics query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analytics query failed: {str(e)}")


@router.get("/recent-collections", summary="Get Recent Collection Activity")
async def get_recent_collections(
    limit: int = Query(20, le=100, description="Number of recent collections"),
    session: AsyncSession = Depends(get_private_db_session)
):
    """
    Get recent collection execution logs
    """
    try:
        query = text("""
            SELECT 
                ce.batch_id,
                ce.execution_type,
                ce.status,
                ce.documents_found,
                ce.documents_new,
                ce.documents_updated,
                ce.execution_time_seconds,
                ce.started_at,
                ce.completed_at,
                ce.error_message,
                stc.term_name,
                stc.description
            FROM collection_executions ce
            JOIN search_terms_config stc ON ce.search_term_id = stc.id
            ORDER BY ce.started_at DESC
            LIMIT :limit
        """)
        
        result = await session.execute(query, {'limit': limit})
        collections = [dict(row._mapping) for row in result.fetchall()]
        
        return {
            "status": "success",
            "recent_collections": collections,
            "data_source": "private_database"
        }
        
    except Exception as e:
        logger.error(f"Recent collections query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Recent collections query failed: {str(e)}")


@router.post("/trigger-collection", summary="Trigger Manual Collection")
async def trigger_manual_collection(
    background_tasks: BackgroundTasks,
    search_term_id: Optional[int] = Query(None, description="Specific search term ID (optional)")
):
    """
    Trigger a manual collection run
    """
    try:
        # Import the collector here to avoid circular imports
        from core.periodic_collection.lexml_collector import LexMLPeriodicCollector
        import os
        
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise HTTPException(status_code=500, detail="Database configuration missing")
        
        # Add background task to run collection
        background_tasks.add_task(
            _run_collection_task, 
            database_url, 
            search_term_id
        )
        
        return {
            "status": "accepted",
            "message": "Collection task started in background",
            "search_term_id": search_term_id,
            "triggered_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to trigger collection: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger collection: {str(e)}")


async def _run_collection_task(database_url: str, search_term_id: Optional[int] = None):
    """Background task to run collection"""
    try:
        from core.periodic_collection.lexml_collector import LexMLPeriodicCollector
        
        async with LexMLPeriodicCollector(database_url) as collector:
            if search_term_id:
                # Collect specific search term
                # This would require implementing a method to get single search term
                logger.info(f"Running collection for search term {search_term_id}")
            else:
                # Run full periodic collection
                result = await collector.run_periodic_collection()
                logger.info(f"Collection completed: {result}")
                
    except Exception as e:
        logger.error(f"Background collection task failed: {e}")


async def _log_search_analytics(session: AsyncSession, query: str, filters: Dict[str, Any], 
                               results_count: int):
    """Log search for analytics"""
    try:
        await session.execute(text("""
            INSERT INTO private_search_analytics 
            (search_query, search_filters, results_count, execution_time_ms, user_session)
            VALUES (:query, :filters, :results_count, 0, 'web_user')
        """), {
            'query': query,
            'filters': filters,
            'results_count': results_count
        })
        await session.commit()
    except Exception as e:
        logger.warning(f"Failed to log search analytics: {e}")


@router.get("/health", summary="Private Database Health Check")
async def private_database_health(
    session: AsyncSession = Depends(get_private_db_session)
):
    """
    Health check for private database functionality
    """
    try:
        # Test basic connectivity
        result = await session.execute(text("SELECT 1 as test"))
        result.scalar()
        
        # Test tables exist
        tables_query = text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('private_legislative_documents', 'search_terms_config', 
                              'collection_executions', 'state_document_density')
        """)
        
        tables_result = await session.execute(tables_query)
        tables = [row[0] for row in tables_result.fetchall()]
        
        # Get document count
        count_query = text("SELECT COUNT(*) FROM private_legislative_documents")
        count_result = await session.execute(count_query)
        document_count = count_result.scalar()
        
        return {
            "status": "healthy",
            "database_connected": True,
            "required_tables": len(tables) == 4,
            "tables_found": tables,
            "total_documents": document_count,
            "checked_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Private database health check failed: {e}")
        return {
            "status": "unhealthy",
            "database_connected": False,
            "error": str(e),
            "checked_at": datetime.now().isoformat()
        } 