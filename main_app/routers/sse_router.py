from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
import asyncio
import json
import logging
from datetime import datetime
from typing import AsyncGenerator
from ..services.database_cache_service import get_database_cache_service
from core.database.two_tier_manager import get_two_tier_manager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sse",
    tags=["Server-Sent Events"]
)

async def event_generator(request: Request) -> AsyncGenerator[str, None]:
    """Generate SSE events for real-time updates"""
    logger.info("SSE connection established")
    
    try:
        cache_service = await get_database_cache_service()
        two_tier_manager = await get_two_tier_manager()
        
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                logger.info("SSE client disconnected")
                break
            
            # Send heartbeat
            yield f"event: heartbeat\ndata: {json.dumps({'timestamp': datetime.now().isoformat()})}\n\n"
            
            # Check for collection status updates
            try:
                if two_tier_manager and two_tier_manager.pool:
                    async with two_tier_manager.pool.acquire() as conn:
                        # Get latest collection status
                        result = await conn.fetchrow("""
                            SELECT 
                                cl.id,
                                cl.search_term_id,
                                st.term as search_term,
                                cl.status,
                                cl.records_collected,
                                cl.records_new,
                                cl.records_updated,
                                cl.records_skipped,
                                cl.execution_time_ms,
                                cl.error_message,
                                cl.started_at,
                                cl.completed_at,
                                cl.sources_used
                            FROM collection_logs cl
                            JOIN search_terms st ON cl.search_term_id = st.id
                            ORDER BY cl.started_at DESC
                            LIMIT 1
                        """)
                        
                        if result:
                            collection_data = {
                                'id': result['id'],
                                'search_term_id': result['search_term_id'],
                                'search_term': result['search_term'],
                                'status': result['status'],
                                'records_collected': result['records_collected'],
                                'records_new': result['records_new'],
                                'records_updated': result['records_updated'],
                                'records_skipped': result['records_skipped'],
                                'execution_time_ms': result['execution_time_ms'],
                                'error_message': result['error_message'],
                                'started_at': result['started_at'].isoformat() if result['started_at'] else None,
                                'completed_at': result['completed_at'].isoformat() if result['completed_at'] else None,
                                'sources_used': result['sources_used'] or []
                            }
                            
                            yield f"event: collection_update\ndata: {json.dumps(collection_data)}\n\n"
                        
                        # Get new documents count from last hour
                        new_docs_result = await conn.fetchrow("""
                            SELECT COUNT(*) as count
                            FROM legislative_documents
                            WHERE collected_at > NOW() - INTERVAL '1 hour'
                        """)
                        
                        if new_docs_result:
                            yield f"event: new_documents\ndata: {json.dumps({'count': new_docs_result['count']})}\n\n"
                
            except Exception as e:
                logger.error(f"Error fetching collection updates: {e}")
                # Send error event but continue
                yield f"event: error\ndata: {json.dumps({'message': 'Failed to fetch updates'})}\n\n"
            
            # Wait before next update
            await asyncio.sleep(10)  # Send updates every 10 seconds
            
    except asyncio.CancelledError:
        logger.info("SSE event generator cancelled")
    except Exception as e:
        logger.error(f"SSE error: {e}")
    finally:
        logger.info("SSE connection closed")

@router.get("/events")
async def sse_endpoint(request: Request):
    """Server-Sent Events endpoint for real-time updates"""
    return StreamingResponse(
        event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Connection": "keep-alive"
        }
    )

@router.get("/collections/latest")
async def get_latest_collection():
    """Get the latest collection status"""
    try:
        two_tier_manager = await get_two_tier_manager()
        
        if not two_tier_manager or not two_tier_manager.pool:
            return {"error": "Database not available"}
        
        async with two_tier_manager.pool.acquire() as conn:
            result = await conn.fetchrow("""
                SELECT 
                    cl.id,
                    cl.search_term_id,
                    st.term as search_term,
                    cl.status,
                    cl.records_collected,
                    cl.records_new,
                    cl.records_updated,
                    cl.records_skipped,
                    cl.execution_time_ms,
                    cl.error_message,
                    cl.started_at,
                    cl.completed_at,
                    cl.sources_used
                FROM collection_logs cl
                JOIN search_terms st ON cl.search_term_id = st.id
                ORDER BY cl.started_at DESC
                LIMIT 1
            """)
            
            if not result:
                return None
            
            return {
                'id': result['id'],
                'search_term_id': result['search_term_id'],
                'search_term': result['search_term'],
                'status': result['status'],
                'records_collected': result['records_collected'],
                'records_new': result['records_new'],
                'records_updated': result['records_updated'],
                'records_skipped': result['records_skipped'],
                'execution_time_ms': result['execution_time_ms'],
                'error_message': result['error_message'],
                'started_at': result['started_at'].isoformat() if result['started_at'] else None,
                'completed_at': result['completed_at'].isoformat() if result['completed_at'] else None,
                'sources_used': result['sources_used'] or []
            }
            
    except Exception as e:
        logger.error(f"Error fetching latest collection: {e}")
        return {"error": str(e)}

@router.get("/collections/recent")
async def get_recent_collections(limit: int = 10):
    """Get recent collection logs"""
    try:
        two_tier_manager = await get_two_tier_manager()
        
        if not two_tier_manager or not two_tier_manager.pool:
            return []
        
        async with two_tier_manager.pool.acquire() as conn:
            results = await conn.fetch("""
                SELECT 
                    cl.id,
                    cl.search_term_id,
                    st.term as search_term,
                    cl.status,
                    cl.records_collected,
                    cl.records_new,
                    cl.records_updated,
                    cl.records_skipped,
                    cl.execution_time_ms,
                    cl.error_message,
                    cl.started_at,
                    cl.completed_at,
                    cl.sources_used
                FROM collection_logs cl
                JOIN search_terms st ON cl.search_term_id = st.id
                ORDER BY cl.started_at DESC
                LIMIT $1
            """, limit)
            
            return [
                {
                    'id': row['id'],
                    'search_term_id': row['search_term_id'],
                    'search_term': row['search_term'],
                    'status': row['status'],
                    'records_collected': row['records_collected'],
                    'records_new': row['records_new'],
                    'records_updated': row['records_updated'],
                    'records_skipped': row['records_skipped'],
                    'execution_time_ms': row['execution_time_ms'],
                    'error_message': row['error_message'],
                    'started_at': row['started_at'].isoformat() if row['started_at'] else None,
                    'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
                    'sources_used': row['sources_used'] or []
                }
                for row in results
            ]
            
    except Exception as e:
        logger.error(f"Error fetching recent collections: {e}")
        return []