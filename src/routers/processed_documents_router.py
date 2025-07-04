from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
from supabase import create_client, Client

from ..config.env_loader import EnvironmentConfig

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Processed Documents"])

def get_supabase_client() -> Client:
    """Get Supabase client for direct access"""
    try:
        supabase_url = EnvironmentConfig.SUPABASE_URL
        supabase_key = EnvironmentConfig.SUPABASE_ANON_KEY
        
        if not supabase_url or not supabase_key:
            raise ValueError("Supabase credentials not configured")
        
        return create_client(supabase_url, supabase_key)
    except Exception as e:
        logger.error(f"Failed to create Supabase client: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

@router.get("/processed-documents")
async def get_processed_documents(
    limit: int = Query(100, ge=1, le=1000, description="Number of documents to return"),
    offset: int = Query(0, ge=0, description="Number of documents to skip"),
    search_term: Optional[str] = Query(None, description="Filter by search term"),
    document_type: Optional[str] = Query(None, description="Filter by document type"),
    state: Optional[str] = Query(None, description="Filter by state"),
    urn_type: Optional[str] = Query(None, description="Filter by URN type")
):
    """
    Get processed legislative documents from Supabase
    """
    try:
        supabase = get_supabase_client()
        
        # Build query
        query = supabase.table('legislative_documents').select('*')
        
        # Apply filters
        if search_term:
            query = query.ilike('search_term', f'%{search_term}%')
        if document_type:
            query = query.ilike('document_type_full', f'%{document_type}%')
        if state:
            query = query.eq('state', state)
        if urn_type:
            query = query.eq('urn_type', urn_type)
        
        # Apply pagination
        query = query.range(offset, offset + limit - 1)
        
        # Execute query
        result = query.execute()
        
        return {
            "status": "success",
            "data": result.data,
            "count": len(result.data),
            "offset": offset,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Error fetching processed documents: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch documents")

@router.get("/processed-documents/categories")
async def get_document_categories():
    """
    Get document categories and their counts for dashboard analytics
    """
    try:
        supabase = get_supabase_client()
        
        # Get all documents to analyze categories
        result = supabase.table('legislative_documents')\
            .select('document_type_full, state, urn_type, search_term')\
            .execute()
        
        data = result.data
        
        # Analyze categories
        document_types = {}
        states = {}
        urn_types = {}
        search_terms = {}
        
        for doc in data:
            # Document types
            doc_type = doc.get('document_type_full', 'Unknown')
            document_types[doc_type] = document_types.get(doc_type, 0) + 1
            
            # States
            state = doc.get('state', 'Federal')
            if state:
                states[state] = states.get(state, 0) + 1
            
            # URN types
            urn_type = doc.get('urn_type', 'Unknown')
            urn_types[urn_type] = urn_types.get(urn_type, 0) + 1
            
            # Search terms
            search_term = doc.get('search_term', 'Unknown')
            search_terms[search_term] = search_terms.get(search_term, 0) + 1
        
        # Sort by count
        document_types = dict(sorted(document_types.items(), key=lambda x: x[1], reverse=True))
        states = dict(sorted(states.items(), key=lambda x: x[1], reverse=True))
        urn_types = dict(sorted(urn_types.items(), key=lambda x: x[1], reverse=True))
        search_terms = dict(sorted(search_terms.items(), key=lambda x: x[1], reverse=True))
        
        return {
            "status": "success",
            "categories": {
                "document_types": document_types,
                "states": states,
                "urn_types": urn_types,
                "search_terms": search_terms
            },
            "total_documents": len(data),
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error fetching categories: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch categories")

@router.get("/processed-documents/stats")
async def get_document_stats():
    """
    Get statistics about processed documents for analytics dashboard
    """
    try:
        supabase = get_supabase_client()
        
        # Get total count
        total_result = supabase.table('legislative_documents')\
            .select('id', count='exact')\
            .execute()
        
        # Get recent documents (last 30 days)
        from datetime import timedelta
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
        
        recent_result = supabase.table('legislative_documents')\
            .select('id', count='exact')\
            .gte('created_at', thirty_days_ago)\
            .execute()
        
        # Get documents by year
        documents_by_year = supabase.table('legislative_documents')\
            .select('promulgation_date')\
            .execute()
        
        # Analyze by year
        year_stats = {}
        for doc in documents_by_year.data:
            if doc.get('promulgation_date'):
                try:
                    year = datetime.fromisoformat(doc['promulgation_date']).year
                    year_stats[year] = year_stats.get(year, 0) + 1
                except:
                    pass
        
        return {
            "status": "success",
            "stats": {
                "total_documents": len(total_result.data) if total_result.data else 0,
                "recent_documents": len(recent_result.data) if recent_result.data else 0,
                "documents_by_year": dict(sorted(year_stats.items(), reverse=True)),
                "data_source": "Supabase - lexml_parsed_enhanced.csv"
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")

@router.get("/processed-documents/search")
async def search_processed_documents(
    q: str = Query(..., description="Search query"),
    limit: int = Query(50, ge=1, le=100, description="Number of results to return")
):
    """
    Search processed documents by title, description, or URN
    """
    try:
        supabase = get_supabase_client()
        
        # Search across multiple fields
        result = supabase.table('legislative_documents')\
            .select('*')\
            .or_(f'title.ilike.%{q}%,document_description.ilike.%{q}%,urn.ilike.%{q}%')\
            .limit(limit)\
            .execute()
        
        return {
            "status": "success",
            "query": q,
            "results": result.data,
            "count": len(result.data)
        }
        
    except Exception as e:
        logger.error(f"Error searching documents: {e}")
        raise HTTPException(status_code=500, detail="Search failed")

@router.get("/processed-documents/{document_id}")
async def get_processed_document(document_id: int):
    """
    Get a specific processed document by ID
    """
    try:
        supabase = get_supabase_client()
        
        result = supabase.table('legislative_documents')\
            .select('*')\
            .eq('id', document_id)\
            .execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Document not found")
        
        return {
            "status": "success",
            "document": result.data[0]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching document {document_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch document") 