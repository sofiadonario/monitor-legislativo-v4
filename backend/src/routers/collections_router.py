from fastapi import APIRouter, HTTPException
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Collections"])

@router.get("/collections/latest")
async def get_latest_collection():
    """
    Get latest collection information
    This endpoint is being requested by the frontend
    """
    try:
        # Return basic collection info - can be enhanced later
        return {
            "status": "success",
            "collection": {
                "id": "latest",
                "name": "Monitor Legislativo Collection",
                "description": "Latest legislative documents with URN parsing",
                "document_count": 889,
                "last_updated": datetime.utcnow().isoformat(),
                "features": [
                    "URN Parsing",
                    "Brazilian Legislation",
                    "Jurisprudence Analysis",
                    "Geographic Classification"
                ]
            },
            "data_sources": [
                "LexML",
                "Brazilian Legislative Archives",
                "Supabase Database"
            ]
        }
    except Exception as e:
        logger.error(f"Error getting latest collection: {e}")
        raise HTTPException(status_code=500, detail="Failed to get collection information")

@router.get("/collections/status")
async def get_collection_status():
    """Get collection processing status"""
    return {
        "status": "available",
        "total_documents": 889,
        "urn_parsed": 889,
        "processing_complete": True,
        "last_update": datetime.utcnow().isoformat()
    } 