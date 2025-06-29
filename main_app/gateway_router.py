"""
API Gateway Router for the Unified Service
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1", tags=["API Gateway"])

# Basic health endpoint
@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "monitor-legislativo-v4"}

# Basic status endpoint  
@router.get("/status")
async def status_check():
    """Status check endpoint"""
    return {
        "status": "operational",
        "version": "4.0.0",
        "environment": "production"
    }

@router.get("/", summary="API Gateway Root")
async def gateway_root():
    """
    Provides a welcome message and basic status of the API gateway.
    """
    return {
        "message": "API Gateway is active.",
        "status": "healthy",
        "service_documentation": "/docs"
    } 