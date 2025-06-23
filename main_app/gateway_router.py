"""
API Gateway Router for the Unified Service
"""

from fastapi import APIRouter
from web.api import routes as web_api_routes
from web.api import health_routes, monitoring_routes, debug_routes

router = APIRouter(prefix="/api/v1", tags=["API Gateway"])

# Include the main application routes
router.include_router(web_api_routes.router, tags=["Main API"])

# Include monitoring and health routes
router.include_router(health_routes.router, tags=["Health"])
router.include_router(monitoring_routes.router, tags=["Monitoring"])

# Include debug routes for implementation verification
router.include_router(debug_routes.router, tags=["Debug"])

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