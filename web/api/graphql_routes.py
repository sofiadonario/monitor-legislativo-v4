"""
GraphQL Routes for Monitor Legislativo v4
Integrates GraphQL with FastAPI

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from fastapi import APIRouter, Depends, Request
from strawberry.fastapi import GraphQLRouter
from typing import Optional
import logging

from .graphql_schema import schema
from core.auth.jwt_manager import get_current_user

logger = logging.getLogger(__name__)

# Create router
router = APIRouter()

# Custom context getter for authentication
async def get_context(request: Request) -> dict:
    """
    Get context for GraphQL resolvers
    Includes authentication and request info
    """
    context = {
        "request": request,
        "user": None
    }
    
    # Try to get authenticated user
    try:
        # Check for Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # TODO: Implement JWT validation
            # For now, just log
            logger.info("GraphQL request with auth token")
    except Exception as e:
        logger.error(f"Error getting auth context: {e}")
    
    return context

# Create GraphQL app with custom context
graphql_app = GraphQLRouter(
    schema,
    context_getter=get_context,
    graphiql=True  # Enable GraphiQL interface in development
)

# Mount GraphQL endpoint
router.include_router(graphql_app, prefix="/graphql")

# Additional REST endpoint for GraphQL schema
@router.get("/graphql/schema")
async def get_schema():
    """
    Get GraphQL schema in SDL format
    """
    return {
        "schema": str(schema),
        "version": "1.0.0",
        "attribution": {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
    }

# Health check for GraphQL endpoint
@router.get("/graphql/health")
async def graphql_health():
    """
    Check GraphQL endpoint health
    """
    return {
        "status": "healthy",
        "endpoint": "/api/v1/graphql",
        "graphiql": "/api/v1/graphql",
        "features": [
            "search_propositions",
            "get_proposition",
            "get_analytics",
            "search_authors",
            "track_proposition",
            "export_search_results"
        ]
    }