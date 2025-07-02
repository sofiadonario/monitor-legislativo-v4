import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class Document(BaseModel):
    """
    A Pydantic model representing a legislative document.
    This ensures compatibility with FastAPI's response_model.
    """
    urn: str
    title: str
    description: Optional[str] = None
    full_text_url: Optional[str] = None
    
class SimpleSearchService:
    """
    A placeholder search service to allow the application to start.
    This service simulates the search functionality required by the routers.
    """
    async def search(self, query: str, limit: int = 50) -> List[Document]:
        logger.warning(f"Using placeholder SimpleSearchService. No real search will be performed for query: {query}")
        # Return an empty list of Document models to ensure the router has a valid response.
        return []

# Singleton instance
_search_service_instance = None

async def get_simple_search_service() -> SimpleSearchService:
    """
    Dependency injector for the SimpleSearchService.
    """
    global _search_service_instance
    if _search_service_instance is None:
        _search_service_instance = SimpleSearchService()
    return _search_service_instance 