"""
Simplified fallback service for production
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SimpleFallbackService:
    """Emergency fallback with minimal dependencies"""
    
    def __init__(self):
        self.default_results = [
            {
                "id": "lei-14300-2022",
                "title": "Lei nº 14.300/2022 - Marco Legal da Microgeração e Minigeração Distribuída",
                "type": "lei",
                "date": "2022-01-06",
                "source": "planalto",
                "summary": "Institui o marco legal da microgeração e minigeração distribuída.",
                "url": "http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2022/lei/L14300.htm"
            },
            {
                "id": "lei-12587-2012",
                "title": "Lei nº 12.587/2012 - Política Nacional de Mobilidade Urbana",
                "type": "lei", 
                "date": "2012-01-03",
                "source": "planalto",
                "summary": "Institui as diretrizes da Política Nacional de Mobilidade Urbana.",
                "url": "http://www.planalto.gov.br/ccivil_03/_ato2011-2014/2012/lei/l12587.htm"
            }
        ]
    
    async def search(self, query: str, **kwargs) -> Dict[str, Any]:
        """Simple search that returns default results"""
        try:
            # Filter results based on query
            results = []
            query_lower = query.lower()
            
            for doc in self.default_results:
                if query_lower in doc["title"].lower() or query_lower in doc["summary"].lower():
                    results.append(doc)
            
            # If no matches, return all as fallback
            if not results:
                results = self.default_results
            
            return {
                "success": True,
                "query": query,
                "total": len(results),
                "results": results,
                "source": "fallback",
                "message": "Using simplified fallback data"
            }
            
        except Exception as e:
            logger.error(f"Fallback search error: {e}")
            return {
                "success": False,
                "error": str(e),
                "results": []
            }

# Global instance
_fallback_service = SimpleFallbackService()

async def get_fallback_results(query: str, **kwargs) -> Dict[str, Any]:
    """Get fallback results"""
    return await _fallback_service.search(query, **kwargs)
