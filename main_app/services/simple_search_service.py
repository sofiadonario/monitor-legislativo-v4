"""
Simple Search Service
====================

Enhanced search service with database integration for caching and analytics.
Provides a three-tier architecture with database-backed performance optimization.
Falls back to CSV data when database or APIs are unavailable.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio

# Import the working CSV data
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / 'src' / 'data'))
from real_legislative_data import realLegislativeData

# Import database cache service
from .database_cache_service import get_database_cache_service

logger = logging.getLogger(__name__)


class LexMLSearchResponse:
    """Simple response format compatible with frontend expectations"""
    
    def __init__(self, documents=None, total_found=0, start_record=1, records_returned=0, 
                 search_time_ms=0, data_source="csv-fallback", cache_hit=False, 
                 api_status="fallback", next_start_record=None):
        self.documents = documents or []
        self.total_found = total_found
        self.start_record = start_record
        self.records_returned = records_returned
        self.search_time_ms = search_time_ms
        self.data_source = data_source
        self.cache_hit = cache_hit
        self.api_status = api_status
        self.next_start_record = next_start_record


class LexMLDocument:
    """Simple document format compatible with frontend expectations"""
    
    def __init__(self, urn="", title="", description="", url="", metadata=None):
        self.urn = urn
        self.title = title
        self.description = description
        self.url = url
        self.metadata = metadata or {}


class SimpleSearchService:
    """
    Enhanced search service with database integration and CSV fallback.
    Implements three-tier search with caching, analytics, and known working Tier 3.
    """
    
    def __init__(self):
        self.documents = realLegislativeData
        self.initialized = False
        self.cache_service = None
        logger.info(f"Enhanced Search Service initialized with {len(self.documents)} documents")
    
    async def initialize(self):
        """Initialize the search service with database integration"""
        if self.initialized:
            return
        
        # Verify we have data
        if not self.documents:
            logger.error("No documents available for search")
            return
        
        # Initialize database cache service
        try:
            self.cache_service = await get_database_cache_service()
            if self.cache_service.db_available:
                logger.info("Database cache service integrated successfully")
            else:
                logger.info("Database cache service in fallback mode - CSV search only")
        except Exception as e:
            logger.warning(f"Database cache service initialization failed: {e}")
            self.cache_service = None
        
        self.initialized = True
        logger.info(f"Enhanced Search Service ready with {len(self.documents)} documents")
    
    async def search(self, request) -> LexMLSearchResponse:
        """
        Perform three-tier search with database caching and CSV fallback
        """
        start_time = datetime.now()
        
        # Extract search parameters
        query = getattr(request, 'query', None) or getattr(request, 'cql_query', '') or ''
        start_record = getattr(request, 'start_record', 1)
        max_records = getattr(request, 'max_records', 50)
        filters = getattr(request, 'filters', {})
        
        cache_hit = False
        cached_result = None
        
        try:
            # Check cache first if database is available
            if self.cache_service and self.cache_service.db_available:
                cached_result = await self.cache_service.get_cached_search_result(query, filters)
                if cached_result:
                    cache_hit = True
                    logger.info(f"Cache hit for query: {query[:50]}...")
                    
                    # Apply pagination to cached results
                    documents = cached_result.get('documents', [])
                    start_idx = start_record - 1
                    end_idx = start_idx + max_records
                    paginated_docs = documents[start_idx:end_idx]
                    
                    search_time = (datetime.now() - start_time).total_seconds() * 1000
                    
                    return LexMLSearchResponse(
                        documents=[LexMLDocument(**doc) for doc in paginated_docs],
                        total_found=len(documents),
                        start_record=start_record,
                        records_returned=len(paginated_docs),
                        search_time_ms=search_time,
                        data_source="database-cache",
                        cache_hit=True,
                        api_status="cached"
                    )
            
            # Tier 1: LexML API (will fail due to dependencies, proceed to Tier 3)
            logger.info("Tier 1 (LexML API): Skipping due to dependency issues")
            
            # Tier 2: Regional APIs (will fail due to dependencies, proceed to Tier 3)
            logger.info("Tier 2 (Regional APIs): Skipping due to dependency issues")
            
            # Tier 3: CSV Fallback (this works!)
            logger.info(f"Tier 3 (CSV Fallback): Searching for '{query}'")
            documents = await self._search_csv_fallback(query, start_record, max_records)
            
            # Calculate timing
            search_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Cache the result if database is available
            if self.cache_service and self.cache_service.db_available and not cache_hit:
                cache_data = {
                    'documents': [
                        {
                            'urn': doc.urn,
                            'title': doc.title,
                            'description': doc.description,
                            'url': doc.url,
                            'metadata': doc.metadata
                        } for doc in documents
                    ]
                }
                await self.cache_service.cache_search_result(query, filters, cache_data)
            
            # Track analytics if database is available
            if self.cache_service and self.cache_service.db_available:
                await self.cache_service.track_search_analytics(
                    query, filters, len(documents), search_time
                )
            
            # Build response
            response = LexMLSearchResponse(
                documents=documents,
                total_found=len(documents),
                start_record=start_record,
                records_returned=len(documents),
                search_time_ms=search_time,
                data_source="csv-fallback",
                cache_hit=cache_hit,
                api_status="fallback"
            )
            
            logger.info(f"Search completed: {len(documents)} documents in {search_time:.2f}ms")
            return response
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            # Return empty response on error
            search_time = (datetime.now() - start_time).total_seconds() * 1000
            return LexMLSearchResponse(
                documents=[],
                total_found=0,
                start_record=start_record,
                records_returned=0,
                search_time_ms=search_time,
                data_source="csv-fallback",
                cache_hit=False,
                api_status="error"
            )
    
    async def _search_csv_fallback(self, query: str, start_record: int, max_records: int) -> List[LexMLDocument]:
        """Search through CSV data"""
        if not query or query == '*':
            # Return all documents (with pagination)
            matching_docs = self.documents
        else:
            # Search for query in title and keywords
            query_lower = query.lower()
            matching_docs = []
            
            for doc in self.documents:
                title = doc.get('title', '').lower()
                keywords = doc.get('keywords', [])
                summary = doc.get('summary', '').lower()
                
                # Check if query matches title, keywords, or summary
                if (query_lower in title or 
                    any(query_lower in kw.lower() for kw in keywords) or
                    query_lower in summary):
                    matching_docs.append(doc)
        
        # Apply pagination
        start_idx = start_record - 1
        end_idx = start_idx + max_records
        paginated_docs = matching_docs[start_idx:end_idx]
        
        # Convert to LexMLDocument format
        result_docs = []
        for doc in paginated_docs:
            lexml_doc = LexMLDocument(
                urn=doc.get('id', ''),
                title=doc.get('title', ''),
                description=doc.get('summary', ''),
                url=doc.get('url', ''),
                metadata={
                    'type': doc.get('type', 'LEI'),
                    'date': doc.get('date', ''),
                    'chamber': doc.get('chamber', ''),
                    'state': doc.get('state', ''),
                    'keywords': doc.get('keywords', []),
                    'tier': 'tier3_csv_fallback',
                    'fallback_reason': 'api_dependencies_unavailable'
                }
            )
            result_docs.append(lexml_doc)
        
        return result_docs
    
    async def get_health_status(self):
        """Get enhanced service health status with database integration"""
        base_status = {
            "is_healthy": True,
            "data_source": "csv_fallback",
            "document_count": len(self.documents),
            "tier_status": {
                "tier1_lexml_api": "unavailable (dependency issues)",
                "tier2_regional_apis": "unavailable (dependency issues)", 
                "tier3_csv_fallback": "operational"
            },
            "fallback_ready": True
        }
        
        # Add database integration status
        if self.cache_service:
            cache_health = await self.cache_service.get_health_status()
            base_status.update({
                "database_integration": cache_health,
                "features_enabled": []
            })
            
            if self.cache_service.db_available:
                base_status["features_enabled"].extend([
                    "search_result_caching",
                    "analytics_tracking",
                    "export_caching",
                    "performance_monitoring"
                ])
            else:
                base_status["features_enabled"].append("basic_search_only")
        else:
            base_status.update({
                "database_integration": {"status": "not_initialized"},
                "features_enabled": ["basic_search_only"]
            })
        
        return base_status


# Global service instance
_simple_search_service: Optional[SimpleSearchService] = None


async def get_simple_search_service() -> SimpleSearchService:
    """Get or create global simple search service instance"""
    global _simple_search_service
    if _simple_search_service is None:
        _simple_search_service = SimpleSearchService()
        await _simple_search_service.initialize()
    return _simple_search_service