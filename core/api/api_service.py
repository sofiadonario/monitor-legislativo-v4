"""
Main API Service Orchestrator
Manages all data sources and coordinates searches
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from .camara_service import CamaraService
from .senado_service import SenadoService
from .planalto_service import PlanaltoService
# Import ANEEL and ANATEL from regulatory_agencies since they were moved
from .regulatory_agencies import ANEELService, ANATELService
from .regulatory_agencies import (
    ANVISAService, ANSService, ANAService, ANCINEService,
    ANTTService, ANTAQService, ANACService, ANPService, ANMService
)
from .lexml_service_official import LexMLOfficialSearchService as LexMLSearchService
from ..models.models import SearchResult, APIStatus, DataSource
from ..config.config import Config
from ..utils.smart_cache import smart_cache


class APIService:
    """Central service for coordinating all API searches"""
    
    def __init__(self, cache_manager=None):
        self.cache_manager = cache_manager  # For compatibility
        self.logger = logging.getLogger(__name__)
        self.services = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Initialize services
        self._initialize_services()
        
        # Status monitoring
        self.last_health_check = {}
        self.health_check_interval = 300  # 5 minutes
    
    def _initialize_services(self):
        """Initialize all available services"""
        config = Config()
        
        # Government services
        if config.APIS["camara"].enabled:
            self.services["camara"] = CamaraService(
                config.APIS["camara"], 
                self.cache_manager
            )
        
        if config.APIS["senado"].enabled:
            self.services["senado"] = SenadoService(
                config.APIS["senado"],
                self.cache_manager
            )
        
        if config.APIS["planalto"].enabled:
            self.services["planalto"] = PlanaltoService(
                config.APIS["planalto"],
                self.cache_manager
            )
        
        # LexML Official Search Service (Primary for Transport Research)
        self.services["lexml"] = LexMLSearchService(config)
        self.logger.info("Initialized LexML Official Search Service with three-tier fallback architecture")
        
        # Regulatory agencies - all 11 agencies
        regulatory_services = {
            "aneel": ANEELService,
            "anatel": ANATELService,
            "anvisa": ANVISAService,
            "ans": ANSService,
            "ana": ANAService,
            "ancine": ANCINEService,
            "antt": ANTTService,
            "antaq": ANTAQService,
            "anac": ANACService,
            "anp": ANPService,
            "anm": ANMService,
        }
        
        for key, service_class in regulatory_services.items():
            if key in config.REGULATORY_AGENCIES and config.REGULATORY_AGENCIES[key].enabled:
                self.services[key] = service_class(
                    config.REGULATORY_AGENCIES[key],
                    self.cache_manager
                )
                self.logger.info(f"Initialized {key.upper()} service")
    
    async def search_all(self, query: str, filters: Dict[str, Any], 
                        sources: Optional[List[str]] = None) -> List[SearchResult]:
        """
        Search across all enabled sources with LexML as primary research engine
        
        Args:
            query: Search query
            filters: Search filters
            sources: List of source keys to search (None = prioritized list)
        
        Returns:
            List of SearchResult objects from each source
        """
        if not sources:
            # Prioritize LexML for comprehensive academic research
            sources = ["lexml"] + [s for s in self.services.keys() if s != "lexml"]
        
        # Filter to only requested and available sources
        sources = [s for s in sources if s in self.services]
        
        if not sources:
            self.logger.warning("No valid sources specified for search")
            return []
        
        # Prioritize LexML search if it's requested
        results = []
        
        # Execute LexML search first if available
        if "lexml" in sources and "lexml" in self.services:
            self.logger.info("Executing primary LexML enhanced search...")
            try:
                lexml_result = await self._search_with_timeout(
                    self.services["lexml"], query, filters, "lexml"
                )
                if isinstance(lexml_result, SearchResult):
                    results.append(lexml_result)
                    self.logger.info(f"LexML search returned {lexml_result.total_count} documents")
                
                # If LexML returns substantial results, prioritize it
                if lexml_result.total_count > 10:
                    self.logger.info("LexML returned substantial results, prioritizing academic data")
                    # Still search other sources but LexML is primary
                    sources = [s for s in sources if s != "lexml"]
                    
            except Exception as e:
                self.logger.error(f"LexML search failed: {e}")
        
        # Search remaining sources in parallel
        if sources:
            tasks = []
            for source_key in sources:
                if source_key == "lexml":  # Skip if already processed
                    continue
                service = self.services[source_key]
                task = asyncio.create_task(
                    self._search_with_timeout(service, query, filters, source_key)
                )
                tasks.append(task)
            
            if tasks:
                # Execute remaining searches in parallel
                additional_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Filter out exceptions and empty results
                for result in additional_results:
                    if isinstance(result, SearchResult):
                        results.append(result)
                    elif isinstance(result, Exception):
                        self.logger.error(f"Search error: {str(result)}")
        
        self.logger.info(f"Total search completed: {len(results)} sources returned data")
        return results
    
    async def _search_with_timeout(self, service, query: str, 
                                  filters: Dict[str, Any], source_key: str) -> SearchResult:
        """Execute search with timeout handling"""
        try:
            # Add source-specific timeout
            timeout = 60  # Default timeout
            if hasattr(service.config, 'timeout'):
                timeout = service.config.timeout
            
            result = await asyncio.wait_for(
                service.search(query, filters),
                timeout=timeout
            )
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.error(f"Search timeout for {source_key}")
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=getattr(DataSource, source_key.upper(), DataSource.CAMARA),
                error=f"Search timeout after {timeout} seconds"
            )
        except Exception as e:
            self.logger.error(f"Search error for {source_key}: {str(e)}")
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=getattr(DataSource, source_key.upper(), DataSource.CAMARA),
                error=str(e)
            )
    
    async def get_api_status(self, force_check: bool = False) -> List[APIStatus]:
        """
        Get health status of all APIs
        
        Args:
            force_check: Force a new health check even if recently checked
        
        Returns:
            List of APIStatus objects
        """
        status_list = []
        current_time = datetime.now()
        
        tasks = []
        for source_key, service in self.services.items():
            # Check if we need to perform health check
            last_check = self.last_health_check.get(source_key)
            
            if force_check or not last_check or \
               (current_time - last_check).total_seconds() > self.health_check_interval:
                # Perform health check
                task = asyncio.create_task(
                    self._check_service_health(source_key, service)
                )
                tasks.append(task)
            else:
                # Use cached status
                status = APIStatus(
                    name=service.config.name,
                    source=getattr(DataSource, source_key.upper(), DataSource.CAMARA),
                    is_healthy=True,  # Assume healthy if recently checked
                    last_check=last_check
                )
                status_list.append(status)
        
        # Wait for all health checks to complete
        if tasks:
            new_statuses = await asyncio.gather(*tasks, return_exceptions=True)
            for status in new_statuses:
                if isinstance(status, APIStatus):
                    status_list.append(status)
        
        return status_list
    
    async def _check_service_health(self, source_key: str, service) -> APIStatus:
        """Check health of a specific service"""
        start_time = datetime.now()
        
        try:
            is_healthy = await service.check_health()
            response_time = (datetime.now() - start_time).total_seconds()
            
            self.last_health_check[source_key] = datetime.now()
            
            return APIStatus(
                name=getattr(service.config, 'name', f"{source_key.upper()} Service"),
                source=getattr(DataSource, source_key.upper(), DataSource.CAMARA),
                is_healthy=is_healthy,
                last_check=datetime.now(),
                response_time=response_time
            )
            
        except Exception as e:
            self.logger.error(f"Health check failed for {source_key}: {str(e)}")
            
            return APIStatus(
                name=getattr(service.config, 'name', f"{source_key.upper()} Service"),
                source=getattr(DataSource, source_key.upper(), DataSource.CAMARA),
                is_healthy=False,
                last_check=datetime.now(),
                error_message=str(e)
            )
    
    def get_available_sources(self) -> Dict[str, str]:
        """Get dictionary of available sources and their display names"""
        sources = {}
        for key, service in self.services.items():
            sources[key] = getattr(service.config, 'name', f"{key.upper()} Service")
        return sources
    
    async def clear_cache(self, source: Optional[str] = None):
        """Clear cache for specific source or all sources"""
        if source:
            await smart_cache.clear_pattern(f"*{source}*", source)
        else:
            await smart_cache.clear_all()
    
    def shutdown(self):
        """Cleanup resources"""
        self.executor.shutdown(wait=True)