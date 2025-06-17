"""
Fixed Câmara dos Deputados API Service
Implements correct API parameters and local filtering
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
import re

from .base_service import BaseAPIService, retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig
from ..utils.parameter_validator import ParameterValidator


class CamaraService(BaseAPIService):
    """Fixed service for interacting with Câmara dos Deputados API"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(config, cache_manager)
        self.base_url = "https://dadosabertos.camara.leg.br/api/v2"
        
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search for propositions in Câmara dos Deputados"""
        start_time = datetime.now()
        
        # Check cache first
        cache_key = self._get_cache_key(query, filters)
        cached_result = self.cache_manager.get(cache_key)
        if cached_result:
            self.logger.info(f"Returning cached results for query: {query}")
            return cached_result
        
        try:
            # Since API doesn't support keyword search, we need to:
            # 1. Get propositions by date range
            # 2. Filter locally by keywords
            
            result = await self._search_with_local_filter(query, filters)
            
            if result.propositions:  # Only cache if we got results
                self.cache_manager.set(cache_key, result, ttl=self.config.cache_ttl)
            
            search_duration = (datetime.now() - start_time).total_seconds()
            result.search_time = search_duration
            return result
            
        except Exception as e:
            self.logger.error(f"Search failed: {str(e)}")
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.CAMARA,
                error=f"Search failed: {str(e)}"
            )
    
    @retry_on_failure(max_retries=3, backoff_factor=0.5)
    async def _search_with_local_filter(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search using date range and filter locally"""
        
        # Determine date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)  # Default to last year
        
        if filters.get("start_date"):
            try:
                start_date = datetime.fromisoformat(filters["start_date"])
            except:
                pass
                
        if filters.get("end_date"):
            try:
                end_date = datetime.fromisoformat(filters["end_date"])
            except:
                pass
        
        # Build API parameters (without keyword search)
        params = {
            "dataInicio": start_date.strftime("%Y-%m-%d"),
            "dataFim": end_date.strftime("%Y-%m-%d"),
            "ordenarPor": "id",
            "ordem": "DESC",
            "itens": 200  # Get more items to filter locally
        }
        
        # Add type filter if specified
        if "types" in filters and filters["types"]:
            if isinstance(filters["types"], list):
                params["siglaTipo"] = ",".join(filters["types"])
            else:
                params["siglaTipo"] = filters["types"]
        
        # Add year filter for better performance
        if end_date.year == start_date.year:
            params["ano"] = str(start_date.year)
        
        # Use the base class session management
        session = await self._get_aiohttp_session()
        
        # Get initial page
        all_propositions = []
        page = 1
        max_pages = 10  # Limit pages to avoid too many requests
        
        while page <= max_pages:
            params["pagina"] = page
            
            async with session.get(
                f"{self.base_url}/proposicoes",
                params=params,
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"API error {response.status}: {error_text}")
                    
                    # Check content type
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' not in content_type:
                        raise Exception(f"Unexpected content type: {content_type}")
                    
                    data = await response.json()
                    
                    if "dados" not in data:
                        break
                    
                    propositions = data["dados"]
                    if not propositions:
                        break
                    
                    all_propositions.extend(propositions)
                    
                    # Check if there are more pages
                    links = data.get("links", [])
                    has_next = any(link.get("rel") == "next" for link in links)
                    
                    if not has_next or len(all_propositions) >= 1000:  # Limit total
                        break
                    
                    page += 1
            
            # Now filter locally by keywords
            query_lower = query.lower()
            query_words = set(query_lower.split())
            
            filtered_propositions = []
            for prop_data in all_propositions:
                # Check if proposition matches query
                searchable_text = " ".join([
                    prop_data.get("ementa", ""),
                    prop_data.get("keywords", ""),
                    prop_data.get("ementaDetalhada", ""),
                    f"{prop_data.get('siglaTipo', '')} {prop_data.get('numero', '')}/{prop_data.get('ano', '')}"
                ]).lower()
                
                # Check if any query word is in the searchable text
                if any(word in searchable_text for word in query_words):
                    proposition = self._parse_proposition(prop_data)
                    if proposition:
                        filtered_propositions.append(proposition)
            
            # Sort by relevance (how many query words match)
            filtered_propositions.sort(
                key=lambda p: sum(1 for word in query_words if word in p.summary.lower()),
                reverse=True
            )
            
            # Limit results
            filtered_propositions = filtered_propositions[:100]
            
            return SearchResult(
                query=query,
                filters=filters,
                propositions=filtered_propositions,
                total_count=len(filtered_propositions),
                source=DataSource.CAMARA
            )
    
    def _parse_proposition(self, data: Dict[str, Any]) -> Optional[Proposition]:
        """Parse proposition from API response"""
        try:
            # Parse type - map sigla to enum
            sigla = data.get("siglaTipo", "").upper()
            prop_type = PropositionType.OTHER  # Default
            
            # Try to match the sigla to an enum value
            for ptype in PropositionType:
                if ptype.name == sigla:
                    prop_type = ptype
                    break
            
            # Parse date
            date_str = data.get("dataApresentacao", "")
            try:
                pub_date = datetime.fromisoformat(date_str.replace("T", " "))
            except:
                pub_date = datetime.now()
            
            # Parse status - use ACTIVE as default for Câmara
            status = PropositionStatus.ACTIVE
            
            # Create proposition
            return Proposition(
                id=str(data.get("id", "")),
                type=prop_type,
                number=str(data.get("numero", "")),
                year=int(data.get("ano", 0)),
                summary=data.get("ementa", ""),
                title=data.get("ementa", "")[:200],  # Use first 200 chars of summary as title
                authors=[],  # Authors need separate API call
                publication_date=pub_date,
                status=status,
                url=data.get("urlInteiroTeor", ""),
                source=DataSource.CAMARA,
                keywords=data.get("keywords", "").split(", ") if data.get("keywords") else []
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing proposition: {e}")
            return None
    
    async def get_proposition_details(self, prop_id: str) -> Optional[Proposition]:
        """Get detailed information about a specific proposition"""
        try:
            # Use the base class session management
            session = await self._get_aiohttp_session()
            
            # Get proposition details
            async with session.get(
                f"{self.base_url}/proposicoes/{prop_id}",
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                    
                    if response.status != 200:
                        return None
                    
                    data = await response.json()
                    prop_data = data.get("dados", {})
                    
                    # Get authors
                    authors = []
                    async with session.get(
                        f"{self.base_url}/proposicoes/{prop_id}/autores",
                        headers={"Accept": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as author_response:
                        
                        if author_response.status == 200:
                            author_data = await author_response.json()
                            for author in author_data.get("dados", []):
                                authors.append(Author(
                                    name=author.get("nome", ""),
                                    party=author.get("siglaPartido", ""),
                                    state=author.get("siglaUf", "")
                                ))
                    
                    # Create detailed proposition
                    proposition = self._parse_proposition(prop_data)
                    if proposition:
                        proposition.authors = authors
                        proposition.full_text = prop_data.get("texto", "")
                    
                    return proposition
                    
        except Exception as e:
            self.logger.error(f"Error getting proposition details: {e}")
            return None
    
    async def check_health(self) -> Dict[str, Any]:
        """Check health of Câmara API"""
        try:
            start_time = datetime.now()
            
            # Try a simple API call
            # Use the base class session management
            session = await self._get_aiohttp_session()
            
            async with session.get(
                f"{self.base_url}/proposicoes",
                params={"itens": 1},
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                    
                    health_status = "healthy" if response.status == 200 else "unhealthy"
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    return {
                        "status": health_status,
                        "response_time": response_time,
                        "status_code": response.status,
                        "service": "Câmara dos Deputados"
                    }
                    
        except Exception as e:
            return {
                "status": "unhealthy",
                "response_time": 0,
                "error": str(e),
                "service": "Câmara dos Deputados"
            }