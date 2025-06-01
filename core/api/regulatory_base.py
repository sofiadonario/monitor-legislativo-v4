"""
Base class for regulatory agency services
Provides common functionality for scraping regulatory agency websites
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
from ..utils.session_factory import SessionFactory, fetch_with_retry
from ..utils.circuit_breaker import circuit_manager
from ..utils.smart_cache import smart_cache

from .base_service import BaseAPIService
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig


class RegulatoryAgencyService(BaseAPIService):
    """Base class for regulatory agency services"""
    
    def __init__(self, config: APIConfig, agency_name: str, 
                 data_source: DataSource, cache_manager=None):
        super().__init__(config, cache_manager)
        self.agency_name = agency_name
        self.data_source = data_source
        self.search_patterns = {
            "resolucao": ["resolução", "resolution"],
            "portaria": ["portaria", "ordinance"],
            "instrucao": ["instrução normativa", "normative instruction"],
            "circular": ["circular"],
            "deliberacao": ["deliberação", "deliberation"],
            "ato": ["ato", "act"]
        }
    
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search for documents in the regulatory agency"""
        start_time = datetime.now()
        
        # Check cache first
        cache_key = self._get_cache_key(query, filters)
        cached_result = await smart_cache.get(cache_key, source=self.data_source.name.lower())
        if cached_result:
            self.logger.info(f"Returning cached results for query: {query}")
            return cached_result
        
        try:
            # Most regulatory agencies don't have APIs, so we scrape their websites
            propositions = await self._search_website(query, filters)
            
            result = SearchResult(
                query=query,
                filters=filters,
                propositions=propositions,
                total_count=len(propositions),
                source=self.data_source,
                search_time=(datetime.now() - start_time).total_seconds()
            )
            
            if propositions:
                await smart_cache.set(cache_key, result, source=self.data_source.name.lower())
            
            return result
            
        except Exception as e:
            self.logger.error(f"Search failed for {self.agency_name}: {str(e)}")
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=self.data_source,
                error=f"Search failed: {str(e)}",
                search_time=(datetime.now() - start_time).total_seconds()
            )
    
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search the agency website - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _search_website")
    
    def _extract_document_type(self, text: str) -> PropositionType:
        """Extract document type from text"""
        text_lower = text.lower()
        
        for doc_type, patterns in self.search_patterns.items():
            for pattern in patterns:
                if pattern in text_lower:
                    if doc_type == "resolucao":
                        return PropositionType.RESOLUCAO
                    elif doc_type == "portaria":
                        return PropositionType.PORTARIA
                    elif doc_type == "instrucao":
                        return PropositionType.INSTRUCAO_NORMATIVA
                    elif doc_type == "circular":
                        return PropositionType.CIRCULAR
        
        return PropositionType.OTHER
    
    def _extract_document_number(self, text: str) -> tuple[str, int]:
        """Extract document number and year from text"""
        import re
        
        # Common patterns for regulatory documents
        patterns = [
            r'n[º°]?\s*(\d+)[/-](\d{4})',  # nº 123/2024
            r'n[º°]?\s*(\d+)\s*de\s*\d+\s*de\s*\w+\s*de\s*(\d{4})',  # nº 123 de 15 de janeiro de 2024
            r'(\d+)[/-](\d{4})',  # 123/2024
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                number = match.group(1)
                year = int(match.group(2))
                return number, year
        
        # If no pattern matches, return defaults
        return "", datetime.now().year
    
    def _create_proposition(self, title: str, summary: str, url: str, 
                          pub_date: Optional[datetime] = None) -> Proposition:
        """Create a proposition from scraped data"""
        doc_type = self._extract_document_type(title)
        number, year = self._extract_document_number(title)
        
        if not pub_date:
            pub_date = datetime.now()
        
        return Proposition(
            id=f"{self.data_source.name.lower()}-{datetime.now().timestamp()}",
            type=doc_type,
            number=number,
            year=year,
            title=title[:200],
            summary=summary[:500] if summary else title[:500],
            source=self.data_source,
            status=PropositionStatus.PUBLISHED,
            url=url,
            publication_date=pub_date,
            authors=[Author(name=self.agency_name, type="Agência Reguladora")]
        )
    
    async def get_proposition_details(self, proposition_id: str) -> Optional[Proposition]:
        """Get detailed information about a specific document"""
        # Most agencies don't have detail APIs
        return None
    
    async def check_health(self) -> bool:
        """Check if the agency website is accessible"""
        try:
            # Simplified health check to avoid event loop issues
            import requests
            response = requests.get(self.config.base_url, timeout=5, verify=False)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Health check failed for {self.agency_name}: {str(e)}")
            return False
    
    async def _get_aiohttp_session(self):
        """Get aiohttp session using SessionFactory"""
        return await SessionFactory.get_session()
    
    async def _generic_gov_br_search(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Generic search for gov.br websites with improved error handling"""
        from ..config.api_endpoints import REGULATORY_SCRAPERS
        
        scraper_config = REGULATORY_SCRAPERS.get(self.agency_name.upper())
        
        if not scraper_config:
            self.logger.error(f"No scraper config found for {self.agency_name}")
            return []
        
        try:
            # Use fetch_with_retry for better reliability
            html = await fetch_with_retry(
                scraper_config.search_url, 
                max_retries=3,
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            return await self._parse_gov_br_html(html, query, scraper_config)
                
        except Exception as e:
            self.logger.error(f"{self.agency_name} search failed: {str(e)}")
            return []
    
    async def _parse_gov_br_html(self, html: str, query: str, scraper_config) -> List[Proposition]:
        """Parse gov.br HTML with multiple fallback strategies"""
        soup = BeautifulSoup(html, 'html.parser')
        propositions = []
        
        # Primary strategy: use configured selectors
        container = soup.select_one(scraper_config.selectors["results_container"])
        
        if container:
            items = container.select(scraper_config.selectors["result_item"])
            
            for item in items[:20]:  # Limit results
                # Filter by query if provided
                if query and query.lower() not in item.get_text().lower():
                    continue
                
                title_elem = item.select_one(scraper_config.selectors["title"])
                link_elem = item.select_one(scraper_config.selectors["link"])
                date_elem = item.select_one(scraper_config.selectors.get("date", ""))
                summary_elem = item.select_one(scraper_config.selectors.get("summary", ""))
                
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    url = link_elem.get('href', '') if link_elem else ""
                    if url and not url.startswith('http'):
                        url = f"https://www.gov.br{url}"
                    
                    date_text = date_elem.get_text(strip=True) if date_elem else ""
                    summary = summary_elem.get_text(strip=True) if summary_elem else title
                    
                    prop = self._create_proposition(title, summary, url)
                    propositions.append(prop)
        
        # Fallback strategy: try common selectors
        if not propositions:
            fallback_selectors = [
                ".tileItem",
                "article", 
                ".item",
                ".content-item",
                "[class*='consulta']",
                "[class*='resultado']"
            ]
            
            for selector in fallback_selectors:
                items = soup.select(selector)
                if items:
                    for item in items[:10]:
                        text = item.get_text().lower()
                        if not query or query.lower() in text:
                            title_elem = item.select_one("h2, h3, h4, .title, .titulo")
                            if title_elem:
                                title = title_elem.get_text(strip=True)
                                link = item.select_one("a")
                                url = link.get('href', '') if link else ''
                                
                                prop = self._create_proposition(title, text[:300], url)
                                propositions.append(prop)
                    
                    if propositions:
                        break
        
        return propositions
