"""
Implementation of all regulatory agency services
Uses centralized configuration for maintainability
"""

import re
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

from .regulatory_base import RegulatoryAgencyService
from .base_service import retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType,
    PropositionStatus, DataSource
)
from ..config.config import APIConfig
from ..config.api_endpoints import REGULATORY_SCRAPERS, DOCUMENT_TYPE_PATTERNS, MONTH_NAMES, DATE_PATTERNS
from ..utils.session_factory import SessionFactory, fetch_with_retry
from ..utils.circuit_breaker import circuit_manager, CircuitBreakerConfig
import aiohttp
import asyncio


class ANVISAService(RegulatoryAgencyService):
    """ANVISA - Agência Nacional de Vigilância Sanitária"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANVISA", 
            DataSource.ANVISA,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANVISA"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANVISA website with JavaScript rendering support"""
        
        # ANVISA requires JavaScript rendering, so we'll use Playwright
        try:
            from playwright.async_api import async_playwright
            
            propositions = []
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Navigate to search page
                await page.goto(self.scraper_config.search_url)
                
                # Wait for content to load
                await page.wait_for_selector(self.scraper_config.selectors["results_container"], timeout=10000)
                
                # Perform search if query provided
                if query:
                    search_input = await page.query_selector('input[type="search"], input.buscar')
                    if search_input:
                        await search_input.fill(query)
                        await search_input.press('Enter')
                        await page.wait_for_load_state('networkidle')
                
                # Extract results
                results = await page.query_selector_all(self.scraper_config.selectors["result_item"])
                
                for result in results[:20]:  # Limit to 20 results
                    title_elem = await result.query_selector(self.scraper_config.selectors["title"])
                    link_elem = await result.query_selector(self.scraper_config.selectors["link"])
                    date_elem = await result.query_selector(self.scraper_config.selectors["date"])
                    summary_elem = await result.query_selector(self.scraper_config.selectors["summary"])
                    
                    if title_elem:
                        title = await title_elem.inner_text()
                        url = await link_elem.get_attribute('href') if link_elem else ""
                        if url and not url.startswith('http'):
                            url = f"https://www.gov.br{url}"
                        
                        date_text = await date_elem.inner_text() if date_elem else ""
                        pub_date = self._parse_date(date_text)
                        
                        summary = await summary_elem.inner_text() if summary_elem else title
                        
                        prop = self._create_proposition(title, summary, url, pub_date)
                        propositions.append(prop)
                
                await browser.close()
            
            return propositions
            
        except ImportError:
            self.logger.error("Playwright not installed. Run: pip install playwright && playwright install chromium")
            return []
        except Exception as e:
            self.logger.error(f"ANVISA search failed: {str(e)}")
            return []
    
    def _parse_date(self, date_text: str) -> Optional[datetime]:
        """Parse Brazilian date formats"""
        if not date_text:
            return None
            
        date_text = date_text.strip().lower()
        
        # Try regex patterns
        for pattern in DOCUMENT_TYPE_PATTERNS.get('date', []):
            match = re.search(pattern, date_text)
            if match:
                try:
                    # Handle DD/MM/YYYY
                    if len(match.groups()) == 3:
                        day, month, year = match.groups()
                        if month.isalpha():
                            month = MONTH_NAMES.get(month.lower(), 0)
                        return datetime(int(year), int(month), int(day))
                except:
                    pass
        
        return None


class ANSService(RegulatoryAgencyService):
    """ANS - Agência Nacional de Saúde Suplementar"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANS",
            DataSource.ANS,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANS"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANS website with improved error handling"""
        breaker = circuit_manager.get_breaker("ans", CircuitBreakerConfig())
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANS search failed: {e}")
            return []


class ANAService(RegulatoryAgencyService):
    """ANA - Agência Nacional de Águas"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANA",
            DataSource.ANA,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANA"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANA website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("ana", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANA search failed: {e}")
            return []


class ANCINEService(RegulatoryAgencyService):
    """ANCINE - Agência Nacional do Cinema"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANCINE",
            DataSource.ANCINE,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANCINE"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANCINE website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("ancine", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANCINE search failed: {e}")
            return []


class ANTTService(RegulatoryAgencyService):
    """ANTT - Agência Nacional de Transportes Terrestres"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANTT",
            DataSource.ANTT,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANTT"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANTT website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("antt", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANTT search failed: {e}")
            return []


class ANTAQService(RegulatoryAgencyService):
    """ANTAQ - Agência Nacional de Transportes Aquaviários"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANTAQ",
            DataSource.ANTAQ,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANTAQ"]
    
    @retry_on_failure(max_retries=3) 
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANTAQ website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("antaq", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANTAQ search failed: {e}")
            return []


class ANACService(RegulatoryAgencyService):
    """ANAC - Agência Nacional de Aviação Civil"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANAC",
            DataSource.ANAC,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANAC"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANAC website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("anac", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANAC search failed: {e}")
            return []


class ANPService(RegulatoryAgencyService):
    """ANP - Agência Nacional do Petróleo"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANP",
            DataSource.ANP,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANP"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANP website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("anp", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANP search failed: {e}")
            return []


class ANMService(RegulatoryAgencyService):
    """ANM - Agência Nacional de Mineração"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANM",
            DataSource.ANM,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANM"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANM website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("anm", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._generic_gov_br_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANM search failed: {e}")
            return []


class ANEELService(RegulatoryAgencyService):
    """ANEEL - Agência Nacional de Energia Elétrica"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config, 
            "ANEEL", 
            DataSource.ANEEL,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANEEL"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANEEL website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("aneel", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300  # 5 minutes
        ))
        
        try:
            return await breaker.execute(self._do_aneel_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANEEL search failed: {e}")
            return []
    
    async def _do_aneel_search(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Actual ANEEL search implementation"""
        # Try multiple URL patterns for ANEEL
        urls_to_try = [
            "https://www.gov.br/aneel/pt-br/assuntos/consultas-publicas",
            "https://www.aneel.gov.br/consultas-publicas",
            "https://www2.aneel.gov.br/aplicacoes/consulta_publica/consulta_publica_cfm.cfm"
        ]
        
        for url in urls_to_try:
            try:
                html = await fetch_with_retry(url, max_retries=2)
                results = await self._parse_aneel_html(html, query)
                if results:
                    return results
            except Exception as e:
                self.logger.warning(f"ANEEL URL {url} failed: {e}")
                continue
        
        return []
    
    async def _parse_aneel_html(self, html: str, query: str) -> List[Proposition]:
        """Parse ANEEL HTML for consultation results"""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'html.parser')
        propositions = []
        
        # Try different selectors for ANEEL content
        selectors = [
            ".tileItem",
            "article",
            ".consulta-item",
            ".resultado-item",
            "[class*='consulta']"
        ]
        
        for selector in selectors:
            items = soup.select(selector)
            if items:
                for item in items[:10]:  # Limit to 10 results
                    text = item.get_text().lower()
                    if not query or query.lower() in text:
                        title_elem = item.select_one("h2, h3, h4, .title, .titulo")
                        if title_elem:
                            title = title_elem.get_text(strip=True)
                            link = item.select_one("a")
                            url = link.get('href', '') if link else ''
                            if url and not url.startswith('http'):
                                url = f"https://www.gov.br{url}"
                            
                            prop = self._create_proposition(title, text[:500], url)
                            propositions.append(prop)
                
                if propositions:
                    break
        
        return propositions


class ANATELService(RegulatoryAgencyService):
    """ANATEL - Agência Nacional de Telecomunicações"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(
            config,
            "ANATEL",
            DataSource.ANATEL,
            cache_manager
        )
        self.scraper_config = REGULATORY_SCRAPERS["ANATEL"]
    
    @retry_on_failure(max_retries=3)
    async def _search_website(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Search ANATEL website with circuit breaker protection"""
        breaker = circuit_manager.get_breaker("anatel", CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300
        ))
        
        try:
            return await breaker.execute(self._do_anatel_search, query, filters)
        except Exception as e:
            self.logger.error(f"ANATEL search failed: {e}")
            return []
    
    async def _do_anatel_search(self, query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Actual ANATEL search implementation"""
        # ANATEL has different possible URLs
        urls_to_try = [
            "https://www.gov.br/anatel/pt-br/assuntos/consultas-publicas",
            "https://sistemas.anatel.gov.br/SACP/Contribuicoes/TextoConsulta.asp",
            "https://www.anatel.gov.br/consumidor/consultas-publicas"
        ]
        
        for url in urls_to_try:
            try:
                html = await fetch_with_retry(url, max_retries=2)
                results = await self._parse_anatel_html(html, query)
                if results:
                    return results
            except Exception as e:
                self.logger.warning(f"ANATEL URL {url} failed: {e}")
                continue
        
        return []
    
    async def _parse_anatel_html(self, html: str, query: str) -> List[Proposition]:
        """Parse ANATEL HTML for consultation results"""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'html.parser')
        propositions = []
        
        # ANATEL might use table structure
        table = soup.select_one("table.tabela, .table, table")
        if table:
            rows = table.select("tr")
            for row in rows[1:11]:  # Skip header, limit to 10
                cells = row.select("td")
                if len(cells) >= 2:
                    text = row.get_text().lower()
                    if not query or query.lower() in text:
                        title = cells[0].get_text(strip=True) if cells else "Resolução ANATEL"
                        link = row.select_one("a")
                        url = link.get('href', '') if link else ''
                        
                        prop = self._create_proposition(title, text[:300], url)
                        propositions.append(prop)
        
        # Try alternative structure
        if not propositions:
            items = soup.select(".tileItem, article, .item")
            for item in items[:5]:
                text = item.get_text().lower()
                if not query or query.lower() in text:
                    title_elem = item.select_one("h2, h3, .title")
                    title = title_elem.get_text(strip=True) if title_elem else "Consulta ANATEL"
                    
                    prop = self._create_proposition(title, text[:300], "")
                    propositions.append(prop)
        
        return propositions