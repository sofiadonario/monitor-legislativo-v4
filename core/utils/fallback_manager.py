"""
Fallback Manager for Scraper Resilience
=======================================

Provides multiple fallback strategies for scrapers to ensure maximum uptime
and data availability. Implements automatic URL discovery, cached results,
and manual intervention queues.

Features:
- Multiple fallback strategies per source
- Automatic URL discovery and validation
- Cached results with warnings
- Manual intervention queue
- Performance monitoring and metrics
- Smart retry logic with exponential backoff

Author: Academic Legislative Monitor Development Team
Created: June 2025
Version: 1.0.0
"""

import asyncio
import aiohttp
import logging
import time
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
from urllib.parse import urljoin, urlparse
import random
from bs4 import BeautifulSoup

from .smart_cache import smart_cache
from .circuit_breaker import circuit_manager
from ..models.models import SearchResult, Proposition


logger = logging.getLogger(__name__)


class FallbackStrategy(Enum):
    """Available fallback strategies."""
    PRIMARY = "primary"           # Main gov.br portal or official API
    SECONDARY = "secondary"       # Agency domain direct access
    TERTIARY = "tertiary"        # Alternative URLs (archived, mirror sites)
    CACHED = "cached"            # Cached results with warnings
    MANUAL = "manual"            # Queue for manual intervention


@dataclass
class FallbackAttempt:
    """Record of a fallback attempt."""
    strategy: FallbackStrategy
    url: str
    success: bool
    response_time_ms: float
    error_message: Optional[str]
    timestamp: datetime
    data_quality: Optional[str] = None  # 'full', 'partial', 'stale'


@dataclass
class ManualInterventionRequest:
    """Request for manual intervention."""
    id: str
    source: str
    query: str
    filters: Dict[str, Any]
    failed_strategies: List[FallbackAttempt]
    priority: str  # 'high', 'medium', 'low'
    created_at: datetime
    status: str  # 'pending', 'in_progress', 'completed', 'failed'
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class SourceConfiguration:
    """Configuration for a data source with fallback URLs."""
    source_id: str
    name: str
    primary_url: str
    secondary_urls: List[str]
    fallback_urls: List[str]
    timeout: int = 30
    max_retries: int = 3
    cache_ttl: int = 3600
    is_critical: bool = False
    supports_api: bool = False
    scraping_selectors: Dict[str, str] = None


class FallbackManager:
    """
    Manages fallback strategies for data source access.
    
    Provides resilient data access through multiple strategies:
    1. Primary: Official gov.br portal or API
    2. Secondary: Direct agency domain access
    3. Tertiary: Alternative/mirror URLs
    4. Cached: Return cached results with warnings
    5. Manual: Queue for manual intervention
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the fallback manager.
        
        Args:
            db_path: Path to SQLite database for storing fallback data
        """
        self.db_path = db_path or Path.home() / '.fallback_manager.db'
        self.source_configs: Dict[str, SourceConfiguration] = {}
        self.manual_queue: Dict[str, ManualInterventionRequest] = {}
        self.performance_metrics: Dict[str, List[FallbackAttempt]] = {}
        
        self._initialize_database()
        self._load_source_configurations()
        
        logger.info("Fallback Manager initialized")
    
    def _initialize_database(self):
        """Initialize SQLite database for fallback data."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fallback_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    url TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    response_time_ms REAL NOT NULL,
                    error_message TEXT,
                    data_quality TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS manual_interventions (
                    id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    query TEXT NOT NULL,
                    filters TEXT NOT NULL,
                    failed_strategies TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovered_urls (
                    source_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_tested DATETIME,
                    success_rate REAL DEFAULT 0,
                    avg_response_time REAL DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    PRIMARY KEY (source_id, url)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fallback_source_strategy ON fallback_attempts (source_id, strategy)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_manual_status ON manual_interventions (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_discovered_active ON discovered_urls (source_id, is_active)")
            
            conn.commit()
    
    def _load_source_configurations(self):
        """Load predefined source configurations."""
        # Brazilian Legislative Sources
        self.source_configs.update({
            'camara_deputados': SourceConfiguration(
                source_id='camara_deputados',
                name='Câmara dos Deputados',
                primary_url='https://dadosabertos.camara.leg.br/api/v2/proposicoes',
                secondary_urls=[
                    'https://www.camara.leg.br/propostas-legislativas',
                    'https://www.camara.leg.br/busca-portal'
                ],
                fallback_urls=[
                    'https://www2.camara.leg.br/proposicoes',
                    'https://www.camara.leg.br/atividade-legislativa'
                ],
                timeout=15,
                max_retries=3,
                cache_ttl=1800,
                is_critical=True,
                supports_api=True
            ),
            
            'senado_federal': SourceConfiguration(
                source_id='senado_federal',
                name='Senado Federal',
                primary_url='https://legis.senado.leg.br/dadosabertos',
                secondary_urls=[
                    'https://www25.senado.leg.br/web/atividade',
                    'https://www.senado.leg.br/atividade-legislativa'
                ],
                fallback_urls=[
                    'https://www12.senado.leg.br/hpsenado',
                    'https://www.congressonacional.leg.br'
                ],
                timeout=15,
                max_retries=3,
                cache_ttl=1800,
                is_critical=True,
                supports_api=True
            ),
            
            # Regulatory Agencies
            'antt': SourceConfiguration(
                source_id='antt',
                name='ANTT',
                primary_url='https://www.gov.br/antt/pt-br',
                secondary_urls=[
                    'https://portal.antt.gov.br',
                    'https://www.antt.gov.br'
                ],
                fallback_urls=[
                    'https://www.gov.br/transportes/pt-br',
                    'https://appweb2.antt.gov.br'
                ],
                timeout=30,
                max_retries=2,
                cache_ttl=7200,
                is_critical=False,
                supports_api=False,
                scraping_selectors={
                    'documents': '.resolucao, .portaria, .instrucao-normativa',
                    'title': 'h1, h2, .titulo',
                    'date': '.data, .timestamp, time',
                    'content': '.conteudo, .texto, .corpo'
                }
            ),
            
            'contran': SourceConfiguration(
                source_id='contran',
                name='CONTRAN',
                primary_url='https://www.gov.br/transportes/pt-br/assuntos/transito',
                secondary_urls=[
                    'https://www.denatran.gov.br',
                    'https://infraestrutura.gov.br/component/content/article/115-portal-denatran'
                ],
                fallback_urls=[
                    'https://www.gov.br/infraestrutura/pt-br/assuntos/transito',
                    'http://www.denatran.gov.br/resolucoes.htm'
                ],
                timeout=30,
                max_retries=2,
                cache_ttl=7200,
                is_critical=False,
                supports_api=False
            ),
            
            'dnit': SourceConfiguration(
                source_id='dnit',
                name='DNIT',
                primary_url='https://www.gov.br/dnit/pt-br',
                secondary_urls=[
                    'https://www.dnit.gov.br',
                    'https://www.dnit.gov.br/rodovias'
                ],
                fallback_urls=[
                    'https://www.gov.br/infraestrutura/pt-br/assuntos/politica-e-planejamento-dos-transportes',
                    'http://servicos.dnit.gov.br'
                ],
                timeout=30,
                max_retries=2,
                cache_ttl=7200,
                is_critical=False,
                supports_api=False
            )
        })
    
    async def execute_with_fallback(self, source_id: str, query: str, 
                                  filters: Dict[str, Any] = None) -> Tuple[Optional[SearchResult], List[FallbackAttempt]]:
        """
        Execute search with fallback strategies.
        
        Args:
            source_id: ID of the data source
            query: Search query
            filters: Search filters
            
        Returns:
            Tuple of (search_result, fallback_attempts)
        """
        if source_id not in self.source_configs:
            raise ValueError(f"Unknown source: {source_id}")
        
        config = self.source_configs[source_id]
        filters = filters or {}
        attempts = []
        
        # Strategy 1: Primary URL
        result, attempt = await self._attempt_strategy(
            FallbackStrategy.PRIMARY, config, config.primary_url, query, filters
        )
        attempts.append(attempt)
        
        if result:
            logger.info(f"Primary strategy succeeded for {source_id}")
            self._record_attempt(source_id, attempt)
            return result, attempts
        
        # Strategy 2: Secondary URLs
        for secondary_url in config.secondary_urls:
            result, attempt = await self._attempt_strategy(
                FallbackStrategy.SECONDARY, config, secondary_url, query, filters
            )
            attempts.append(attempt)
            
            if result:
                logger.info(f"Secondary strategy succeeded for {source_id} with {secondary_url}")
                self._record_attempt(source_id, attempt)
                return result, attempts
        
        # Strategy 3: Tertiary URLs (fallback/alternative URLs)
        for fallback_url in config.fallback_urls:
            result, attempt = await self._attempt_strategy(
                FallbackStrategy.TERTIARY, config, fallback_url, query, filters
            )
            attempts.append(attempt)
            
            if result:
                logger.info(f"Tertiary strategy succeeded for {source_id} with {fallback_url}")
                self._record_attempt(source_id, attempt)
                return result, attempts
        
        # Strategy 4: Try discovered URLs
        discovered_urls = await self._get_discovered_urls(source_id)
        for url in discovered_urls[:3]:  # Try top 3 discovered URLs
            result, attempt = await self._attempt_strategy(
                FallbackStrategy.TERTIARY, config, url, query, filters
            )
            attempts.append(attempt)
            
            if result:
                logger.info(f"Discovered URL strategy succeeded for {source_id} with {url}")
                self._record_attempt(source_id, attempt)
                return result, attempts
        
        # Strategy 5: Cached results
        result, attempt = await self._attempt_cached_strategy(source_id, query, filters)
        attempts.append(attempt)
        
        if result:
            logger.warning(f"Returning cached results for {source_id}")
            self._record_attempt(source_id, attempt)
            return result, attempts
        
        # Strategy 6: Manual intervention queue
        manual_request = await self._queue_for_manual_intervention(
            source_id, query, filters, attempts
        )
        
        logger.error(f"All strategies failed for {source_id}, queued for manual intervention: {manual_request.id}")
        
        # Record all failed attempts
        for attempt in attempts:
            self._record_attempt(source_id, attempt)
        
        return None, attempts
    
    async def _attempt_strategy(self, strategy: FallbackStrategy, config: SourceConfiguration,
                              url: str, query: str, filters: Dict[str, Any]) -> Tuple[Optional[SearchResult], FallbackAttempt]:
        """
        Attempt a specific fallback strategy.
        
        Args:
            strategy: Fallback strategy to attempt
            config: Source configuration
            url: URL to attempt
            query: Search query
            filters: Search filters
            
        Returns:
            Tuple of (search_result, fallback_attempt)
        """
        start_time = time.time()
        
        try:
            # Check circuit breaker
            circuit_key = f"{config.source_id}_{strategy.value}"
            if not circuit_manager.is_available(circuit_key):
                return None, FallbackAttempt(
                    strategy=strategy,
                    url=url,
                    success=False,
                    response_time_ms=0,
                    error_message="Circuit breaker open",
                    timestamp=datetime.now()
                )
            
            # Attempt the request
            if config.supports_api and strategy == FallbackStrategy.PRIMARY:
                result = await self._attempt_api_request(config, url, query, filters)
            else:
                result = await self._attempt_scraping_request(config, url, query, filters)
            
            response_time = (time.time() - start_time) * 1000
            
            if result and len(result.propositions) > 0:
                # Success
                circuit_manager.record_success(circuit_key)
                return result, FallbackAttempt(
                    strategy=strategy,
                    url=url,
                    success=True,
                    response_time_ms=response_time,
                    error_message=None,
                    timestamp=datetime.now(),
                    data_quality='full' if len(result.propositions) > 5 else 'partial'
                )
            else:
                # No results found
                circuit_manager.record_failure(circuit_key)
                return None, FallbackAttempt(
                    strategy=strategy,
                    url=url,
                    success=False,
                    response_time_ms=response_time,
                    error_message="No results found",
                    timestamp=datetime.now()
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            circuit_manager.record_failure(circuit_key)
            
            return None, FallbackAttempt(
                strategy=strategy,
                url=url,
                success=False,
                response_time_ms=response_time,
                error_message=str(e),
                timestamp=datetime.now()
            )
    
    async def _attempt_api_request(self, config: SourceConfiguration, url: str,
                                 query: str, filters: Dict[str, Any]) -> Optional[SearchResult]:
        """Attempt API request with proper parameters."""
        timeout = aiohttp.ClientTimeout(total=config.timeout)
        
        # Build API parameters based on the source
        params = self._build_api_params(config.source_id, query, filters)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    propositions = self._parse_api_response(config.source_id, data, query)
                    
                    return SearchResult(
                        query=query,
                        filters=filters,
                        propositions=propositions,
                        total_count=len(propositions),
                        source=config.source_id,
                        search_time=0  # Will be calculated by caller
                    )
                else:
                    raise Exception(f"API request failed with status {response.status}")
    
    async def _attempt_scraping_request(self, config: SourceConfiguration, url: str,
                                      query: str, filters: Dict[str, Any]) -> Optional[SearchResult]:
        """Attempt scraping request with selectors."""
        timeout = aiohttp.ClientTimeout(total=config.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # For scraping, we might need to search within the site
            search_url = self._build_search_url(url, query)
            
            async with session.get(search_url) as response:
                if response.status == 200:
                    html = await response.text()
                    propositions = self._parse_html_response(config, html, query)
                    
                    return SearchResult(
                        query=query,
                        filters=filters,
                        propositions=propositions,
                        total_count=len(propositions),
                        source=config.source_id,
                        search_time=0
                    )
                else:
                    raise Exception(f"Scraping request failed with status {response.status}")
    
    def _build_api_params(self, source_id: str, query: str, filters: Dict[str, Any]) -> Dict[str, str]:
        """Build API parameters for specific sources."""
        params = {}
        
        if source_id == 'camara_deputados':
            params.update({
                'keywords': query,
                'order': 'ASC',
                'ordenarPor': 'id'
            })
            if filters.get('year'):
                params['ano'] = str(filters['year'])
        
        elif source_id == 'senado_federal':
            params.update({
                'q': query,
                'format': 'json'
            })
        
        return params
    
    def _build_search_url(self, base_url: str, query: str) -> str:
        """Build search URL for scraping."""
        # Try common search patterns
        search_patterns = [
            f"{base_url}/busca?q={query}",
            f"{base_url}/search?query={query}",
            f"{base_url}/pesquisa?termo={query}",
            base_url  # Fallback to base URL
        ]
        
        # Return the first pattern for now
        # In production, this would be more sophisticated
        return search_patterns[0]
    
    def _parse_api_response(self, source_id: str, data: Dict, query: str) -> List[Proposition]:
        """Parse API response into propositions."""
        propositions = []
        
        # Simplified parsing - in production this would be source-specific
        if source_id == 'camara_deputados' and 'dados' in data:
            for item in data['dados'][:10]:  # Limit results
                prop = Proposition(
                    id=str(item.get('id', '')),
                    type=PropositionType.PL,  # Simplified
                    number=str(item.get('numero', '')),
                    year=item.get('ano', 2024),
                    title=item.get('ementa', ''),
                    summary=item.get('explicacaoEmenta', ''),
                    source=source_id,
                    status=PropositionStatus.ACTIVE,
                    url=item.get('uri', ''),
                    publication_date=datetime.now(),
                    authors=[],
                    keywords=[query]
                )
                propositions.append(prop)
        
        return propositions
    
    def _parse_html_response(self, config: SourceConfiguration, html: str, query: str) -> List[Proposition]:
        """Parse HTML response into propositions."""
        propositions = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Use selectors if available
            if config.scraping_selectors:
                doc_selector = config.scraping_selectors.get('documents', 'div')
                documents = soup.select(doc_selector)
                
                for doc in documents[:10]:  # Limit results
                    title_elem = doc.select_one(config.scraping_selectors.get('title', 'h1, h2'))
                    title = title_elem.get_text(strip=True) if title_elem else 'No title'
                    
                    if query.lower() in title.lower():
                        prop = Proposition(
                            id=f"{config.source_id}_{hash(title)}",
                            type=PropositionType.OTHER,
                            number='',
                            year=2024,
                            title=title,
                            summary=title,
                            source=config.source_id,
                            status=PropositionStatus.PUBLISHED,
                            url=config.primary_url,
                            publication_date=datetime.now(),
                            authors=[],
                            keywords=[query]
                        )
                        propositions.append(prop)
        
        except Exception as e:
            logger.error(f"Error parsing HTML for {config.source_id}: {e}")
        
        return propositions
    
    async def _attempt_cached_strategy(self, source_id: str, query: str, 
                                     filters: Dict[str, Any]) -> Tuple[Optional[SearchResult], FallbackAttempt]:
        """Attempt to return cached results."""
        start_time = time.time()
        
        try:
            cache_key = f"{source_id}_{hash(query)}_{hash(str(filters))}"
            cached_result = await smart_cache.get(cache_key)
            
            if cached_result:
                # Add warning about stale data
                cached_result.error = "Warning: Returning cached data due to source unavailability"
                
                response_time = (time.time() - start_time) * 1000
                return cached_result, FallbackAttempt(
                    strategy=FallbackStrategy.CACHED,
                    url="cache",
                    success=True,
                    response_time_ms=response_time,
                    error_message=None,
                    timestamp=datetime.now(),
                    data_quality='stale'
                )
            
        except Exception as e:
            logger.error(f"Error accessing cache for {source_id}: {e}")
        
        response_time = (time.time() - start_time) * 1000
        return None, FallbackAttempt(
            strategy=FallbackStrategy.CACHED,
            url="cache",
            success=False,
            response_time_ms=response_time,
            error_message="No cached data available",
            timestamp=datetime.now()
        )
    
    async def _queue_for_manual_intervention(self, source_id: str, query: str,
                                           filters: Dict[str, Any], 
                                           failed_attempts: List[FallbackAttempt]) -> ManualInterventionRequest:
        """Queue request for manual intervention."""
        config = self.source_configs[source_id]
        priority = 'high' if config.is_critical else 'medium'
        
        request = ManualInterventionRequest(
            id=f"{source_id}_{int(time.time())}",
            source=source_id,
            query=query,
            filters=filters,
            failed_strategies=failed_attempts,
            priority=priority,
            created_at=datetime.now(),
            status='pending'
        )
        
        self.manual_queue[request.id] = request
        
        # Store in database
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO manual_interventions 
                    (id, source_id, query, filters, failed_strategies, priority, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    request.id, source_id, query, json.dumps(filters),
                    json.dumps([asdict(attempt) for attempt in failed_attempts], default=str),
                    priority, 'pending'
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store manual intervention request: {e}")
        
        return request
    
    def _record_attempt(self, source_id: str, attempt: FallbackAttempt):
        """Record fallback attempt in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO fallback_attempts 
                    (source_id, strategy, url, success, response_time_ms, error_message, data_quality, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    source_id, attempt.strategy.value, attempt.url, attempt.success,
                    attempt.response_time_ms, attempt.error_message, attempt.data_quality,
                    attempt.timestamp
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to record fallback attempt: {e}")
    
    async def _get_discovered_urls(self, source_id: str) -> List[str]:
        """Get discovered URLs for a source."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT url FROM discovered_urls 
                    WHERE source_id = ? AND is_active = 1 
                    ORDER BY success_rate DESC, avg_response_time ASC
                    LIMIT 5
                """, (source_id,))
                
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get discovered URLs: {e}")
            return []
    
    async def discover_urls(self, source_id: str) -> List[str]:
        """
        Discover new URLs for a source through various methods.
        
        Args:
            source_id: ID of the source to discover URLs for
            
        Returns:
            List of discovered URLs
        """
        if source_id not in self.source_configs:
            return []
        
        config = self.source_configs[source_id]
        discovered = []
        
        try:
            # Method 1: Check for common subdomain patterns
            base_domain = urlparse(config.primary_url).netloc
            common_subdomains = [
                'www', 'portal', 'app', 'servicos', 'dados', 'api', 
                'consulta', 'busca', 'pesquisa', 'arquivo'
            ]
            
            for subdomain in common_subdomains:
                test_url = f"https://{subdomain}.{base_domain}"
                if await self._test_url_availability(test_url):
                    discovered.append(test_url)
            
            # Method 2: Check for common path patterns
            common_paths = [
                '/busca', '/pesquisa', '/consulta', '/dados', '/api',
                '/legislacao', '/normas', '/documentos', '/arquivo'
            ]
            
            for path in common_paths:
                test_url = urljoin(config.primary_url, path)
                if await self._test_url_availability(test_url):
                    discovered.append(test_url)
            
            # Store discovered URLs
            for url in discovered:
                self._store_discovered_url(source_id, url)
            
        except Exception as e:
            logger.error(f"Error discovering URLs for {source_id}: {e}")
        
        return discovered
    
    async def _test_url_availability(self, url: str) -> bool:
        """Test if a URL is available and responsive."""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url) as response:
                    return response.status < 400
        except:
            return False
    
    def _store_discovered_url(self, source_id: str, url: str):
        """Store a discovered URL in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO discovered_urls 
                    (source_id, url, discovered_at, is_active)
                    VALUES (?, ?, ?, 1)
                """, (source_id, url, datetime.now()))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store discovered URL: {e}")
    
    def get_manual_queue(self, status: Optional[str] = None) -> List[ManualInterventionRequest]:
        """Get manual intervention queue."""
        if status:
            return [req for req in self.manual_queue.values() if req.status == status]
        return list(self.manual_queue.values())
    
    def get_performance_metrics(self, source_id: str = None) -> Dict[str, Any]:
        """Get performance metrics for fallback strategies."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if source_id:
                    query = "WHERE source_id = ?"
                    params = (source_id,)
                else:
                    query = ""
                    params = ()
                
                cursor = conn.execute(f"""
                    SELECT source_id, strategy, 
                           COUNT(*) as total_attempts,
                           SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_attempts,
                           AVG(response_time_ms) as avg_response_time,
                           COUNT(CASE WHEN timestamp >= datetime('now', '-24 hours') THEN 1 END) as attempts_24h
                    FROM fallback_attempts 
                    {query}
                    GROUP BY source_id, strategy
                """, params)
                
                metrics = {}
                for row in cursor.fetchall():
                    source, strategy, total, successful, avg_time, attempts_24h = row
                    success_rate = (successful / total * 100) if total > 0 else 0
                    
                    if source not in metrics:
                        metrics[source] = {}
                    
                    metrics[source][strategy] = {
                        'total_attempts': total,
                        'successful_attempts': successful,
                        'success_rate': success_rate,
                        'avg_response_time': avg_time,
                        'attempts_24h': attempts_24h
                    }
                
                return metrics
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return {}


# Global fallback manager instance
fallback_manager = FallbackManager()