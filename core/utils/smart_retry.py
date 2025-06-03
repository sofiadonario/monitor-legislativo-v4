"""
Smart Retry and Error Recovery System
Implements advanced fallback strategies from monitor-legislativo-analysis.md
"""

import asyncio
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import aiohttp
import logging

from .circuit_breaker import circuit_manager, CircuitBreakerConfig
from .session_factory import SessionFactory


class ErrorType(Enum):
    """Types of errors we can handle"""
    NOT_FOUND = "404"
    SERVICE_UNAVAILABLE = "503"
    TIMEOUT = "timeout"
    SSL_ERROR = "ssl"
    CONNECTION_ERROR = "connection"
    PARSING_ERROR = "parsing"
    JAVASCRIPT_ERROR = "javascript"


class FallbackStrategy(Enum):
    """Fallback strategy types"""
    ALTERNATIVE_URL = "alternative_url"
    CACHED_RESULT = "cached_result"
    MANUAL_QUEUE = "manual_queue"
    SIMPLIFIED_PARSING = "simplified_parsing"
    BYPASS_JAVASCRIPT = "bypass_javascript"


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    timeout_multiplier: float = 1.5


@dataclass
class FallbackOption:
    """Individual fallback option"""
    strategy: FallbackStrategy
    url: Optional[str] = None
    parser: Optional[Callable] = None
    timeout: Optional[int] = None
    headers: Optional[Dict[str, str]] = None
    priority: int = 1  # Lower number = higher priority


class SmartRetry:
    """
    Intelligent retry system with multiple fallback strategies
    Implements recommendations for enhanced scraper resilience
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Strategy handlers
        self.error_handlers = {
            ErrorType.NOT_FOUND: self._handle_not_found,
            ErrorType.SERVICE_UNAVAILABLE: self._handle_service_unavailable,
            ErrorType.TIMEOUT: self._handle_timeout,
            ErrorType.SSL_ERROR: self._handle_ssl_error,
            ErrorType.CONNECTION_ERROR: self._handle_connection_error,
            ErrorType.PARSING_ERROR: self._handle_parsing_error,
            ErrorType.JAVASCRIPT_ERROR: self._handle_javascript_error
        }
        
        # Fallback URLs for each source
        self.fallback_urls = {
            'aneel': [
                "https://www.gov.br/aneel/pt-br/assuntos/consultas-publicas",
                "https://www.aneel.gov.br/consultas-publicas",
                "https://www2.aneel.gov.br/aplicacoes/consulta_publica/consulta_publica_cfm.cfm"
            ],
            'anatel': [
                "https://www.gov.br/anatel/pt-br/assuntos/consultas-publicas",
                "https://sistemas.anatel.gov.br/SACP/Contribuicoes/TextoConsulta.asp",
                "https://www.anatel.gov.br/consumidor/consultas-publicas"
            ],
            'anvisa': [
                "https://consultas.anvisa.gov.br/#/consultas/q/?mapaTematico=true",
                "https://www.gov.br/anvisa/pt-br/assuntos/regulamentacao/consultas-publicas",
                "https://consultas.anvisa.gov.br/"
            ],
            'ans': [
                "https://www.gov.br/ans/pt-br/assuntos/participacao-da-sociedade/consultas-publicas",
                "https://www.ans.gov.br/participacao-da-sociedade/consultas-publicas"
            ],
            'ana': [
                "https://www.gov.br/ana/pt-br/acesso-a-informacao/participacao-social/consulta-publica",
                "https://www.ana.gov.br/acesso-a-informacao/consulta-publica"
            ]
        }
        
        # Adaptive URL learning
        self.url_success_rates: Dict[str, Dict[str, float]] = {}
        self.last_successful_urls: Dict[str, str] = {}
        
        # Manual intervention queue
        self.manual_queue: List[Dict[str, Any]] = []
        
        # Cache for failed attempts
        self.failure_cache: Dict[str, Dict[str, Any]] = {}
    
    async def execute_with_fallback(self, 
                                  source: str,
                                  primary_function: Callable,
                                  *args,
                                  config: Optional[RetryConfig] = None,
                                  **kwargs) -> Any:
        """
        Execute function with comprehensive fallback strategies
        """
        if config is None:
            config = RetryConfig()
        
        last_exception = None
        
        # Strategy 1: Try primary function with smart retry
        try:
            return await self._retry_with_backoff(
                primary_function, *args, config=config, **kwargs
            )
        except Exception as e:
            last_exception = e
            self.logger.warning(f"Primary function failed for {source}: {e}")
        
        # Strategy 2: Try fallback URLs
        if source in self.fallback_urls:
            for fallback_url in self._get_ordered_fallback_urls(source):
                try:
                    # Update URL in kwargs if it's a scraping function
                    if 'url' in kwargs:
                        kwargs['url'] = fallback_url
                    elif len(args) > 0 and isinstance(args[0], str) and args[0].startswith('http'):
                        args = (fallback_url,) + args[1:]
                    
                    result = await self._retry_with_backoff(
                        primary_function, *args, config=config, **kwargs
                    )
                    
                    # Update success tracking
                    self._record_url_success(source, fallback_url)
                    return result
                    
                except Exception as e:
                    self._record_url_failure(source, fallback_url)
                    self.logger.warning(f"Fallback URL {fallback_url} failed for {source}: {e}")
                    continue
        
        # Strategy 3: Try cached result with warning
        cached_result = await self._try_cached_fallback(source, *args, **kwargs)
        if cached_result is not None:
            self.logger.warning(f"Using cached fallback for {source}")
            return cached_result
        
        # Strategy 4: Add to manual intervention queue
        await self._add_to_manual_queue(source, str(last_exception), *args, **kwargs)
        
        # Final fallback: return empty result
        self.logger.error(f"All fallback strategies failed for {source}")
        return self._get_empty_result(source)
    
    async def _retry_with_backoff(self,
                                func: Callable,
                                *args,
                                config: RetryConfig,
                                **kwargs) -> Any:
        """Execute function with exponential backoff retry"""
        last_exception = None
        
        for attempt in range(config.max_retries + 1):
            try:
                # Adjust timeout for retries
                if 'timeout' in kwargs and attempt > 0:
                    kwargs['timeout'] *= config.timeout_multiplier
                
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
                    
            except Exception as e:
                last_exception = e
                
                if attempt < config.max_retries:
                    # Calculate delay with exponential backoff
                    delay = min(
                        config.base_delay * (config.exponential_base ** attempt),
                        config.max_delay
                    )
                    
                    # Add jitter to prevent thundering herd
                    if config.jitter:
                        delay *= (0.5 + random.random() * 0.5)
                    
                    self.logger.debug(f"Retry {attempt + 1} in {delay:.1f}s: {e}")
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(f"All retries exhausted: {e}")
        
        raise last_exception
    
    async def _handle_not_found(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle 404 Not Found errors"""
        self.logger.warning(f"404 Not Found for {source}, trying fallback URLs")
        
        # Mark current URL as potentially broken
        if source in self.last_successful_urls:
            self._record_url_failure(source, self.last_successful_urls[source])
        
        # Try alternative URLs
        if source in self.fallback_urls:
            for alt_url in self.fallback_urls[source]:
                try:
                    # Test URL availability first
                    if await self._test_url_availability(alt_url):
                        self.last_successful_urls[source] = alt_url
                        return alt_url  # Return new URL to try
                except Exception as e:
                    self.logger.debug(f"Alternative URL {alt_url} also failed: {e}")
                    continue
        
        return None
    
    async def _handle_service_unavailable(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle 503 Service Unavailable errors"""
        self.logger.warning(f"Service unavailable for {source}, implementing circuit breaker")
        
        # Get or create circuit breaker for this source
        breaker = circuit_manager.get_breaker(
            f"{source}_service_unavailable",
            CircuitBreakerConfig(failure_threshold=2, recovery_timeout=300)
        )
        
        # If circuit is open, return cached result
        if breaker.state.value == "open":
            return await self._try_cached_fallback(source, *args, **kwargs)
        
        return None
    
    async def _handle_timeout(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle timeout errors"""
        self.logger.warning(f"Timeout for {source}, trying with increased timeout")
        
        # Increase timeout and try again
        if 'timeout' in kwargs:
            kwargs['timeout'] = min(kwargs['timeout'] * 2, 120)  # Max 2 minutes
        
        return kwargs
    
    async def _handle_ssl_error(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle SSL certificate errors"""
        self.logger.warning(f"SSL error for {source}, trying with relaxed SSL")
        
        # Try with SSL verification disabled
        if 'ssl' not in kwargs:
            kwargs['ssl'] = False
        
        return kwargs
    
    async def _handle_connection_error(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle connection errors"""
        self.logger.warning(f"Connection error for {source}, trying fresh session")
        
        # Force new session
        await SessionFactory.get_fresh_session()
        
        return None
    
    async def _handle_parsing_error(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle HTML/XML parsing errors"""
        self.logger.warning(f"Parsing error for {source}, trying simplified parsing")
        
        # Try simplified parsing strategy
        kwargs['simple_parsing'] = True
        return kwargs
    
    async def _handle_javascript_error(self, source: str, error: Exception, *args, **kwargs) -> Any:
        """Handle JavaScript rendering errors"""
        self.logger.warning(f"JavaScript error for {source}, trying without JS")
        
        # Try without JavaScript rendering
        kwargs['no_javascript'] = True
        return kwargs
    
    def _get_ordered_fallback_urls(self, source: str) -> List[str]:
        """Get fallback URLs ordered by success rate"""
        if source not in self.fallback_urls:
            return []
        
        urls = self.fallback_urls[source]
        
        # Sort by success rate (highest first)
        success_rates = self.url_success_rates.get(source, {})
        return sorted(urls, key=lambda url: success_rates.get(url, 0.5), reverse=True)
    
    def _record_url_success(self, source: str, url: str):
        """Record successful URL usage"""
        if source not in self.url_success_rates:
            self.url_success_rates[source] = {}
        
        current_rate = self.url_success_rates[source].get(url, 0.5)
        # Exponential moving average
        self.url_success_rates[source][url] = current_rate * 0.9 + 0.1 * 1.0
        
        self.last_successful_urls[source] = url
    
    def _record_url_failure(self, source: str, url: str):
        """Record failed URL usage"""
        if source not in self.url_success_rates:
            self.url_success_rates[source] = {}
        
        current_rate = self.url_success_rates[source].get(url, 0.5)
        # Exponential moving average
        self.url_success_rates[source][url] = current_rate * 0.9 + 0.1 * 0.0
    
    async def _test_url_availability(self, url: str) -> bool:
        """Test if URL is available"""
        try:
            session = await SessionFactory.get_session()
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                return response.status < 400
        except Exception:
            return False
    
    async def _try_cached_fallback(self, source: str, *args, **kwargs) -> Optional[Any]:
        """Try to return cached result as fallback"""
        from .smart_cache import cached as smart_cache
        
        # Generate cache key from arguments
        cache_key = f"fallback_{source}_{hash(str(args) + str(sorted(kwargs.items())))}"
        
        cached_result = await smart_cache.get(cache_key, source=source)
        if cached_result is not None:
            self.logger.info(f"Using cached fallback result for {source}")
            # Mark result as potentially stale
            if hasattr(cached_result, 'metadata'):
                cached_result.metadata = cached_result.metadata or {}
                cached_result.metadata['fallback_cache'] = True
                cached_result.metadata['cache_timestamp'] = datetime.now().isoformat()
        
        return cached_result
    
    async def _add_to_manual_queue(self, source: str, error: str, *args, **kwargs):
        """Add failed request to manual intervention queue"""
        queue_item = {
            'id': f"{source}_{int(time.time())}",
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'error': error,
            'args': str(args),
            'kwargs': {k: str(v) for k, v in kwargs.items()},
            'status': 'pending',
            'priority': self._calculate_priority(source, error)
        }
        
        self.manual_queue.append(queue_item)
        
        # Keep queue manageable
        if len(self.manual_queue) > 1000:
            self.manual_queue = sorted(self.manual_queue, key=lambda x: x['priority'])[:1000]
        
        self.logger.error(f"Added to manual queue: {queue_item['id']}")
    
    def _calculate_priority(self, source: str, error: str) -> int:
        """Calculate priority for manual queue (lower = higher priority)"""
        # High priority sources
        if source in ['camara', 'senado']:
            return 1
        
        # Medium priority for major agencies
        if source in ['aneel', 'anvisa', 'anatel']:
            return 2
        
        # Lower priority for others
        return 3
    
    def _get_empty_result(self, source: str) -> Any:
        """Get appropriate empty result for source"""
        from ..models.models import SearchResult, DataSource
        
        # Return empty SearchResult
        return SearchResult(
            query="",
            filters={},
            propositions=[],
            total_count=0,
            source=getattr(DataSource, source.upper(), DataSource.UNKNOWN),
            error="All fallback strategies failed",
            search_time=0.0,
            metadata={'fallback_failure': True, 'timestamp': datetime.now().isoformat()}
        )
    
    def get_manual_queue(self) -> List[Dict[str, Any]]:
        """Get current manual intervention queue"""
        return sorted(self.manual_queue, key=lambda x: (x['priority'], x['timestamp']))
    
    def resolve_manual_item(self, item_id: str, resolution: str = "resolved"):
        """Mark manual queue item as resolved"""
        for item in self.manual_queue:
            if item['id'] == item_id:
                item['status'] = resolution
                item['resolved_at'] = datetime.now().isoformat()
                break
    
    def get_url_statistics(self) -> Dict[str, Dict[str, float]]:
        """Get URL success rate statistics"""
        return dict(self.url_success_rates)


# Global smart retry instance
smart_retry = SmartRetry()