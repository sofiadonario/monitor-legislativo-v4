"""
Base service class for all API integrations
"""

import logging
import time
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Union
from functools import wraps
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config.config import APIConfig
from ..models.models import SearchResult, Proposition
from ..utils.smart_cache import smart_cache
from ..utils.circuit_breaker import circuit_manager, CircuitBreakerError
from ..utils.monitoring import metrics_collector


def retry_on_failure(max_retries: int = 3, backoff_factor: float = 0.5):
    """Decorator for retrying failed API calls with exponential backoff"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor * (2 ** attempt)
                        logging.warning(
                            f"Attempt {attempt + 1} failed: {str(e)}. "
                            f"Retrying in {wait_time} seconds..."
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logging.error(f"All {max_retries} attempts failed: {str(e)}")
            raise last_exception
            
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor * (2 ** attempt)
                        logging.warning(
                            f"Attempt {attempt + 1} failed: {str(e)}. "
                            f"Retrying in {wait_time} seconds..."
                        )
                        time.sleep(wait_time)
                    else:
                        logging.error(f"All {max_retries} attempts failed: {str(e)}")
            raise last_exception
            
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator


class BaseAPIService(ABC):
    """Base class for API service implementations"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        self.config = config
        self.cache_manager = cache_manager  # For compatibility, but we'll use smart_cache
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configure sessions with retry strategy
        self.session = self._create_session()
        self._aiohttp_session: Optional[aiohttp.ClientSession] = None
        
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry configuration"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.retry_count,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],  # Updated from method_whitelist
            backoff_factor=0.5
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            "User-Agent": "Monitor-Legislativo/4.0 (https://github.com/mackintegridade)",
            **self.config.headers
        })
        
        return session
    
    @abstractmethod
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search for propositions based on query and filters"""
        pass
    
    @abstractmethod
    async def get_proposition_details(self, proposition_id: str) -> Optional[Proposition]:
        """Get detailed information about a specific proposition"""
        pass
    
    @abstractmethod
    async def check_health(self) -> bool:
        """Check if the API is healthy and responding"""
        pass
    
    async def _get_aiohttp_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session using SessionFactory"""
        from ..utils.session_factory import SessionFactory
        return await SessionFactory.get_session()
    
    async def _make_async_request(self, url: str, params: Dict[str, Any] = None,
                                 method: str = "GET", data: Any = None,
                                 json: Any = None) -> Union[dict, str]:
        """Make an async HTTP request with circuit breaker and monitoring"""
        start_time = time.time()
        source_name = self.config.name if hasattr(self, 'config') else 'unknown'
        
        try:
            # Use circuit breaker
            return await circuit_manager.call_with_breaker(
                f"{source_name}_async",
                self._execute_async_request,
                url, params, method, data, json
            )
            
        except CircuitBreakerOpenError:
            # Circuit breaker is open
            response_time = time.time() - start_time
            metrics_collector.record_api_call(
                source=source_name,
                endpoint=url,
                method=method,
                response_time=response_time,
                success=False,
                error_message="Circuit breaker open"
            )
            raise
        except Exception as e:
            # Record failed request
            response_time = time.time() - start_time
            metrics_collector.record_api_call(
                source=source_name,
                endpoint=url,
                method=method,
                response_time=response_time,
                success=False,
                error_message=str(e)
            )
            raise
    
    async def _execute_async_request(self, url: str, params: Dict[str, Any] = None,
                                    method: str = "GET", data: Any = None,
                                    json: Any = None) -> Union[dict, str]:
        """Execute the actual async request"""
        start_time = time.time()
        source_name = self.config.name if hasattr(self, 'config') else 'unknown'
        session = await self._get_aiohttp_session()
        
        try:
            async with session.request(
                method, url, params=params, data=data, json=json
            ) as response:
                response.raise_for_status()
                
                # Try to return JSON, fallback to text
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    result = await response.json()
                else:
                    result = await response.text()
                
                # Record successful request
                response_time = time.time() - start_time
                result_count = len(result) if isinstance(result, (list, dict)) else 1
                metrics_collector.record_api_call(
                    source=source_name,
                    endpoint=url,
                    method=method,
                    status_code=response.status,
                    response_time=response_time,
                    success=True,
                    result_count=result_count
                )
                
                return result
                
        except asyncio.TimeoutError:
            self.logger.error(f"Request timeout for {url}")
            raise
        except aiohttp.ClientError as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            raise
    
    def _make_request(self, url: str, params: Dict[str, Any] = None, 
                     timeout: Optional[int] = None) -> requests.Response:
        """Make a sync HTTP request with circuit breaker and monitoring"""
        start_time = time.time()
        source_name = self.config.name if hasattr(self, 'config') else 'unknown'
        timeout = timeout or self.config.timeout
        
        try:
            # Use circuit breaker for sync requests
            return circuit_manager.call_with_breaker(
                f"{source_name}_sync",
                self._execute_sync_request,
                url, params, timeout
            )
            
        except CircuitBreakerOpenError:
            # Circuit breaker is open
            response_time = time.time() - start_time
            metrics_collector.record_api_call(
                source=source_name,
                endpoint=url,
                method="GET",
                response_time=response_time,
                success=False,
                error_message="Circuit breaker open"
            )
            raise
        except Exception as e:
            # Record failed request
            response_time = time.time() - start_time
            metrics_collector.record_api_call(
                source=source_name,
                endpoint=url,
                method="GET",
                response_time=response_time,
                success=False,
                error_message=str(e)
            )
            raise
    
    def _execute_sync_request(self, url: str, params: Dict[str, Any] = None,
                             timeout: Optional[int] = None) -> requests.Response:
        """Execute the actual sync request"""
        start_time = time.time()
        source_name = self.config.name if hasattr(self, 'config') else 'unknown'
        
        try:
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            
            # Record successful request
            response_time = time.time() - start_time
            metrics_collector.record_api_call(
                source=source_name,
                endpoint=url,
                method="GET",
                status_code=response.status_code,
                response_time=response_time,
                success=True,
                result_count=1
            )
            
            return response
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout for {url}")
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            raise
    
    def _get_cache_key(self, query: str, filters: Dict[str, Any]) -> str:
        """Generate a cache key for the search query"""
        import hashlib
        import json
        
        cache_data = {
            "service": self.config.name,
            "query": query,
            "filters": filters
        }
        
        return hashlib.md5(
            json.dumps(cache_data, sort_keys=True).encode()
        ).hexdigest()
    
    def _standardize_date(self, date_str: str) -> Optional[str]:
        """Standardize date format to ISO 8601"""
        from datetime import datetime
        
        if not date_str:
            return None
            
        # Try common date formats
        formats = [
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%d-%m-%Y",
            "%Y/%m/%d",
            "%d.%m.%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ"
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
        
        self.logger.warning(f"Could not parse date: {date_str}")
        return date_str
    
    async def close(self):
        """Close any open sessions"""
        try:
            if hasattr(self, '_aiohttp_session') and self._aiohttp_session and not self._aiohttp_session.closed:
                await self._aiohttp_session.close()
        except Exception:
            pass  # Ignore closing errors
    
    def __del__(self):
        """Cleanup on deletion"""
        if hasattr(self, '_aiohttp_session') and self._aiohttp_session and not self._aiohttp_session.closed:
            try:
                asyncio.create_task(self._aiohttp_session.close())
            except RuntimeError:
                # Event loop might be closed
                pass