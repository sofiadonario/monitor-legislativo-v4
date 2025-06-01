"""Secure base service with SSL verification and security improvements."""

import logging
from typing import Any, Dict, Optional
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from core.config.secure_config import SecureConfig
from core.utils.circuit_breaker import CircuitBreaker

logger = logging.getLogger(__name__)


class SecureAPIError(Exception):
    """Base exception for secure API operations."""
    pass


class SecureBaseService:
    """Base service class with security improvements and SSL verification."""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.config = SecureConfig.get_api_config().get(service_name, {})
        self.session = self._create_secure_session()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=requests.RequestException
        )
    
    def _create_secure_session(self) -> requests.Session:
        """Create a secure session with retry logic and SSL verification."""
        session = requests.Session()
        
        # Always verify SSL certificates
        session.verify = True
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.get('retry_count', 3),
            backoff_factor=self.config.get('retry_delay', 1),
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # Set default timeout
        session.timeout = self.config.get('timeout', 30)
        
        # Add API key if configured
        if self.config.get('api_key'):
            session.headers.update({
                'Authorization': f"Bearer {self.config['api_key']}"
            })
        
        # Add security headers
        session.headers.update({
            'User-Agent': 'Legislative-Monitor/1.0',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def _validate_url(self, url: str) -> None:
        """Validate URL to prevent SSRF attacks."""
        if not url.startswith(('http://', 'https://')):
            raise SecureAPIError(f"Invalid URL scheme: {url}")
        
        # Check against allowed domains
        allowed_domains = [
            'camara.leg.br',
            'senado.leg.br',
            'planalto.gov.br',
            'anatel.gov.br',
            'aneel.gov.br',
            'anvisa.gov.br',
        ]
        
        if not any(domain in url for domain in allowed_domains):
            raise SecureAPIError(f"URL not in allowed domains: {url}")
    
    def _sanitize_params(self, params: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Sanitize parameters to prevent injection attacks."""
        if not params:
            return params
        
        sanitized = {}
        for key, value in params.items():
            # Remove any potentially dangerous characters
            if isinstance(value, str):
                # Basic sanitization - expand based on specific needs
                sanitized[key] = value.replace(';', '').replace('|', '').replace('&', '')
            else:
                sanitized[key] = value
        
        return sanitized
    
    @CircuitBreaker.call
    def make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> requests.Response:
        """Make a secure HTTP request with circuit breaker protection."""
        url = f"{self.config['base_url']}/{endpoint.lstrip('/')}"
        
        # Validate URL
        self._validate_url(url)
        
        # Sanitize parameters
        params = self._sanitize_params(params)
        
        # Log request (without sensitive data)
        logger.info(f"{method} request to {self.service_name}: {endpoint}")
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                timeout=kwargs.get('timeout', self.config.get('timeout', 30)),
                **kwargs
            )
            
            # Check for successful response
            response.raise_for_status()
            
            # Log successful response
            logger.info(f"Successful response from {self.service_name}: {response.status_code}")
            
            return response
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL verification failed for {url}: {e}")
            raise SecureAPIError(f"SSL verification failed: {e}")
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Request timeout for {url}: {e}")
            raise SecureAPIError(f"Request timeout: {e}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            raise SecureAPIError(f"Request failed: {e}")
    
    def get(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make a GET request."""
        response = self.make_request('GET', endpoint, **kwargs)
        return response.json()
    
    def post(self, endpoint: str, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Make a POST request."""
        response = self.make_request('POST', endpoint, data=data, **kwargs)
        return response.json()
    
    def put(self, endpoint: str, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Make a PUT request."""
        response = self.make_request('PUT', endpoint, data=data, **kwargs)
        return response.json()
    
    def delete(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make a DELETE request."""
        response = self.make_request('DELETE', endpoint, **kwargs)
        return response.json()
    
    def health_check(self) -> bool:
        """Check if the service is healthy."""
        try:
            # Make a simple request to check connectivity
            self.make_request('GET', '/', timeout=5)
            return True
        except Exception as e:
            logger.warning(f"Health check failed for {self.service_name}: {e}")
            return False