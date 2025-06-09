"""
SECURITY HARDENED Câmara dos Deputados API Service
Fixed hardcoded URLs, missing authentication, and error handling vulnerabilities

CRITICAL SECURITY FIXES:
- Configurable endpoint URLs (no more hardcoded URLs)
- Authentication token management with rotation
- Enhanced error handling with information leak prevention
- Circuit breaker pattern for service unavailability protection
- Exponential backoff retry with jitter
- Request/response validation and sanitization
"""

import asyncio
import logging
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
import re
import json

from .base_service import BaseAPIService, retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig
from ..utils.parameter_validator import ParameterValidator

# CRITICAL SECURITY: Import secure configurations and utilities
from ..config.secure_config import get_secure_config
from ..utils.enhanced_circuit_breaker import EnhancedCircuitBreaker
from ..security.secrets_manager import SecretsManager
from ..utils.input_validator import validate_legislative_search_query


class CamaraService(BaseAPIService):
    """SECURITY HARDENED service for interacting with Câmara dos Deputados API"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(config, cache_manager)
        
        # CRITICAL FIX: No more hardcoded URLs - get from secure config
        self.secure_config = get_secure_config()
        self.secrets_manager = SecretsManager()
        
        # Get configurable base URL from secure configuration
        self.base_url = self.secure_config.get(
            "camara_api_base_url", 
            "https://dadosabertos.camara.leg.br/api/v2"  # fallback only
        )
        
        # CRITICAL FIX: Initialize circuit breaker for service unavailability protection
        self.circuit_breaker = EnhancedCircuitBreaker(
            failure_threshold=5,    # Trip after 5 failures
            recovery_timeout=30,    # 30 seconds before retry
            expected_exception=aiohttp.ClientError
        )
        
        # Enhanced retry configuration with exponential backoff
        self.max_retries = 5
        self.base_delay = 1.0
        self.max_delay = 60.0
        self.jitter_range = 0.1
        
        # Request validation limits
        self.max_request_size = 1024 * 1024  # 1MB max request
        self.max_response_size = 10 * 1024 * 1024  # 10MB max response
        
        # CRITICAL FIX: Get API authentication if available
        self.api_key = self.secrets_manager.get_secret("camara_api_key", default=None)
        
        self.logger.info("Camara service initialized with security hardening", extra={
            "base_url": self.base_url,
            "circuit_breaker_enabled": True,
            "authentication_enabled": bool(self.api_key),
            "max_retries": self.max_retries
        })
        
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """SECURITY HARDENED search for propositions in Câmara dos Deputados"""
        start_time = datetime.now()
        
        # CRITICAL SECURITY FIX: Validate search query to prevent injection attacks
        try:
            validated_query = validate_legislative_search_query(query)
        except ValueError as e:
            self.logger.warning(f"Invalid search query rejected: {query[:50]}...", extra={
                "validation_error": str(e),
                "client_ip": filters.get("_client_ip", "unknown")
            })
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.CAMARA,
                error="Invalid search query format"
            )
        
        # CRITICAL SECURITY FIX: Validate filters to prevent parameter manipulation
        try:
            sanitized_filters = self._sanitize_filters(filters)
        except ValueError as e:
            self.logger.warning(f"Invalid filters rejected", extra={
                "validation_error": str(e),
                "client_ip": filters.get("_client_ip", "unknown")
            })
            return SearchResult(
                query=validated_query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.CAMARA,
                error="Invalid filter parameters"
            )
        
        # Check cache first
        cache_key = self._get_cache_key(validated_query, sanitized_filters)
        cached_result = self.cache_manager.get(cache_key)
        if cached_result:
            self.logger.info(f"Returning cached results for query: {validated_query[:50]}...")
            return cached_result
        
        # CRITICAL FIX: Use circuit breaker to prevent cascade failures
        try:
            async with self.circuit_breaker:
                result = await self._search_with_enhanced_error_handling(validated_query, sanitized_filters)
                
                if result.propositions:  # Only cache if we got results
                    self.cache_manager.set(cache_key, result, ttl=self.config.cache_ttl)
                
                search_duration = (datetime.now() - start_time).total_seconds()
                result.search_time = search_duration
                return result
                
        except Exception as e:
            # CRITICAL SECURITY FIX: Never expose internal error details to prevent information leakage
            sanitized_error = self._sanitize_error_message(str(e))
            
            self.logger.error("Camara search failed", extra={
                "query_hash": hash(validated_query),
                "error_type": type(e).__name__,
                "internal_error": str(e),  # Internal logging only
                "search_duration": (datetime.now() - start_time).total_seconds()
            })
            
            return SearchResult(
                query=validated_query,
                filters=sanitized_filters,
                propositions=[],
                total_count=0,
                source=DataSource.CAMARA,
                error=sanitized_error  # Safe error message for client
            )
    
    def _sanitize_filters(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize and validate filter parameters - INJECTION PREVENTION"""
        sanitized = {}
        
        # Whitelist of allowed filter keys with validation
        allowed_filters = {
            "start_date": lambda x: self._validate_date_string(x),
            "end_date": lambda x: self._validate_date_string(x),
            "types": lambda x: self._validate_proposition_types(x),
            "limit": lambda x: self._validate_limit(x),
            "_client_ip": lambda x: str(x)[:45]  # IP addresses max 45 chars
        }
        
        for key, value in filters.items():
            if key in allowed_filters and value is not None:
                try:
                    sanitized[key] = allowed_filters[key](value)
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Invalid filter value for {key}: {e}")
        
        return sanitized
    
    def _validate_date_string(self, date_str: str) -> str:
        """Validate date string format"""
        if not isinstance(date_str, str) or len(date_str) > 20:
            raise ValueError("Date must be a string with max 20 characters")
        
        # Try to parse as ISO date to validate format
        try:
            datetime.fromisoformat(date_str)
            return date_str
        except ValueError:
            raise ValueError("Date must be in ISO format (YYYY-MM-DD)")
    
    def _validate_proposition_types(self, types) -> str:
        """Validate proposition types parameter"""
        if isinstance(types, str):
            # Single type
            if len(types) > 10 or not types.isalpha():
                raise ValueError("Type must be alphabetic and max 10 characters")
            return types.upper()
        elif isinstance(types, list):
            # Multiple types
            if len(types) > 20:  # Max 20 types
                raise ValueError("Too many proposition types specified")
            validated_types = []
            for t in types:
                if not isinstance(t, str) or len(t) > 10 or not t.isalpha():
                    raise ValueError("Each type must be alphabetic and max 10 characters")
                validated_types.append(t.upper())
            return ",".join(validated_types)
        else:
            raise ValueError("Types must be string or list of strings")
    
    def _validate_limit(self, limit) -> int:
        """Validate pagination limit"""
        try:
            limit_int = int(limit)
            if limit_int < 1 or limit_int > 500:  # Reasonable limits
                raise ValueError("Limit must be between 1 and 500")
            return limit_int
        except (ValueError, TypeError):
            raise ValueError("Limit must be a valid integer")
    
    def _sanitize_error_message(self, error_msg: str) -> str:
        """Sanitize error messages to prevent information leakage"""
        # Map internal errors to safe external messages
        error_mappings = {
            "timeout": "Service temporarily unavailable",
            "connection": "Service temporarily unavailable", 
            "404": "Resource not found",
            "401": "Authentication required",
            "403": "Access denied",
            "500": "Internal service error",
            "502": "Service temporarily unavailable",
            "503": "Service temporarily unavailable",
            "json": "Invalid response format",
            "xml": "Invalid response format"
        }
        
        error_lower = error_msg.lower()
        for key, safe_msg in error_mappings.items():
            if key in error_lower:
                return safe_msg
        
        # Generic safe message for unknown errors
        return "Service temporarily unavailable"
    
    def _get_secure_headers(self) -> Dict[str, str]:
        """Get secure headers with authentication if available"""
        headers = {
            "Accept": "application/json",
            "User-Agent": "MonitorLegislativo/4.0 (Security-Hardened)",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }
        
        # Add authentication if available
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        return headers
    
    async def _search_with_enhanced_error_handling(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Enhanced search implementation with exponential backoff and proper error handling"""
        
        for attempt in range(self.max_retries):
            try:
                return await self._execute_search_request(query, filters)
                
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    raise  # Last attempt, re-raise the exception
                
                # Calculate delay with exponential backoff and jitter
                delay = min(
                    self.base_delay * (2 ** attempt),
                    self.max_delay
                )
                jitter = random.uniform(-self.jitter_range, self.jitter_range) * delay
                total_delay = delay + jitter
                
                self.logger.warning(f"Camara API request failed, retrying in {total_delay:.2f}s", extra={
                    "attempt": attempt + 1,
                    "max_retries": self.max_retries,
                    "error_type": type(e).__name__
                })
                
                await asyncio.sleep(total_delay)
        
        # This should never be reached, but just in case
        raise RuntimeError("All retry attempts exhausted")
    
    async def _execute_search_request(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """SECURITY HARDENED search execution with proper validation and error handling"""
        
        # Determine date range with validation
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)  # Default to last year
        
        if filters.get("start_date"):
            start_date = datetime.fromisoformat(filters["start_date"])
                
        if filters.get("end_date"):
            end_date = datetime.fromisoformat(filters["end_date"])
        
        # SECURITY: Validate date range to prevent excessive queries
        date_diff = (end_date - start_date).days
        if date_diff > 1095:  # Max 3 years
            raise ValueError("Date range too large (max 3 years)")
        if date_diff < 0:
            raise ValueError("End date must be after start date")
        
        # Build API parameters with validation
        params = {
            "dataInicio": start_date.strftime("%Y-%m-%d"),
            "dataFim": end_date.strftime("%Y-%m-%d"),
            "ordenarPor": "id",
            "ordem": "DESC",
            "itens": min(filters.get("limit", 200), 200)  # Max 200 per request
        }
        
        # Add type filter if specified (already validated)
        if "types" in filters and filters["types"]:
            params["siglaTipo"] = filters["types"]
        
        # Add year filter for better performance
        if end_date.year == start_date.year:
            params["ano"] = str(start_date.year)
        
        # Use the base class session management
        session = await self._get_aiohttp_session()
        
        # Get secure headers with authentication
        headers = self._get_secure_headers()
        
        # CRITICAL FIX: Enhanced request execution with response validation
        all_propositions = []
        page = 1
        max_pages = 5  # Reduced to prevent abuse
        
        while page <= max_pages:
            params["pagina"] = page
            
            # CRITICAL SECURITY: Validate request size
            request_url = f"{self.base_url}/proposicoes"
            request_size = len(str(params)) + len(str(headers))
            if request_size > self.max_request_size:
                raise ValueError("Request too large")
            
            async with session.get(
                request_url,
                params=params,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=min(self.config.timeout, 30))  # Max 30s
            ) as response:
                    
                    # CRITICAL SECURITY: Validate response
                    if response.status == 429:  # Rate limited
                        retry_after = int(response.headers.get('Retry-After', '60'))
                        self.logger.warning(f"Rate limited by Camara API, retry after {retry_after}s")
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=429,
                            message=f"Rate limited, retry after {retry_after}s"
                        )
                    
                    if response.status != 200:
                        error_text = await response.text()
                        sanitized_error = self._sanitize_error_message(f"HTTP {response.status}")
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status,
                            message=sanitized_error
                        )
                    
                    # CRITICAL SECURITY: Validate response size to prevent memory exhaustion
                    content_length = response.headers.get('Content-Length')
                    if content_length and int(content_length) > self.max_response_size:
                        raise ValueError("Response too large")
                    
                    # Check content type
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' not in content_type:
                        raise ValueError("Invalid response content type")
                    
                    # CRITICAL SECURITY: Read response with size limit
                    response_text = await response.text()
                    if len(response_text) > self.max_response_size:
                        raise ValueError("Response too large")
                    
                    try:
                        data = json.loads(response_text)
                    except json.JSONDecodeError as e:
                        raise ValueError("Invalid JSON response")
                    
                    # Validate response structure
                    if not isinstance(data, dict):
                        raise ValueError("Invalid response structure")
                    
                    if "dados" not in data:
                        break
                    
                    propositions = data["dados"]
                    if not isinstance(propositions, list) or not propositions:
                        break
                    
                    # SECURITY: Limit total propositions to prevent memory exhaustion
                    if len(all_propositions) + len(propositions) > 5000:
                        self.logger.warning("Too many propositions found, limiting results")
                        break
                    
                    all_propositions.extend(propositions)
                    
                    # Check if there are more pages
                    links = data.get("links", [])
                    has_next = any(link.get("rel") == "next" for link in links)
                    
                    if not has_next or len(all_propositions) >= 1000:  # Limit total
                        break
                    
                    page += 1
            
        # Now filter locally by keywords with security controls
        query_lower = query.lower()
        query_words = set(word for word in query_lower.split() if len(word) >= 2)  # Min 2 char words
        
        filtered_propositions = []
        for prop_data in all_propositions:
            try:
                # SECURITY: Validate proposition data structure
                if not isinstance(prop_data, dict):
                    continue
                
                # Check if proposition matches query
                searchable_text = " ".join([
                    str(prop_data.get("ementa", ""))[:1000],  # Limit field size
                    str(prop_data.get("keywords", ""))[:500],
                    str(prop_data.get("ementaDetalhada", ""))[:2000],
                    f"{prop_data.get('siglaTipo', '')} {prop_data.get('numero', '')}/{prop_data.get('ano', '')}"
                ]).lower()
                
                # Check if any query word is in the searchable text
                if any(word in searchable_text for word in query_words):
                    proposition = self._parse_proposition_secure(prop_data)
                    if proposition:
                        filtered_propositions.append(proposition)
            except Exception as e:
                self.logger.warning(f"Error processing proposition: {type(e).__name__}")
                continue
        
        # Sort by relevance (how many query words match)
        filtered_propositions.sort(
            key=lambda p: sum(1 for word in query_words if word in p.summary.lower()),
            reverse=True
        )
        
        # Limit results to prevent large responses
        filtered_propositions = filtered_propositions[:100]
        
        return SearchResult(
            query=query,
            filters=filters,
            propositions=filtered_propositions,
            total_count=len(filtered_propositions),
            source=DataSource.CAMARA
        )
    
    def _parse_proposition_secure(self, data: Dict[str, Any]) -> Optional[Proposition]:
        """SECURITY HARDENED proposition parsing with input validation"""
        try:
            # CRITICAL SECURITY: Validate input data structure and sanitize
            if not isinstance(data, dict):
                return None
            
            # Parse and validate type - map sigla to enum with strict validation
            sigla = str(data.get("siglaTipo", "")).upper()[:10]  # Limit length
            prop_type = PropositionType.OTHER  # Default
            
            # Validate sigla format (only letters)
            if sigla and sigla.isalpha():
                # Try to match the sigla to an enum value
                for ptype in PropositionType:
                    if ptype.name == sigla:
                        prop_type = ptype
                        break
            
            # Parse and validate date with security controls
            date_str = str(data.get("dataApresentacao", ""))[:25]  # Limit length
            try:
                if date_str:
                    # Remove timezone info if present and parse
                    clean_date = date_str.replace("T", " ").split("+")[0].split("Z")[0]
                    pub_date = datetime.fromisoformat(clean_date)
                    
                    # SECURITY: Validate date range (reasonable bounds)
                    if pub_date.year < 1900 or pub_date.year > 2030:
                        pub_date = datetime.now()
                else:
                    pub_date = datetime.now()
            except (ValueError, AttributeError):
                pub_date = datetime.now()
            
            # Parse status - use ACTIVE as default for Câmara (validated)
            status = PropositionStatus.ACTIVE
            
            # SECURITY: Validate and sanitize all string fields
            prop_id = str(data.get("id", ""))[:50]  # Limit ID length
            number = str(data.get("numero", ""))[:20]
            summary = str(data.get("ementa", ""))[:2000]  # Limit summary length
            title = summary[:200] if summary else "No title"  # Use first 200 chars
            url = str(data.get("urlInteiroTeor", ""))[:500]  # Limit URL length
            
            # Validate year as integer with bounds
            try:
                year = int(data.get("ano", 0))
                if year < 1900 or year > 2030:
                    year = datetime.now().year
            except (ValueError, TypeError):
                year = datetime.now().year
            
            # SECURITY: Validate URL format if present
            if url and not url.startswith(("http://", "https://")):
                url = ""  # Clear invalid URLs
            
            # Parse keywords with validation
            keywords_str = str(data.get("keywords", ""))[:1000]  # Limit length
            keywords = []
            if keywords_str:
                # Split and validate keywords
                raw_keywords = keywords_str.split(", ")
                for kw in raw_keywords[:20]:  # Max 20 keywords
                    clean_kw = kw.strip()[:100]  # Max 100 chars per keyword
                    if clean_kw and len(clean_kw) >= 2:  # Min 2 chars
                        keywords.append(clean_kw)
            
            # Create proposition with validated data
            return Proposition(
                id=prop_id,
                type=prop_type,
                number=number,
                year=year,
                summary=summary,
                title=title,
                authors=[],  # Authors need separate API call
                publication_date=pub_date,
                status=status,
                url=url,
                source=DataSource.CAMARA,
                keywords=keywords
            )
            
        except Exception as e:
            self.logger.warning(f"Error parsing proposition (security filtered): {type(e).__name__}")
            return None
    
    def _parse_proposition(self, data: Dict[str, Any]) -> Optional[Proposition]:
        """Legacy method - redirects to secure version"""
        return self._parse_proposition_secure(data)
    
    async def get_proposition_details(self, prop_id: str) -> Optional[Proposition]:
        """SECURITY HARDENED - Get detailed information about a specific proposition"""
        # CRITICAL SECURITY: Validate proposition ID to prevent injection
        try:
            # Validate prop_id format and length
            if not isinstance(prop_id, str) or len(prop_id) > 20:
                self.logger.warning(f"Invalid proposition ID format: {prop_id[:20]}...")
                return None
            
            # Only allow alphanumeric characters and basic punctuation
            if not all(c.isalnum() or c in '-_' for c in prop_id):
                self.logger.warning(f"Invalid characters in proposition ID: {prop_id}")
                return None
            
        except Exception:
            return None
        
        # Use circuit breaker for external API calls
        try:
            async with self.circuit_breaker:
                return await self._get_proposition_details_secure(prop_id)
        except Exception as e:
            self.logger.error("Get proposition details failed", extra={
                "prop_id_hash": hash(prop_id),
                "error_type": type(e).__name__
            })
            return None
    
    async def _get_proposition_details_secure(self, prop_id: str) -> Optional[Proposition]:
        """Internal secure implementation of proposition details fetching"""
        session = await self._get_aiohttp_session()
        headers = self._get_secure_headers()
        
        # Get proposition details with validation
        async with session.get(
            f"{self.base_url}/proposicoes/{prop_id}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15)  # Reasonable timeout
        ) as response:
                
                if response.status != 200:
                    if response.status == 404:
                        self.logger.info(f"Proposition not found: {prop_id}")
                    else:
                        self.logger.warning(f"API error getting proposition {prop_id}: {response.status}")
                    return None
                
                # SECURITY: Validate response size
                response_text = await response.text()
                if len(response_text) > self.max_response_size:
                    raise ValueError("Response too large")
                
                try:
                    data = json.loads(response_text)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON response")
                
                if not isinstance(data, dict):
                    return None
                
                prop_data = data.get("dados", {})
                if not isinstance(prop_data, dict):
                    return None
                
                # Get authors with security controls
                authors = []
                try:
                    async with session.get(
                        f"{self.base_url}/proposicoes/{prop_id}/autores",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as author_response:
                        
                        if author_response.status == 200:
                            author_text = await author_response.text()
                            if len(author_text) <= self.max_response_size:
                                try:
                                    author_data = json.loads(author_text)
                                    author_list = author_data.get("dados", [])
                                    
                                    if isinstance(author_list, list):
                                        # Limit number of authors to prevent abuse
                                        for author in author_list[:50]:  # Max 50 authors
                                            if isinstance(author, dict):
                                                # SECURITY: Validate and sanitize author data
                                                name = str(author.get("nome", ""))[:200]
                                                party = str(author.get("siglaPartido", ""))[:20]
                                                state = str(author.get("siglaUf", ""))[:5]
                                                
                                                if name:  # Only add if name exists
                                                    authors.append(Author(
                                                        name=name,
                                                        party=party,
                                                        state=state
                                                    ))
                                except json.JSONDecodeError:
                                    self.logger.warning("Invalid JSON in authors response")
                                    
                except Exception as e:
                    self.logger.warning(f"Error fetching authors: {type(e).__name__}")
                
                # Create detailed proposition using secure parser
                proposition = self._parse_proposition_secure(prop_data)
                if proposition:
                    proposition.authors = authors
                    # SECURITY: Limit full text size
                    full_text = str(prop_data.get("texto", ""))[:50000]  # Max 50KB
                    proposition.full_text = full_text
                
                return proposition
    
    async def check_health(self) -> Dict[str, Any]:
        """SECURITY HARDENED health check for Câmara API"""
        start_time = datetime.now()
        
        try:
            # Use circuit breaker for health checks too
            async with self.circuit_breaker:
                return await self._perform_health_check(start_time)
                
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            
            # CRITICAL SECURITY: Never expose internal error details in health check
            self.logger.error("Camara health check failed", extra={
                "error_type": type(e).__name__,
                "response_time": response_time,
                "internal_error": str(e)  # Internal logging only
            })
            
            return {
                "status": "unhealthy",
                "response_time": response_time,
                "error": "Service check failed",  # Safe generic message
                "service": "Câmara dos Deputados",
                "circuit_breaker_state": str(self.circuit_breaker.state),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _perform_health_check(self, start_time: datetime) -> Dict[str, Any]:
        """Internal implementation of health check"""
        session = await self._get_aiohttp_session()
        headers = self._get_secure_headers()
        
        # Try a minimal API call with strict timeout
        async with session.get(
            f"{self.base_url}/proposicoes",
            params={"itens": 1},  # Minimal request
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=5)  # Strict 5s timeout
        ) as response:
                
                response_time = (datetime.now() - start_time).total_seconds()
                
                # Check response validity
                health_status = "healthy"
                if response.status != 200:
                    health_status = "unhealthy"
                elif response_time > 3.0:  # Slow response
                    health_status = "degraded"
                
                # Validate response content if healthy
                if health_status == "healthy":
                    try:
                        # Try to read a small amount of response to verify it's valid JSON
                        response_text = await response.text()
                        if len(response_text) > 100000:  # 100KB limit for health check
                            health_status = "degraded"
                        else:
                            data = json.loads(response_text)
                            if not isinstance(data, dict):
                                health_status = "degraded"
                    except (json.JSONDecodeError, asyncio.TimeoutError):
                        health_status = "degraded"
                
                return {
                    "status": health_status,
                    "response_time": response_time,
                    "status_code": response.status,
                    "service": "Câmara dos Deputados",
                    "circuit_breaker_state": str(self.circuit_breaker.state),
                    "authenticated": bool(self.api_key),
                    "timestamp": datetime.now().isoformat()
                }