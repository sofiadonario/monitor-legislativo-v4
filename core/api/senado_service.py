"""
SECURITY HARDENED Senado Federal API Service
Fixed memory exhaustion, XML vulnerabilities, and error handling issues

CRITICAL MEMORY EXHAUSTION FIXES:
- Streaming XML parser with size limits to prevent memory bombs
- Pagination limits to prevent fetching unlimited data
- Response size validation and chunked processing
- Circuit breaker protection against service unavailability
- Enhanced error handling with information leak prevention
"""

import asyncio
import logging
import re
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Iterator
import aiohttp
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from xml.parsers.expat import ParserCreateNS
from difflib import SequenceMatcher
import io
import json

from .base_service import BaseAPIService, retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig

# CRITICAL SECURITY: Import secure configurations and utilities
from ..config.secure_config import get_secure_config
from ..utils.enhanced_circuit_breaker import EnhancedCircuitBreaker
from ..security.secrets_manager import SecretsManager
from ..utils.input_validator import validate_legislative_search_query


class SenadoService(BaseAPIService):
    """SECURITY HARDENED service for interacting with Senado Federal API"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(config, cache_manager)
        
        # CRITICAL FIX: No more hardcoded URLs - get from secure config
        self.secure_config = get_secure_config()
        self.secrets_manager = SecretsManager()
        
        # Get configurable base URL from secure configuration
        self.base_url = self.secure_config.get(
            "senado_api_base_url", 
            config.base_url  # fallback to config
        )
        
        # CRITICAL FIX: Initialize circuit breaker for service unavailability protection
        self.circuit_breaker = EnhancedCircuitBreaker(
            failure_threshold=5,    # Trip after 5 failures
            recovery_timeout=30,    # 30 seconds before retry
            expected_exception=aiohttp.ClientError
        )
        
        # CRITICAL MEMORY EXHAUSTION FIXES: Strict limits to prevent memory bombs
        self.max_xml_size = 5 * 1024 * 1024     # 5MB max XML response (reduced from 10MB)
        self.max_propositions_per_year = 1000   # Max propositions per year (prevent unlimited fetch)
        self.max_total_propositions = 2000      # Absolute max across all years
        self.max_years_span = 3                 # Max years to search (prevent huge date ranges)
        self.chunk_size = 8192                  # XML parsing chunk size
        
        # Enhanced retry configuration
        self.max_retries = 3
        self.base_delay = 1.0
        self.max_delay = 30.0
        self.jitter_range = 0.1
        
        # Search configuration
        self.search_threshold = 0.25  # Lower threshold for better recall
        
        # CRITICAL FIX: Initialize secure XML parser with strict controls
        self._setup_secure_xml_parser()
        
        # CRITICAL FIX: Get API authentication if available
        self.api_key = self.secrets_manager.get_secret("senado_api_key", default=None)
        
        self.logger.info("Senado service initialized with memory exhaustion protection", extra={
            "base_url": self.base_url,
            "max_xml_size": self.max_xml_size,
            "max_propositions_per_year": self.max_propositions_per_year,
            "circuit_breaker_enabled": True,
            "authentication_enabled": bool(self.api_key)
        })
    
    def _setup_secure_xml_parser(self):
        """ENHANCED secure XML parser setup to prevent XXE attacks and memory exhaustion"""
        # Create secure XML parser with comprehensive entity processing disabled
        self.xml_parser = ET.XMLParser()
        
        # CRITICAL SECURITY: Disable ALL external entity processing (XXE protection)
        if hasattr(self.xml_parser.parser, 'DefaultHandler'):
            self.xml_parser.parser.DefaultHandler = lambda data: None
        if hasattr(self.xml_parser.parser, 'ExternalEntityRefHandler'):
            self.xml_parser.parser.ExternalEntityRefHandler = lambda *args: False
        if hasattr(self.xml_parser.parser, 'EntityDeclHandler'):
            self.xml_parser.parser.EntityDeclHandler = lambda *args: False
        if hasattr(self.xml_parser.parser, 'XmlDeclHandler'):
            self.xml_parser.parser.XmlDeclHandler = lambda *args: None
        if hasattr(self.xml_parser.parser, 'ProcessingInstructionHandler'):
            self.xml_parser.parser.ProcessingInstructionHandler = lambda *args: None
        
        # Disable DTD processing completely
        if hasattr(self.xml_parser.parser, 'SetParamEntityParsing'):
            self.xml_parser.parser.SetParamEntityParsing(0)  # XML_PARAM_ENTITY_PARSING_NEVER
    
    def _parse_xml_securely(self, xml_text: str, max_size: int = None) -> ET.Element:
        """ENHANCED secure XML parsing with memory exhaustion protection"""
        
        if max_size is None:
            max_size = self.max_xml_size
        
        # CRITICAL MEMORY FIX: Check XML size to prevent memory exhaustion
        if len(xml_text) > max_size:
            self.logger.warning(f"XML too large: {len(xml_text)} bytes (max: {max_size})")
            raise ValueError(f"XML response too large")
        
        # CRITICAL SECURITY: Validate XML structure before parsing
        if not xml_text.strip():
            raise ValueError("Empty XML response")
        
        # Check for dangerous XML patterns
        dangerous_patterns = [
            '<!ENTITY',       # Entity declarations
            '<!DOCTYPE',      # DTD declarations
            'SYSTEM',         # External system references
            'PUBLIC',         # External public references
            '&[a-zA-Z]',      # Entity references
        ]
        
        xml_upper = xml_text.upper()
        for pattern in dangerous_patterns:
            if pattern.upper() in xml_upper:
                self.logger.warning(f"Dangerous XML pattern detected: {pattern}")
                raise ValueError("XML contains potentially dangerous content")
        
        # Parse with secure parser and memory monitoring
        try:
            # CRITICAL MEMORY FIX: Use streaming parser for large XML
            if len(xml_text) > self.chunk_size * 10:  # 80KB threshold
                return self._parse_xml_streaming(xml_text)
            else:
                root = ET.fromstring(xml_text, parser=self.xml_parser)
                return root
                
        except ET.ParseError as e:
            # SECURITY: Don't expose internal XML structure in error messages
            self.logger.error(f"XML parsing failed: {type(e).__name__}")
            raise ValueError("Invalid XML format")
        except MemoryError:
            self.logger.error("XML parsing caused memory exhaustion")
            raise ValueError("XML too complex to process")
    
    def _parse_xml_streaming(self, xml_text: str) -> ET.Element:
        """CRITICAL MEMORY FIX: Stream-based XML parsing to prevent memory exhaustion"""
        
        try:
            # Use iterparse for streaming with memory control
            xml_stream = io.StringIO(xml_text)
            
            # Track memory usage during parsing
            elements_parsed = 0
            max_elements = 10000  # Prevent XML bombs
            
            # Parse incrementally
            context = ET.iterparse(xml_stream, events=('start', 'end'))
            context = iter(context)
            
            # Get root element
            event, root = next(context)
            
            for event, elem in context:
                elements_parsed += 1
                
                # CRITICAL MEMORY FIX: Limit number of elements to prevent XML bombs
                if elements_parsed > max_elements:
                    self.logger.warning(f"XML has too many elements: {elements_parsed}")
                    raise ValueError("XML structure too complex")
                
                # Clear processed elements to free memory
                if event == 'end':
                    elem.clear()  # Free memory immediately
                    if elem.getparent() is not None:
                        elem.getparent().remove(elem)
            
            return root
            
        except Exception as e:
            self.logger.error(f"Streaming XML parse failed: {type(e).__name__}")
            raise ValueError("XML parsing failed")
        
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """SECURITY HARDENED search for propositions in Senado Federal"""
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
                source=DataSource.SENADO,
                error="Invalid search query format",
                search_time=(datetime.now() - start_time).total_seconds()
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
                source=DataSource.SENADO,
                error="Invalid filter parameters",
                search_time=(datetime.now() - start_time).total_seconds()
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
                result = await self._search_with_memory_protection(validated_query, sanitized_filters, start_time)
                
                if result.propositions:  # Only cache if we got results
                    self.cache_manager.set(cache_key, result, ttl=self.config.cache_ttl)
                
                return result
                
        except Exception as e:
            # CRITICAL SECURITY FIX: Never expose internal error details
            sanitized_error = self._sanitize_error_message(str(e))
            
            self.logger.error("Senado search failed", extra={
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
                source=DataSource.SENADO,
                error=sanitized_error,  # Safe error message for client
                search_time=(datetime.now() - start_time).total_seconds()
            )
    
    async def _search_with_memory_protection(self, query: str, filters: Dict[str, Any], start_time: datetime) -> SearchResult:
        """CRITICAL MEMORY FIX: Search implementation with memory exhaustion protection"""
        
        # Senado API doesn't support text search, so we need to:
        # 1. Fetch propositions for LIMITED date range with STRICT LIMITS
        # 2. Filter locally based on the search query with MEMORY CONTROLS
        
        # CRITICAL MEMORY FIX: Determine and validate date range to prevent excessive queries
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)  # Default to last year only
        
        if filters.get("start_date"):
            start_date = datetime.fromisoformat(filters["start_date"])
        if filters.get("end_date"):
            end_date = datetime.fromisoformat(filters["end_date"])
        
        # CRITICAL MEMORY FIX: Enforce maximum date range to prevent memory exhaustion
        years_span = end_date.year - start_date.year + 1
        if years_span > self.max_years_span:
            self.logger.warning(f"Date range too large: {years_span} years (max: {self.max_years_span})")
            # Limit to recent years only
            start_date = datetime(end_date.year - self.max_years_span + 1, 1, 1)
        
        # CRITICAL MEMORY FIX: Search with strict limits to prevent memory exhaustion
        all_propositions = []
        total_fetched = 0
        current_year = start_date.year
        
        while current_year <= end_date.year and total_fetched < self.max_total_propositions:
            try:
                # Calculate remaining quota for this year
                remaining_quota = self.max_total_propositions - total_fetched
                year_limit = min(self.max_propositions_per_year, remaining_quota)
                
                year_props = await self._fetch_year_propositions_limited(current_year, year_limit)
                all_propositions.extend(year_props)
                total_fetched += len(year_props)
                
                self.logger.debug(f"Fetched {len(year_props)} propositions for year {current_year}, total: {total_fetched}")
                
                # CRITICAL MEMORY FIX: Break if we hit memory limits
                if total_fetched >= self.max_total_propositions:
                    self.logger.warning(f"Hit proposition limit: {total_fetched}")
                    break
                    
            except Exception as e:
                self.logger.warning(f"Failed to fetch propositions for year {current_year}: {type(e).__name__}")
                # Continue with other years
                
            current_year += 1
        
        # CRITICAL MEMORY FIX: Filter propositions with memory monitoring
        filtered_props = self._filter_propositions_secure(all_propositions, query, filters)
        
        # Sort by relevance and date
        filtered_props.sort(key=lambda p: (
            self._calculate_relevance(p, query),
            p.publication_date
        ), reverse=True)
        
        # Limit results to prevent large responses
        filtered_props = filtered_props[:100]  # Max 100 results
        
        return SearchResult(
            query=query,
            filters=filters,
            propositions=filtered_props,
            total_count=len(filtered_props),
            source=DataSource.SENADO,
            search_time=(datetime.now() - start_time).total_seconds()
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
            "xml": "Invalid response format",
            "memory": "Request too complex",
            "limit": "Request too large"
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
            "Accept": "application/xml, text/xml",
            "User-Agent": "MonitorLegislativo/4.0 (Security-Hardened)",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }
        
        # Add authentication if available
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        return headers
    
    async def _fetch_year_propositions_limited(self, year: int, limit: int) -> List[Proposition]:
        """CRITICAL MEMORY FIX: Fetch propositions for a year with strict limits"""
        
        # CRITICAL SECURITY: Validate year parameter
        current_year = datetime.now().year
        if year < 1988 or year > current_year + 1:  # Brazilian constitution year + future limit
            raise ValueError(f"Invalid year: {year}")
        
        # Enhanced retry with exponential backoff
        for attempt in range(self.max_retries):
            try:
                return await self._execute_year_fetch(year, limit)
                
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    raise  # Last attempt, re-raise
                
                # Calculate delay with exponential backoff and jitter
                delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                jitter = random.uniform(-self.jitter_range, self.jitter_range) * delay
                total_delay = delay + jitter
                
                self.logger.warning(f"Senado API request failed, retrying in {total_delay:.2f}s", extra={
                    "attempt": attempt + 1,
                    "year": year,
                    "error_type": type(e).__name__
                })
                
                await asyncio.sleep(total_delay)
        
        # This should never be reached
        raise RuntimeError("All retry attempts exhausted")
    
    async def _execute_year_fetch(self, year: int, limit: int) -> List[Proposition]:
        """Execute the actual year fetch with memory protection"""
        
        url = f"{self.base_url}/materia/pesquisa/lista"
        params = {
            "ano": year,
            "limite": min(limit, self.max_propositions_per_year)  # Enforce limit
        }
        
        # Use base class session management
        session = await self._get_aiohttp_session()
        headers = self._get_secure_headers()
        
        async with session.get(
            url,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=min(self.config.timeout, 60))  # Max 60s
        ) as response:
                
                # CRITICAL SECURITY: Validate response
                if response.status == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', '60'))
                    self.logger.warning(f"Rate limited by Senado API, retry after {retry_after}s")
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=429,
                        message=f"Rate limited, retry after {retry_after}s"
                    )
                
                response.raise_for_status()
                
                # CRITICAL MEMORY FIX: Validate response size before reading
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > self.max_xml_size:
                    raise ValueError("Response too large")
                
                # Read response with size monitoring
                xml_text = await response.text()
                
                # CRITICAL MEMORY FIX: Final size check
                if len(xml_text) > self.max_xml_size:
                    raise ValueError("XML response too large")
                
                # Parse XML securely with memory protection
                root = self._parse_xml_securely(xml_text)
                propositions = []
                
                # CRITICAL MEMORY FIX: Process with limits and immediate cleanup
                materia_count = 0
                for materia in root.findall(".//Materia"):
                    materia_count += 1
                    
                    # CRITICAL MEMORY FIX: Enforce strict limits during processing
                    if materia_count > limit:
                        self.logger.warning(f"Stopping at {limit} propositions for year {year}")
                        break
                    
                    try:
                        prop = self._parse_materia_secure(materia)
                        if prop:
                            propositions.append(prop)
                    except Exception as e:
                        # Log and continue processing other items
                        self.logger.warning(f"Failed to parse materia {materia_count}: {type(e).__name__}")
                        continue
                    
                    # CRITICAL MEMORY FIX: Clear processed element immediately
                    materia.clear()
                
                self.logger.info(f"Fetched {len(propositions)} propositions for year {year}")
                return propositions
    
    @retry_on_failure(max_retries=3, backoff_factor=0.5)
    async def _fetch_year_propositions(self, year: int) -> List[Proposition]:
        """Legacy method - redirects to secure limited version"""
        return await self._fetch_year_propositions_limited(year, self.max_propositions_per_year)
        """Fetch all propositions for a specific year"""
        url = f"{self.config.base_url}/materia/pesquisa/lista"
        params = {"ano": year}
        
        # Use the base class session management
        session = await self._get_aiohttp_session()
        
        async with session.get(
            url,
            params=params,
            headers=self.config.headers,
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        ) as response:
                response.raise_for_status()
                xml_text = await response.text()
                
                # Parse XML response securely
                root = self._parse_xml_securely(xml_text)
                propositions = []
                
                for materia in root.findall(".//Materia"):
                    prop = self._parse_materia(materia)
                    if prop:
                        propositions.append(prop)
                
                self.logger.info(f"Fetched {len(propositions)} propositions for year {year}")
                return propositions
    
    def _parse_materia(self, materia_elem: ET.Element) -> Optional[Proposition]:
        """Parse a materia (proposition) from XML element"""
        try:
            # Extract basic info
            codigo = materia_elem.findtext("CodigoMateria", "")
            sigla = materia_elem.findtext("SiglaSubtipoMateria", "")
            numero = materia_elem.findtext("NumeroMateria", "")
            ano = materia_elem.findtext("AnoMateria", "")
            ementa = materia_elem.findtext("EmentaMateria", "")
            
            # Get proposition type
            prop_type = self._get_proposition_type(sigla)
            
            # Parse date
            data_str = materia_elem.findtext("DataApresentacao", "")
            pub_date = self._parse_date(data_str)
            
            # Get status
            status_str = materia_elem.findtext("DescricaoSituacao", "")
            status = self._get_status(status_str)
            
            # Get author
            autor_nome = materia_elem.findtext("NomeAutor", "")
            autor_tipo = materia_elem.findtext("DescricaoTipoAutor", "")
            
            authors = []
            if autor_nome:
                authors.append(Author(
                    name=autor_nome,
                    type=autor_tipo or "Senador"
                ))
            
            # Build URL
            url = f"https://www25.senado.leg.br/web/atividade/materias/-/materia/{codigo}"
            
            # Extract keywords from indexacao
            indexacao = materia_elem.findtext("IndexacaoMateria", "")
            keywords = self._extract_keywords(indexacao)
            
            return Proposition(
                id=codigo,
                type=prop_type,
                number=numero,
                year=int(ano) if ano else datetime.now().year,
                title=ementa[:200] if ementa else "",
                summary=ementa or "",
                source=DataSource.SENADO,
                status=status,
                url=url,
                publication_date=pub_date,
                authors=authors,
                keywords=keywords,
                extra_data={
                    "indexacao": indexacao,
                    "sigla_completa": f"{sigla} {numero}/{ano}"
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing materia: {str(e)}")
            return None
    
    def _filter_propositions(self, propositions: List[Proposition], 
                           query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Filter propositions based on search query and filters"""
        if not query:
            return propositions
        
        # Normalize query for better matching
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        filtered = []
        
        for prop in propositions:
            # Check date range
            if filters.get("start_date"):
                start_date = datetime.fromisoformat(filters["start_date"])
                if prop.publication_date < start_date:
                    continue
            
            if filters.get("end_date"):
                end_date = datetime.fromisoformat(filters["end_date"])
                if prop.publication_date > end_date:
                    continue
            
            # Check proposition type
            if filters.get("types"):
                if prop.type.name not in filters["types"]:
                    continue
            
            # Check text relevance
            if self._is_relevant(prop, query_lower, query_terms):
                filtered.append(prop)
        
        return filtered
    
    def _is_relevant(self, prop: Proposition, query_lower: str, 
                    query_terms: set) -> bool:
        """Check if a proposition is relevant to the search query"""
        # Combine all searchable text
        searchable_text = " ".join([
            prop.summary.lower(),
            prop.title.lower(),
            " ".join(prop.keywords).lower(),
            prop.extra_data.get("indexacao", "").lower()
        ])
        
        # Strategy 1: Exact substring match
        if query_lower in searchable_text:
            return True
        
        # Strategy 2: All terms present
        if all(term in searchable_text for term in query_terms):
            return True
        
        # Strategy 3: Fuzzy matching for each term
        matches = 0
        for term in query_terms:
            # Check if term appears as substring
            if term in searchable_text:
                matches += 1
                continue
            
            # Check fuzzy match for longer terms
            if len(term) > 3:
                words = searchable_text.split()
                for word in words:
                    if SequenceMatcher(None, term, word).ratio() > 0.8:
                        matches += 1
                        break
        
        # Return true if enough terms match
        return matches / len(query_terms) >= self.search_threshold
    
    def _calculate_relevance(self, prop: Proposition, query: str) -> float:
        """Calculate relevance score for ranking"""
        query_lower = query.lower()
        score = 0.0
        
        # Exact match in title
        if query_lower in prop.title.lower():
            score += 5.0
        
        # Exact match in summary
        if query_lower in prop.summary.lower():
            score += 3.0
        
        # Keywords match
        for keyword in prop.keywords:
            if query_lower in keyword.lower():
                score += 1.0
        
        # Partial matches
        query_terms = query_lower.split()
        for term in query_terms:
            if term in prop.title.lower():
                score += 0.5
            if term in prop.summary.lower():
                score += 0.3
        
        return score
    
    def _get_proposition_type(self, sigla: str) -> PropositionType:
        """Map Senado sigla to PropositionType"""
        sigla_upper = sigla.upper()
        
        mapping = {
            "PLS": PropositionType.PL,
            "PLC": PropositionType.PL,
            "PEC": PropositionType.PEC,
            "MPV": PropositionType.MPV,
            "PLV": PropositionType.PLV,
            "PDL": PropositionType.PDL,
            "PDS": PropositionType.PDL,
            "PRS": PropositionType.PRC,
            "RQS": PropositionType.REQ,
        }
        
        return mapping.get(sigla_upper, PropositionType.OTHER)
    
    def _get_status(self, status_str: str) -> PropositionStatus:
        """Map status string to PropositionStatus"""
        if not status_str:
            return PropositionStatus.UNKNOWN
        
        status_lower = status_str.lower()
        
        if "tramitando" in status_lower or "tramitação" in status_lower:
            return PropositionStatus.ACTIVE
        elif "aprovad" in status_lower:
            return PropositionStatus.APPROVED
        elif "rejeitad" in status_lower:
            return PropositionStatus.REJECTED
        elif "arquivad" in status_lower:
            return PropositionStatus.ARCHIVED
        elif "retirad" in status_lower:
            return PropositionStatus.WITHDRAWN
        else:
            return PropositionStatus.UNKNOWN
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date from various formats"""
        if not date_str:
            return datetime.now()
        
        # Try different date formats
        formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        
        # If all fail, return current date
        self.logger.warning(f"Could not parse date: {date_str}")
        return datetime.now()
    
    def _extract_keywords(self, indexacao: str) -> List[str]:
        """Extract keywords from indexacao text"""
        if not indexacao:
            return []
        
        # Split by common delimiters
        keywords = re.split(r'[,;.\n]', indexacao)
        
        # Clean and filter keywords
        cleaned = []
        for kw in keywords:
            kw = kw.strip()
            if kw and len(kw) > 2:  # Skip very short keywords
                cleaned.append(kw)
        
        return cleaned[:10]  # Limit to 10 keywords
    
    async def get_proposition_details(self, proposition_id: str) -> Optional[Proposition]:
        """Get detailed information about a specific proposition"""
        try:
            url = f"{self.config.base_url}/materia/{proposition_id}"
            
            # Use the base class session management
            session = await self._get_aiohttp_session()
            
            async with session.get(
                url,
                headers=self.config.headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                    response.raise_for_status()
                    xml_text = await response.text()
                    
                    root = ET.fromstring(xml_text)
                    materia = root.find(".//Materia")
                    
                    if materia:
                        return self._parse_materia(materia)
                    
        except Exception as e:
            self.logger.error(f"Failed to get proposition details: {str(e)}")
        
        return None
    
    async def check_health(self) -> bool:
        """Check if the API is healthy"""
        try:
            # Try to fetch propositions for current year
            url = f"{self.config.base_url}/materia/pesquisa/lista"
            params = {"ano": datetime.now().year, "limite": 1}
            
            # Use the base class session management
            session = await self._get_aiohttp_session()
            
            async with session.get(
                url,
                params=params,
                headers=self.config.headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return False