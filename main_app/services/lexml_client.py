"""
LexML Brasil API client service
Handles SRU protocol communication with LexML Brasil
"""

import asyncio
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import httpx
import logging
from urllib.parse import urlencode

try:
    from ..models.lexml_models import (
        LexMLDocument, LexMLMetadata, LexMLSearchRequest, LexMLSearchResponse,
        CQLQuery, DocumentType, Autoridade, DataSource, APIHealthStatus,
        CircuitBreakerState
    )
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from models.lexml_models import (
        LexMLDocument, LexMLMetadata, LexMLSearchRequest, LexMLSearchResponse,
        CQLQuery, DocumentType, Autoridade, DataSource, APIHealthStatus,
        CircuitBreakerState
    )

logger = logging.getLogger(__name__)


class LexMLAPIError(Exception):
    """Custom exception for LexML API errors"""
    pass


class LexMLClient:
    """
    LexML Brasil API client using SRU protocol
    Implements circuit breaker pattern and caching
    """
    
    def __init__(self):
        # LexML Brasil SRU endpoint (based on research)
        self.base_url = "http://www.lexml.gov.br/oai/sru"
        self.timeout = 10.0
        self.max_retries = 3
        self.rate_limit_per_minute = 100
        self.max_concurrent_requests = 10
        
        # Circuit breaker configuration
        self.circuit_breaker = CircuitBreakerState()
        self.failure_threshold = 5
        self.recovery_timeout = 300  # 5 minutes
        
        # Request tracking
        self.request_count = 0
        self.last_request_time = datetime.now()
        self.semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        
        # HTTP client
        self.http_client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.http_client:
            await self.http_client.aclose()
    
    async def _check_rate_limit(self):
        """Implement respectful rate limiting"""
        current_time = datetime.now()
        time_since_last = (current_time - self.last_request_time).total_seconds()
        
        # Reset counter every minute
        if time_since_last > 60:
            self.request_count = 0
            self.last_request_time = current_time
        
        # Check rate limit
        if self.request_count >= self.rate_limit_per_minute:
            wait_time = 60 - time_since_last
            if wait_time > 0:
                logger.warning(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)
                self.request_count = 0
                self.last_request_time = datetime.now()
    
    def _check_circuit_breaker(self) -> bool:
        """Check if circuit breaker allows requests"""
        if self.circuit_breaker.status == "OPEN":
            if (datetime.now() - (self.circuit_breaker.next_attempt_time or datetime.now())).total_seconds() > 0:
                self.circuit_breaker.status = "HALF_OPEN"
                logger.info("Circuit breaker transitioning to HALF_OPEN")
            else:
                return False
        return True
    
    def _update_circuit_breaker(self, success: bool):
        """Update circuit breaker state based on request result"""
        self.circuit_breaker.total_requests += 1
        
        if success:
            self.circuit_breaker.successful_requests += 1
            if self.circuit_breaker.status == "HALF_OPEN":
                self.circuit_breaker.status = "CLOSED"
                self.circuit_breaker.failure_count = 0
                logger.info("Circuit breaker reset to CLOSED")
        else:
            self.circuit_breaker.failed_requests += 1
            self.circuit_breaker.failure_count += 1
            self.circuit_breaker.last_failure_time = datetime.now()
            
            if self.circuit_breaker.failure_count >= self.failure_threshold:
                self.circuit_breaker.status = "OPEN"
                self.circuit_breaker.next_attempt_time = datetime.now() + timedelta(seconds=self.recovery_timeout)
                logger.error(f"Circuit breaker OPEN due to {self.circuit_breaker.failure_count} failures")
    
    def build_cql_query(self, request: LexMLSearchRequest) -> str:
        """Build CQL query from search request"""
        cql_parts = []
        
        # Direct CQL query takes precedence
        if request.cql_query:
            return request.cql_query
        
        # Build from filters
        filters = request.filters
        
        # Free text search
        if request.query:
            # Search in title and description
            text_query = f'title any "{request.query}" OR description any "{request.query}"'
            cql_parts.append(f"({text_query})")
        
        # Document type filter
        if filters.tipoDocumento:
            tipo_queries = [f'tipoDocumento exact "{tipo.value}"' for tipo in filters.tipoDocumento]
            cql_parts.append(f"({' OR '.join(tipo_queries)})")
        
        # Authority filter
        if filters.autoridade:
            auth_queries = [f'autoridade exact "{auth.value}"' for auth in filters.autoridade]
            cql_parts.append(f"({' OR '.join(auth_queries)})")
        
        # Locality filter
        if filters.localidade:
            loc_queries = [f'localidade any "{loc}"' for loc in filters.localidade]
            cql_parts.append(f"({' OR '.join(loc_queries)})")
        
        # Date range filter
        if filters.date_from or filters.date_to:
            if filters.date_from and filters.date_to:
                date_query = f'date within "{filters.date_from.year} {filters.date_to.year}"'
            elif filters.date_from:
                date_query = f'date >= "{filters.date_from.year}"'
            else:
                date_query = f'date <= "{filters.date_to.year}"'
            cql_parts.append(date_query)
        
        # Subject filter
        if filters.subject:
            subj_queries = [f'subject any "{subj}"' for subj in filters.subject]
            cql_parts.append(f"({' OR '.join(subj_queries)})")
        
        # Combine with AND
        final_query = " AND ".join(cql_parts) if cql_parts else "*"
        
        logger.debug(f"Built CQL query: {final_query}")
        return final_query
    
    def _parse_xml_response(self, xml_content: str) -> List[LexMLDocument]:
        """Parse LexML SRU XML response into document objects"""
        documents = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # Find all record elements (SRU standard)
            records = root.findall(".//record")
            
            for record in records:
                try:
                    doc = self._parse_single_record(record)
                    if doc:
                        documents.append(doc)
                except Exception as e:
                    logger.warning(f"Failed to parse record: {e}")
                    continue
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            raise LexMLAPIError(f"Invalid XML response: {e}")
        
        return documents
    
    def _parse_single_record(self, record: ET.Element) -> Optional[LexMLDocument]:
        """Parse a single LexML record into a document"""
        try:
            # Extract metadata (adjust namespaces based on actual LexML response)
            metadata_elem = record.find(".//metadata") or record
            
            # Basic required fields
            urn = self._get_text(metadata_elem, ".//urn") or self._get_text(metadata_elem, ".//identifier")
            title = self._get_text(metadata_elem, ".//title")
            date_str = self._get_text(metadata_elem, ".//date")
            
            if not all([urn, title, date_str]):
                logger.warning("Missing required fields in record")
                return None
            
            # Parse date
            try:
                date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except ValueError:
                # Try other date formats
                for fmt in ['%Y-%m-%d', '%Y-%m', '%Y']:
                    try:
                        date = datetime.strptime(date_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    date = datetime.now()
            
            # Extract document type
            tipo_str = self._get_text(metadata_elem, ".//tipoDocumento") or "Lei"
            try:
                tipo_documento = DocumentType(tipo_str)
            except ValueError:
                tipo_documento = DocumentType.LEI
            
            # Extract authority
            auth_str = self._get_text(metadata_elem, ".//autoridade") or "federal"
            try:
                autoridade = Autoridade(auth_str.lower())
            except ValueError:
                autoridade = Autoridade.FEDERAL
            
            # Other metadata
            description = self._get_text(metadata_elem, ".//description")
            localidade = self._get_text(metadata_elem, ".//localidade") or "br"
            identifier_url = self._get_text(metadata_elem, ".//identifier")
            
            # Extract subjects
            subject_elements = metadata_elem.findall(".//subject")
            subjects = [elem.text.strip() for elem in subject_elements if elem.text]
            
            # Create metadata object
            metadata = LexMLMetadata(
                urn=urn,
                title=title,
                description=description,
                date=date,
                tipoDocumento=tipo_documento,
                autoridade=autoridade,
                localidade=localidade,
                subject=subjects,
                identifier=identifier_url
            )
            
            # Create document
            document = LexMLDocument(
                metadata=metadata,
                data_source=DataSource.LIVE_API,
                cache_key=f"lexml:{urn}"
            )
            
            return document
            
        except Exception as e:
            logger.error(f"Error parsing record: {e}")
            return None
    
    def _get_text(self, element: ET.Element, xpath: str) -> Optional[str]:
        """Safely extract text from XML element"""
        found = element.find(xpath)
        return found.text.strip() if found is not None and found.text else None
    
    async def search(self, request: LexMLSearchRequest) -> LexMLSearchResponse:
        """
        Search LexML using SRU protocol
        """
        start_time = datetime.now()
        
        # Check circuit breaker
        if not self._check_circuit_breaker():
            logger.warning("Circuit breaker OPEN, rejecting request")
            raise LexMLAPIError("LexML API temporarily unavailable (circuit breaker OPEN)")
        
        # Rate limiting and concurrency control
        async with self.semaphore:
            await self._check_rate_limit()
            self.request_count += 1
            
            try:
                # Build CQL query
                cql_query = self.build_cql_query(request)
                
                # SRU parameters
                params = {
                    "operation": "searchRetrieve",
                    "query": cql_query,
                    "startRecord": request.start_record,
                    "maximumRecordsPerPage": request.max_records,
                    "recordSchema": "oai_dc"  # Dublin Core format
                }
                
                # Make request
                if not self.http_client:
                    raise LexMLAPIError("HTTP client not initialized")
                
                logger.info(f"LexML API request: {params}")
                response = await self.http_client.get(self.base_url, params=params)
                response.raise_for_status()
                
                # Parse response
                documents = self._parse_xml_response(response.text)
                
                # Calculate timing
                search_time = (datetime.now() - start_time).total_seconds() * 1000
                
                # Update circuit breaker
                self._update_circuit_breaker(success=True)
                
                # Build response
                search_response = LexMLSearchResponse(
                    documents=documents,
                    total_found=len(documents),  # SRU might provide this in numberOfRecords
                    start_record=request.start_record,
                    records_returned=len(documents),
                    next_start_record=request.start_record + len(documents) if len(documents) == request.max_records else None,
                    search_time_ms=search_time,
                    data_source=DataSource.LIVE_API,
                    cache_hit=False,
                    api_status="healthy"
                )
                
                logger.info(f"LexML search completed: {len(documents)} documents in {search_time:.2f}ms")
                return search_response
                
            except Exception as e:
                # Update circuit breaker
                self._update_circuit_breaker(success=False)
                logger.error(f"LexML API error: {e}")
                raise LexMLAPIError(f"LexML API request failed: {e}")
    
    async def get_health_status(self) -> APIHealthStatus:
        """Get current API health status"""
        try:
            # Simple health check query
            test_request = LexMLSearchRequest(
                cql_query="*",
                max_records=1
            )
            
            start_time = datetime.now()
            await self.search(test_request)
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            success_rate = (
                (self.circuit_breaker.successful_requests / max(self.circuit_breaker.total_requests, 1)) * 100
            )
            
            return APIHealthStatus(
                is_healthy=True,
                response_time_ms=response_time,
                success_rate=success_rate,
                circuit_breaker=self.circuit_breaker
            )
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return APIHealthStatus(
                is_healthy=False,
                response_time_ms=0.0,
                success_rate=0.0,
                circuit_breaker=self.circuit_breaker,
                error_message=str(e)
            )