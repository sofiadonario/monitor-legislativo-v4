"""
LexML Brasil Official API Client
================================

Official implementation of LexML Brasil SRU (Search/Retrieve via URL) protocol client.
Based on LexML Brasil specifications and official documentation.

Features:
- SRU protocol implementation per LexML standards
- Official XML schema parsing (oai_lexml format)
- URN resolution and metadata extraction
- Rate limiting (100 requests/minute as per LexML specs)
- Proper error handling and circuit breaker pattern

Reference: LexML Brasil Kit Provedor de Dados v3.4.3
Author: Academic Legislative Monitor Development Team
"""

import asyncio
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlencode, quote
import aiohttp
import logging
from dataclasses import dataclass
import time

# Import the proper models from the models module
from ..models.lexml_official_models import LexMLDocument, LexMLSearchResponse

logger = logging.getLogger(__name__)

class LexMLRateLimiter:
    """Rate limiter implementing LexML's 100 requests/minute limit"""
    
    def __init__(self, max_requests: int = 100, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        async with self._lock:
            now = time.time()
            # Remove old requests outside the time window
            self.requests = [req_time for req_time in self.requests if now - req_time < self.time_window]
            
            if len(self.requests) >= self.max_requests:
                # Calculate how long to wait
                oldest_request = min(self.requests)
                wait_time = self.time_window - (now - oldest_request)
                if wait_time > 0:
                    logger.info(f"Rate limit reached, waiting {wait_time:.2f}s")
                    await asyncio.sleep(wait_time)
            
            self.requests.append(now)

class LexMLOfficialClient:
    """
    Official LexML Brasil SRU client implementation
    
    Implements the Search/Retrieve via URL protocol as specified by LexML Brasil.
    Handles official XML schema parsing and proper metadata extraction.
    """
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        # Official LexML Brasil SRU endpoint
        self.base_url = "http://www.lexml.gov.br/oai/sru"
        self.session = session
        self.rate_limiter = LexMLRateLimiter()
        
        # Official namespaces from LexML schema
        self.namespaces = {
            'sru': 'http://www.loc.gov/zing/srw/',
            'lexml': 'http://www.lexml.gov.br/oai_lexml',
            '': 'http://www.lexml.gov.br/oai_lexml'  # Default namespace
        }
        
        # Circuit breaker state
        self.failure_count = 0
        self.last_failure_time = None
        self.circuit_open = False
        self.circuit_timeout = 300  # 5 minutes
        
        logger.info("LexML Official Client initialized with SRU endpoint")
    
    async def search(self, query: str, max_records: int = 50, start_record: int = 1) -> LexMLSearchResponse:
        """
        Perform search using LexML Brasil SRU protocol
        
        Args:
            query: CQL (Contextual Query Language) search query
            max_records: Maximum number of records to return (default 50)
            start_record: Starting record position (1-based)
            
        Returns:
            LexMLSearchResponse with documents and metadata
        """
        if self._is_circuit_open():
            logger.warning("Circuit breaker is open, using fallback")
            raise Exception("LexML service temporarily unavailable")
        
        start_time = time.time()
        
        try:
            await self.rate_limiter.acquire()
            
            # Build SRU request parameters
            params = {
                'operation': 'searchRetrieve',
                'version': '1.1',
                'query': query,
                'recordSchema': 'oai_lexml',
                'maximumRecords': str(max_records),
                'startRecord': str(start_record)
            }
            
            url = f"{self.base_url}?{urlencode(params)}"
            logger.info(f"SRU request: {url}")
            
            # Make HTTP request
            session = await self._get_session()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status != 200:
                    raise Exception(f"SRU request failed with status {response.status}")
                
                xml_content = await response.text()
                    
            # Parse SRU response
            documents, total_count, next_position = self._parse_sru_response(xml_content)
            
            response_time_ms = int((time.time() - start_time) * 1000)
            
            # Reset circuit breaker on success
            self.failure_count = 0
            self.circuit_open = False
            
            logger.info(f"SRU search completed: {len(documents)} documents, {total_count} total, {response_time_ms}ms")
            
            return LexMLSearchResponse(
                documents=documents,
                total_count=total_count,
                query=query,
                next_record_position=next_position,
                response_time_ms=response_time_ms
            )
            
        except Exception as e:
            self._handle_failure()
            logger.error(f"SRU search failed: {e}")
            raise
    
    def _parse_sru_response(self, xml_content: str) -> Tuple[List[LexMLDocument], int, Optional[int]]:
        """
        Parse SRU XML response according to LexML oai_lexml schema
        
        Returns:
            Tuple of (documents, total_count, next_record_position)
        """
        try:
            root = ET.fromstring(xml_content)
            
            # Extract total count from SRU response
            total_count = 0
            num_records_elem = root.find('.//sru:numberOfRecords', self.namespaces)
            if num_records_elem is not None and num_records_elem.text:
                total_count = int(num_records_elem.text)
            
            # Extract next record position
            next_position = None
            next_position_elem = root.find('.//sru:nextRecordPosition', self.namespaces)
            if next_position_elem is not None and next_position_elem.text:
                next_position = int(next_position_elem.text)
            
            # Parse individual records
            documents = []
            record_elements = root.findall('.//sru:record', self.namespaces)
            
            for record_elem in record_elements:
                # Find the LexML data within the record
                lexml_elem = record_elem.find('.//lexml:LexML', self.namespaces)
                if lexml_elem is None:
                    # Try without namespace prefix (post-2010 format)
                    lexml_elem = record_elem.find('.//LexML', self.namespaces)
                
                if lexml_elem is not None:
                    doc = self._parse_lexml_record(lexml_elem)
                    if doc:
                        documents.append(doc)
            
            logger.debug(f"Parsed {len(documents)} documents from SRU response")
            return documents, total_count, next_position
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return [], 0, None
        except Exception as e:
            logger.error(f"SRU response parsing error: {e}")
            return [], 0, None
    
    def _parse_lexml_record(self, lexml_elem: ET.Element) -> Optional[LexMLDocument]:
        """
        Parse individual LexML record according to official schema
        
        Args:
            lexml_elem: LexML XML element
            
        Returns:
            LexMLDocument or None if parsing fails
        """
        try:
            # Find the Item element (main document container)
            item_elem = lexml_elem.find('.//Item')
            if item_elem is None:
                logger.warning("No Item element found in LexML record")
                return None
            
            # Extract URN (required field)
            urn = item_elem.get('urn', '')
            if not urn:
                logger.warning("No URN found in LexML record")
                return None
            
            # Extract basic metadata
            title = self._get_element_text(item_elem, 'titulo', 'Documento sem título')
            autoridade = self._get_element_text(item_elem, 'autoridade', 'Não informado')
            evento = self._get_element_text(item_elem, 'evento', 'publicacao')
            localidade = self._get_element_text(item_elem, 'localidade', 'BR')
            data_evento = self._get_element_text(item_elem, 'data', datetime.now().strftime('%Y-%m-%d'))
            
            # Extract document type from URN or metadata
            tipo_documento = self._extract_document_type(urn, item_elem)
            
            # Extract optional fields
            texto_integral_url = self._get_element_text(item_elem, 'textoIntegralUrl')
            resumo = self._get_element_text(item_elem, 'resumo')
            
            # Extract keywords
            palavras_chave = []
            keywords_elem = item_elem.find('palavrasChave')
            if keywords_elem is not None:
                for keyword_elem in keywords_elem.findall('keyword'):
                    if keyword_elem.text:
                        palavras_chave.append(keyword_elem.text.strip())
            
            return LexMLDocument(
                urn=urn,
                title=title,
                autoridade=autoridade,
                evento=evento,
                localidade=localidade,
                data_evento=data_evento,
                tipo_documento=tipo_documento,
                texto_integral_url=texto_integral_url,
                resumo=resumo,
                palavras_chave=palavras_chave
            )
            
        except Exception as e:
            logger.error(f"Error parsing LexML record: {e}")
            return None
    
    def _get_element_text(self, parent: ET.Element, tag: str, default: str = '') -> str:
        """Extract text from XML element with fallback"""
        elem = parent.find(tag)
        if elem is not None and elem.text:
            return elem.text.strip()
        return default
    
    def _extract_document_type(self, urn: str, item_elem: ET.Element) -> str:
        """Extract document type from URN or metadata"""
        # Try to get from metadata first
        tipo_elem = item_elem.find('tipoDocumento')
        if tipo_elem is not None and tipo_elem.text:
            return tipo_elem.text.strip()
        
        # Extract from URN
        urn_lower = urn.lower()
        if 'lei:' in urn_lower:
            return 'lei'
        elif 'decreto:' in urn_lower:
            return 'decreto'
        elif 'portaria:' in urn_lower:
            return 'portaria'
        elif 'resolucao:' in urn_lower or 'resolução:' in urn_lower:
            return 'resolucao'
        elif 'medida.provisoria:' in urn_lower or 'mpv:' in urn_lower:
            return 'medida_provisoria'
        elif 'projeto.lei:' in urn_lower:
            return 'projeto_lei'
        else:
            return 'outros'
    
    def _is_circuit_open(self) -> bool:
        """Check if circuit breaker is open"""
        if not self.circuit_open:
            return False
        
        if self.last_failure_time and time.time() - self.last_failure_time > self.circuit_timeout:
            logger.info("Circuit breaker timeout expired, attempting to close")
            self.circuit_open = False
            self.failure_count = 0
            return False
        
        return True
    
    def _handle_failure(self):
        """Handle API failure for circuit breaker"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= 3:
            self.circuit_open = True
            logger.warning("Circuit breaker opened due to repeated failures")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get HTTP session (create if not provided)"""
        if self.session:
            return self.session
        
        # Create new session with proper headers and store it
        headers = {
            'User-Agent': 'MonitorLegislativoV4/1.0 (Academic Research; Python/aiohttp)',
            'Accept': 'application/xml, text/xml',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
        }
        
        self.session = aiohttp.ClientSession(headers=headers)
        return self.session
    
    def build_cql_query(self, terms: List[str], autoridade: Optional[str] = None, 
                       evento: Optional[str] = None, date_from: Optional[str] = None,
                       date_to: Optional[str] = None) -> str:
        """
        Build CQL query for LexML search
        
        Args:
            terms: Search terms
            autoridade: Authority filter
            evento: Event filter  
            date_from: Start date (YYYY-MM-DD)
            date_to: End date (YYYY-MM-DD)
            
        Returns:
            CQL query string
        """
        query_parts = []
        
        # Add search terms
        if terms:
            term_queries = []
            for term in terms:
                # Search in title and full text
                term_clean = quote(term.strip())
                term_queries.append(f'(titulo="{term_clean}" OR textoIntegral="{term_clean}")')
            
            if term_queries:
                query_parts.append(f"({' OR '.join(term_queries)})")
        
        # Add filters
        if autoridade:
            query_parts.append(f'autoridade="{quote(autoridade)}"')
        
        if evento:
            query_parts.append(f'evento="{quote(evento)}"')
        
        if date_from and date_to:
            query_parts.append(f'data>="{date_from}" AND data<="{date_to}"')
        elif date_from:
            query_parts.append(f'data>="{date_from}"')
        elif date_to:
            query_parts.append(f'data<="{date_to}"')
        
        # Combine with AND
        if query_parts:
            return ' AND '.join(query_parts)
        else:
            return '*'  # Match all if no specific criteria
    
    async def health_check(self) -> bool:
        """Check if LexML service is available"""
        try:
            # Simple search to test connectivity
            response = await self.search("*", max_records=1)
            return response.total_count >= 0
        except Exception as e:
            logger.error(f"LexML health check failed: {e}")
            return False
    
    async def close(self):
        """Close HTTP session if created by this client"""
        if self.session and not self.session.closed:
            await self.session.close()