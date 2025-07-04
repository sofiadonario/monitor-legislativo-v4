import logging
import asyncio
import csv
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
from pydantic import BaseModel
import httpx
import aiohttp

from ..config.env_loader import EnvironmentConfig
from ..database.supabase_config import get_database_manager
from sqlalchemy import text

logger = logging.getLogger(__name__)

class Document(BaseModel):
    """
    A Pydantic model representing a legislative document.
    This ensures compatibility with FastAPI's response_model.
    """
    urn: str
    title: str
    description: Optional[str] = None
    full_text_url: Optional[str] = None
    document_type: Optional[str] = None
    date: Optional[str] = None
    authority: Optional[str] = None
    subject: Optional[str] = None
    source: str = "lexml"  # lexml or csv
    
class SimpleSearchService:
    """
    LexML search service with CSV fallback.
    Implements real search functionality using LexML Brasil SRU API.
    """
    def __init__(self):
        self.base_url = EnvironmentConfig.LEXML_API_URL
        self.timeout = EnvironmentConfig.LEXML_TIMEOUT
        self.max_records = EnvironmentConfig.LEXML_MAX_RECORDS
        self.use_csv_fallback = EnvironmentConfig.USE_CSV_FALLBACK
        
        # CSV fallback data path
        self.csv_path = Path(__file__).parent.parent.parent / "public" / "data" / "lexml_transport_results_20250606_123100.csv"
        self.csv_data: Optional[List[Dict[str, Any]]] = None
        
    async def initialize(self):
        """Initialize the search service and load CSV fallback data if enabled"""
        if self.use_csv_fallback:
            self._load_csv_data()
    
    def _load_csv_data(self):
        """Load CSV fallback data"""
        try:
            if self.csv_path.exists():
                self.csv_data = []
                with open(self.csv_path, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.csv_data.append(row)
                logger.info(f"Loaded {len(self.csv_data)} fallback documents from CSV")
            else:
                logger.warning(f"CSV fallback file not found at {self.csv_path}")
        except Exception as e:
            logger.error(f"Error loading CSV fallback data: {e}")
            self.csv_data = None
    
    def _build_lexml_query(self, query: str) -> str:
        """Build LexML SRU query URL"""
        # Basic query with transport-related terms
        cql_query = f'"{query}"'
        
        # Add document type filter for legislative documents
        legislative_filter = '(type any "lei" OR type any "decreto" OR type any "portaria" OR type any "resolução" OR type any "medida provisória" OR type any "projeto de lei" OR type any "instrução normativa")'
        
        # Combine query with filters
        full_query = f'({cql_query}) AND {legislative_filter}'
        
        # URL encode the query
        encoded_query = quote(full_query)
        
        # Build SRU URL
        url = f"{self.base_url}?operation=searchRetrieve&query={encoded_query}&maximumRecords={self.max_records}"
        
        return url
    
    def _parse_lexml_response(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse LexML SRU XML response"""
        try:
            root = ET.fromstring(xml_content)
            
            # Define namespaces
            namespaces = {
                'srw': 'http://www.loc.gov/zing/srw/',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'lexml': 'http://www.lexml.gov.br/namespace/1.0'
            }
            
            documents = []
            
            # Find all records
            for record in root.findall('.//srw:record', namespaces):
                doc_data = {}
                
                # Helper function to safely extract text
                def safe_extract(elem_name, namespace=None):
                    if namespace:
                        elem = record.find(f'.//{namespace}:{elem_name}', namespaces)
                    else:
                        elem = record.find(f'.//{elem_name}')
                    return elem.text if elem is not None and elem.text else ''
                
                # Extract standard fields
                doc_data['urn'] = safe_extract('urn') or safe_extract('identifier', 'dc')
                doc_data['title'] = safe_extract('title', 'dc')
                doc_data['description'] = safe_extract('description', 'dc')
                doc_data['date'] = safe_extract('date', 'dc')
                doc_data['subject'] = safe_extract('subject', 'dc')
                doc_data['authority'] = safe_extract('autoridade')
                doc_data['document_type'] = safe_extract('tipoDocumento') or safe_extract('type', 'dc')
                
                # Build full text URL from URN
                if doc_data['urn']:
                    doc_data['full_text_url'] = f"https://www.lexml.gov.br/urn/{doc_data['urn']}"
                
                # Only add if we have at least URN and title
                if doc_data['urn'] and doc_data['title']:
                    documents.append(doc_data)
            
            return documents
            
        except Exception as e:
            logger.error(f"Error parsing LexML response: {e}")
            return []
    
    async def _search_lexml(self, query: str) -> List[Dict[str, Any]]:
        """Search LexML API"""
        url = self._build_lexml_query(query)
        logger.info(f"Searching LexML with query: {query}")
        
        try:
            # Try with httpx first
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                documents = self._parse_lexml_response(response.text)
                logger.info(f"Found {len(documents)} documents from LexML")
                return documents
                
        except httpx.TimeoutException:
            logger.warning(f"LexML search timed out for query: {query}")
        except httpx.HTTPError as e:
            logger.warning(f"HTTP error searching LexML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error searching LexML: {e}")
            
        # Try with aiohttp as fallback
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        text = await response.text()
                        documents = self._parse_lexml_response(text)
                        logger.info(f"Found {len(documents)} documents from LexML (aiohttp)")
                        return documents
        except Exception as e:
            logger.error(f"Aiohttp fallback also failed: {e}")
            
        return []
    
    def _search_csv_fallback(self, query: str) -> List[Dict[str, Any]]:
        """Search in CSV fallback data"""
        if not self.csv_data:
            self._load_csv_data()
            
        if not self.csv_data:
            return []
        
        query_lower = query.lower()
        results = []
        
        for row in self.csv_data:
            # Search in title and search_term fields
            if (query_lower in row.get('title', '').lower() or 
                query_lower in row.get('search_term', '').lower()):
                
                # Convert CSV row to document format
                doc = {
                    'urn': row.get('urn', ''),
                    'title': row.get('title', ''),
                    'description': f"Transport legislation document (searched: {row.get('search_term', '')})",
                    'full_text_url': row.get('url', ''),
                    'document_type': self._extract_document_type(row.get('title', '')),
                    'date': row.get('date_searched', ''),
                    'authority': 'Federal',  # Default for CSV data
                    'subject': 'Transporte',
                    'source': 'csv'
                }
                results.append(doc)
        
        logger.info(f"Found {len(results)} documents from CSV fallback")
        return results
    
    def _extract_document_type(self, title: str) -> str:
        """Extract document type from title"""
        title_lower = title.lower()
        
        if 'lei' in title_lower and 'projeto' not in title_lower:
            return 'Lei'
        elif 'decreto' in title_lower:
            return 'Decreto'
        elif 'portaria' in title_lower:
            return 'Portaria'
        elif 'resolução' in title_lower or 'resolucao' in title_lower:
            return 'Resolução'
        elif 'medida provisória' in title_lower or 'mpv' in title_lower:
            return 'Medida Provisória'
        elif 'projeto' in title_lower:
            return 'Projeto de Lei'
        elif 'instrução normativa' in title_lower:
            return 'Instrução Normativa'
        elif 'acordão' in title_lower or 'acórdão' in title_lower:
            return 'Acórdão'
        else:
            return 'Outros'
    
    async def search(self, query: str, limit: int = 1000) -> List[Document]:
        """
        Search for legislative documents directly from the Supabase database.
        """
        if not query:
            return []
        
        logger.info(f"Searching database for query: '{query}' with limit: {limit}")
        
        db_manager = await get_database_manager()
        if not db_manager or not db_manager.session_factory:
            logger.error("Database manager not available for search.")
            return []
            
        document_objects = []
        try:
            async with db_manager.session_factory() as session:
                # A simple query to find documents that match the query in title or summary.
                # This is a basic search and can be improved with full-text search later.
                sql_query = text("""
                    SELECT urn, title, summary as description, url as full_text_url, type as document_type, date, author as authority, '' as subject, source
                    FROM legislative_documents
                    WHERE title ILIKE :query OR summary ILIKE :query
                    ORDER BY date DESC
                    LIMIT :limit
                """)
                
                result = await session.execute(
                    sql_query, 
                    {"query": f"%{query}%", "limit": limit}
                )
                
                rows = result.fetchall()
                logger.info(f"Found {len(rows)} documents from database.")
                
                for row in rows:
                    doc_data = dict(row)
                    document_objects.append(Document(**doc_data))

        except Exception as e:
            logger.error(f"Database search failed for query '{query}': {e}", exc_info=True)
            # Fallback to CSV if the database fails
            if self.use_csv_fallback:
                logger.info("Database failed, trying CSV fallback")
                csv_results = self._search_csv_fallback(query)
                for doc_data in csv_results[:limit]:
                    document_objects.append(Document(**doc_data))

        logger.info(f"Returning {len(document_objects)} documents for query: {query}")
        return document_objects

# Singleton instance
_search_service_instance = None

async def get_simple_search_service() -> SimpleSearchService:
    """
    Dependency injector for the SimpleSearchService.
    """
    global _search_service_instance
    if _search_service_instance is None:
        _search_service_instance = SimpleSearchService()
        await _search_service_instance.initialize()
    return _search_service_instance 