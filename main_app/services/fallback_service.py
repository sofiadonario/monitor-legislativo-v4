"""
Fallback service for CSV data when LexML API is unavailable
Provides seamless transition between live API and static data
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import os
import csv

from ..models.lexml_models import (
    LexMLSearchRequest, LexMLSearchResponse, LexMLDocument, 
    LexMLMetadata, DataSource, DocumentType, Autoridade
)
from ..services.cql_builder import CQLQueryBuilder

logger = logging.getLogger(__name__)


class CSVFallbackService:
    """
    Fallback service using the existing 890-document CSV dataset
    Provides compatibility with LexML API interface
    """
    
    def __init__(self, csv_file_path: Optional[str] = None):
        self.csv_file_path = csv_file_path or self._find_csv_file()
        self.documents: List[LexMLDocument] = []
        self.loaded = False
        self.cql_builder = CQLQueryBuilder()
        
        # Cache for parsed documents
        self._document_cache: Dict[str, LexMLDocument] = {}
    
    def _find_csv_file(self) -> str:
        """Find the CSV file in the project"""
        possible_paths = [
            "public/lexml_transport_results_20250606_123100.csv",
            "../public/lexml_transport_results_20250606_123100.csv",
            "../../public/lexml_transport_results_20250606_123100.csv",
            "lexml_transport_results_20250606_123100.csv"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        logger.warning("CSV file not found in standard locations")
        return "public/lexml_transport_results_20250606_123100.csv"
    
    async def load_documents(self) -> bool:
        """Load documents from CSV file"""
        if self.loaded:
            return True
        
        try:
            if not os.path.exists(self.csv_file_path):
                logger.error(f"CSV file not found: {self.csv_file_path}")
                return False
            
            # Load CSV data asynchronously
            await asyncio.to_thread(self._load_csv_sync)
            
            self.loaded = True
            logger.info(f"Loaded {len(self.documents)} documents from CSV fallback")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load CSV fallback data: {e}")
            return False
    
    def _load_csv_sync(self):
        """Synchronous CSV loading (runs in thread)"""
        documents = []
        
        with open(self.csv_file_path, 'r', encoding='utf-8-sig') as file:
            # Skip BOM if present
            content = file.read()
            if content.startswith('\ufeff'):
                content = content[1:]
            
            # Parse CSV
            lines = content.split('\n')
            reader = csv.reader(lines)
            
            # Skip header
            headers = next(reader, None)
            if not headers:
                raise ValueError("CSV file is empty or malformed")
            
            logger.debug(f"CSV Headers: {headers}")
            
            for row_num, row in enumerate(reader, start=2):
                if not row or len(row) < 5:
                    continue
                
                try:
                    document = self._parse_csv_row(row, row_num)
                    if document:
                        documents.append(document)
                        self._document_cache[document.metadata.urn] = document
                except Exception as e:
                    logger.warning(f"Failed to parse CSV row {row_num}: {e}")
                    continue
        
        self.documents = documents
    
    def _parse_csv_row(self, row: List[str], row_num: int) -> Optional[LexMLDocument]:
        """Parse a single CSV row into LexMLDocument"""
        try:
            # CSV structure: search_term, date_searched, url, title, urn
            if len(row) < 5:
                return None
            
            search_term = row[0].strip()
            date_searched = row[1].strip()
            url = row[2].strip()
            title = row[3].strip()
            urn = row[4].strip()
            
            if not all([title, urn, url]):
                logger.warning(f"Missing required fields in row {row_num}")
                return None
            
            # Parse URN to extract metadata
            metadata = self._parse_urn_metadata(urn, title, url, date_searched, search_term)
            
            if not metadata:
                return None
            
            # Create document
            document = LexMLDocument(
                metadata=metadata,
                data_source=DataSource.CSV_FALLBACK,
                cache_key=f"csv:{urn}",
                last_modified=datetime.now()
            )
            
            return document
            
        except Exception as e:
            logger.warning(f"Error parsing CSV row {row_num}: {e}")
            return None
    
    def _parse_urn_metadata(
        self, 
        urn: str, 
        title: str, 
        url: str, 
        date_searched: str,
        search_term: str
    ) -> Optional[LexMLMetadata]:
        """Parse URN to extract legal document metadata"""
        try:
            # URN format: urn:lex:br;location:authority:type:date;number
            parts = urn.split(':')
            
            if len(parts) < 4:
                logger.warning(f"Invalid URN format: {urn}")
                return None
            
            # Default values
            localidade = "br"
            autoridade = Autoridade.FEDERAL
            tipo_documento = DocumentType.LEI
            date = datetime.now()
            
            # Extract location and authority from URN
            if len(parts) > 2 and parts[2]:
                location_part = parts[2]
                if ';' in location_part:
                    localidade = location_part.split(';')[0]
                else:
                    localidade = location_part
                
                # Determine authority level
                if localidade == "br":
                    autoridade = Autoridade.FEDERAL
                elif "." in localidade:
                    autoridade = Autoridade.MUNICIPAL
                else:
                    autoridade = Autoridade.ESTADUAL
            
            # Extract document type
            if len(parts) > 3:
                type_part = parts[3]
                if ':' in type_part:
                    doc_type_str = type_part.split(':')[0]
                else:
                    doc_type_str = type_part
                
                # Map to DocumentType enum
                type_mapping = {
                    'lei': DocumentType.LEI,
                    'decreto': DocumentType.DECRETO,
                    'portaria': DocumentType.PORTARIA,
                    'resolucao': DocumentType.RESOLUCAO,
                    'medida.provisoria': DocumentType.MEDIDA_PROVISORIA,
                    'instrucao.normativa': DocumentType.INSTRUCAO_NORMATIVA
                }
                
                tipo_documento = type_mapping.get(doc_type_str.lower(), DocumentType.LEI)
            
            # Try to extract date
            try:
                if date_searched:
                    date = datetime.fromisoformat(date_searched.replace('Z', '+00:00'))
            except ValueError:
                # Use current date as fallback
                date = datetime.now()
            
            # Generate description
            description = f"Document retrieved on {date_searched} for search term '{search_term}'"
            
            # Extract keywords from search term and title
            keywords = self._extract_keywords(search_term, title)
            
            metadata = LexMLMetadata(
                urn=urn,
                title=title,
                description=description,
                date=date,
                tipoDocumento=tipo_documento,
                autoridade=autoridade,
                localidade=localidade,
                subject=keywords,
                identifier=url
            )
            
            return metadata
            
        except Exception as e:
            logger.warning(f"Error parsing URN metadata for {urn}: {e}")
            return None
    
    def _extract_keywords(self, search_term: str, title: str) -> List[str]:
        """Extract keywords from search term and title"""
        keywords = set()
        
        # Add search term
        if search_term:
            keywords.add(search_term.lower())
        
        # Extract keywords from title
        title_words = title.lower().replace(',', ' ').replace('.', ' ').split()
        for word in title_words:
            word = word.strip()
            if len(word) > 3 and word not in self.cql_builder.legal_stopwords:
                keywords.add(word)
        
        # Add transport-related terms if present
        for term in self.cql_builder.transport_terms:
            if term in title.lower():
                keywords.add(term)
        
        return list(keywords)[:8]  # Limit to 8 keywords
    
    async def search(self, request: LexMLSearchRequest) -> LexMLSearchResponse:
        """
        Search CSV documents with LexML API compatibility
        """
        start_time = datetime.now()
        
        # Ensure documents are loaded
        if not self.loaded:
            if not await self.load_documents():
                return LexMLSearchResponse(
                    documents=[],
                    total_found=0,
                    start_record=request.start_record,
                    records_returned=0,
                    search_time_ms=0.0,
                    data_source=DataSource.CSV_FALLBACK,
                    api_status="fallback"
                )
        
        # Filter documents based on request
        filtered_docs = await self._filter_documents(request)
        
        # Apply pagination
        start_idx = request.start_record - 1
        end_idx = start_idx + request.max_records
        paginated_docs = filtered_docs[start_idx:end_idx]
        
        # Calculate timing
        search_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # Build response
        response = LexMLSearchResponse(
            documents=paginated_docs,
            total_found=len(filtered_docs),
            start_record=request.start_record,
            records_returned=len(paginated_docs),
            next_start_record=end_idx + 1 if end_idx < len(filtered_docs) else None,
            search_time_ms=search_time,
            data_source=DataSource.CSV_FALLBACK,
            cache_hit=False,
            api_status="fallback"
        )
        
        logger.info(
            f"CSV fallback search: {len(paginated_docs)}/{len(filtered_docs)} documents "
            f"in {search_time:.2f}ms"
        )
        
        return response
    
    async def _filter_documents(self, request: LexMLSearchRequest) -> List[LexMLDocument]:
        """Filter documents based on search request"""
        filtered = self.documents.copy()
        
        # Text search
        if request.query:
            query_lower = request.query.lower()
            filtered = [
                doc for doc in filtered
                if (query_lower in doc.metadata.title.lower() or
                    (doc.metadata.description and query_lower in doc.metadata.description.lower()) or
                    any(query_lower in keyword.lower() for keyword in doc.metadata.subject))
            ]
        
        # CQL query (basic implementation)
        if request.cql_query and request.cql_query != "*":
            filtered = await self._apply_cql_filter(filtered, request.cql_query)
        
        # Apply filters
        if request.filters:
            filtered = await self._apply_filters(filtered, request.filters)
        
        return filtered
    
    async def _apply_cql_filter(self, documents: List[LexMLDocument], cql_query: str) -> List[LexMLDocument]:
        """Apply basic CQL filtering (simplified implementation)"""
        try:
            # Very basic CQL parsing - in production this would be more sophisticated
            query_lower = cql_query.lower()
            
            # Handle exact matches
            if 'exact' in query_lower:
                # Extract field and value for exact matches
                if 'tipodocumento exact' in query_lower:
                    # Extract document type
                    import re
                    match = re.search(r'tipodocumento exact "([^"]+)"', query_lower)
                    if match:
                        doc_type = match.group(1)
                        documents = [
                            doc for doc in documents
                            if doc.metadata.tipoDocumento.value.lower() == doc_type.lower()
                        ]
                
                if 'autoridade exact' in query_lower:
                    # Extract authority
                    import re
                    match = re.search(r'autoridade exact "([^"]+)"', query_lower)
                    if match:
                        authority = match.group(1)
                        documents = [
                            doc for doc in documents
                            if doc.metadata.autoridade.value.lower() == authority.lower()
                        ]
            
            # Handle any matches
            if 'any' in query_lower:
                if 'title any' in query_lower:
                    import re
                    match = re.search(r'title any "([^"]+)"', query_lower)
                    if match:
                        term = match.group(1)
                        documents = [
                            doc for doc in documents
                            if term.lower() in doc.metadata.title.lower()
                        ]
            
            return documents
            
        except Exception as e:
            logger.warning(f"CQL filter error: {e}")
            return documents
    
    async def _apply_filters(self, documents: List[LexMLDocument], filters) -> List[LexMLDocument]:
        """Apply search filters to documents"""
        try:
            # Document type filter
            if hasattr(filters, 'tipoDocumento') and filters.tipoDocumento:
                tipo_values = [t.value if hasattr(t, 'value') else str(t) for t in filters.tipoDocumento]
                documents = [
                    doc for doc in documents
                    if doc.metadata.tipoDocumento.value in tipo_values
                ]
            
            # Authority filter
            if hasattr(filters, 'autoridade') and filters.autoridade:
                auth_values = [a.value if hasattr(a, 'value') else str(a) for a in filters.autoridade]
                documents = [
                    doc for doc in documents
                    if doc.metadata.autoridade.value in auth_values
                ]
            
            # Locality filter
            if hasattr(filters, 'localidade') and filters.localidade:
                documents = [
                    doc for doc in documents
                    if any(loc in doc.metadata.localidade for loc in filters.localidade)
                ]
            
            # Date range filter
            if hasattr(filters, 'date_from') and filters.date_from:
                documents = [
                    doc for doc in documents
                    if doc.metadata.date >= filters.date_from
                ]
            
            if hasattr(filters, 'date_to') and filters.date_to:
                documents = [
                    doc for doc in documents
                    if doc.metadata.date <= filters.date_to
                ]
            
            # Subject filter
            if hasattr(filters, 'subject') and filters.subject:
                documents = [
                    doc for doc in documents
                    if any(
                        any(subj.lower() in keyword.lower() for keyword in doc.metadata.subject)
                        for subj in filters.subject
                    )
                ]
            
            return documents
            
        except Exception as e:
            logger.warning(f"Filter application error: {e}")
            return documents
    
    async def get_document_by_urn(self, urn: str) -> Optional[LexMLDocument]:
        """Get a specific document by URN"""
        if not self.loaded:
            await self.load_documents()
        
        return self._document_cache.get(urn)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fallback service statistics"""
        return {
            'loaded': self.loaded,
            'document_count': len(self.documents),
            'csv_file_path': self.csv_file_path,
            'cache_size': len(self._document_cache),
            'data_source': 'csv_fallback'
        }