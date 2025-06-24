"""
LexML Collection Client with Production Features
Comprehensive integration with LexML Brasil SRU protocol
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import httpx
from urllib.parse import quote
import hashlib
import json

logger = logging.getLogger(__name__)


class LexMLCollectionClient:
    """Production LexML client with retry and error handling"""
    
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br/busca/SRU"
        self.timeout = httpx.Timeout(30.0, connect=10.0)
        self.max_retries = 3
        self.retry_delay = 1.0
        
        # Namespace mappings for XML parsing
        self.namespaces = {
            'srw': 'http://www.loc.gov/zing/srw/',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'lexml': 'http://www.lexml.gov.br/namespace',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
        }
    
    async def collect_documents(self, query: str, max_records: int = 100, 
                              start_record: int = 1, date_from: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Collect documents from LexML with pagination support
        
        Args:
            query: CQL query string
            max_records: Maximum records to retrieve
            start_record: Starting record for pagination
            date_from: Optional date filter (YYYY-MM-DD)
        
        Returns:
            List of document dictionaries
        """
        all_documents = []
        current_start = start_record
        
        # Add date filter to query if provided
        if date_from:
            query = f"{query} AND dc.date >= \"{date_from}\""
        
        logger.info(f"Starting collection: {query} (max_records: {max_records})")
        
        while len(all_documents) < max_records:
            try:
                # Prepare SRU parameters
                params = {
                    'operation': 'searchRetrieve',
                    'version': '1.1',
                    'query': query,
                    'startRecord': str(current_start),
                    'maximumRecords': str(min(100, max_records - len(all_documents)))  # LexML limit
                }
                
                # Execute request with retries
                response = await self._make_request_with_retry(params)
                
                # Parse response
                documents, total_records = self._parse_sru_response(response)
                
                if not documents:
                    logger.info("No more documents found")
                    break
                
                all_documents.extend(documents)
                current_start += len(documents)
                
                logger.info(f"Collected {len(all_documents)}/{min(max_records, total_records)} documents")
                
                # Check if we've retrieved all available records
                if current_start > total_records:
                    break
                
                # Small delay between requests to avoid rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error collecting documents: {e}")
                break
        
        logger.info(f"Collection completed: {len(all_documents)} documents")
        return all_documents[:max_records]
    
    async def _make_request_with_retry(self, params: Dict[str, str]) -> str:
        """Make HTTP request with retry logic"""
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(self.base_url, params=params)
                    response.raise_for_status()
                    return response.text
                    
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    delay = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    logger.warning(f"Rate limited, waiting {delay}s before retry")
                    await asyncio.sleep(delay)
                else:
                    last_exception = e
                    logger.error(f"HTTP error on attempt {attempt + 1}: {e}")
                    
            except httpx.TimeoutException as e:
                last_exception = e
                logger.error(f"Timeout on attempt {attempt + 1}: {e}")
                await asyncio.sleep(self.retry_delay)
                
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
                break
        
        raise last_exception or Exception("Max retries exceeded")
    
    def _parse_sru_response(self, xml_content: str) -> tuple[List[Dict[str, Any]], int]:
        """Parse SRU XML response to extract documents"""
        documents = []
        total_records = 0
        
        try:
            root = ET.fromstring(xml_content)
            
            # Get total number of records
            num_records_elem = root.find('.//srw:numberOfRecords', self.namespaces)
            if num_records_elem is not None:
                total_records = int(num_records_elem.text)
            
            # Extract records
            for record in root.findall('.//srw:record', self.namespaces):
                doc = self._extract_document_from_record(record)
                if doc:
                    documents.append(doc)
                    
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        except Exception as e:
            logger.error(f"Error parsing SRU response: {e}")
        
        return documents, total_records
    
    def _extract_document_from_record(self, record: ET.Element) -> Optional[Dict[str, Any]]:
        """Extract document data from SRU record"""
        try:
            doc = {}
            
            # Extract URN (required)
            urn_elem = record.find('.//dc:identifier', self.namespaces)
            if urn_elem is None or not urn_elem.text:
                return None
            doc['urn'] = urn_elem.text.strip()
            
            # Extract title (required)
            title_elem = record.find('.//dc:title', self.namespaces)
            if title_elem is None or not title_elem.text:
                return None
            doc['title'] = title_elem.text.strip()
            
            # Extract description
            desc_elem = record.find('.//dc:description', self.namespaces)
            doc['description'] = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ''
            
            # Extract date
            date_elem = record.find('.//dc:date', self.namespaces)
            if date_elem is not None and date_elem.text:
                doc['document_date'] = self._parse_date(date_elem.text.strip())
            
            # Extract document type from URN
            doc['document_type'] = self._extract_document_type_from_urn(doc['urn'])
            
            # Extract metadata
            metadata = {}
            
            # Authority
            auth_elem = record.find('.//dc:publisher', self.namespaces)
            if auth_elem is not None and auth_elem.text:
                metadata['authority'] = auth_elem.text.strip()
            
            # Subject/keywords
            subjects = []
            for subj_elem in record.findall('.//dc:subject', self.namespaces):
                if subj_elem.text:
                    subjects.append(subj_elem.text.strip())
            if subjects:
                metadata['subjects'] = subjects
            
            # Source URL
            source_elem = record.find('.//dc:source', self.namespaces)
            if source_elem is not None and source_elem.text:
                metadata['source_url'] = source_elem.text.strip()
            
            # Add collection timestamp
            metadata['collected_at'] = datetime.now().isoformat()
            
            doc['metadata'] = metadata
            
            # Generate document hash for deduplication
            doc['content_hash'] = self._generate_content_hash(doc)
            
            return doc
            
        except Exception as e:
            logger.error(f"Error extracting document from record: {e}")
            return None
    
    def _parse_date(self, date_str: str) -> Optional[str]:
        """Parse various date formats to ISO format"""
        date_formats = [
            '%Y-%m-%d',
            '%d/%m/%Y',
            '%d-%m-%Y',
            '%Y'
        ]
        
        for fmt in date_formats:
            try:
                parsed_date = datetime.strptime(date_str, fmt)
                return parsed_date.strftime('%Y-%m-%d')
            except ValueError:
                continue
        
        logger.warning(f"Could not parse date: {date_str}")
        return None
    
    def _extract_document_type_from_urn(self, urn: str) -> str:
        """Extract document type from URN:LEX identifier"""
        # URN format: urn:lex:br:federal:lei:2024-06-15;12345
        try:
            parts = urn.split(':')
            if len(parts) >= 5:
                doc_type = parts[4]
                # Map to standard types
                type_mapping = {
                    'lei': 'Lei',
                    'decreto': 'Decreto',
                    'decreto-lei': 'Decreto-Lei',
                    'medida.provisoria': 'Medida Provisória',
                    'portaria': 'Portaria',
                    'resolucao': 'Resolução',
                    'instrucao.normativa': 'Instrução Normativa'
                }
                return type_mapping.get(doc_type, doc_type.title())
        except Exception:
            pass
        
        return 'Unknown'
    
    def _generate_content_hash(self, doc: Dict[str, Any]) -> str:
        """Generate hash for document deduplication"""
        content = f"{doc['urn']}:{doc['title']}:{doc.get('description', '')}"
        return hashlib.sha256(content.encode()).hexdigest()


class GovernmentAPIClient:
    """Base client for Brazilian government APIs"""
    
    def __init__(self, api_name: str, base_url: str):
        self.api_name = api_name
        self.base_url = base_url
        self.timeout = httpx.Timeout(30.0, connect=10.0)
        self.session = None
    
    async def __aenter__(self):
        self.session = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
    
    async def search(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """Search implementation to be overridden by specific API clients"""
        raise NotImplementedError("Subclasses must implement search method")


class CamaraAPIClient(GovernmentAPIClient):
    """Client for Câmara dos Deputados API"""
    
    def __init__(self):
        super().__init__(
            api_name="Câmara dos Deputados",
            base_url="https://dadosabertos.camara.leg.br/api/v2"
        )
    
    async def search(self, query: str, tipo: Optional[str] = None, 
                    ano: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search proposições in Câmara"""
        documents = []
        
        try:
            params = {
                'keywords': query,
                'ordem': 'DESC',
                'ordenarPor': 'ano',
                'itens': min(limit, 100)
            }
            
            if tipo:
                params['siglaTipo'] = tipo
            if ano:
                params['ano'] = str(ano)
            
            response = await self.session.get(f"{self.base_url}/proposicoes", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            for prop in data.get('dados', []):
                doc = {
                    'urn': f"urn:lex:br:camara.deputados:proposicao:{prop['ano']};{prop['id']}",
                    'title': f"{prop['siglaTipo']} {prop['numero']}/{prop['ano']} - {prop['ementa']}",
                    'description': prop['ementa'],
                    'document_type': prop['siglaTipo'],
                    'document_date': prop.get('dataApresentacao'),
                    'metadata': {
                        'api_source': 'camara',
                        'proposal_id': prop['id'],
                        'author': prop.get('autor'),
                        'status': prop.get('statusProposicao', {}).get('descricaoSituacao'),
                        'url': prop['uri']
                    },
                    'content_hash': hashlib.sha256(f"{prop['id']}:{prop['ementa']}".encode()).hexdigest()
                }
                documents.append(doc)
                
        except Exception as e:
            logger.error(f"Câmara API error: {e}")
        
        return documents


class SenadoAPIClient(GovernmentAPIClient):
    """Client for Senado Federal API"""
    
    def __init__(self):
        super().__init__(
            api_name="Senado Federal",
            base_url="https://legis.senado.leg.br/dadosabertos"
        )
    
    async def search(self, query: str, ano: Optional[int] = None, 
                    limit: int = 100) -> List[Dict[str, Any]]:
        """Search matérias in Senado"""
        documents = []
        
        try:
            # Senado uses different endpoint structure
            endpoint = f"{self.base_url}/materia/pesquisa/lista"
            params = {
                'palavraChave': query,
                'limite': min(limit, 100)
            }
            
            if ano:
                params['ano'] = str(ano)
            
            response = await self.session.get(endpoint, params=params)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            for materia in root.findall('.//Materia'):
                codigo = materia.find('CodigoMateria')
                if codigo is not None:
                    doc = {
                        'urn': f"urn:lex:br:senado.federal:materia:{ano or datetime.now().year};{codigo.text}",
                        'title': self._extract_text(materia, 'DescricaoIdentificacaoMateria'),
                        'description': self._extract_text(materia, 'EmentaMateria'),
                        'document_type': self._extract_text(materia, 'SiglaSubtipoMateria'),
                        'document_date': self._extract_text(materia, 'DataApresentacao'),
                        'metadata': {
                            'api_source': 'senado',
                            'materia_id': codigo.text,
                            'author': self._extract_text(materia, 'NomeAutor'),
                            'status': self._extract_text(materia, 'DescricaoSituacao')
                        },
                        'content_hash': hashlib.sha256(f"{codigo.text}:{self._extract_text(materia, 'EmentaMateria')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"Senado API error: {e}")
        
        return documents
    
    def _extract_text(self, element: ET.Element, tag: str) -> str:
        """Safely extract text from XML element"""
        child = element.find(tag)
        return child.text if child is not None and child.text else ''


class ANTTAPIClient(GovernmentAPIClient):
    """Client for ANTT (Agência Nacional de Transportes Terrestres)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANTT",
            base_url="https://dados.antt.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANTT regulations and resolutions"""
        documents = []
        
        try:
            # ANTT uses CKAN API
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:portaria'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:antt:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'antt',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANTT API error: {e}")
        
        return documents


class ANACAPIClient(GovernmentAPIClient):
    """Client for ANAC (Agência Nacional de Aviação Civil)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANAC",
            base_url="https://sistemas.anac.gov.br/dadosabertos/api"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANAC regulations and resolutions"""
        documents = []
        
        try:
            # ANAC often uses datasets endpoint
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:portaria OR type:instrucao_normativa'
            }
            
            response = await self.session.get(f"{self.base_url}/datasets", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            for item in data.get('results', []):
                doc = {
                    'urn': f"urn:lex:br:anac:{item.get('type', 'documento')}:{item.get('id', 'unknown')}",
                    'title': item.get('title', 'Sem título'),
                    'description': item.get('description', ''),
                    'document_type': item.get('type', 'Resolução').title(),
                    'document_date': item.get('created', '').split('T')[0],
                    'metadata': {
                        'api_source': 'anac',
                        'item_id': item.get('id'),
                        'category': item.get('category'),
                        'tags': item.get('tags', [])
                    },
                    'content_hash': hashlib.sha256(f"{item.get('id', '')}:{item.get('title', '')}".encode()).hexdigest()
                }
                documents.append(doc)
                
        except Exception as e:
            logger.error(f"ANAC API error: {e}")
        
        return documents


class ANEELAPIClient(GovernmentAPIClient):
    """Client for ANEEL (Agência Nacional de Energia Elétrica)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANEEL",
            base_url="https://dadosabertos.aneel.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANEEL regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:despacho OR type:nota_tecnica'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:aneel:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'aneel',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANEEL API error: {e}")
        
        return documents


class ANATELAPIClient(GovernmentAPIClient):
    """Client for ANATEL (Agência Nacional de Telecomunicações)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANATEL",
            base_url="https://sistemas.anatel.gov.br/dadosabertos/api"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANATEL regulations and resolutions"""
        documents = []
        
        try:
            # ANATEL may use different API structure
            params = {
                'termo': query,
                'limite': min(limit, 100),
                'tipo': 'resolucao,ato,portaria'
            }
            
            response = await self.session.get(f"{self.base_url}/documentos", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            for item in data.get('documentos', []):
                doc = {
                    'urn': f"urn:lex:br:anatel:{item.get('tipo', 'documento')}:{item.get('numero', 'unknown')}",
                    'title': f"{item.get('tipo', 'Documento')} {item.get('numero', '')} - {item.get('ementa', '')}",
                    'description': item.get('ementa', ''),
                    'document_type': item.get('tipo', 'Resolução').title(),
                    'document_date': item.get('data_publicacao'),
                    'metadata': {
                        'api_source': 'anatel',
                        'numero': item.get('numero'),
                        'ano': item.get('ano'),
                        'status': item.get('status')
                    },
                    'content_hash': hashlib.sha256(f"{item.get('numero', '')}:{item.get('ementa', '')}".encode()).hexdigest()
                }
                documents.append(doc)
                
        except Exception as e:
            logger.error(f"ANATEL API error: {e}")
        
        return documents


class ANVISAAPIClient(GovernmentAPIClient):
    """Client for ANVISA (Agência Nacional de Vigilância Sanitária)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANVISA", 
            base_url="https://dadosabertos.anvisa.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANVISA regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:instrucao_normativa OR type:portaria'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:anvisa:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'anvisa',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANVISA API error: {e}")
        
        return documents


class ANSAPIClient(GovernmentAPIClient):
    """Client for ANS (Agência Nacional de Saúde Suplementar)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANS",
            base_url="https://dadosabertos.ans.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANS regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:instrucao_normativa OR type:comunicado'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:ans:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'ans',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANS API error: {e}")
        
        return documents


class ANAAPIClient(GovernmentAPIClient):
    """Client for ANA (Agência Nacional de Águas)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANA",
            base_url="https://dadosabertos.ana.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANA regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:portaria OR type:instrucao_normativa'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:ana:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'ana',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANA API error: {e}")
        
        return documents


class ANCINEAPIClient(GovernmentAPIClient):
    """Client for ANCINE (Agência Nacional do Cinema)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANCINE",
            base_url="https://dadosabertos.ancine.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANCINE regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:instrucao_normativa OR type:portaria OR type:resolucao'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:ancine:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Instrução Normativa').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'ancine',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANCINE API error: {e}")
        
        return documents


class ANMAPIClient(GovernmentAPIClient):
    """Client for ANM (Agência Nacional de Mineração)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANM",
            base_url="https://dadosabertos.anm.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANM regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:portaria OR type:instrucao_normativa OR type:resolucao'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:anm:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Portaria').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'anm',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANM API error: {e}")
        
        return documents


class ANPAPIClient(GovernmentAPIClient):
    """Client for ANP (Agência Nacional do Petróleo)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANP",
            base_url="https://dadosabertos.anp.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANP regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:portaria OR type:regulamento_tecnico'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:anp:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'anp',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANP API error: {e}")
        
        return documents


class ANTAQAPIClient(GovernmentAPIClient):
    """Client for ANTAQ (Agência Nacional de Transportes Aquaviários)"""
    
    def __init__(self):
        super().__init__(
            api_name="ANTAQ",
            base_url="https://dados.antaq.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search ANTAQ regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:portaria OR type:instrucao_normativa'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:antaq:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'antaq',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"ANTAQ API error: {e}")
        
        return documents


class CADEAPIClient(GovernmentAPIClient):
    """Client for CADE (Conselho Administrativo de Defesa Econômica)"""
    
    def __init__(self):
        super().__init__(
            api_name="CADE",
            base_url="https://dadosabertos.cade.gov.br/api/3/action"
        )
    
    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search CADE regulations and resolutions"""
        documents = []
        
        try:
            params = {
                'q': query,
                'rows': min(limit, 100),
                'fq': 'type:resolucao OR type:portaria OR type:instrucao'
            }
            
            response = await self.session.get(f"{self.base_url}/package_search", params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('success'):
                for package in data.get('result', {}).get('results', []):
                    doc = {
                        'urn': f"urn:lex:br:cade:{package.get('type', 'documento')}:{package['id']}",
                        'title': package.get('title', 'Sem título'),
                        'description': package.get('notes', ''),
                        'document_type': package.get('type', 'Resolução').title(),
                        'document_date': package.get('metadata_created', '').split('T')[0],
                        'metadata': {
                            'api_source': 'cade',
                            'package_id': package['id'],
                            'organization': package.get('organization', {}).get('title'),
                            'tags': [tag['name'] for tag in package.get('tags', [])]
                        },
                        'content_hash': hashlib.sha256(f"{package['id']}:{package.get('title', '')}".encode()).hexdigest()
                    }
                    documents.append(doc)
                    
        except Exception as e:
            logger.error(f"CADE API error: {e}")
        
        return documents


class MultiSourceCollector:
    """Collector that aggregates results from multiple government APIs"""
    
    def __init__(self):
        self.clients = {
            'lexml': LexMLCollectionClient(),
            'camara': CamaraAPIClient(),
            'senado': SenadoAPIClient(),
            'antt': ANTTAPIClient(),
            'anac': ANACAPIClient(),
            'aneel': ANEELAPIClient(),
            'anatel': ANATELAPIClient(),
            'anvisa': ANVISAAPIClient(),
            'ans': ANSAPIClient(),
            'ana': ANAAPIClient(),
            'ancine': ANCINEAPIClient(),
            'anm': ANMAPIClient(),
            'anp': ANPAPIClient(),
            'antaq': ANTAQAPIClient(),
            'cade': CADEAPIClient()
        }
        
        # Agency categories for targeted collection
        self.agency_categories = {
            'transport': ['antt', 'anac', 'antaq'],
            'energy': ['aneel', 'anp'],
            'telecommunications': ['anatel'],
            'health': ['anvisa', 'ans'],
            'environment': ['ana'],
            'culture': ['ancine'],
            'mining': ['anm'],
            'competition': ['cade'],
            'legislative': ['camara', 'senado'],
            'legal_database': ['lexml']
        }
    
    async def collect_from_all_sources(self, query: str, max_records_per_source: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Collect documents from all available sources"""
        results = {}
        
        # Collect from main sources
        for source_name, client in self.clients.items():
            try:
                logger.info(f"Collecting from {source_name}...")
                
                if source_name == 'lexml':
                    documents = await client.collect_documents(query, max_records_per_source)
                else:
                    async with client:
                        documents = await client.search(query, limit=max_records_per_source)
                
                results[source_name] = documents
                logger.info(f"Collected {len(documents)} documents from {source_name}")
                
            except Exception as e:
                logger.error(f"Error collecting from {source_name}: {e}")
                results[source_name] = []
        
        return results
    
    async def collect_from_category(self, query: str, category: str, max_records_per_source: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Collect documents from specific category of agencies"""
        if category not in self.agency_categories:
            logger.error(f"Unknown category: {category}")
            return {}
        
        results = {}
        agencies = self.agency_categories[category]
        
        for agency in agencies:
            if agency in self.clients:
                try:
                    logger.info(f"Collecting from {agency} (category: {category})...")
                    client = self.clients[agency]
                    
                    if agency == 'lexml':
                        documents = await client.collect_documents(query, max_records_per_source)
                    else:
                        async with client:
                            documents = await client.search(query, limit=max_records_per_source)
                    
                    results[agency] = documents
                    logger.info(f"Collected {len(documents)} documents from {agency}")
                    
                except Exception as e:
                    logger.error(f"Error collecting from {agency}: {e}")
                    results[agency] = []
        
        return results
    
    async def collect_transport_focused(self, query: str, max_records_per_source: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Specialized collection for transport-related queries"""
        # Prioritize transport agencies and LexML
        priority_sources = ['lexml', 'antt', 'anac', 'antaq', 'camara', 'senado']
        results = {}
        
        for source_name in priority_sources:
            if source_name in self.clients:
                try:
                    logger.info(f"Transport collection from {source_name}...")
                    client = self.clients[source_name]
                    
                    if source_name == 'lexml':
                        # Use transport-specific query expansion for LexML
                        transport_query = f"{query} AND (transporte OR mobilidade OR trânsito OR aviação OR portuário OR rodoviário OR ferroviário)"
                        documents = await client.collect_documents(transport_query, max_records_per_source)
                    else:
                        async with client:
                            documents = await client.search(query, limit=max_records_per_source)
                    
                    results[source_name] = documents
                    logger.info(f"Transport collection: {len(documents)} documents from {source_name}")
                    
                except Exception as e:
                    logger.error(f"Transport collection error from {source_name}: {e}")
                    results[source_name] = []
        
        return results
    
    def get_available_sources(self) -> List[str]:
        """Get list of all available sources"""
        return list(self.clients.keys())
    
    def get_category_sources(self, category: str) -> List[str]:
        """Get sources for a specific category"""
        return self.agency_categories.get(category, [])
    
    def get_source_info(self) -> Dict[str, Dict[str, str]]:
        """Get information about all sources"""
        source_info = {}
        
        for source_name, client in self.clients.items():
            if hasattr(client, 'api_name'):
                source_info[source_name] = {
                    'name': client.api_name,
                    'base_url': client.base_url,
                    'type': 'government_api'
                }
            else:
                source_info[source_name] = {
                    'name': 'LexML Brasil',
                    'base_url': client.base_url,
                    'type': 'legal_database'
                }
        
        return source_info