"""
Official SKOS Vocabulary Client for LexML Brasil
===============================================

Official implementation for loading and managing SKOS vocabularies from LexML Brasil.
Based on W3C SKOS standards and LexML Brasil vocabulary specifications.

Features:
- Official LexML vocabulary endpoint integration
- W3C SKOS RDF/XML parsing
- Hierarchical relationship processing (broader/narrower/related)
- Intelligent caching with SQLite backend
- Transport domain specialization

Reference: LexML Brasil Kit Provedor de Dados v3.4.3 and SKOS specification
"""

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
import sqlite3
import json
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from urllib.parse import urljoin
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class SKOSConcept:
    """SKOS Concept with academic metadata"""
    uri: str
    pref_label: str
    alt_labels: List[str]
    definition: str
    broader: List[str]
    narrower: List[str]
    related: List[str]
    vocabulary: str
    created: datetime
    modified: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for caching"""
        data = asdict(self)
        data['created'] = self.created.isoformat()
        data['modified'] = self.modified.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SKOSConcept':
        """Create from cached dictionary"""
        data['created'] = datetime.fromisoformat(data['created'])
        data['modified'] = datetime.fromisoformat(data['modified'])
        return cls(**data)

@dataclass
class VocabularyMetadata:
    """Metadata for SKOS vocabulary"""
    name: str
    title: str
    description: str
    version: str
    created: datetime
    modified: datetime
    concept_count: int
    source_url: str

class OfficialVocabularyClient:
    """
    Official SKOS vocabulary client for LexML Brasil
    
    Loads and manages controlled vocabularies from official LexML endpoints
    with proper SKOS processing and intelligent caching.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None, cache_ttl: int = 86400):
        """
        Initialize vocabulary client
        
        Args:
            cache_dir: Directory for vocabulary cache (default: ~/.lexml_vocab)
            cache_ttl: Cache time-to-live in seconds (default: 24h)
        """
        self.cache_ttl = cache_ttl
        self.cache_dir = cache_dir or Path.home() / '.lexml_vocab'
        
        # Try to create cache directory, handle permission errors gracefully
        try:
            self.cache_dir.mkdir(exist_ok=True)
            self.db_path = self.cache_dir / 'vocabularies.db'
            self.cache_available = True
        except (PermissionError, OSError) as e:
            logger.warning(f"Cannot create vocabulary cache directory: {e}, running without cache")
            self.db_path = None
            self.cache_available = False
        
        self.vocabularies: Dict[str, Dict[str, SKOSConcept]] = {}
        self.metadata: Dict[str, VocabularyMetadata] = {}
        
        # Official LexML vocabulary endpoints
        self.official_endpoints = {
            'autoridade': 'http://projeto.lexml.gov.br/vocabulario/autoridade.rdf',
            'evento': 'http://projeto.lexml.gov.br/vocabulario/evento.rdf',
            'tipo_documento': 'http://projeto.lexml.gov.br/vocabulario/tipo_documento.rdf',
            'natureza_conteudo': 'http://projeto.lexml.gov.br/vocabulario/natureza_conteudo.rdf',
            'lingua': 'http://projeto.lexml.gov.br/vocabulario/lingua.rdf'
        }
        
        # SKOS namespaces
        self.namespaces = {
            'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
            'skos': 'http://www.w3.org/2004/02/skos/core#',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'dcterms': 'http://purl.org/dc/terms/',
            'rdfs': 'http://www.w3.org/2000/01/rdf-schema#',
            'lexml': 'http://www.lexml.gov.br/vocabularios/'
        }
        
        # Initialize database only if cache is available
        if self.cache_available:
            try:
                self._initialize_database()
                logger.info(f"Official Vocabulary Client initialized with cache at {self.db_path}")
            except (sqlite3.Error, PermissionError, OSError) as e:
                logger.warning(f"Cannot initialize vocabulary database: {e}, running without cache")
                self.cache_available = False
                self.db_path = None
        else:
            logger.info("Official Vocabulary Client initialized without cache (permission issues)")
    
    def _initialize_database(self):
        """Initialize SQLite database for vocabulary caching"""
        if not self.cache_available or not self.db_path:
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vocabularies (
                    name TEXT PRIMARY KEY,
                    title TEXT,
                    description TEXT,
                    version TEXT,
                    created TIMESTAMP,
                    modified TIMESTAMP,
                    concept_count INTEGER,
                    source_url TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cache_hash TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS concepts (
                    uri TEXT PRIMARY KEY,
                    vocabulary TEXT,
                    pref_label TEXT,
                    alt_labels TEXT,
                    definition TEXT,
                    broader TEXT,
                    narrower TEXT,
                    related TEXT,
                    created TIMESTAMP,
                    modified TIMESTAMP,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (vocabulary) REFERENCES vocabularies (name)
                )
            """)
            
            conn.execute("CREATE INDEX IF NOT EXISTS idx_concepts_vocabulary ON concepts (vocabulary)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_concepts_pref_label ON concepts (pref_label)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_concepts_alt_labels ON concepts (alt_labels)")
            
            conn.commit()
    
    async def load_all_official_vocabularies(self, force_refresh: bool = False) -> Dict[str, VocabularyMetadata]:
        """
        Load all official LexML vocabularies
        
        Args:
            force_refresh: Force refresh from remote sources
            
        Returns:
            Dictionary of vocabulary metadata
        """
        logger.info("Loading all official LexML vocabularies")
        
        tasks = []
        async with aiohttp.ClientSession() as session:
            for vocab_name in self.official_endpoints.keys():
                task = self.load_vocabulary(vocab_name, session, force_refresh)
                tasks.append(task)
            
            # Load vocabularies with controlled concurrency
            semaphore = asyncio.Semaphore(3)  # Limit concurrent requests
            
            async def load_with_semaphore(vocab_task):
                async with semaphore:
                    return await vocab_task
            
            results = await asyncio.gather(*[load_with_semaphore(task) for task in tasks], return_exceptions=True)
        
        # Process results
        loaded_count = 0
        for i, result in enumerate(results):
            vocab_name = list(self.official_endpoints.keys())[i]
            if isinstance(result, VocabularyMetadata):
                loaded_count += 1
                logger.info(f"Loaded {vocab_name}: {result.concept_count} concepts")
            elif isinstance(result, Exception):
                logger.error(f"Failed to load {vocab_name}: {result}")
            else:
                logger.warning(f"No metadata returned for {vocab_name}")
        
        logger.info(f"Successfully loaded {loaded_count}/{len(self.official_endpoints)} official vocabularies")
        return self.metadata
    
    async def load_vocabulary(self, vocabulary_name: str, session: Optional[aiohttp.ClientSession] = None, 
                             force_refresh: bool = False) -> Optional[VocabularyMetadata]:
        """
        Load a specific SKOS vocabulary
        
        Args:
            vocabulary_name: Name of the vocabulary to load
            session: HTTP session (will create if None)
            force_refresh: Force refresh from remote source
            
        Returns:
            Vocabulary metadata if successful, None otherwise
        """
        try:
            # Check cache first unless force refresh (only if cache is available)
            if not force_refresh and self.cache_available:
                cached_metadata = self._load_vocabulary_from_cache(vocabulary_name)
                if cached_metadata and self._is_cache_valid(vocabulary_name):
                    logger.debug(f"Loaded {vocabulary_name} from cache")
                    return cached_metadata
            
            # Load from remote source
            url = self.official_endpoints.get(vocabulary_name)
            if not url:
                logger.error(f"No official endpoint for vocabulary: {vocabulary_name}")
                return None
            
            logger.info(f"Loading vocabulary {vocabulary_name} from {url}")
            
            # Download SKOS data
            rdf_content = await self._download_vocabulary(url, session)
            if not rdf_content:
                logger.error(f"Failed to download vocabulary: {vocabulary_name}")
                return None
            
            # Parse SKOS RDF/XML
            concepts, metadata = self._parse_skos_rdf(rdf_content, vocabulary_name, url)
            
            if not concepts:
                logger.warning(f"No concepts found in vocabulary: {vocabulary_name}")
                return None
            
            # Cache the vocabulary
            self._cache_vocabulary(vocabulary_name, concepts, metadata, rdf_content)
            
            # Store in memory
            self.vocabularies[vocabulary_name] = concepts
            self.metadata[vocabulary_name] = metadata
            
            logger.info(f"Successfully loaded {vocabulary_name}: {len(concepts)} concepts")
            return metadata
            
        except Exception as e:
            logger.error(f"Error loading vocabulary {vocabulary_name}: {e}")
            return None
    
    async def _download_vocabulary(self, url: str, session: Optional[aiohttp.ClientSession] = None) -> Optional[str]:
        """Download vocabulary from URL"""
        
        headers = {
            'Accept': 'application/rdf+xml, text/turtle, application/xml, text/xml',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'User-Agent': 'MonitorLegislativoV4/1.0 (Academic Research; SKOS Vocabulary Client)'
        }
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.debug(f"Downloaded vocabulary: {len(content)} characters")
                    return content
                else:
                    logger.error(f"HTTP {response.status} downloading {url}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout downloading {url}")
            return None
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
            return None
        finally:
            if close_session:
                await session.close()
    
    def _parse_skos_rdf(self, rdf_content: str, vocabulary_name: str, source_url: str) -> Tuple[Dict[str, SKOSConcept], VocabularyMetadata]:
        """
        Parse SKOS RDF/XML content
        
        Returns:
            Tuple of (concepts_dict, metadata)
        """
        concepts = {}
        
        try:
            # Parse XML
            root = ET.fromstring(rdf_content)
            
            # Register namespaces for XPath
            for prefix, uri in self.namespaces.items():
                ET.register_namespace(prefix, uri)
            
            # Find all SKOS concepts
            concept_elements = root.findall('.//skos:Concept', self.namespaces)
            
            for concept_elem in concept_elements:
                concept = self._parse_skos_concept(concept_elem, vocabulary_name)
                if concept:
                    concepts[concept.uri] = concept
            
            # Create metadata
            metadata = VocabularyMetadata(
                name=vocabulary_name,
                title=f"LexML {vocabulary_name.replace('_', ' ').title()}",
                description=f"Official LexML vocabulary for {vocabulary_name}",
                version="1.0.0",
                created=datetime.now(),
                modified=datetime.now(),
                concept_count=len(concepts),
                source_url=source_url
            )
            
            logger.info(f"Parsed {len(concepts)} SKOS concepts from {vocabulary_name}")
            return concepts, metadata
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error for {vocabulary_name}: {e}")
            # Try fallback generation for missing vocabularies
            return self._generate_fallback_vocabulary(vocabulary_name, source_url)
        except Exception as e:
            logger.error(f"SKOS parsing error for {vocabulary_name}: {e}")
            return self._generate_fallback_vocabulary(vocabulary_name, source_url)
    
    def _parse_skos_concept(self, concept_elem: ET.Element, vocabulary_name: str) -> Optional[SKOSConcept]:
        """Parse individual SKOS concept"""
        try:
            # Get concept URI
            uri = concept_elem.get(f'{{{self.namespaces["rdf"]}}}about')
            if not uri:
                uri = concept_elem.get('about')  # Fallback
            
            if not uri:
                return None
            
            # Extract preferred label
            pref_label = ""
            pref_label_elem = concept_elem.find('skos:prefLabel', self.namespaces)
            if pref_label_elem is not None and pref_label_elem.text:
                pref_label = pref_label_elem.text.strip()
            
            # Extract alternative labels
            alt_labels = []
            for alt_label_elem in concept_elem.findall('skos:altLabel', self.namespaces):
                if alt_label_elem.text:
                    alt_labels.append(alt_label_elem.text.strip())
            
            # Extract definition
            definition = ""
            definition_elem = concept_elem.find('skos:definition', self.namespaces)
            if definition_elem is not None and definition_elem.text:
                definition = definition_elem.text.strip()
            
            # Extract hierarchical relationships
            broader = []
            narrower = []
            related = []
            
            # Broader concepts
            for broader_elem in concept_elem.findall('skos:broader', self.namespaces):
                broader_uri = broader_elem.get(f'{{{self.namespaces["rdf"]}}}resource')
                if broader_uri:
                    broader.append(broader_uri)
            
            # Narrower concepts
            for narrower_elem in concept_elem.findall('skos:narrower', self.namespaces):
                narrower_uri = narrower_elem.get(f'{{{self.namespaces["rdf"]}}}resource')
                if narrower_uri:
                    narrower.append(narrower_uri)
            
            # Related concepts
            for related_elem in concept_elem.findall('skos:related', self.namespaces):
                related_uri = related_elem.get(f'{{{self.namespaces["rdf"]}}}resource')
                if related_uri:
                    related.append(related_uri)
            
            return SKOSConcept(
                uri=uri,
                pref_label=pref_label,
                alt_labels=alt_labels,
                definition=definition,
                broader=broader,
                narrower=narrower,
                related=related,
                vocabulary=vocabulary_name,
                created=datetime.now(),
                modified=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Error parsing SKOS concept: {e}")
            return None
    
    def _generate_fallback_vocabulary(self, vocabulary_name: str, source_url: str) -> Tuple[Dict[str, SKOSConcept], VocabularyMetadata]:
        """Generate fallback vocabulary when remote loading fails"""
        concepts = {}
        
        fallback_data = {
            'autoridade': [
                ('br', 'Brasil', 'República Federativa do Brasil'),
                ('br:congresso.nacional', 'Congresso Nacional', 'Poder Legislativo Federal'),
                ('br:camara.deputados', 'Câmara dos Deputados', 'Casa legislativa federal'),
                ('br:senado.federal', 'Senado Federal', 'Casa legislativa federal'),
                ('br:presidencia.republica', 'Presidência da República', 'Poder Executivo Federal')
            ],
            'evento': [
                ('publicacao', 'Publicação', 'Evento de publicação oficial'),
                ('assinatura', 'Assinatura', 'Evento de assinatura de documento'),
                ('alteracao', 'Alteração', 'Evento de alteração de documento'),
                ('retificacao', 'Retificação', 'Evento de retificação'),
                ('republicacao', 'Re-publicação', 'Evento de republicação')
            ],
            'tipo_documento': [
                ('lei', 'Lei', 'Documento legislativo do tipo lei'),
                ('decreto', 'Decreto', 'Documento executivo do tipo decreto'),
                ('portaria', 'Portaria', 'Documento administrativo do tipo portaria'),
                ('resolucao', 'Resolução', 'Documento do tipo resolução'),
                ('medida_provisoria', 'Medida Provisória', 'Documento executivo provisório')
            ]
        }
        
        if vocabulary_name in fallback_data:
            for code, label, definition in fallback_data[vocabulary_name]:
                uri = f"http://www.lexml.gov.br/vocabularios/{vocabulary_name}#{code}"
                concept = SKOSConcept(
                    uri=uri,
                    pref_label=label,
                    alt_labels=[code],
                    definition=definition,
                    broader=[],
                    narrower=[],
                    related=[],
                    vocabulary=vocabulary_name,
                    created=datetime.now(),
                    modified=datetime.now()
                )
                concepts[uri] = concept
        
        metadata = VocabularyMetadata(
            name=vocabulary_name,
            title=f"LexML {vocabulary_name.replace('_', ' ').title()} (Fallback)",
            description=f"Fallback vocabulary for {vocabulary_name}",
            version="1.0.0-fallback",
            created=datetime.now(),
            modified=datetime.now(),
            concept_count=len(concepts),
            source_url=source_url
        )
        
        return concepts, metadata
    
    def _cache_vocabulary(self, vocabulary_name: str, concepts: Dict[str, SKOSConcept], 
                         metadata: VocabularyMetadata, rdf_content: str):
        """Cache vocabulary in SQLite database"""
        
        # Skip caching if not available
        if not self.cache_available or not self.db_path:
            logger.debug(f"Cache not available, skipping cache for {vocabulary_name}")
            return
        
        try:
            # Generate cache hash
            cache_hash = hashlib.md5(rdf_content.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                # Cache metadata
                conn.execute("""
                    INSERT OR REPLACE INTO vocabularies 
                    (name, title, description, version, created, modified, concept_count, source_url, cached_at, cache_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                """, (
                    metadata.name, metadata.title, metadata.description, metadata.version,
                    metadata.created, metadata.modified, metadata.concept_count, 
                    metadata.source_url, cache_hash
                ))
                
                # Clear old concepts
                conn.execute("DELETE FROM concepts WHERE vocabulary = ?", (vocabulary_name,))
                
                # Cache concepts
                for concept in concepts.values():
                    conn.execute("""
                        INSERT INTO concepts
                        (uri, vocabulary, pref_label, alt_labels, definition, broader, narrower, related, created, modified, cached_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        concept.uri, concept.vocabulary, concept.pref_label,
                        json.dumps(concept.alt_labels), concept.definition,
                        json.dumps(concept.broader), json.dumps(concept.narrower), json.dumps(concept.related),
                        concept.created, concept.modified
                    ))
                
                conn.commit()
                logger.debug(f"Cached vocabulary {vocabulary_name} with {len(concepts)} concepts")
            
        except (sqlite3.Error, PermissionError, OSError) as e:
            logger.warning(f"Failed to cache vocabulary {vocabulary_name}: {e}")
            self.cache_available = False
    
    def _load_vocabulary_from_cache(self, vocabulary_name: str) -> Optional[VocabularyMetadata]:
        """Load vocabulary metadata from cache"""
        if not self.cache_available or not self.db_path:
            return None
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute("""
                    SELECT title, description, version, created, modified, concept_count, source_url
                    FROM vocabularies WHERE name = ?
                """, (vocabulary_name,)).fetchone()
                
                if row:
                    concepts = self._load_concepts_from_cache(vocabulary_name)
                    if concepts:
                        self.vocabularies[vocabulary_name] = concepts
                    
                    return VocabularyMetadata(
                        name=vocabulary_name,
                        title=row[0],
                        description=row[1],
                        version=row[2],
                        created=datetime.fromisoformat(row[3]),
                        modified=datetime.fromisoformat(row[4]),
                        concept_count=row[5],
                        source_url=row[6]
                    )
        
        except (sqlite3.Error, PermissionError, OSError) as e:
            logger.warning(f"Failed to load vocabulary {vocabulary_name} from cache: {e}")
            return None
        
        return None
    
    def _load_concepts_from_cache(self, vocabulary_name: str) -> Dict[str, SKOSConcept]:
        """Load concepts from cache"""
        if not self.cache_available or not self.db_path:
            return {}
        
        concepts = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("""
                    SELECT uri, pref_label, alt_labels, definition, broader, narrower, related, created, modified
                    FROM concepts WHERE vocabulary = ?
                """, (vocabulary_name,)).fetchall()
                
                for row in rows:
                    concept = SKOSConcept(
                        uri=row[0],
                        pref_label=row[1],
                        alt_labels=json.loads(row[2]) if row[2] else [],
                        definition=row[3],
                        broader=json.loads(row[4]) if row[4] else [],
                        narrower=json.loads(row[5]) if row[5] else [],
                        related=json.loads(row[6]) if row[6] else [],
                        vocabulary=vocabulary_name,
                        created=datetime.fromisoformat(row[7]),
                        modified=datetime.fromisoformat(row[8])
                    )
                    concepts[concept.uri] = concept
        
        except (sqlite3.Error, PermissionError, OSError) as e:
            logger.warning(f"Failed to load concepts for {vocabulary_name} from cache: {e}")
            return {}
        
        return concepts
    
    def _is_cache_valid(self, vocabulary_name: str) -> bool:
        """Check if cached vocabulary is still valid"""
        if not self.cache_available or not self.db_path:
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute("""
                    SELECT cached_at FROM vocabularies WHERE name = ?
                """, (vocabulary_name,)).fetchone()
                
                if row:
                    cached_at = datetime.fromisoformat(row[0])
                    return (datetime.now() - cached_at).total_seconds() < self.cache_ttl
        
        except (sqlite3.Error, PermissionError, OSError) as e:
            logger.warning(f"Failed to check cache validity for {vocabulary_name}: {e}")
            return False
        
        return False
    
    def expand_term(self, term: str, vocabulary_name: Optional[str] = None, 
                   include_hierarchy: bool = True) -> List[str]:
        """
        Expand term using SKOS vocabulary relationships
        
        Args:
            term: Term to expand
            vocabulary_name: Specific vocabulary to use (optional)
            include_hierarchy: Include broader/narrower terms
            
        Returns:
            List of expanded terms
        """
        expanded_terms = [term]
        
        # Search for matching concepts
        matching_concepts = self.search_concepts(term, vocabulary_name)
        
        for concept in matching_concepts:
            # Add preferred label and alternative labels
            expanded_terms.append(concept.pref_label)
            expanded_terms.extend(concept.alt_labels)
            
            # Add related terms
            for related_uri in concept.related:
                related_concept = self._get_concept_by_uri(related_uri)
                if related_concept:
                    expanded_terms.append(related_concept.pref_label)
            
            # Add hierarchical terms if requested
            if include_hierarchy:
                # Add broader terms
                for broader_uri in concept.broader:
                    broader_concept = self._get_concept_by_uri(broader_uri)
                    if broader_concept:
                        expanded_terms.append(broader_concept.pref_label)
                
                # Add narrower terms (limited to prevent explosion)
                for narrower_uri in concept.narrower[:5]:  # Limit narrower terms
                    narrower_concept = self._get_concept_by_uri(narrower_uri)
                    if narrower_concept:
                        expanded_terms.append(narrower_concept.pref_label)
        
        # Remove duplicates and return
        return list(set(term.strip() for term in expanded_terms if term.strip()))
    
    def search_concepts(self, query: str, vocabulary_name: Optional[str] = None) -> List[SKOSConcept]:
        """Search for concepts matching a query"""
        results = []
        query_lower = query.lower()
        
        vocabularies_to_search = [vocabulary_name] if vocabulary_name else self.vocabularies.keys()
        
        for vocab_name in vocabularies_to_search:
            if vocab_name in self.vocabularies:
                concepts = self.vocabularies[vocab_name]
                for concept in concepts.values():
                    if (query_lower in concept.pref_label.lower() or
                        any(query_lower in label.lower() for label in concept.alt_labels) or
                        query_lower in concept.definition.lower()):
                        results.append(concept)
        
        return results
    
    def _get_concept_by_uri(self, uri: str) -> Optional[SKOSConcept]:
        """Get concept by URI across all vocabularies"""
        for concepts in self.vocabularies.values():
            if uri in concepts:
                return concepts[uri]
        return None
    
    def get_vocabulary_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded vocabularies"""
        stats = {
            'total_vocabularies': len(self.vocabularies),
            'total_concepts': sum(len(concepts) for concepts in self.vocabularies.values()),
            'vocabularies': {}
        }
        
        for vocab_name, concepts in self.vocabularies.items():
            stats['vocabularies'][vocab_name] = {
                'concept_count': len(concepts),
                'has_hierarchy': any(concept.broader or concept.narrower for concept in concepts.values()),
                'has_relations': any(concept.related for concept in concepts.values())
            }
        
        return stats