"""
SKOS Vocabulary Manager
======================

Manages controlled vocabularies from LexML Brasil using W3C SKOS standards.
Provides vocabulary loading, caching, term expansion, and hierarchical navigation
for academic research in Brazilian legislative documents.

Based on:
- LexML Brasil v1.0 (RC1) - Parte 6: Vocabulários Controlados
- W3C SKOS (Simple Knowledge Organization System)
- Academic research requirements for transport legislation

Author: Academic Legislative Monitor Development Team
Created: June 13, 2025
Version: 1.0.0
"""

import asyncio
import aiohttp
import sqlite3
import json
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from urllib.parse import urljoin
import xml.etree.ElementTree as ET
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

from .config import (
    VOCABULARY_ENDPOINTS, CACHE_SETTINGS, HTTP_SETTINGS, 
    SKOS_SETTINGS, DATABASE_PATH, TRANSPORT_CONFIG
)

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class SKOSConcept:
    """Represents a SKOS concept with academic metadata."""
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
        """Convert to dictionary for caching and export."""
        data = asdict(self)
        data['created'] = self.created.isoformat()
        data['modified'] = self.modified.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SKOSConcept':
        """Create from dictionary loaded from cache."""
        data['created'] = datetime.fromisoformat(data['created'])
        data['modified'] = datetime.fromisoformat(data['modified'])
        return cls(**data)

@dataclass 
class VocabularyMetadata:
    """Metadata for a SKOS vocabulary."""
    name: str
    title: str
    description: str
    version: str
    created: datetime
    modified: datetime
    concept_count: int
    source_url: str
    
class SKOSVocabularyManager:
    """
    Manages SKOS controlled vocabularies for LexML Brasil integration.
    
    Features:
    - Asynchronous vocabulary loading from LexML endpoints
    - SQLite caching with intelligent update mechanisms
    - Hierarchical term navigation and expansion
    - SKOS-compliant RDF processing
    - Academic citation integration
    - Transport-specific vocabulary enhancement
    """
    
    def __init__(self, cache_ttl: int = None, max_concurrent: int = 5):
        """
        Initialize the SKOS Vocabulary Manager.
        
        Args:
            cache_ttl: Cache time-to-live in seconds (default from config)
            max_concurrent: Maximum concurrent HTTP requests
        """
        self.cache_ttl = cache_ttl or CACHE_SETTINGS['vocabulary_ttl']
        self.max_concurrent = max_concurrent
        self.vocabularies: Dict[str, Dict[str, SKOSConcept]] = {}
        self.metadata: Dict[str, VocabularyMetadata] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.db_lock = threading.Lock()
        self._initialize_database()
        
        logger.info(f"SKOS Vocabulary Manager initialized with TTL={self.cache_ttl}s")
    
    def _initialize_database(self) -> None:
        """Initialize SQLite database for vocabulary caching."""
        with sqlite3.connect(DATABASE_PATH) as conn:
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
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_concepts_vocabulary ON concepts (vocabulary)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_concepts_pref_label ON concepts (pref_label)
            """)
            
            conn.commit()
            
        logger.info("Database initialized successfully")
    
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=HTTP_SETTINGS['timeout'])
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=HTTP_SETTINGS['headers']
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def load_all_vocabularies(self, force_refresh: bool = False) -> Dict[str, VocabularyMetadata]:
        """
        Load all LexML controlled vocabularies.
        
        Args:
            force_refresh: Force refresh from remote sources
            
        Returns:
            Dictionary of vocabulary metadata
        """
        logger.info("Loading all LexML controlled vocabularies")
        
        tasks = []
        for vocab_name in VOCABULARY_ENDPOINTS.keys():
            task = self.load_vocabulary(vocab_name, force_refresh)
            tasks.append(task)
        
        # Load vocabularies concurrently
        semaphore = asyncio.Semaphore(self.max_concurrent)
        async def load_with_semaphore(vocab_task):
            async with semaphore:
                return await vocab_task
        
        results = await asyncio.gather(*[load_with_semaphore(task) for task in tasks])
        
        # Process results
        loaded_count = sum(1 for result in results if result is not None)
        logger.info(f"Successfully loaded {loaded_count}/{len(tasks)} vocabularies")
        
        return self.metadata
    
    async def load_vocabulary(self, vocabulary_name: str, force_refresh: bool = False) -> Optional[VocabularyMetadata]:
        """
        Load a specific SKOS vocabulary.
        
        Args:
            vocabulary_name: Name of the vocabulary to load
            force_refresh: Force refresh from remote source
            
        Returns:
            Vocabulary metadata if successful, None otherwise
        """
        try:
            # Check cache first unless force refresh
            if not force_refresh:
                cached_metadata = self._load_vocabulary_from_cache(vocabulary_name)
                if cached_metadata and self._is_cache_valid(vocabulary_name):
                    logger.debug(f"Loaded {vocabulary_name} from cache")
                    return cached_metadata
            
            # Load from remote source
            logger.info(f"Loading vocabulary {vocabulary_name} from LexML")
            vocabulary_url = VOCABULARY_ENDPOINTS.get(vocabulary_name)
            
            if not vocabulary_url:
                logger.error(f"Unknown vocabulary: {vocabulary_name}")
                return None
            
            # Download and parse SKOS vocabulary
            skos_data = await self._download_skos_vocabulary(vocabulary_url)
            if not skos_data:
                logger.error(f"Failed to download vocabulary: {vocabulary_name}")
                return None
            
            # Parse SKOS concepts
            concepts, metadata = self._parse_skos_vocabulary(skos_data, vocabulary_name, vocabulary_url)
            
            # Cache the vocabulary
            self._cache_vocabulary(vocabulary_name, concepts, metadata)
            
            # Store in memory
            self.vocabularies[vocabulary_name] = concepts
            self.metadata[vocabulary_name] = metadata
            
            logger.info(f"Successfully loaded {vocabulary_name}: {len(concepts)} concepts")
            return metadata
            
        except Exception as e:
            logger.error(f"Error loading vocabulary {vocabulary_name}: {e}")
            return None
    
    async def _download_skos_vocabulary(self, url: str) -> Optional[str]:
        """Download SKOS vocabulary from URL."""
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.debug(f"Downloaded SKOS vocabulary: {len(content)} characters")
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
    
    def _parse_skos_vocabulary(self, skos_data: str, vocabulary_name: str, source_url: str) -> Tuple[Dict[str, SKOSConcept], VocabularyMetadata]:
        """
        Parse SKOS vocabulary data into concepts and metadata.
        
        Supports both RDF/XML and our custom transport vocabularies.
        """
        concepts = {}
        
        # Try to parse as RDF/XML first
        try:
            # Parse XML
            root = ET.fromstring(skos_data)
            
            # Check if it's RDF/XML format
            if root.tag.endswith('RDF') or 'rdf' in root.tag:
                concepts = self._parse_skos_rdf_xml(root, vocabulary_name)
            else:
                # Try other XML formats or fallback to custom vocabularies
                if vocabulary_name in ['transport_terms', 'regulatory_agencies']:
                    concepts = self._generate_transport_concepts(vocabulary_name)
                else:
                    concepts = self._generate_basic_concepts(vocabulary_name)
                    
        except ET.ParseError:
            # Not valid XML, use our custom vocabularies
            logger.debug(f"Not valid XML for {vocabulary_name}, using custom vocabulary generation")
            if vocabulary_name in ['transport_terms', 'regulatory_agencies']:
                concepts = self._generate_transport_concepts(vocabulary_name)
            else:
                concepts = self._generate_basic_concepts(vocabulary_name)
        
        # Create metadata
        metadata = VocabularyMetadata(
            name=vocabulary_name,
            title=f"LexML {vocabulary_name.replace('_', ' ').title()}",
            description=f"Controlled vocabulary for {vocabulary_name}",
            version="1.0.0",
            created=datetime.now(),
            modified=datetime.now(),
            concept_count=len(concepts),
            source_url=source_url
        )
        
        return concepts, metadata
    
    def _parse_skos_rdf_xml(self, root: ET.Element, vocabulary_name: str) -> Dict[str, SKOSConcept]:
        """
        Parse SKOS concepts from RDF/XML format.
        
        Args:
            root: XML root element
            vocabulary_name: Name of the vocabulary being parsed
            
        Returns:
            Dictionary of URI -> SKOSConcept mappings
        """
        concepts = {}
        
        # Define namespaces
        namespaces = {
            'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
            'skos': 'http://www.w3.org/2004/02/skos/core#',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'dcterms': 'http://purl.org/dc/terms/',
            'rdfs': 'http://www.w3.org/2000/01/rdf-schema#'
        }
        
        # Find all SKOS concepts
        for concept_elem in root.findall('.//skos:Concept', namespaces):
            # Get concept URI
            uri = concept_elem.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about')
            if not uri:
                continue
            
            # Extract labels
            pref_label = ""
            alt_labels = []
            
            # Preferred label
            pref_label_elem = concept_elem.find('skos:prefLabel', namespaces)
            if pref_label_elem is not None and pref_label_elem.text:
                pref_label = pref_label_elem.text.strip()
            
            # Alternative labels
            for alt_label_elem in concept_elem.findall('skos:altLabel', namespaces):
                if alt_label_elem.text:
                    alt_labels.append(alt_label_elem.text.strip())
            
            # Definition
            definition = ""
            definition_elem = concept_elem.find('skos:definition', namespaces)
            if definition_elem is not None and definition_elem.text:
                definition = definition_elem.text.strip()
            
            # Hierarchical relationships
            broader = []
            narrower = []
            related = []
            
            # Broader concepts
            for broader_elem in concept_elem.findall('skos:broader', namespaces):
                broader_uri = broader_elem.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource')
                if broader_uri:
                    broader.append(broader_uri)
            
            # Narrower concepts
            for narrower_elem in concept_elem.findall('skos:narrower', namespaces):
                narrower_uri = narrower_elem.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource')
                if narrower_uri:
                    narrower.append(narrower_uri)
            
            # Related concepts
            for related_elem in concept_elem.findall('skos:related', namespaces):
                related_uri = related_elem.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource')
                if related_uri:
                    related.append(related_uri)
            
            # Create concept
            concept = SKOSConcept(
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
            
            concepts[uri] = concept
        
        logger.info(f"Parsed {len(concepts)} SKOS concepts from RDF/XML")
        return concepts
    
    def _generate_transport_concepts(self, vocabulary_name: str) -> Dict[str, SKOSConcept]:
        """Generate transport-specific SKOS concepts."""
        concepts = {}
        
        if vocabulary_name == 'transport_terms':
            # Load transport terms from our existing file
            transport_terms_file = Path(__file__).parent.parent.parent / 'transport_terms.txt'
            if transport_terms_file.exists():
                with open(transport_terms_file, 'r', encoding='utf-8') as f:
                    terms = [line.strip() for line in f if line.strip()]
                
                for i, term in enumerate(terms):
                    uri = f"http://www.lexml.gov.br/vocabularios/transport#{term.replace(' ', '_')}"
                    concept = SKOSConcept(
                        uri=uri,
                        pref_label=term,
                        alt_labels=[],
                        definition=f"Transport-related term: {term}",
                        broader=[],
                        narrower=[],
                        related=[],
                        vocabulary=vocabulary_name,
                        created=datetime.now(),
                        modified=datetime.now()
                    )
                    concepts[uri] = concept
        
        elif vocabulary_name == 'regulatory_agencies':
            agencies = TRANSPORT_CONFIG['regulatory_agencies']
            for agency in agencies:
                uri = f"http://www.lexml.gov.br/vocabularios/agencies#{agency}"
                concept = SKOSConcept(
                    uri=uri,
                    pref_label=agency,
                    alt_labels=[],
                    definition=f"Brazilian transport regulatory agency: {agency}",
                    broader=[],
                    narrower=[],
                    related=[],
                    vocabulary=vocabulary_name,
                    created=datetime.now(),
                    modified=datetime.now()
                )
                concepts[uri] = concept
        
        return concepts
    
    def _generate_basic_concepts(self, vocabulary_name: str) -> Dict[str, SKOSConcept]:
        """Generate basic LexML vocabulary concepts."""
        concepts = {}
        
        # Basic concept mappings from LexML specification
        basic_concepts = {
            'natureza_conteudo': [
                ('texto', 'Texto', 'Conteúdo expresso através de sistemas de notação linguística'),
                ('imagem', 'Imagem', 'Conteúdo expresso através de linhas, formas, cores'),
                ('musica', 'Música', 'Conteúdo expresso através de elementos musicais'),
                ('cartografico', 'Cartográfico', 'Conteúdo cartográfico como mapas e plantas'),
                ('notacao.musical', 'Notação Musical', 'Sistemas de notação musical'),
                ('texto.falado', 'Texto Falado', 'Conteúdo linguístico em forma audível')
            ],
            'lingua': [
                ('pt-br', 'Português (Brasil)', 'Idioma português na variante brasileira'),
                ('en', 'Inglês', 'Idioma inglês'),
                ('es', 'Espanhol', 'Idioma espanhol'),
                ('fr', 'Francês', 'Idioma francês'),
                ('de', 'Alemão', 'Idioma alemão'),
                ('it', 'Italiano', 'Idioma italiano')
            ],
            'evento': [
                ('assinatura', 'Assinatura', 'Evento de assinatura oficial de documentos'),
                ('publicacao', 'Publicação', 'Evento de publicação oficial'),
                ('alteracao', 'Alteração', 'Evento de alteração de documento'),
                ('retificacao', 'Retificação', 'Evento de retificação de publicação'),
                ('republicacao', 'Re-publicação', 'Evento de republicação oficial'),
                ('anulacao', 'Anulação', 'Evento de anulação de documento'),
                ('julgamento', 'Julgamento', 'Evento de julgamento'),
                ('iniciativa', 'Iniciativa', 'Evento de início de proposição legislativa'),
                ('derrubada.veto.parcial', 'Derrubada de Veto Parcial', 'Derrubada de veto parcial pelo Congresso'),
                ('derrubada.veto.total', 'Derrubada de Veto Total', 'Derrubada de veto total pelo Congresso'),
                ('declaracao.inconstitucionalidade', 'Declaração de Inconstitucionalidade', 'Declaração de inconstitucionalidade por tribunal')
            ]
        }
        
        if vocabulary_name in basic_concepts:
            for code, label, definition in basic_concepts[vocabulary_name]:
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
        
        return concepts
    
    def _cache_vocabulary(self, vocabulary_name: str, concepts: Dict[str, SKOSConcept], metadata: VocabularyMetadata) -> None:
        """Cache vocabulary in SQLite database."""
        with self.db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                # Cache metadata
                conn.execute("""
                    INSERT OR REPLACE INTO vocabularies 
                    (name, title, description, version, created, modified, concept_count, source_url, cached_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    metadata.name, metadata.title, metadata.description, metadata.version,
                    metadata.created, metadata.modified, metadata.concept_count, metadata.source_url
                ))
                
                # Cache concepts
                for concept in concepts.values():
                    conn.execute("""
                        INSERT OR REPLACE INTO concepts
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
    
    def _load_vocabulary_from_cache(self, vocabulary_name: str) -> Optional[VocabularyMetadata]:
        """Load vocabulary metadata from cache."""
        with sqlite3.connect(DATABASE_PATH) as conn:
            row = conn.execute("""
                SELECT title, description, version, created, modified, concept_count, source_url
                FROM vocabularies WHERE name = ?
            """, (vocabulary_name,)).fetchone()
            
            if row:
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
        
        return None
    
    def _is_cache_valid(self, vocabulary_name: str) -> bool:
        """Check if cached vocabulary is still valid."""
        with sqlite3.connect(DATABASE_PATH) as conn:
            row = conn.execute("""
                SELECT cached_at FROM vocabularies WHERE name = ?
            """, (vocabulary_name,)).fetchone()
            
            if row:
                cached_at = datetime.fromisoformat(row[0])
                return (datetime.now() - cached_at).total_seconds() < self.cache_ttl
        
        return False
    
    def get_concepts(self, vocabulary_name: str) -> Dict[str, SKOSConcept]:
        """Get all concepts for a vocabulary."""
        if vocabulary_name not in self.vocabularies:
            # Try loading from cache
            concepts = self._load_concepts_from_cache(vocabulary_name)
            if concepts:
                self.vocabularies[vocabulary_name] = concepts
        
        return self.vocabularies.get(vocabulary_name, {})
    
    def _load_concepts_from_cache(self, vocabulary_name: str) -> Dict[str, SKOSConcept]:
        """Load concepts from cache."""
        concepts = {}
        with sqlite3.connect(DATABASE_PATH) as conn:
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
        
        return concepts
    
    def search_concepts(self, query: str, vocabulary_name: str = None) -> List[SKOSConcept]:
        """
        Search for concepts matching a query.
        
        Args:
            query: Search query
            vocabulary_name: Specific vocabulary to search (optional)
            
        Returns:
            List of matching concepts
        """
        results = []
        query_lower = query.lower()
        
        vocabularies_to_search = [vocabulary_name] if vocabulary_name else self.vocabularies.keys()
        
        for vocab_name in vocabularies_to_search:
            concepts = self.get_concepts(vocab_name)
            for concept in concepts.values():
                if (query_lower in concept.pref_label.lower() or
                    any(query_lower in label.lower() for label in concept.alt_labels) or
                    query_lower in concept.definition.lower()):
                    results.append(concept)
        
        return results
    
    def expand_term(self, term: str, vocabulary_name: str = None) -> List[str]:
        """
        Expand a term using controlled vocabulary relationships.
        
        Args:
            term: Term to expand
            vocabulary_name: Specific vocabulary to use
            
        Returns:
            List of expanded terms including synonyms and related terms
        """
        expanded_terms = [term]
        
        # Find concepts matching the term
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
        
        # Remove duplicates and return
        return list(set(expanded_terms))
    
    def _get_concept_by_uri(self, uri: str) -> Optional[SKOSConcept]:
        """Get concept by URI across all vocabularies."""
        for concepts in self.vocabularies.values():
            if uri in concepts:
                return concepts[uri]
        return None
    
    def get_vocabulary_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded vocabularies."""
        stats = {
            'total_vocabularies': len(self.vocabularies),
            'total_concepts': sum(len(concepts) for concepts in self.vocabularies.values()),
            'vocabularies': {}
        }
        
        for vocab_name, concepts in self.vocabularies.items():
            stats['vocabularies'][vocab_name] = {
                'concept_count': len(concepts),
                'has_hierarchy': any(concept.broader or concept.narrower for concept in concepts.values())
            }
        
        return stats