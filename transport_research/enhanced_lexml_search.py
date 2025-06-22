#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced LexML Transport Search with Controlled Vocabularies
===========================================================

Integrates SKOS vocabulary management for enhanced transport legislation search
with hierarchical term expansion, authority filtering, and event-based temporal search.

Features:
- SKOS controlled vocabulary integration
- Hierarchical term expansion
- Authority-based filtering
- Event-based temporal search
- Academic citation support
- FRBROO metadata preparation

Author: Academic Legislative Monitor Development Team
Created: June 2025
Version: 2.0.0
"""

import asyncio
import requests
import xml.etree.ElementTree as ET
import csv
import time
import os
import sys
import signal
import json
from datetime import datetime
from urllib.parse import quote
import logging
from pathlib import Path
import threading
from tqdm import tqdm
import argparse
from typing import List, Dict, Set, Tuple, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.lexml.vocabulary_manager import SKOSVocabularyManager, SKOSConcept
from core.lexml.config import VOCABULARY_ENDPOINTS, TRANSPORT_CONFIG, CITATION_STANDARDS

# Configure logging
log_dir = Path.home() / '.lexml_logs'
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / f'enhanced_lexml_search_{datetime.now().strftime("%Y%m%d")}.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ControlledVocabularyTransportSearcher:
    """
    Enhanced transport search with controlled vocabulary expansion.
    
    This class extends the basic LexML search functionality with:
    - SKOS vocabulary integration for term expansion
    - Hierarchical navigation of controlled vocabularies
    - Authority-based filtering using controlled terms
    - Event-based temporal search capabilities
    - Academic metadata enhancement for FRBROO compliance
    """
    
    def __init__(self, output_dir=None, resume=False, use_vocabularies=True):
        """
        Initialize the enhanced searcher.
        
        Args:
            output_dir: Output directory for results
            resume: Resume from previous search
            use_vocabularies: Enable controlled vocabulary features
        """
        self.base_url = "https://www.lexml.gov.br/busca/SRU"
        self.use_vocabularies = use_vocabularies
        self.vocabulary_manager = None
        self.expanded_terms_cache = {}
        
        # Initialize results structure with enhanced metadata
        self.results = {
            'lei': [],
            'decreto': [],
            'portaria': [],
            'resolucao': [],
            'medida_provisoria': [],
            'projeto_lei': [],
            'instrucao_normativa': [],
            'outros': []
        }
        
        # Enhanced metadata tracking
        self.metadata = {
            'search_session': {
                'id': datetime.now().strftime('%Y%m%d_%H%M%S'),
                'start_time': datetime.now(),
                'vocabulary_enabled': use_vocabularies,
                'vocabularies_loaded': []
            },
            'term_expansions': {},
            'authority_filters': [],
            'event_filters': []
        }
        
        # Output directory setup
        if output_dir:
            self.output_dir = Path(output_dir).expanduser()
        else:
            self.output_dir = Path.home() / 'lexml_enhanced_results'
        
        self.output_dir.mkdir(exist_ok=True)
        
        # Progress tracking
        self.progress_file = self.output_dir / '.enhanced_progress.json'
        self.processed_terms = set()
        self.stop_signal = False
        
        # Resume capability
        if resume and self.progress_file.exists():
            self.load_progress()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"Enhanced Transport Searcher initialized (vocabularies: {use_vocabularies})")
    
    async def initialize_vocabularies(self):
        """Initialize SKOS vocabulary manager and load vocabularies."""
        if not self.use_vocabularies:
            return
        
        logger.info("Initializing SKOS vocabulary manager...")
        
        try:
            async with SKOSVocabularyManager() as vocab_manager:
                self.vocabulary_manager = vocab_manager
                
                # Load transport-specific vocabularies
                transport_vocabs = ['transport_terms', 'regulatory_agencies', 
                                  'autoridade', 'evento', 'tipo_documento']
                
                for vocab_name in transport_vocabs:
                    logger.info(f"Loading vocabulary: {vocab_name}")
                    metadata = await vocab_manager.load_vocabulary(vocab_name)
                    if metadata:
                        self.metadata['search_session']['vocabularies_loaded'].append(vocab_name)
                        logger.info(f"Loaded {metadata.concept_count} concepts from {vocab_name}")
                
                # Get vocabulary statistics
                stats = vocab_manager.get_vocabulary_stats()
                logger.info(f"Vocabulary initialization complete: {stats['total_concepts']} total concepts")
                
        except Exception as e:
            logger.error(f"Error initializing vocabularies: {e}")
            logger.warning("Continuing without vocabulary enhancement")
            self.use_vocabularies = False
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully."""
        logger.info("\nReceived interrupt signal. Saving progress...")
        self.stop_signal = True
        self.save_progress()
        logger.info("Progress saved. You can resume later with --resume flag")
        sys.exit(0)
    
    def save_progress(self):
        """Save current progress for resume capability."""
        progress_data = {
            'processed_terms': list(self.processed_terms),
            'results': {k: len(v) for k, v in self.results.items()},
            'metadata': self.metadata,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(self.progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, ensure_ascii=False, indent=2)
    
    def load_progress(self):
        """Load previous progress."""
        try:
            with open(self.progress_file, 'r', encoding='utf-8') as f:
                progress_data = json.load(f)
                self.processed_terms = set(progress_data.get('processed_terms', []))
                self.metadata = progress_data.get('metadata', self.metadata)
                logger.info(f"Resumed from previous session. {len(self.processed_terms)} terms already processed.")
        except Exception as e:
            logger.error(f"Error loading progress: {e}")
    
    async def expand_search_term(self, term: str) -> List[str]:
        """
        Expand a search term using controlled vocabularies.
        
        Args:
            term: Base search term
            
        Returns:
            List of expanded terms including synonyms and related concepts
        """
        if not self.use_vocabularies or not self.vocabulary_manager:
            return [term]
        
        # Check cache
        if term in self.expanded_terms_cache:
            return self.expanded_terms_cache[term]
        
        expanded_terms = [term]
        
        try:
            # Search for concepts matching the term
            concepts = self.vocabulary_manager.search_concepts(term)
            
            for concept in concepts:
                # Add preferred and alternative labels
                expanded_terms.append(concept.pref_label)
                expanded_terms.extend(concept.alt_labels)
                
                # Add narrower terms (more specific)
                for narrower_uri in concept.narrower:
                    narrower_concept = self.vocabulary_manager._get_concept_by_uri(narrower_uri)
                    if narrower_concept:
                        expanded_terms.append(narrower_concept.pref_label)
                
                # Optionally add related terms
                for related_uri in concept.related[:3]:  # Limit to avoid over-expansion
                    related_concept = self.vocabulary_manager._get_concept_by_uri(related_uri)
                    if related_concept:
                        expanded_terms.append(related_concept.pref_label)
            
            # Remove duplicates and clean
            expanded_terms = list(set(term.strip() for term in expanded_terms if term.strip()))
            
            # Cache the result
            self.expanded_terms_cache[term] = expanded_terms
            
            # Track expansion in metadata
            if len(expanded_terms) > 1:
                self.metadata['term_expansions'][term] = expanded_terms
            
        except Exception as e:
            logger.warning(f"Error expanding term '{term}': {e}")
        
        return expanded_terms
    
    def get_authority_filters(self) -> List[str]:
        """Get authority filters from controlled vocabulary."""
        if not self.use_vocabularies or not self.vocabulary_manager:
            return ['Federal']
        
        authorities = []
        
        try:
            # Get concepts from authority vocabulary
            authority_concepts = self.vocabulary_manager.get_concepts('autoridade')
            
            # Filter for transport-relevant authorities
            transport_authorities = ['Federal', 'ANTT', 'CONTRAN', 'DNIT', 'ANTAQ', 'ANAC']
            
            for concept in authority_concepts.values():
                if any(auth in concept.pref_label for auth in transport_authorities):
                    authorities.append(concept.pref_label)
            
            self.metadata['authority_filters'] = authorities
            
        except Exception as e:
            logger.warning(f"Error getting authority filters: {e}")
            authorities = ['Federal']
        
        return authorities
    
    def get_event_filters(self) -> List[str]:
        """Get event filters from controlled vocabulary."""
        if not self.use_vocabularies or not self.vocabulary_manager:
            return []
        
        events = []
        
        try:
            # Get concepts from event vocabulary
            event_concepts = self.vocabulary_manager.get_concepts('evento')
            
            # Transport-relevant events
            relevant_events = ['publicacao', 'alteracao', 'retificacao', 'assinatura']
            
            for concept in event_concepts.values():
                if any(event in concept.pref_label.lower() for event in relevant_events):
                    events.append(concept.pref_label)
            
            self.metadata['event_filters'] = events
            
        except Exception as e:
            logger.warning(f"Error getting event filters: {e}")
        
        return events
    
    async def build_enhanced_search_terms(self) -> List[Tuple[str, List[str]]]:
        """
        Build search terms with vocabulary expansion.
        
        Returns:
            List of tuples (original_term, expanded_terms)
        """
        # Get base terms from original implementation
        base_terms = self._get_base_transport_terms()
        
        enhanced_terms = []
        
        for term in base_terms:
            # Expand each term using vocabularies
            expanded = await self.expand_search_term(term)
            enhanced_terms.append((term, expanded))
        
        return enhanced_terms
    
    def _get_base_transport_terms(self) -> List[str]:
        """Get base transport search terms."""
        # Basic transport terms
        general_terms = [
            'transporte de carga',
            'transporte rodoviário',
            'logística',
            'frete',
            'caminhão',
            'veículos pesados',
            'veículos comerciais'
        ]
        
        # Fuel and sustainability terms
        fuel_terms = [
            'gás natural veicular',
            'biometano',
            'combustível sustentável',
            'hidrogênio',
            'descarbonização'
        ]
        
        # Regulatory terms
        regulatory_terms = [
            'ANTT',
            'CONTRAN',
            'RNTRC',
            'licenciamento'
        ]
        
        # Programs and initiatives
        program_terms = [
            'Rota 2030',
            'PATEN',
            'mobilidade sustentável'
        ]
        
        return general_terms + fuel_terms + regulatory_terms + program_terms
    
    def build_enhanced_query_url(self, search_terms: List[str], authorities: List[str], 
                                events: List[str], start_record=1, maximum_records=100) -> str:
        """
        Build enhanced SRU query URL with vocabulary filters.
        
        Args:
            search_terms: List of search terms (already expanded)
            authorities: List of authority filters
            events: List of event filters
            start_record: Starting record number
            maximum_records: Maximum records to retrieve
            
        Returns:
            Formatted query URL
        """
        # Build search term query
        term_query = ' OR '.join([f'"{term}"' for term in search_terms])
        
        # Legislative document type filter
        legislative_filter = '(lei OR decreto OR portaria OR resolução OR "medida provisória" OR "projeto de lei" OR "instrução normativa")'
        
        # Authority filter
        authority_filter = ' OR '.join([f'autoridade any "{auth}"' for auth in authorities]) if authorities else 'autoridade any "Federal"'
        
        # Event filter (optional)
        event_filter = ''
        if events:
            event_parts = [f'evento any "{event}"' for event in events]
            event_filter = f' AND ({" OR ".join(event_parts)})'
        
        # Date range filter
        date_filter = ' OR '.join([f'date any "{year}"' for year in range(2015, 2026)])
        
        # Build complete query
        query = f'({term_query}) AND {legislative_filter} AND ({authority_filter}) AND ({date_filter}){event_filter}'
        
        # URL encode
        encoded_query = quote(query)
        
        # Build URL
        url = f"{self.base_url}?operation=searchRetrieve&query={encoded_query}&startRecord={start_record}&maximumRecords={maximum_records}"
        
        return url
    
    def parse_enhanced_sru_response(self, xml_content: bytes) -> Tuple[List[Dict], int]:
        """
        Parse SRU response with enhanced metadata extraction.
        
        Args:
            xml_content: XML response content
            
        Returns:
            Tuple of (records, total_count)
        """
        try:
            root = ET.fromstring(xml_content.decode('utf-8', errors='replace'))
            
            namespaces = {
                'srw': 'http://www.loc.gov/zing/srw/',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'srw_dc': 'info:srw/schema/1/dc-schema'
            }
            
            records = []
            
            for record in root.findall('.//srw:record', namespaces):
                record_data = {}
                
                def safe_extract(elem_name, namespace=None):
                    if namespace:
                        elem = record.find(f'.//{namespace}:{elem_name}', namespaces)
                    else:
                        elem = record.find(f'.//{elem_name}')
                    return elem.text if elem is not None and elem.text else ''
                
                # Standard fields
                record_data['urn'] = safe_extract('urn')
                record_data['tipo_documento'] = safe_extract('tipoDocumento')
                record_data['data'] = safe_extract('date', 'dc')
                record_data['titulo'] = safe_extract('title', 'dc')
                record_data['descricao'] = safe_extract('description', 'dc')
                record_data['assunto'] = safe_extract('subject', 'dc')
                record_data['identificador'] = safe_extract('identifier', 'dc')
                record_data['localidade'] = safe_extract('localidade')
                record_data['autoridade'] = safe_extract('autoridade')
                
                # Enhanced metadata for FRBROO preparation
                record_data['enhanced_metadata'] = {
                    'search_session_id': self.metadata['search_session']['id'],
                    'vocabulary_matched': False,
                    'expanded_from': None,
                    'temporal_event': None,
                    'frbroo_work_type': 'legislative_work'
                }
                
                if record_data['titulo'] or record_data['urn']:
                    records.append(record_data)
            
            # Extract total records
            num_records_elem = root.find('.//srw:numberOfRecords', namespaces)
            total_records = 0
            if num_records_elem is not None and num_records_elem.text:
                try:
                    total_records = int(num_records_elem.text)
                except ValueError:
                    total_records = 0
            
            return records, total_records
            
        except Exception as e:
            logger.error(f"Error parsing XML: {e}")
            return [], 0
    
    def categorize_document(self, tipo_documento: str, titulo: str) -> str:
        """Categorize document based on type."""
        tipo_lower = tipo_documento.lower() if tipo_documento else ''
        titulo_lower = titulo.lower() if titulo else ''
        
        if 'lei' in tipo_lower and 'projeto' not in tipo_lower:
            return 'lei'
        elif 'decreto' in tipo_lower:
            return 'decreto'
        elif 'portaria' in tipo_lower:
            return 'portaria'
        elif 'resolução' in tipo_lower or 'resolucao' in tipo_lower:
            return 'resolucao'
        elif 'medida provisória' in tipo_lower or 'medida provisoria' in tipo_lower:
            return 'medida_provisoria'
        elif 'projeto' in tipo_lower and 'lei' in tipo_lower:
            return 'projeto_lei'
        elif 'instrução normativa' in tipo_lower or 'instrucao normativa' in tipo_lower:
            return 'instrucao_normativa'
        else:
            return 'outros'
    
    async def search_enhanced_term(self, original_term: str, expanded_terms: List[str], pbar=None):
        """
        Search for a term with vocabulary expansion.
        
        Args:
            original_term: Original search term
            expanded_terms: List of expanded terms
            pbar: Progress bar instance
        """
        # Get filters
        authorities = self.get_authority_filters()
        events = self.get_event_filters()
        
        start_record = 1
        maximum_records = 100
        total_retrieved = 0
        
        while True:
            if self.stop_signal:
                break
            
            try:
                # Build enhanced URL
                url = self.build_enhanced_query_url(
                    expanded_terms, authorities, events, 
                    start_record, maximum_records
                )
                
                # Make request with retries
                for attempt in range(3):
                    try:
                        response = requests.get(url, timeout=30)
                        response.raise_for_status()
                        break
                    except requests.exceptions.RequestException as e:
                        if attempt == 2:
                            raise e
                        time.sleep(2 ** attempt)
                
                # Parse response
                records, total_records = self.parse_enhanced_sru_response(response.content)
                
                # Enhance record metadata
                for record in records:
                    record['termo_busca'] = original_term
                    record['termos_expandidos'] = expanded_terms
                    record['enhanced_metadata']['vocabulary_matched'] = len(expanded_terms) > 1
                    record['enhanced_metadata']['expanded_from'] = original_term
                    
                    # Categorize and store
                    category = self.categorize_document(
                        record.get('tipo_documento', ''),
                        record.get('titulo', '')
                    )
                    self.results[category].append(record)
                
                total_retrieved += len(records)
                
                if pbar:
                    pbar.set_postfix({'Retrieved': f'{total_retrieved}/{total_records}'})
                
                if total_retrieved >= total_records or len(records) == 0:
                    break
                
                start_record += maximum_records
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error searching for '{original_term}': {e}")
                break
    
    async def search_all_enhanced_terms(self):
        """Search all terms with vocabulary enhancement."""
        # Get enhanced terms
        enhanced_terms = await self.build_enhanced_search_terms()
        
        # Filter out processed terms
        remaining_terms = [(orig, exp) for orig, exp in enhanced_terms 
                          if orig not in self.processed_terms]
        
        if not remaining_terms:
            logger.info("All terms have been processed!")
            return
        
        logger.info(f"Processing {len(remaining_terms)} terms with vocabulary expansion...")
        
        with tqdm(total=len(remaining_terms), desc="Enhanced search", unit="term") as pbar:
            for original_term, expanded_terms in remaining_terms:
                if self.stop_signal:
                    break
                
                expansion_info = f" → {len(expanded_terms)} terms" if len(expanded_terms) > 1 else ""
                pbar.set_description(f"Searching: {original_term[:30]}...{expansion_info}")
                
                await self.search_enhanced_term(original_term, expanded_terms, pbar)
                self.processed_terms.add(original_term)
                
                if len(self.processed_terms) % 5 == 0:
                    self.save_progress()
                
                pbar.update(1)
                time.sleep(2)
    
    def deduplicate_results(self):
        """Remove duplicate records based on URN."""
        logger.info("Removing duplicates...")
        
        for category in self.results:
            seen_urns = set()
            unique_records = []
            
            for record in self.results[category]:
                urn = record.get('urn', '')
                if urn and urn not in seen_urns:
                    seen_urns.add(urn)
                    unique_records.append(record)
                elif not urn:
                    unique_records.append(record)
            
            self.results[category] = unique_records
    
    def export_enhanced_results(self):
        """Export results with enhanced metadata."""
        self.deduplicate_results()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export each category with enhanced fields
        for category, records in self.results.items():
            if records:
                filename = self.output_dir / f'{category}_enhanced_{timestamp}.csv'
                
                with open(filename, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    fieldnames = [
                        'urn', 'tipo_documento', 'data', 'titulo', 'descricao',
                        'assunto', 'identificador', 'localidade', 'autoridade',
                        'termo_busca', 'vocabulary_expanded', 'num_expanded_terms'
                    ]
                    
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    
                    # Write with enhanced fields
                    for record in records:
                        enhanced_record = record.copy()
                        enhanced_record['vocabulary_expanded'] = record['enhanced_metadata']['vocabulary_matched']
                        enhanced_record['num_expanded_terms'] = len(record.get('termos_expandidos', []))
                        writer.writerow(enhanced_record)
                
                os.chmod(filename, 0o644)
                logger.info(f"Exported {len(records)} enhanced records to {filename}")
        
        # Create enhanced summary
        summary_file = self.output_dir / f'enhanced_summary_{timestamp}.json'
        summary_data = {
            'search_session': self.metadata['search_session'],
            'statistics': {
                'total_documents': sum(len(records) for records in self.results.values()),
                'documents_by_type': {cat: len(records) for cat, records in self.results.items()},
                'vocabulary_expansions': len(self.metadata['term_expansions']),
                'authorities_used': self.metadata['authority_filters'],
                'events_filtered': self.metadata['event_filters']
            },
            'term_expansions': self.metadata['term_expansions']
        }
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, ensure_ascii=False, indent=2, default=str)
        
        os.chmod(summary_file, 0o644)
        logger.info(f"Enhanced summary saved to {summary_file}")


async def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Enhanced LexML Transport Search with Controlled Vocabularies')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume from previous search')
    parser.add_argument('--no-vocab', action='store_true', help='Disable vocabulary enhancement')
    
    args = parser.parse_args()
    
    logger.info("Starting Enhanced LexML Transport Search")
    logger.info("=" * 60)
    
    # Create searcher instance
    searcher = ControlledVocabularyTransportSearcher(
        output_dir=args.output,
        resume=args.resume,
        use_vocabularies=not args.no_vocab
    )
    
    try:
        # Initialize vocabularies if enabled
        if not args.no_vocab:
            await searcher.initialize_vocabularies()
        
        # Perform enhanced searches
        await searcher.search_all_enhanced_terms()
        
        # Export results
        searcher.export_enhanced_results()
        
        logger.info("Enhanced search completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("\nSearch interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        searcher.save_progress()


if __name__ == "__main__":
    asyncio.run(main())