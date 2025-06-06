#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Brasil API Integration with Fallback Web Scraping
Implements SRU protocol with CQL queries and automatic fallback to web scraping
"""

import requests
import xml.etree.ElementTree as ET
import csv
import json
import time
import re
from datetime import datetime
from urllib.parse import urlencode, quote
from typing import List, Dict, Optional, Set
from pathlib import Path
import logging

# Import the fallback scraper
from fallback_scraper import LexMLWebScraperFallback


class LexMLIntegration:
    """
    Main class for LexML API integration with fallback web scraping
    Implements SRU 1.1/1.2 protocol with CQL queries
    """
    
    def __init__(self, output_dir: str = "data/lexml_results"):
        self.api_base_url = "https://www.lexml.gov.br/busca/SRU"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/xml'
        })
        
        # Initialize fallback scraper
        self.fallback_scraper = LexMLWebScraperFallback()
        
        # Setup output directory
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Track processed URNs to avoid duplicates
        self.processed_urns: Set[str] = set()
        
        # Statistics
        self.stats = {
            'total_searches': 0,
            'api_successes': 0,
            'api_failures': 0,
            'fallback_uses': 0,
            'total_results': 0,
            'duplicates_removed': 0,
            'search_errors': {}
        }
    
    def search_all_terms(self, terms_file: str = "transport_terms.txt") -> List[Dict]:
        """
        Search for all terms in the provided file
        Returns consolidated results
        """
        # Load search terms
        terms = self._load_search_terms(terms_file)
        self.logger.info(f"Loaded {len(terms)} search terms")
        
        all_results = []
        
        for i, term in enumerate(terms, 1):
            self.logger.info(f"Searching term {i}/{len(terms)}: {term}")
            self.stats['total_searches'] += 1
            
            # Try API first
            results = self._search_api(term)
            
            # If API fails, use fallback scraper
            if results is None:
                self.logger.warning(f"API failed for '{term}', using fallback scraper")
                self.stats['fallback_uses'] += 1
                results = self.fallback_scraper.search_term(term, max_pages=3)
            
            # Process and deduplicate results
            for result in results:
                if self._is_unique_result(result):
                    all_results.append(result)
                    self.stats['total_results'] += 1
                else:
                    self.stats['duplicates_removed'] += 1
            
            # Rate limiting
            time.sleep(1)
        
        return all_results
    
    def _load_search_terms(self, filename: str) -> List[str]:
        """Load and clean search terms from file"""
        terms = []
        
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    # Remove quotes if present
                    term = line.strip('"\'')
                    if term:
                        terms.append(term)
        
        return terms
    
    def _search_api(self, search_term: str, max_retries: int = 3) -> Optional[List[Dict]]:
        """
        Search using LexML SRU API with retry logic
        Returns None if API fails after retries
        """
        all_results = []
        start_record = 1
        max_records = 100
        
        while True:
            # Build CQL query
            cql_query = f'urn any "{search_term}" or subject any "{search_term}" or title any "{search_term}"'
            
            params = {
                'operation': 'searchRetrieve',
                'version': '1.1',
                'query': cql_query,
                'maximumRecords': max_records,
                'startRecord': start_record
            }
            
            # Retry logic
            for attempt in range(max_retries):
                try:
                    response = self.session.get(
                        self.api_base_url,
                        params=params,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        # Parse XML response
                        results, total_records = self._parse_sru_response(
                            response.text,
                            search_term
                        )
                        all_results.extend(results)
                        
                        # Check if we need to paginate
                        if start_record + len(results) >= total_records:
                            self.stats['api_successes'] += 1
                            return all_results
                        
                        start_record += max_records
                        break
                    
                    elif response.status_code == 500:
                        self.logger.error(f"API returned 500 error for '{search_term}'")
                        if attempt < max_retries - 1:
                            time.sleep(2 ** attempt)  # Exponential backoff
                            continue
                    
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request error for '{search_term}': {e}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
            
            # If we get here, all retries failed
            self.stats['api_failures'] += 1
            self.stats['search_errors'][search_term] = "API failed after retries"
            return None
    
    def _parse_sru_response(self, xml_content: str, search_term: str) -> tuple:
        """
        Parse SRU XML response and extract metadata
        Returns (results, total_records)
        """
        results = []
        total_records = 0
        
        try:
            # Parse XML
            root = ET.fromstring(xml_content)
            
            # Define namespaces
            namespaces = {
                'srw': 'http://www.loc.gov/zing/srw/',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'lex': 'http://www.lexml.gov.br/namespace/1.0/'
            }
            
            # Get total records
            total_elem = root.find('.//srw:numberOfRecords', namespaces)
            if total_elem is not None:
                total_records = int(total_elem.text)
            
            # Extract records
            records = root.findall('.//srw:record', namespaces)
            
            for record in records:
                # Extract Dublin Core metadata
                result = {
                    'search_term': search_term,
                    'date_searched': datetime.now().isoformat(),
                    'source': 'api'
                }
                
                # URN/Identifier
                urn_elem = record.find('.//dc:identifier', namespaces)
                if urn_elem is not None:
                    result['urn'] = urn_elem.text
                    result['url'] = f"https://www.lexml.gov.br/urn/{urn_elem.text}"
                
                # Title
                title_elem = record.find('.//dc:title', namespaces)
                if title_elem is not None:
                    result['title'] = title_elem.text
                
                # Date
                date_elem = record.find('.//dc:date', namespaces)
                if date_elem is not None:
                    result['document_date'] = date_elem.text
                
                # Type
                type_elem = record.find('.//dc:type', namespaces)
                if type_elem is not None:
                    result['document_type'] = type_elem.text
                
                # Description
                desc_elem = record.find('.//dc:description', namespaces)
                if desc_elem is not None:
                    result['description'] = desc_elem.text
                
                # Subject
                subject_elems = record.findall('.//dc:subject', namespaces)
                if subject_elems:
                    result['subjects'] = '; '.join([s.text for s in subject_elems if s.text])
                
                # Publisher/Authority
                publisher_elem = record.find('.//dc:publisher', namespaces)
                if publisher_elem is not None:
                    result['authority'] = publisher_elem.text
                
                results.append(result)
        
        except ET.ParseError as e:
            self.logger.error(f"XML parsing error for '{search_term}': {e}")
            return [], 0
        
        return results, total_records
    
    def _is_unique_result(self, result: Dict) -> bool:
        """Check if result is unique based on URN"""
        urn = result.get('urn', '')
        
        if not urn:
            # If no URN, use URL as identifier
            urn = result.get('url', '')
        
        if urn in self.processed_urns:
            return False
        
        self.processed_urns.add(urn)
        return True
    
    def save_results(self, results: List[Dict], filename: str = None):
        """Save results to CSV file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"lexml_results_{timestamp}.csv"
        
        # Define CSV columns
        fieldnames = [
            'search_term', 'urn', 'title', 'document_date', 'document_type',
            'authority', 'description', 'subjects', 'url', 'source', 'date_searched'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Ensure all fields exist
                row = {field: result.get(field, '') for field in fieldnames}
                writer.writerow(row)
        
        self.logger.info(f"Saved {len(results)} results to {filename}")
        return filename
    
    def generate_summary_report(self, results: List[Dict], filename: str = None):
        """Generate a summary report of the search results"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"lexml_summary_{timestamp}.json"
        
        # Analyze results
        summary = {
            'execution_date': datetime.now().isoformat(),
            'statistics': self.stats,
            'results_by_type': {},
            'results_by_authority': {},
            'results_by_year': {},
            'results_by_search_term': {},
            'top_subjects': {}
        }
        
        # Count by document type
        for result in results:
            doc_type = result.get('document_type', 'Unknown')
            summary['results_by_type'][doc_type] = summary['results_by_type'].get(doc_type, 0) + 1
            
            # Count by authority
            authority = result.get('authority', 'Unknown')
            summary['results_by_authority'][authority] = summary['results_by_authority'].get(authority, 0) + 1
            
            # Count by year
            doc_date = result.get('document_date', '')
            if doc_date:
                year = doc_date[:4]
                summary['results_by_year'][year] = summary['results_by_year'].get(year, 0) + 1
            
            # Count by search term
            term = result.get('search_term', 'Unknown')
            summary['results_by_search_term'][term] = summary['results_by_search_term'].get(term, 0) + 1
            
            # Extract subjects
            subjects = result.get('subjects', '')
            if subjects:
                for subject in subjects.split(';'):
                    subject = subject.strip()
                    if subject:
                        summary['top_subjects'][subject] = summary['top_subjects'].get(subject, 0) + 1
        
        # Sort and limit top subjects
        summary['top_subjects'] = dict(
            sorted(summary['top_subjects'].items(), key=lambda x: x[1], reverse=True)[:20]
        )
        
        # Save report
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        
        self.logger.info(f"Generated summary report: {filename}")
        return filename


def main():
    """Example usage of LexML integration"""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create integration instance
    lexml = LexMLIntegration()
    
    # Search all terms
    print("Starting LexML search for transport-related legislation...")
    results = lexml.search_all_terms()
    
    # Save results
    csv_file = lexml.save_results(results)
    print(f"\nResults saved to: {csv_file}")
    
    # Generate summary report
    report_file = lexml.generate_summary_report(results)
    print(f"Summary report saved to: {report_file}")
    
    # Print statistics
    print("\nSearch Statistics:")
    print(f"Total searches: {lexml.stats['total_searches']}")
    print(f"API successes: {lexml.stats['api_successes']}")
    print(f"API failures: {lexml.stats['api_failures']}")
    print(f"Fallback uses: {lexml.stats['fallback_uses']}")
    print(f"Total results: {lexml.stats['total_results']}")
    print(f"Duplicates removed: {lexml.stats['duplicates_removed']}")
    
    if lexml.stats['search_errors']:
        print("\nSearch errors:")
        for term, error in lexml.stats['search_errors'].items():
            print(f"  {term}: {error}")


if __name__ == "__main__":
    main()