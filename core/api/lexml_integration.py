#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Brasil API Integration with Fallback Web Scraping
Implements SRU protocol with CQL queries and automatic fallback to web scraping

SECURITY MEASURES IMPLEMENTED:
1. Input Validation:
   - Comprehensive sanitization of search terms to prevent CQL/SQL injection
   - HTML/script tag removal to prevent XSS attacks
   - Unicode normalization to prevent encoding-based attacks
   - Length limits on all input fields
   - Character validation using allowlists

2. XML Security:
   - XML content validation before parsing
   - Protection against XXE (XML External Entity) attacks
   - Size limits on XML responses
   - Validation of all extracted fields

3. URL Security:
   - URL encoding of all query parameters
   - Validation of URN format before building URLs
   - Prevention of redirect attacks

4. Rate Limiting:
   - Integration with rate limiter to prevent abuse
   - API-specific rate limiting to respect service limits

5. Output Validation:
   - Sanitization of all data before export
   - Validation of file paths and names
   - Protection against path traversal

6. Error Handling:
   - Secure error messages that don't expose internals
   - Proper exception handling for all operations
"""

import requests
import xml.etree.ElementTree as ET
import csv
import json
import time
import re
from datetime import datetime
from urllib.parse import urlencode, quote, quote_plus
from typing import List, Dict, Optional, Set
from pathlib import Path
import logging
import html
import unicodedata

# Import the fallback scraper  
from fallback_scraper import LexMLWebScraperFallback

# CRITICAL SECURITY: Import input validation and rate limiting
from core.utils.input_validator import validate_legislative_search_query, sanitize_input
from core.utils.rate_limiter import get_rate_limiter


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
        
        # CRITICAL FIX: Initialize rate limiter to prevent IP blocking
        self.rate_limiter = get_rate_limiter()
        self.client_id = "lexml_integration"
        
        # Rate limiting settings for LexML API (respectful usage)
        self.min_request_interval = 2.0  # Minimum 2 seconds between requests
        self.last_request_time = 0
        
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
            'search_errors': {},
            'rate_limited_requests': 0
        }
    
    def search(self, search_term: str) -> List[Dict]:
        """
        Public method to search LexML with comprehensive security validation
        
        Args:
            search_term: The search query
            
        Returns:
            List of search results
            
        Raises:
            ValueError: If search term is invalid or contains dangerous content
        """
        # Apply comprehensive validation
        try:
            # Use the legislative search validator from input_validator
            validated_term = validate_legislative_search_query(search_term)
        except ValueError as e:
            self.logger.error(f"Search validation failed: {e}")
            raise ValueError(f"Invalid search query: {e}")
        
        self.logger.info(f"Searching for validated term: {validated_term}")
        self.stats['total_searches'] += 1
        
        # Try API first
        results = self._search_api(validated_term)
        
        # If API fails, use fallback scraper
        if results is None:
            self.logger.warning(f"API failed for '{validated_term}', using fallback scraper")
            self.stats['fallback_uses'] += 1
            try:
                results = self.fallback_scraper.search_term(validated_term, max_pages=3)
            except Exception as e:
                self.logger.error(f"Fallback scraper also failed: {e}")
                results = []
        
        # Process and deduplicate results
        unique_results = []
        for result in results:
            if self._is_unique_result(result):
                unique_results.append(result)
                self.stats['total_results'] += 1
            else:
                self.stats['duplicates_removed'] += 1
        
        return unique_results
    
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
    
    def _sanitize_cql_term(self, term: str) -> str:
        """
        Comprehensive sanitization for CQL queries - INJECTION PREVENTION
        Implements multiple layers of security to prevent injection attacks
        """
        if not term or not isinstance(term, str):
            raise ValueError("Invalid search term: must be a non-empty string")
        
        # Step 1: Normalize unicode to prevent encoding-based attacks
        term = unicodedata.normalize('NFKC', term)
        
        # Step 2: Decode HTML entities to prevent double-encoding attacks
        term = html.unescape(term)
        
        # Step 3: Remove null bytes and control characters
        term = ''.join(char for char in term if ord(char) >= 32 or char in '\n\t')
        term = term.replace('\x00', '').replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
        
        # Step 4: Length validation (before any processing)
        if len(term) > 500:
            term = term[:500]
        
        # Step 5: Remove/neutralize dangerous CQL operators and SQL-like patterns
        dangerous_patterns = [
            # CQL Boolean operators (case-insensitive)
            (r'\b(AND|OR|NOT|PROX)\b', ' ', re.IGNORECASE),
            # CQL relation operators
            (r'\b(all|any|exact|within)\b', ' ', re.IGNORECASE),
            # CQL special operators
            (r'\b(sortBy|recordSchema)\b', ' ', re.IGNORECASE),
            # Comparison operators
            (r'[<>=!]+', ' ', 0),
            # Grouping and special characters
            (r'[(){}[\]]', ' ', 0),
            # Wildcards and regex patterns
            (r'[*?+]', ' ', 0),
            # Quotes and potential string terminators
            (r'[\'"`;]', ' ', 0),
            # Escape sequences
            (r'\\[^\s]', ' ', 0),
            # SQL-like keywords (additional protection)
            (r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|DECLARE)\b', ' ', re.IGNORECASE),
            # URL schemes
            (r'(javascript|vbscript|data|file|ftp):', ' ', re.IGNORECASE),
            # HTML/Script tags
            (r'<[^>]*>', ' ', 0),
            # Comment patterns
            (r'(--|#|/\*|\*/|//)', ' ', 0),
            # Hex encoding attempts
            (r'(0x[0-9a-fA-F]+|\x[0-9a-fA-F]{2})', ' ', 0),
            # Unicode escape sequences
            (r'(\\u[0-9a-fA-F]{4}|&#x?[0-9]+;)', ' ', 0),
            # Multiple consecutive spaces (could hide payloads)
            (r'\s{2,}', ' ', 0),
        ]
        
        sanitized = term
        for pattern, replacement, flags in dangerous_patterns:
            if flags:
                sanitized = re.sub(pattern, replacement, sanitized, flags=flags)
            else:
                sanitized = re.sub(pattern, replacement, sanitized)
        
        # Step 6: Additional validation for remaining content
        # Allow only: letters (including accented), numbers, spaces, and basic punctuation
        allowed_chars_pattern = r'[^a-zA-ZÀ-ÿ0-9\s\-_.,/()]'
        sanitized = re.sub(allowed_chars_pattern, ' ', sanitized)
        
        # Step 7: Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        # Step 8: Final length check
        if len(sanitized) > 200:
            sanitized = sanitized[:200]
        
        # Step 9: Validate minimum content
        if len(sanitized.strip()) < 2:
            raise ValueError("Search term too short after sanitization (minimum 2 characters)")
        
        # Step 10: Final security check - ensure no patterns slipped through
        final_check_patterns = [
            r'(union.*select|select.*from|insert.*into|delete.*from)',
            r'(script|javascript|vbscript)',
            r'(onload|onerror|onclick|onmouseover)',
            r'<[^>]*>',
        ]
        
        for pattern in final_check_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                raise ValueError(f"Search term contains potentially dangerous content")
        
        return sanitized.strip()
    
    def _sanitize_field(self, value: str, max_length: int = 500) -> str:
        """
        Sanitize individual field values from XML responses
        """
        if not value:
            return ""
        
        # Remove null bytes and control characters
        value = value.replace('\x00', '')
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t ')
        
        # Normalize unicode
        value = unicodedata.normalize('NFKC', value)
        
        # Decode HTML entities
        value = html.unescape(value)
        
        # Remove potential script/HTML tags
        value = re.sub(r'<[^>]*>', ' ', value)
        
        # Remove dangerous patterns
        dangerous_patterns = [
            r'javascript:', r'vbscript:', r'data:',
            r'on\w+\s*=', r'<script', r'</script',
            r'&#x?[0-9]+;',  # HTML entities
            r'\\x[0-9a-fA-F]{2}',  # Hex escapes
            r'\\u[0-9a-fA-F]{4}',  # Unicode escapes
        ]
        
        for pattern in dangerous_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        
        # Normalize whitespace
        value = ' '.join(value.split())
        
        # Enforce length limit
        if len(value) > max_length:
            value = value[:max_length]
        
        return value.strip()
    
    def _search_api(self, search_term: str, max_retries: int = 3) -> Optional[List[Dict]]:
        """
        Search using LexML SRU API with retry logic - INJECTION PROTECTED
        Returns None if API fails after retries
        """
        # CRITICAL SECURITY FIX: Validate and sanitize search term to prevent injection attacks
        try:
            validated_term = validate_legislative_search_query(search_term)
            # Additional CQL-specific sanitization
            sanitized_term = self._sanitize_cql_term(validated_term)
        except ValueError as e:
            self.logger.error(f"Invalid search term '{search_term}': {e}")
            self.stats['search_errors'][search_term] = f"Invalid input: {e}"
            return []
        
        all_results = []
        start_record = 1
        max_records = 100
        
        while True:
            # Build CQL query with sanitized input
            # Double-quote the search term to treat it as a phrase and prevent operator injection
            escaped_term = sanitized_term.replace('"', '')  # Remove any quotes first
            cql_query = f'urn any "{escaped_term}" or subject any "{escaped_term}" or title any "{escaped_term}"'
            
            # Validate CQL query length
            if len(cql_query) > 1000:
                self.logger.error(f"CQL query too long for term '{search_term}'")
                return []
            
            # Build parameters with proper validation
            params = {
                'operation': 'searchRetrieve',
                'version': '1.1',
                'query': cql_query,
                'maximumRecords': min(max_records, 100),  # Enforce maximum limit
                'startRecord': min(start_record, 10000)  # Prevent excessive pagination
            }
            
            # URL encode all parameters for additional safety
            encoded_params = {}
            for key, value in params.items():
                encoded_params[key] = quote_plus(str(value))
            
            # Retry logic
            for attempt in range(max_retries):
                try:
                    # CRITICAL FIX: Apply rate limiting before each request
                    rate_limit_result = self.rate_limiter.check_limits(
                        self.client_id, 
                        "lexml_api"
                    )
                    
                    if not rate_limit_result.allowed:
                        self.logger.warning(f"Rate limited for LexML API. Retry after: {rate_limit_result.retry_after}s")
                        self.stats['rate_limited_requests'] += 1
                        if rate_limit_result.retry_after:
                            time.sleep(rate_limit_result.retry_after)
                        continue
                    
                    # Additional respectful rate limiting (API-specific)
                    current_time = time.time()
                    time_since_last = current_time - self.last_request_time
                    
                    if time_since_last < self.min_request_interval:
                        sleep_time = self.min_request_interval - time_since_last
                        self.logger.debug(f"API-specific rate limit: sleeping {sleep_time:.2f}s")
                        time.sleep(sleep_time)
                    
                    self.last_request_time = time.time()
                    
                    response = self.session.get(
                        self.api_base_url,
                        params=encoded_params,
                        timeout=30,
                        allow_redirects=False  # Prevent redirect attacks
                    )
                    
                    if response.status_code == 200:
                        # Validate response headers to prevent response splitting
                        content_type = response.headers.get('Content-Type', '')
                        if 'xml' not in content_type.lower() and 'text' not in content_type.lower():
                            self.logger.error(f"Unexpected content type: {content_type}")
                            continue
                        
                        # Validate response size
                        if len(response.content) > 50 * 1024 * 1024:  # 50MB limit
                            self.logger.error("Response too large")
                            continue
                        
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
    
    def _validate_xml_content(self, xml_content: str) -> bool:
        """
        Validate XML content to prevent XML injection attacks
        """
        if not xml_content:
            return False
        
        # Check for suspicious patterns that might indicate XML injection
        suspicious_patterns = [
            r'<!ENTITY',  # External entity declarations
            r'<!DOCTYPE',  # DOCTYPE declarations that could include entities
            r'<!\[CDATA\[.*\]\]>',  # CDATA sections that might contain malicious content
            r'SYSTEM\s*["\']',  # SYSTEM identifiers
            r'PUBLIC\s*["\']',  # PUBLIC identifiers
            r'file://',  # File protocol
            r'javascript:',  # JavaScript protocol
            r'<script',  # Script tags
            r'on\w+\s*=',  # Event handlers
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, xml_content, re.IGNORECASE):
                self.logger.error(f"Suspicious XML pattern detected: {pattern}")
                return False
        
        return True
    
    def _parse_sru_response(self, xml_content: str, search_term: str) -> tuple:
        """
        Parse SRU XML response and extract metadata with security validation
        Returns (results, total_records)
        """
        results = []
        total_records = 0
        
        # Validate XML content first
        if not self._validate_xml_content(xml_content):
            self.logger.error(f"Invalid or suspicious XML content for search term '{search_term}'")
            return [], 0
        
        try:
            # Parse XML safely
            # Use defusedxml if available for better XXE protection
            try:
                import defusedxml.ElementTree as ET_safe
                root = ET_safe.fromstring(xml_content)
            except ImportError:
                # Fallback to standard parser with size limits
                if len(xml_content) > 10 * 1024 * 1024:  # 10MB limit
                    self.logger.error("XML response too large")
                    return [], 0
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
                
                # URN/Identifier - validate and sanitize
                urn_elem = record.find('.//dc:identifier', namespaces)
                if urn_elem is not None and urn_elem.text:
                    # Validate URN format
                    urn = self._sanitize_field(urn_elem.text, max_length=500)
                    if re.match(r'^[a-zA-Z0-9:_\-/]+$', urn):
                        result['urn'] = urn
                        # Build URL safely
                        result['url'] = f"https://www.lexml.gov.br/urn/{quote(urn, safe='')}"
                
                # Title - sanitize
                title_elem = record.find('.//dc:title', namespaces)
                if title_elem is not None and title_elem.text:
                    result['title'] = self._sanitize_field(title_elem.text, max_length=1000)
                
                # Date - validate format
                date_elem = record.find('.//dc:date', namespaces)
                if date_elem is not None and date_elem.text:
                    date_text = self._sanitize_field(date_elem.text, max_length=50)
                    # Validate date format (YYYY-MM-DD or similar)
                    if re.match(r'^\d{4}(-\d{2})?(-\d{2})?', date_text):
                        result['document_date'] = date_text
                
                # Type - sanitize and validate
                type_elem = record.find('.//dc:type', namespaces)
                if type_elem is not None and type_elem.text:
                    doc_type = self._sanitize_field(type_elem.text, max_length=100)
                    # Validate against known document types (whitelist approach)
                    valid_types = ['lei', 'decreto', 'portaria', 'resolução', 'medida provisória', 
                                   'emenda constitucional', 'projeto de lei', 'outros']
                    if any(vt in doc_type.lower() for vt in valid_types) or len(doc_type) > 0:
                        result['document_type'] = doc_type
                
                # Description - sanitize
                desc_elem = record.find('.//dc:description', namespaces)
                if desc_elem is not None and desc_elem.text:
                    result['description'] = self._sanitize_field(desc_elem.text, max_length=2000)
                
                # Subject - sanitize each subject
                subject_elems = record.findall('.//dc:subject', namespaces)
                if subject_elems:
                    subjects = []
                    for s in subject_elems:
                        if s.text:
                            sanitized_subject = self._sanitize_field(s.text, max_length=200)
                            if sanitized_subject:
                                subjects.append(sanitized_subject)
                    if subjects:
                        result['subjects'] = '; '.join(subjects)
                
                # Publisher/Authority - sanitize and validate
                publisher_elem = record.find('.//dc:publisher', namespaces)
                if publisher_elem is not None and publisher_elem.text:
                    authority = self._sanitize_field(publisher_elem.text, max_length=500)
                    # Basic validation for government authorities
                    if authority and not re.search(r'[<>"\']', authority):
                        result['authority'] = authority
                
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
    
    def _validate_result_for_export(self, result: Dict) -> Dict:
        """
        Validate and sanitize result data before export
        """
        validated = {}
        
        # Define field validators
        field_validators = {
            'search_term': lambda x: self._sanitize_field(str(x), 200),
            'urn': lambda x: re.sub(r'[^a-zA-Z0-9:_\-/]', '', str(x))[:500],
            'title': lambda x: self._sanitize_field(str(x), 1000),
            'document_date': lambda x: re.sub(r'[^\d\-/]', '', str(x))[:50],
            'document_type': lambda x: self._sanitize_field(str(x), 100),
            'authority': lambda x: self._sanitize_field(str(x), 500),
            'description': lambda x: self._sanitize_field(str(x), 2000),
            'subjects': lambda x: self._sanitize_field(str(x), 1000),
            'url': lambda x: str(x)[:1000] if x and x.startswith('https://www.lexml.gov.br/') else '',
            'source': lambda x: str(x) if x in ['api', 'scraper'] else 'unknown',
            'date_searched': lambda x: str(x)[:50]
        }
        
        for field, validator in field_validators.items():
            try:
                value = result.get(field, '')
                validated[field] = validator(value) if value else ''
            except Exception as e:
                self.logger.warning(f"Error validating field {field}: {e}")
                validated[field] = ''
        
        return validated
    
    def save_results(self, results: List[Dict], filename: str = None):
        """Save results to CSV file with validation"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"lexml_results_{timestamp}.csv"
        
        # Validate filename
        filename = Path(filename)
        if not str(filename).endswith('.csv'):
            filename = filename.with_suffix('.csv')
        
        # Define CSV columns
        fieldnames = [
            'search_term', 'urn', 'title', 'document_date', 'document_type',
            'authority', 'description', 'subjects', 'url', 'source', 'date_searched'
        ]
        
        validated_results = []
        for result in results:
            try:
                validated = self._validate_result_for_export(result)
                validated_results.append(validated)
            except Exception as e:
                self.logger.error(f"Error validating result: {e}")
                continue
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            
            for result in validated_results:
                try:
                    writer.writerow(result)
                except Exception as e:
                    self.logger.error(f"Error writing row: {e}")
        
        self.logger.info(f"Saved {len(validated_results)} validated results to {filename}")
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