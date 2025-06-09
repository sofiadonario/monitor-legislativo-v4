#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Web Scraper - Fallback Method - SECURITY HARDENED
Used when the API is unavailable or returns errors
"""

import requests
import re
import time
import html
from datetime import datetime
from urllib.parse import urlencode
from typing import List, Dict

# CRITICAL SECURITY: Import input validation  
from core.utils.input_validator import validate_legislative_search_query

class LexMLWebScraperFallback:
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br"
        self.search_url = "https://www.lexml.gov.br/busca/search"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    def search_term(self, term: str, max_pages: int = 3) -> List[Dict]:
        """Search using web interface when API fails - SECURITY PROTECTED"""
        # CRITICAL SECURITY FIX: Validate input to prevent injection attacks
        try:
            validated_term = validate_legislative_search_query(term)
            # Additional web-specific sanitization
            sanitized_term = self._sanitize_web_term(validated_term)
        except ValueError as e:
            print(f"Invalid search term '{term}': {e}")
            return []
        
        results = []
        
        # Limit max pages to prevent abuse
        max_pages = min(max_pages, 5)  # Never more than 5 pages
        
        for page in range(1, max_pages + 1):
            params = {
                'keyword': sanitized_term,
                'startDoc': (page - 1) * 20 + 1
            }
            
            try:
                response = self.session.get(
                    self.search_url, 
                    params=params, 
                    timeout=15,
                    allow_redirects=False  # SECURITY: Prevent redirect attacks
                )
                
                if response.status_code == 200:
                    # Validate response size to prevent memory exhaustion
                    if len(response.text) > 2_000_000:  # 2MB limit
                        print(f"Response too large for '{term}', skipping")
                        break
                    
                    # Extract results from HTML
                    page_results = self._parse_html_results(response.text, term)
                    results.extend(page_results)
                    
                    # If no results found, stop pagination
                    if not page_results:
                        break
                else:
                    break
                    
                time.sleep(2)  # Respectful rate limiting (increased)
                
            except Exception as e:
                print(f"Scraper error for '{term}': {e}")
                break
                
        return results
    
    def _sanitize_web_term(self, term: str) -> str:
        """
        Sanitize search term for web interface - INJECTION PREVENTION
        Remove dangerous characters that could be used in web attacks
        """
        # Remove HTML and URL dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '%', '\\', '{', '}', '[', ']']
        sanitized = term
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, ' ')
        
        # Normalize whitespace and limit length  
        sanitized = ' '.join(sanitized.split())[:150]  # Max 150 chars
        
        return sanitized.strip()
    
    def _parse_html_results(self, html: str, search_term: str) -> List[Dict]:
        """Parse results from HTML response - SECURITY HARDENED"""
        results = []
        
        try:
            # SECURITY FIX: More restrictive regex to prevent ReDoS attacks
            # Limit matches and validate URN format
            urn_pattern = r'<a[^>]{1,200}href="(/urn/urn:lex:br[a-zA-Z0-9:_\-\.;]{1,300})"[^>]{0,100}>([^<]{1,500})</a>'
            matches = re.findall(urn_pattern, html, re.DOTALL)
            
            # Limit number of results to prevent memory exhaustion
            matches = matches[:100]  # Max 100 results per page
            
            for url_part, title in matches:
                # SECURITY: Validate and sanitize extracted data
                if not self._is_valid_urn_path(url_part):
                    continue
                
                # HTML decode and sanitize title
                clean_title = html.unescape(title)
                clean_title = re.sub(r'<[^>]+>', '', clean_title)  # Remove any HTML tags
                clean_title = clean_title.strip()[:500]  # Limit length
                
                # Validate URN format
                urn = url_part.replace('/urn/', '')
                if not self._is_valid_urn(urn):
                    continue
                
                result = {
                    'search_term': search_term,
                    'date_searched': datetime.now().isoformat(),
                    'url': self.base_url + url_part,
                    'title': clean_title,
                    'urn': urn,
                    'source': 'web_scraper'
                }
                results.append(result)
                
        except re.error as e:
            print(f"Regex error parsing HTML: {e}")
        except Exception as e:
            print(f"Error parsing HTML results: {e}")
        
        return results
    
    def _is_valid_urn_path(self, path: str) -> bool:
        """Validate URN path format to prevent malicious URLs"""
        if not path.startswith('/urn/urn:lex:br'):
            return False
        if len(path) > 400:  # Reasonable length limit
            return False
        # Check for dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '%', '\\', '{', '}']
        return not any(char in path for char in dangerous_chars)
    
    def _is_valid_urn(self, urn: str) -> bool:
        """Validate URN format"""
        if not urn.startswith('urn:lex:br'):
            return False
        if len(urn) > 300:  # Reasonable length limit
            return False
        # URN should only contain valid characters
        valid_pattern = r'^urn:lex:br[a-zA-Z0-9:_\-\.;]+$'
        return bool(re.match(valid_pattern, urn))