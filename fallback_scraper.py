#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Web Scraper - Fallback Method
Used when the API is unavailable or returns errors
"""

import requests
import re
import time
from datetime import datetime
from urllib.parse import urlencode

class LexMLWebScraperFallback:
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br"
        self.search_url = "https://www.lexml.gov.br/busca/search"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    def search_term(self, term, max_pages=3):
        """Search using web interface when API fails"""
        results = []
        
        for page in range(1, max_pages + 1):
            params = {
                'keyword': term,
                'startDoc': (page - 1) * 20 + 1
            }
            
            try:
                response = self.session.get(self.search_url, params=params, timeout=15)
                
                if response.status_code == 200:
                    # Extract results from HTML
                    results.extend(self._parse_html_results(response.text, term))
                else:
                    break
                    
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                print(f"Scraper error for '{term}': {e}")
                break
                
        return results
    
    def _parse_html_results(self, html, search_term):
        """Parse results from HTML response"""
        results = []
        
        # Look for URN links
        urn_pattern = r'<a[^>]+href="(/urn/urn:lex:br[^"]+)"[^>]*>([^<]+)</a>'
        matches = re.findall(urn_pattern, html)
        
        for url_part, title in matches:
            result = {
                'search_term': search_term,
                'date_searched': datetime.now().isoformat(),
                'url': self.base_url + url_part,
                'title': re.sub(r'<[^>]+>', '', title).strip(),
                'urn': url_part.replace('/urn/', ''),
                'source': 'web_scraper'
            }
            results.append(result)
        
        return results