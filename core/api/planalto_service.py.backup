"""
Diário Oficial da União (Planalto) Service
Uses Playwright for JavaScript-rendered content with multiple fallback strategies
"""

import asyncio
import logging
import json
import os
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup

from .base_service import BaseAPIService, retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig


class PlanaltoService(BaseAPIService):
    """Service for searching Diário Oficial da União"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(config, cache_manager)
        self.playwright_installed = self._check_playwright()
        
    def _check_playwright(self) -> bool:
        """Check if Playwright is installed and install if needed"""
        try:
            import playwright
            return True
        except ImportError:
            self.logger.info("Playwright not installed. Installing...")
            try:
                subprocess.run(
                    ["pip", "install", "playwright"],
                    check=True,
                    capture_output=True
                )
                subprocess.run(
                    ["playwright", "install", "chromium"],
                    check=True,
                    capture_output=True
                )
                self.logger.info("Playwright installed successfully")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to install Playwright: {e}")
                return False
    
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search for documents in Diário Oficial"""
        start_time = datetime.now()
        
        # Check cache first
        cache_key = self._get_cache_key(query, filters)
        cached_result = self.cache_manager.get(cache_key)
        if cached_result:
            self.logger.info(f"Returning cached results for query: {query}")
            return cached_result
        
        # Try different search strategies
        strategies = [
            ("Playwright", self._search_with_playwright),
            ("Direct API", self._search_direct_api),
            ("LEXML", self._search_lexml)
        ]
        
        for strategy_name, strategy_func in strategies:
            if strategy_name == "Playwright" and not self.playwright_installed:
                continue
                
            try:
                self.logger.info(f"Trying {strategy_name} strategy")
                result = await strategy_func(query, filters)
                
                if result.propositions:
                    # Cache successful results
                    self.cache_manager.set(cache_key, result, ttl=self.config.cache_ttl)
                    result.search_time = (datetime.now() - start_time).total_seconds()
                    return result
                    
            except Exception as e:
                self.logger.warning(f"{strategy_name} strategy failed: {str(e)}")
                continue
        
        # All strategies failed
        return SearchResult(
            query=query,
            filters=filters,
            propositions=[],
            total_count=0,
            source=DataSource.PLANALTO,
            error="All search strategies failed",
            search_time=(datetime.now() - start_time).total_seconds()
        )
    
    async def _search_with_playwright(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search using Playwright for JavaScript-rendered content"""
        from playwright.async_api import async_playwright
        
        propositions = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            try:
                # Navigate to search page
                search_url = "https://www.in.gov.br/consulta/-/buscar/dou"
                await page.goto(search_url, wait_until="networkidle")
                
                # Fill search form
                await page.fill('input[name="q"]', query)
                
                # Set date range if provided
                if filters.get("start_date"):
                    await page.fill('input[name="publishFrom"]', filters["start_date"])
                if filters.get("end_date"):
                    await page.fill('input[name="publishTo"]', filters["end_date"])
                
                # Submit search
                await page.click('button[type="submit"]')
                
                # Wait for results with multiple strategies
                try:
                    await page.wait_for_selector('.resultado-item', timeout=10000)
                except:
                    # Try JavaScript extraction if selector not found
                    pass
                
                # Extract results
                results_data = await page.evaluate("""
                    () => {
                        const results = [];
                        
                        // Try multiple selectors
                        const selectors = [
                            '.resultado-item',
                            '.resultado-busca',
                            '[class*="resultado"]',
                            'article',
                            '.content-item'
                        ];
                        
                        let items = [];
                        for (const selector of selectors) {
                            items = document.querySelectorAll(selector);
                            if (items.length > 0) break;
                        }
                        
                        // If no specific items found, extract from page content
                        if (items.length === 0) {
                            const content = document.body.innerText;
                            if (content.includes('Portaria') || content.includes('Decreto') || 
                                content.includes('Resolução') || content.includes('Instrução')) {
                                // Extract data from text content
                                const lines = content.split('\\n').filter(line => line.trim());
                                for (let i = 0; i < lines.length; i++) {
                                    const line = lines[i];
                                    if (line.match(/(Portaria|Decreto|Resolução|Instrução)/i)) {
                                        results.push({
                                            title: line.substring(0, 200),
                                            summary: lines[i+1] || line,
                                            date: new Date().toISOString(),
                                            url: window.location.href
                                        });
                                    }
                                }
                            }
                        } else {
                            // Extract from structured items
                            items.forEach(item => {
                                const title = item.querySelector('h3, h4, .titulo, [class*="title"]')?.innerText || 
                                            item.innerText.split('\\n')[0];
                                const summary = item.querySelector('p, .resumo, .descricao')?.innerText || 
                                              item.innerText;
                                const link = item.querySelector('a')?.href || window.location.href;
                                const date = item.querySelector('.data, [class*="date"]')?.innerText || 
                                           new Date().toISOString();
                                
                                if (title) {
                                    results.push({
                                        title: title.substring(0, 200),
                                        summary: summary.substring(0, 500),
                                        url: link,
                                        date: date
                                    });
                                }
                            });
                        }
                        
                        return results.slice(0, 50); // Limit to 50 results
                    }
                """)
                
                # Parse results
                for item in results_data:
                    prop = self._parse_web_result(item)
                    if prop:
                        propositions.append(prop)
                
            finally:
                await browser.close()
        
        return SearchResult(
            query=query,
            filters=filters,
            propositions=propositions,
            total_count=len(propositions),
            source=DataSource.PLANALTO
        )
    
    async def _search_direct_api(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Try direct API access"""
        # Multiple API endpoints to try
        api_endpoints = [
            "https://www.in.gov.br/consulta/-/buscar/dou/json",
            "https://www.in.gov.br/api/v1/diarios",
            "https://www.in.gov.br/servicos/diario-oficial/consulta"
        ]
        
        params = {
            "q": query,
            "publishFrom": filters.get("start_date", ""),
            "publishTo": filters.get("end_date", ""),
            "delta": 50
        }
        
        for endpoint in api_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        endpoint,
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        if response.status == 200:
                            content_type = response.headers.get("Content-Type", "")
                            
                            if "json" in content_type:
                                data = await response.json()
                                propositions = self._parse_json_results(data)
                            else:
                                html = await response.text()
                                propositions = self._parse_html_results(html)
                            
                            if propositions:
                                return SearchResult(
                                    query=query,
                                    filters=filters,
                                    propositions=propositions,
                                    total_count=len(propositions),
                                    source=DataSource.PLANALTO
                                )
                                
            except Exception as e:
                self.logger.warning(f"Direct API failed for {endpoint}: {str(e)}")
                continue
        
        return SearchResult(
            query=query,
            filters=filters,
            propositions=[],
            total_count=0,
            source=DataSource.PLANALTO
        )
    
    async def _search_lexml(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Fallback to LEXML search"""
        url = "https://www.lexml.gov.br/busca/search"
        params = {
            "keyword": query,
            "f1-tipoDocumento": "Legislação::Decreto",
            "sort": "date"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    propositions = []
                    for item in soup.select('.resultado-busca-item'):
                        prop = self._parse_lexml_result(item)
                        if prop:
                            propositions.append(prop)
                    
                    return SearchResult(
                        query=query,
                        filters=filters,
                        propositions=propositions,
                        total_count=len(propositions),
                        source=DataSource.PLANALTO
                    )
                    
        except Exception as e:
            self.logger.error(f"LEXML search failed: {str(e)}")
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.PLANALTO,
                error=str(e)
            )
    
    def _parse_web_result(self, data: Dict[str, Any]) -> Optional[Proposition]:
        """Parse result from web scraping"""
        try:
            title = data.get("title", "").strip()
            if not title:
                return None
            
            # Extract type from title
            prop_type = PropositionType.OTHER
            type_mapping = {
                "DECRETO": PropositionType.DECRETO,
                "PORTARIA": PropositionType.PORTARIA,
                "RESOLUÇÃO": PropositionType.RESOLUCAO,
                "INSTRUÇÃO NORMATIVA": PropositionType.INSTRUCAO_NORMATIVA,
                "CIRCULAR": PropositionType.CIRCULAR
            }
            
            title_upper = title.upper()
            for key, value in type_mapping.items():
                if key in title_upper:
                    prop_type = value
                    break
            
            # Extract number from title
            import re
            number_match = re.search(r'n[º°]?\s*(\d+)', title, re.IGNORECASE)
            number = number_match.group(1) if number_match else ""
            
            # Parse date
            date_str = data.get("date", "")
            pub_date = self._parse_date(date_str) or datetime.now()
            
            return Proposition(
                id=f"dou-{datetime.now().timestamp()}",
                type=prop_type,
                number=number,
                year=pub_date.year,
                title=title[:200],
                summary=data.get("summary", title)[:500],
                source=DataSource.PLANALTO,
                status=PropositionStatus.PUBLISHED,
                url=data.get("url", ""),
                publication_date=pub_date,
                authors=[Author(name="Presidência da República", type="Órgão")]
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing web result: {str(e)}")
            return None
    
    def _parse_json_results(self, data: Any) -> List[Proposition]:
        """Parse JSON API results"""
        propositions = []
        
        # Handle different JSON structures
        if isinstance(data, dict):
            items = data.get("items", data.get("results", data.get("data", [])))
        elif isinstance(data, list):
            items = data
        else:
            return propositions
        
        for item in items:
            if isinstance(item, dict):
                prop = self._parse_web_result({
                    "title": item.get("title", item.get("titulo", "")),
                    "summary": item.get("summary", item.get("resumo", item.get("ementa", ""))),
                    "url": item.get("url", item.get("link", "")),
                    "date": item.get("date", item.get("data", item.get("dataPublicacao", "")))
                })
                if prop:
                    propositions.append(prop)
        
        return propositions
    
    def _parse_html_results(self, html: str) -> List[Proposition]:
        """Parse HTML results"""
        soup = BeautifulSoup(html, 'html.parser')
        propositions = []
        
        # Try multiple selectors
        selectors = [
            '.resultado-item',
            '.resultado-busca',
            '.search-result',
            'article',
            '.item'
        ]
        
        for selector in selectors:
            items = soup.select(selector)
            if items:
                for item in items:
                    title_elem = item.select_one('h3, h4, .title, .titulo')
                    if title_elem:
                        prop = self._parse_web_result({
                            "title": title_elem.get_text(strip=True),
                            "summary": item.get_text(strip=True)[:500],
                            "url": item.select_one('a')['href'] if item.select_one('a') else "",
                            "date": item.select_one('.date, .data').get_text(strip=True) if item.select_one('.date, .data') else ""
                        })
                        if prop:
                            propositions.append(prop)
                break
        
        return propositions
    
    def _parse_lexml_result(self, soup_item) -> Optional[Proposition]:
        """Parse LEXML search result"""
        try:
            title_elem = soup_item.select_one('.titulo-resultado')
            if not title_elem:
                return None
            
            title = title_elem.get_text(strip=True)
            url = title_elem.get('href', '')
            
            summary_elem = soup_item.select_one('.descricao-resultado')
            summary = summary_elem.get_text(strip=True) if summary_elem else title
            
            date_elem = soup_item.select_one('.data-resultado')
            date_str = date_elem.get_text(strip=True) if date_elem else ""
            
            return self._parse_web_result({
                "title": title,
                "summary": summary,
                "url": f"https://www.lexml.gov.br{url}" if url.startswith('/') else url,
                "date": date_str
            })
            
        except Exception as e:
            self.logger.error(f"Error parsing LEXML result: {str(e)}")
            return None
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date from various formats"""
        if not date_str:
            return None
        
        formats = [
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%d-%m-%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%d de %B de %Y"  # Portuguese format
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        
        # Try to extract date components
        import re
        date_match = re.search(r'(\d{1,2})[/-](\d{1,2})[/-](\d{4})', date_str)
        if date_match:
            day, month, year = date_match.groups()
            try:
                return datetime(int(year), int(month), int(day))
            except ValueError:
                pass
        
        return None
    
    async def get_proposition_details(self, proposition_id: str) -> Optional[Proposition]:
        """Get detailed information about a specific document"""
        # Planalto doesn't have a details API, return None
        return None
    
    async def check_health(self) -> bool:
        """Check if the service is healthy"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://www.in.gov.br",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return False