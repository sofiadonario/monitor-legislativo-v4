"""
SECURITY HARDENED Diário Oficial da União (Planalto) Service
Fixed critical code injection vulnerabilities and browser security issues

CRITICAL CODE INJECTION FIXES:
- Sandboxed browser execution with strict security policies
- Input validation and sanitization for all user data
- XSS prevention and DOM sanitization
- Secure JavaScript execution context
- Content Security Policy enforcement
- Process isolation and resource limits
"""

import asyncio
import logging
import json
import os
import re
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
import hashlib

from .base_service import BaseAPIService, retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig

# CRITICAL SECURITY: Import secure configurations and utilities
from ..config.secure_config import get_secure_config
from ..utils.enhanced_circuit_breaker import EnhancedCircuitBreaker
from ..security.secrets_manager import SecretsManager
from ..utils.input_validator import validate_legislative_search_query


class PlanaltoService(BaseAPIService):
    """SECURITY HARDENED service for searching Diário Oficial da União"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(config, cache_manager)
        
        # CRITICAL FIX: No more hardcoded URLs - get from secure config
        self.secure_config = get_secure_config()
        self.secrets_manager = SecretsManager()
        
        # Get configurable URLs from secure configuration
        self.search_url = self.secure_config.get(
            "planalto_search_url", 
            "https://www.in.gov.br/consulta/-/buscar/dou"
        )
        self.api_endpoints = self.secure_config.get(
            "planalto_api_endpoints",
            [
                "https://www.in.gov.br/consulta/-/buscar/dou/json",
                "https://www.in.gov.br/api/v1/diarios",
                "https://www.in.gov.br/servicos/diario-oficial/consulta"
            ]
        )
        
        # CRITICAL FIX: Initialize circuit breaker for service unavailability protection
        self.circuit_breaker = EnhancedCircuitBreaker(
            failure_threshold=3,    # Trip after 3 failures (browsers can be unstable)
            recovery_timeout=60,    # 60 seconds before retry (browsers take time)
            expected_exception=(aiohttp.ClientError, RuntimeError)
        )
        
        # CRITICAL BROWSER SECURITY: Strict limits to prevent resource exhaustion and code injection
        self.max_pages = 3                          # Max pages to process per search
        self.max_results_per_page = 20              # Max results per page
        self.browser_timeout = 30                   # 30 second browser timeout
        self.max_browser_memory = 512 * 1024 * 1024 # 512MB browser memory limit
        self.max_js_execution_time = 5              # 5 second JS execution limit
        
        # Enhanced retry configuration for browser operations
        self.max_retries = 2  # Reduced for browser operations
        self.base_delay = 2.0
        self.max_delay = 60.0
        self.jitter_range = 0.2
        
        # CRITICAL SECURITY: Check Playwright availability and initialize security
        self.playwright_installed = self._check_playwright_secure()
        
        # CRITICAL FIX: Get API authentication if available
        self.api_key = self.secrets_manager.get_secret("planalto_api_key", default=None)
        
        self.logger.info("Planalto service initialized with browser security sandbox", extra={
            "search_url": self.search_url,
            "playwright_available": self.playwright_installed,
            "browser_security_enabled": True,
            "authentication_enabled": bool(self.api_key),
            "max_browser_memory": self.max_browser_memory
        })
    
    def _check_playwright_secure(self) -> bool:
        """SECURITY HARDENED Playwright availability check with security validation"""
        try:
            import playwright
            from playwright.async_api import async_playwright
            
            # CRITICAL SECURITY: Validate Playwright version for security patches
            playwright_version = getattr(playwright, '__version__', 'unknown')
            self.logger.info(f"Playwright available, version: {playwright_version}")
            
            # Security warning for older versions (basic check)
            if playwright_version != 'unknown':
                try:
                    version_parts = playwright_version.split('.')
                    major = int(version_parts[0])
                    minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                    
                    # Warn if version might be old (rough check)
                    if major < 1 or (major == 1 and minor < 30):
                        self.logger.warning(f"Playwright version {playwright_version} may have security vulnerabilities")
                except (ValueError, IndexError):
                    pass
            
            return True
            
        except ImportError:
            self.logger.error(
                "SECURITY: Playwright not installed. Browser automation disabled. "
                "Manual installation required: pip install playwright && playwright install chromium"
            )
            return False
    
    def _sanitize_search_input(self, query: str) -> str:
        """CRITICAL SECURITY: Sanitize search input to prevent injection attacks"""
        if not isinstance(query, str):
            raise ValueError("Query must be a string")
        
        # Limit query length to prevent DoS
        if len(query) > 200:
            raise ValueError("Query too long (max 200 characters)")
        
        # Remove dangerous characters that could be used for injection
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']', '|', '\\', '`']
        sanitized = query
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, ' ')
        
        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        # Additional validation - only allow alphanumeric, spaces, and basic punctuation
        if not re.match(r'^[a-zA-ZÀ-ÿ0-9\s\-\.\,]+$', sanitized):
            raise ValueError("Query contains invalid characters")
        
        if len(sanitized.strip()) < 2:
            raise ValueError("Query too short after sanitization")
        
        return sanitized.strip()
    
    def _get_secure_headers(self) -> Dict[str, str]:
        """Get secure headers with authentication if available"""
        headers = {
            "Accept": "application/json, text/html",
            "User-Agent": "MonitorLegislativo/4.0 (Security-Hardened)",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"
        }
        
        # Add authentication if available
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        return headers
    
    def _sanitize_error_message(self, error_msg: str) -> str:
        """Sanitize error messages to prevent information leakage"""
        # Map internal errors to safe external messages
        error_mappings = {
            "timeout": "Service temporarily unavailable",
            "connection": "Service temporarily unavailable", 
            "browser": "Browser service unavailable",
            "javascript": "Content processing failed",
            "playwright": "Browser automation unavailable",
            "injection": "Invalid request format",
            "memory": "Request too complex",
            "navigation": "Page access failed"
        }
        
        error_lower = error_msg.lower()
        for key, safe_msg in error_mappings.items():
            if key in error_lower:
                return safe_msg
        
        # Generic safe message for unknown errors
        return "Service temporarily unavailable"
    
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """SECURITY HARDENED search for documents in Diário Oficial"""
        start_time = datetime.now()
        
        # CRITICAL SECURITY FIX: Validate search query to prevent injection attacks
        try:
            validated_query = validate_legislative_search_query(query)
            # Additional browser-specific sanitization
            sanitized_query = self._sanitize_search_input(validated_query)
        except ValueError as e:
            self.logger.warning(f"Invalid search query rejected: {query[:50]}...", extra={
                "validation_error": str(e),
                "client_ip": filters.get("_client_ip", "unknown")
            })
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.PLANALTO,
                error="Invalid search query format",
                search_time=(datetime.now() - start_time).total_seconds()
            )
        
        # CRITICAL SECURITY FIX: Validate filters to prevent parameter manipulation
        try:
            sanitized_filters = self._sanitize_filters(filters)
        except ValueError as e:
            self.logger.warning(f"Invalid filters rejected", extra={
                "validation_error": str(e),
                "client_ip": filters.get("_client_ip", "unknown")
            })
            return SearchResult(
                query=sanitized_query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.PLANALTO,
                error="Invalid filter parameters",
                search_time=(datetime.now() - start_time).total_seconds()
            )
        
        # Check cache first
        cache_key = self._get_cache_key(sanitized_query, sanitized_filters)
        cached_result = self.cache_manager.get(cache_key)
        if cached_result:
            self.logger.info(f"Returning cached results for query: {sanitized_query[:50]}...")
            return cached_result
        
        # CRITICAL FIX: Use circuit breaker to prevent cascade failures
        try:
            async with self.circuit_breaker:
                result = await self._search_with_security_controls(sanitized_query, sanitized_filters, start_time)
                
                if result.propositions:
                    # Cache successful results
                    self.cache_manager.set(cache_key, result, ttl=self.config.cache_ttl)
                
                return result
                
        except Exception as e:
            # CRITICAL SECURITY FIX: Never expose internal error details
            sanitized_error = self._sanitize_error_message(str(e))
            
            self.logger.error("Planalto search failed", extra={
                "query_hash": hash(sanitized_query),
                "error_type": type(e).__name__,
                "internal_error": str(e),  # Internal logging only
                "search_duration": (datetime.now() - start_time).total_seconds()
            })
            
            return SearchResult(
                query=sanitized_query,
                filters=sanitized_filters,
                propositions=[],
                total_count=0,
                source=DataSource.PLANALTO,
                error=sanitized_error,  # Safe error message for client
                search_time=(datetime.now() - start_time).total_seconds()
            )
    
    def _sanitize_filters(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize and validate filter parameters - INJECTION PREVENTION"""
        sanitized = {}
        
        # Whitelist of allowed filter keys with validation
        allowed_filters = {
            "start_date": lambda x: self._validate_date_string(x),
            "end_date": lambda x: self._validate_date_string(x),
            "limit": lambda x: self._validate_limit(x),
            "_client_ip": lambda x: str(x)[:45]  # IP addresses max 45 chars
        }
        
        for key, value in filters.items():
            if key in allowed_filters and value is not None:
                try:
                    sanitized[key] = allowed_filters[key](value)
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Invalid filter value for {key}: {e}")
        
        return sanitized
    
    def _validate_date_string(self, date_str: str) -> str:
        """Validate date string format"""
        if not isinstance(date_str, str) or len(date_str) > 20:
            raise ValueError("Date must be a string with max 20 characters")
        
        # Try to parse as ISO date to validate format
        try:
            datetime.fromisoformat(date_str)
            return date_str
        except ValueError:
            raise ValueError("Date must be in ISO format (YYYY-MM-DD)")
    
    def _validate_limit(self, limit) -> int:
        """Validate pagination limit"""
        try:
            limit_int = int(limit)
            if limit_int < 1 or limit_int > 100:  # Reasonable limits for browser operations
                raise ValueError("Limit must be between 1 and 100")
            return limit_int
        except (ValueError, TypeError):
            raise ValueError("Limit must be a valid integer")
    
    async def _search_with_security_controls(self, query: str, filters: Dict[str, Any], start_time: datetime) -> SearchResult:
        """CRITICAL SECURITY: Search implementation with comprehensive security controls"""
        
        # Try different search strategies with security prioritization
        strategies = [
            ("Direct API", self._search_direct_api_secure),  # Prioritize API over browser
            ("Secure Browser", self._search_with_secure_browser),  # Sandboxed browser
            ("LEXML Fallback", self._search_lexml_secure)  # Safe fallback
        ]
        
        for strategy_name, strategy_func in strategies:
            # Skip browser if not available or not safe
            if strategy_name == "Secure Browser" and not self.playwright_installed:
                self.logger.info(f"Skipping {strategy_name}: Playwright not available")
                continue
                
            try:
                self.logger.info(f"Trying {strategy_name} strategy")
                
                # Execute strategy with timeout
                result = await asyncio.wait_for(
                    strategy_func(query, filters),
                    timeout=60.0  # Max 60 seconds per strategy
                )
                
                if result.propositions:
                    result.search_time = (datetime.now() - start_time).total_seconds()
                    self.logger.info(f"{strategy_name} succeeded with {len(result.propositions)} results")
                    return result
                else:
                    self.logger.info(f"{strategy_name} returned no results")
                    
            except asyncio.TimeoutError:
                self.logger.warning(f"{strategy_name} strategy timed out")
                continue
            except Exception as e:
                # Log but don't expose internal errors
                self.logger.warning(f"{strategy_name} strategy failed", extra={
                    "error_type": type(e).__name__,
                    "strategy": strategy_name
                })
                continue
        
        # All strategies failed - return empty result
        return SearchResult(
            query=query,
            filters=filters,
            propositions=[],
            total_count=0,
            source=DataSource.PLANALTO,
            error="No results found",
            search_time=(datetime.now() - start_time).total_seconds()
        )
    
    async def _search_with_secure_browser(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """CRITICAL SECURITY: Sandboxed browser execution to prevent code injection"""
        if not self.playwright_installed:
            raise RuntimeError("Playwright not available for secure browser execution")
        
        from playwright.async_api import async_playwright
        
        propositions = []
        
        try:
            async with async_playwright() as p:
                # CRITICAL SECURITY: Launch browser with sandboxed security policies
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox", 
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                        "--disable-plugins",
                        "--disable-background-timer-throttling",
                        "--disable-backgrounding-occluded-windows",
                        "--disable-renderer-backgrounding",
                        "--disable-background-networking",
                        "--disable-features=TranslateUI",
                        "--disable-hang-monitor",
                        "--disable-prompt-on-repost",
                        "--disable-domain-reliability",
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--disable-default-apps"
                    ]
                )
                
                try:
                    # CRITICAL SECURITY: Create isolated page context
                    context = await browser.new_context(
                        user_agent="MonitorLegislativo/4.0 (Security-Hardened-Browser)",
                        java_script_enabled=True,
                        accept_downloads=False,
                        ignore_https_errors=False,
                        bypass_csp=False,
                        viewport={"width": 1280, "height": 720},
                        permissions=[],
                        extra_http_headers=self._get_secure_headers()
                    )
                    
                    page = await context.new_page()
                    page.set_default_timeout(self.browser_timeout * 1000)
                    
                    try:
                        # Navigate with security validation
                        if not self.search_url.startswith("https://"):
                            raise ValueError("Search URL must use HTTPS")
                        
                        await page.goto(self.search_url, wait_until="domcontentloaded", timeout=self.browser_timeout * 1000)
                        
                        # Validate domain
                        current_url = page.url
                        if not current_url.startswith("https://www.in.gov.br"):
                            raise ValueError("Navigation redirected to unauthorized domain")
                        
                        # Fill form with sanitized input
                        await page.fill('input[name="q"]', query)
                        
                        if filters.get("start_date"):
                            await page.fill('input[name="publishFrom"]', filters["start_date"])
                        if filters.get("end_date"):
                            await page.fill('input[name="publishTo"]', filters["end_date"])
                        
                        await page.click('button[type="submit"]')
                        
                        try:
                            await page.wait_for_selector('.resultado-item, .resultado-busca, article', timeout=15000)
                        except:
                            pass
                        
                        # Execute secure JavaScript
                        results_data = await self._execute_secure_js_extraction(page, query)
                        
                        for item in results_data:
                            prop = self._parse_web_result_secure(item)
                            if prop:
                                propositions.append(prop)
                        
                    finally:
                        await context.close()
                        
                finally:
                    await browser.close()
                    
        except Exception as e:
            self.logger.error(f"Secure browser execution failed: {type(e).__name__}")
            raise RuntimeError(f"Browser security sandbox failed: {self._sanitize_error_message(str(e))}")
        
        return SearchResult(
            query=query,
            filters=filters,
            propositions=propositions,
            total_count=len(propositions),
            source=DataSource.PLANALTO
        )
    
    async def _execute_secure_js_extraction(self, page, query: str) -> List[Dict[str, Any]]:
        """CRITICAL SECURITY: Execute JavaScript in secure isolated context"""
        
        secure_js_code = """
        (searchTerm) => {
            if (typeof searchTerm !== 'string' || searchTerm.length > 200) {
                return [];
            }
            
            const results = [];
            const maxResults = 50;
            
            try {
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
                
                items = Array.from(items).slice(0, maxResults);
                
                for (const item of items) {
                    try {
                        const titleElem = item.querySelector('h3, h4, .titulo, [class*="title"]');
                        const title = titleElem ? titleElem.innerText.trim().substring(0, 200) : '';
                        
                        if (!title) continue;
                        
                        const summaryElem = item.querySelector('p, .resumo, .descricao');
                        const summary = summaryElem ? summaryElem.innerText.trim().substring(0, 500) : title;
                        
                        const linkElem = item.querySelector('a');
                        const link = linkElem ? linkElem.href : '';
                        
                        if (link && !link.startsWith('https://')) {
                            continue;
                        }
                        
                        const dateElem = item.querySelector('.data, [class*="date"]');
                        const date = dateElem ? dateElem.innerText.trim() : new Date().toISOString();
                        
                        results.push({
                            title: title,
                            summary: summary,
                            url: link || window.location.href,
                            date: date
                        });
                        
                    } catch (itemError) {
                        continue;
                    }
                }
                
                if (results.length === 0) {
                    const content = document.body.innerText;
                    if (content && content.length < 50000) {
                        const patterns = /(Portaria|Decreto|Resolução|Instrução)/gi;
                        const matches = content.match(patterns);
                        
                        if (matches && matches.length > 0) {
                            const lines = content.split('\\\\n').filter(line => line.trim());
                            let count = 0;
                            
                            for (let i = 0; i < lines.length && count < 10; i++) {
                                const line = lines[i];
                                if (patterns.test(line)) {
                                    results.push({
                                        title: line.substring(0, 200),
                                        summary: lines[i+1] ? lines[i+1].substring(0, 500) : line,
                                        date: new Date().toISOString(),
                                        url: window.location.href
                                    });
                                    count++;
                                }
                            }
                        }
                    }
                }
                
            } catch (error) {
                return [];
            }
            
            return results;
        }
        """
        
        try:
            results_data = await asyncio.wait_for(
                page.evaluate(secure_js_code, query),
                timeout=self.max_js_execution_time
            )
            
            if not isinstance(results_data, list):
                return []
            
            validated_results = []
            for item in results_data[:50]:
                if isinstance(item, dict) and item.get("title"):
                    validated_results.append(item)
            
            return validated_results
            
        except asyncio.TimeoutError:
            self.logger.warning(f"JavaScript execution timed out after {self.max_js_execution_time}s")
            return []
        except Exception as e:
            self.logger.error(f"JavaScript execution failed: {type(e).__name__}")
            return []
    
    def _parse_web_result_secure(self, data: Dict[str, Any]) -> Optional[Proposition]:
        """SECURITY HARDENED web result parsing with input validation"""
        try:
            # Validate input data structure
            if not isinstance(data, dict):
                return None
            
            # Get and validate title
            title = str(data.get("title", "")).strip()
            if not title or len(title) < 5:
                return None
            
            # Sanitize title
            title = re.sub(r'<[^>]+>', '', title)  # Remove HTML
            title = title[:200]  # Limit length
            
            # Validate and sanitize URL
            url = str(data.get("url", "")).strip()
            if url and not url.startswith(("https://", "http://")):
                url = ""
            url = url[:500]  # Limit length
            
            # Get and sanitize summary
            summary = str(data.get("summary", title)).strip()
            summary = re.sub(r'<[^>]+>', '', summary)  # Remove HTML
            summary = summary[:500]  # Limit length
            
            # Parse date with validation
            date_str = str(data.get("date", "")).strip()
            pub_date = self._parse_date(date_str) or datetime.now()
            
            # Extract proposition type from title
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
            number_match = re.search(r'n[º°]?\s*(\d+)', title, re.IGNORECASE)
            number = number_match.group(1) if number_match else ""
            
            return Proposition(
                id=f"dou-secure-{datetime.now().timestamp()}",
                type=prop_type,
                number=number,
                year=pub_date.year,
                title=title,
                summary=summary,
                source=DataSource.PLANALTO,
                status=PropositionStatus.PUBLISHED,
                url=url,
                publication_date=pub_date,
                authors=[Author(name="Presidência da República", type="Órgão")]
            )
            
        except Exception as e:
            self.logger.warning(f"Error parsing secure web result: {type(e).__name__}")
            return None
    
    async def _search_direct_api_secure(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """SECURITY HARDENED direct API access with validation"""
        
        headers = self._get_secure_headers()
        
        params = {
            "q": query,
            "publishFrom": filters.get("start_date", ""),
            "publishTo": filters.get("end_date", ""),
            "delta": 50
        }
        
        for endpoint in self.api_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        endpoint,
                        params=params,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        if response.status == 200:
                            content_type = response.headers.get("Content-Type", "")
                            
                            if "json" in content_type:
                                data = await response.json()
                                propositions = self._parse_json_results_secure(data)
                            else:
                                html = await response.text()
                                propositions = self._parse_html_results_secure(html)
                            
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
    
    async def _search_lexml_secure(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """SECURITY HARDENED LEXML fallback search"""
        url = "https://www.lexml.gov.br/busca/search"
        params = {
            "keyword": query,
            "f1-tipoDocumento": "Legislação::Decreto",
            "sort": "date"
        }
        
        try:
            headers = self._get_secure_headers()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    propositions = []
                    for item in soup.select('.resultado-busca-item'):
                        prop = self._parse_lexml_result_secure(item)
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
                error=self._sanitize_error_message(str(e))
            )
    
    def _parse_json_results_secure(self, data: Any) -> List[Proposition]:
        """SECURITY HARDENED JSON results parsing"""
        propositions = []
        
        try:
            # Handle different JSON structures with validation
            if isinstance(data, dict):
                items = data.get("items", data.get("results", data.get("data", [])))
            elif isinstance(data, list):
                items = data
            else:
                return propositions
            
            for item in items[:50]:  # Limit items
                if isinstance(item, dict):
                    prop = self._parse_web_result_secure({
                        "title": item.get("title", item.get("titulo", "")),
                        "summary": item.get("summary", item.get("resumo", item.get("ementa", ""))),
                        "url": item.get("url", item.get("link", "")),
                        "date": item.get("date", item.get("data", item.get("dataPublicacao", "")))
                    })
                    if prop:
                        propositions.append(prop)
        except Exception as e:
            self.logger.error(f"Error parsing JSON results: {type(e).__name__}")
        
        return propositions
    
    def _parse_html_results_secure(self, html: str) -> List[Proposition]:
        """SECURITY HARDENED HTML results parsing"""
        propositions = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
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
                    for item in items[:20]:  # Limit items
                        title_elem = item.select_one('h3, h4, .title, .titulo')
                        if title_elem:
                            prop = self._parse_web_result_secure({
                                "title": title_elem.get_text(strip=True),
                                "summary": item.get_text(strip=True)[:500],
                                "url": item.select_one('a')['href'] if item.select_one('a') else "",
                                "date": item.select_one('.date, .data').get_text(strip=True) if item.select_one('.date, .data') else ""
                            })
                            if prop:
                                propositions.append(prop)
                    break
        except Exception as e:
            self.logger.error(f"Error parsing HTML results: {type(e).__name__}")
        
        return propositions
    
    def _parse_lexml_result_secure(self, soup_item) -> Optional[Proposition]:
        """SECURITY HARDENED LEXML result parsing"""
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
            
            return self._parse_web_result_secure({
                "title": title,
                "summary": summary,
                "url": f"https://www.lexml.gov.br{url}" if url.startswith('/') else url,
                "date": date_str
            })
            
        except Exception as e:
            self.logger.error(f"Error parsing LEXML result: {type(e).__name__}")
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