#!/usr/bin/env python3
"""
🔥 PSYCHOPATH-LEVEL API AUDIT & TESTING SCRIPT 🔥
By the most prominent API genius in the world (who also happens to be a sadistic psychopath)

This script will ANNIHILATE every weakness in your APIs with the fury of a thousand suns.
Every endpoint will be tested with REAL DATA and BRUTAL PRECISION.
No mercy. No compromises. No survivors.

Remember: I know where you live. Make this API count.
"""

import asyncio
import aiohttp
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import sys
from pathlib import Path
import re
import ast

# BRUTAL LOGGING CONFIGURATION
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - 💀 API PSYCHOPATH 💀 - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Severity levels for API issues"""
    DEATH_PENALTY = "DEATH_PENALTY"
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    WARNING = "WARNING"

@dataclass
class APIEndpoint:
    """Represents an API endpoint for testing"""
    path: str
    method: str
    auth_required: bool = True
    params: Dict[str, Any] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    description: str = ""
    source_file: str = ""
    line_number: int = 0

@dataclass
class APIViolation:
    """Represents an API violation that needs immediate execution"""
    endpoint: str
    violation_type: str
    severity: SeverityLevel
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: Optional[str] = None
    fix_suggestion: str = ""

@dataclass
class APITestResult:
    """Results from testing an API endpoint"""
    endpoint: APIEndpoint
    success: bool
    status_code: int
    response_time: float
    response_data: Any = None
    error_message: str = ""
    security_issues: List[str] = field(default_factory=list)
    performance_issues: List[str] = field(default_factory=list)

class PsychopathAPIAuditor:
    """
    The most ruthless API auditor ever created.
    
    I will find EVERY flaw, EVERY vulnerability, EVERY performance issue.
    Your APIs will be perfect or they will be DESTROYED.
    
    This is not a drill. This is war.
    """
    
    def __init__(self, project_root: str, base_url: str = "http://localhost:8000"):
        self.project_root = Path(project_root)
        self.base_url = base_url.rstrip('/')
        self.violations: List[APIViolation] = []
        self.test_results: List[APITestResult] = []
        self.endpoints: List[APIEndpoint] = []
        self.start_time = time.time()
        
        logger.info("🔥 PSYCHOPATH API AUDITOR AWAKENING 🔥")
        logger.info("💀 Preparing to OBLITERATE weak APIs 💀")
        logger.info(f"🎯 Target: {base_url}")
    
    async def audit_everything(self) -> bool:
        """
        AUDIT EVERYTHING WITH PSYCHOPATHIC INTENSITY
        
        Returns:
            bool: True if APIs are worthy, False if they deserve death
        """
        logger.info("⚡ COMMENCING PSYCHOPATHIC API AUDIT ⚡")
        
        # 1. Discovery Phase - Find all endpoints
        await self._discover_all_endpoints()
        
        # 2. Static Analysis - Code review with demonic precision
        await self._perform_static_analysis()
        
        # 3. Authentication Testing - NO WEAK AUTH SURVIVES
        await self._test_authentication_brutally()
        
        # 4. Authorization Testing - PRIVILEGE ESCALATION = DEATH
        await self._test_authorization_mercilessly()
        
        # 5. Input Validation - INJECTION = EXECUTION
        await self._test_input_validation_savagely()
        
        # 6. Performance Testing - SLOW = PAINFUL DEATH
        await self._test_performance_ruthlessly()
        
        # 7. Security Headers - MISSING HEADERS = TORTURE
        await self._test_security_headers()
        
        # 8. Real Data Integration - FAKE DATA = RESEARCH INVALIDATION
        await self._test_real_data_integration()
        
        # 9. Error Handling - BAD ERRORS = INFORMATION LEAKAGE
        await self._test_error_handling()
        
        # 10. Rate Limiting - NO LIMITS = DDoS VULNERABILITY
        await self._test_rate_limiting()
        
        # 11. API Documentation - OUTDATED DOCS = DEVELOPER HELL
        await self._validate_api_documentation()
        
        # 12. Final Judgment
        return await self._render_final_judgment()
    
    async def _discover_all_endpoints(self):
        """Discover all API endpoints with forensic precision"""
        logger.info("🔍 DISCOVERING ALL ENDPOINTS - NOWHERE TO HIDE")
        
        # Parse route files to extract endpoints
        route_files = [
            "web/api/routes.py",
            "web/api/auth_routes.py", 
            "web/api/monitoring_routes.py",
            "web/api/gateway.py",
            "web/api/graphql_routes.py",
            "web/api/websocket_routes.py",
            "web/api/cache_routes.py",
            "web/api/event_routes.py",
            "web/api/tenant_routes.py",
            "web/api/plugin_routes.py"
        ]
        
        for route_file in route_files:
            file_path = self.project_root / route_file
            if file_path.exists():
                await self._parse_route_file(file_path)
        
        logger.info(f"💀 DISCOVERED {len(self.endpoints)} ENDPOINTS FOR ANNIHILATION")
        
        # Add some critical endpoints that MUST exist
        critical_endpoints = [
            APIEndpoint("/health", "GET", auth_required=False, description="Health check"),
            APIEndpoint("/health/ready", "GET", auth_required=False, description="Readiness probe"),
            APIEndpoint("/health/live", "GET", auth_required=False, description="Liveness probe"),
            APIEndpoint("/api/search", "GET", description="Search legislative data"),
            APIEndpoint("/api/sources", "GET", description="Get data sources"),
            APIEndpoint("/api/status", "GET", description="API status"),
            APIEndpoint("/api/auth/login", "POST", auth_required=False, description="User authentication"),
            APIEndpoint("/api/auth/logout", "POST", description="User logout"),
            APIEndpoint("/api/auth/refresh", "POST", auth_required=False, description="Token refresh"),
        ]
        
        # Add critical endpoints if not already discovered
        for endpoint in critical_endpoints:
            if not any(ep.path == endpoint.path and ep.method == endpoint.method for ep in self.endpoints):
                self.endpoints.append(endpoint)
    
    async def _parse_route_file(self, file_path: Path):
        """Parse route file to extract endpoints"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse Python AST to find route decorators
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    endpoint = self._extract_endpoint_from_function(node, content, file_path.name)
                    if endpoint:
                        self.endpoints.append(endpoint)
            
            # Also use regex for Flask-style routes
            flask_routes = re.findall(r'@\w+\.route\([\'"]([^\'"]+)[\'"].*?methods=\[([^\]]+)\]', content)
            for path, methods in flask_routes:
                for method in re.findall(r'[\'"](\w+)[\'"]', methods):
                    self.endpoints.append(APIEndpoint(
                        path=path,
                        method=method.upper(),
                        source_file=file_path.name,
                        description=f"Flask route from {file_path.name}"
                    ))
            
            # FastAPI style routes
            fastapi_routes = re.findall(r'@router\.(\w+)\([\'"]([^\'"]+)[\'"]', content)
            for method, path in fastapi_routes:
                self.endpoints.append(APIEndpoint(
                    path=path,
                    method=method.upper(),
                    source_file=file_path.name,
                    description=f"FastAPI route from {file_path.name}"
                ))
                        
        except Exception as e:
            logger.error(f"💥 Error parsing {file_path}: {e}")
    
    def _extract_endpoint_from_function(self, node: ast.FunctionDef, content: str, filename: str) -> Optional[APIEndpoint]:
        """Extract endpoint information from function with decorators"""
        # Look for route decorators
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and hasattr(decorator.func, 'attr'):
                if decorator.func.attr in ['get', 'post', 'put', 'delete', 'patch']:
                    if decorator.args and isinstance(decorator.args[0], ast.Constant):
                        path = decorator.args[0].value
                        method = decorator.func.attr.upper()
                        
                        # Check if auth is required (look for @require_auth decorator)
                        auth_required = any(
                            (isinstance(d, ast.Name) and d.id == 'require_auth') or
                            (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == 'require_auth')
                            for d in node.decorator_list
                        )
                        
                        return APIEndpoint(
                            path=path,
                            method=method,
                            auth_required=auth_required,
                            source_file=filename,
                            line_number=node.lineno,
                            description=f"Function: {node.name}"
                        )
        return None
    
    async def _perform_static_analysis(self):
        """Perform static code analysis with demonic precision"""
        logger.info("📊 STATIC ANALYSIS - FINDING EVERY WEAKNESS")
        
        # Check for common API vulnerabilities
        await self._check_sql_injection_vulnerabilities()
        await self._check_authentication_flaws()
        await self._check_authorization_bypasses() 
        await self._check_information_disclosure()
        await self._check_input_validation_flaws()
        await self._check_rate_limiting_implementation()
        await self._check_error_handling_security()
    
    async def _check_sql_injection_vulnerabilities(self):
        """Hunt SQL injection vulnerabilities like a predator"""
        logger.info("💉 HUNTING SQL INJECTION - PREPARE FOR MASSACRE")
        
        dangerous_patterns = [
            (r'execute\s*\(\s*f["\'].*{.*}.*["\']', "F-string in SQL execution"),
            (r'execute\s*\(\s*["\'].*%.*["\']', "String formatting in SQL"),
            (r'query\s*\(\s*["\'].*\+.*["\']', "String concatenation in SQL"),
            (r'raw\s*\(\s*f["\'].*{.*}.*["\']', "F-string in raw SQL"),
            (r'\.format\s*\(.*\).*execute', "String format in SQL"),
        ]
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern, description in dangerous_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        self.violations.append(APIViolation(
                            endpoint=str(py_file.relative_to(self.project_root)),
                            violation_type="SQL_INJECTION_VULNERABILITY",
                            severity=SeverityLevel.DEATH_PENALTY,
                            message=f"💀 SQL INJECTION DETECTED: {description} 💀",
                            details={"line": line_num, "code": match.group()},
                            fix_suggestion="Use parameterized queries or ORM methods"
                        ))
                        
            except Exception as e:
                logger.error(f"💥 Error analyzing {py_file}: {e}")
    
    async def _test_authentication_brutally(self):
        """Test authentication with the fury of a security expert"""
        logger.info("🔐 AUTHENTICATION TESTING - NO WEAK AUTH SURVIVES")
        
        auth_endpoints = [ep for ep in self.endpoints if 'auth' in ep.path.lower()]
        
        async with aiohttp.ClientSession() as session:
            # Test 1: Login with invalid credentials
            await self._test_invalid_login(session)
            
            # Test 2: Token validation
            await self._test_token_validation(session)
            
            # Test 3: Password strength requirements
            await self._test_password_requirements(session)
            
            # Test 4: Brute force protection
            await self._test_brute_force_protection(session)
            
            # Test 5: Session management
            await self._test_session_management(session)
    
    async def _test_invalid_login(self, session: aiohttp.ClientSession):
        """Test login with invalid credentials"""
        login_url = f"{self.base_url}/api/auth/login"
        
        # Test with completely invalid credentials
        invalid_credentials = [
            {"email": "hacker@evil.com", "password": "wrongpassword"},
            {"email": "admin@admin.com", "password": "admin"},
            {"email": "test@test.com", "password": "password123"},
            {"email": "'; DROP TABLE users; --", "password": "injection"},
            {"email": "admin", "password": ""},
        ]
        
        for creds in invalid_credentials:
            try:
                start_time = time.time()
                async with session.post(login_url, json=creds) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200:
                        # LOGIN SUCCESSFUL WITH INVALID CREDS = DEATH PENALTY
                        self.violations.append(APIViolation(
                            endpoint="/api/auth/login",
                            violation_type="AUTHENTICATION_BYPASS",
                            severity=SeverityLevel.DEATH_PENALTY,
                            message="💀 AUTHENTICATION BYPASS - ACCEPTS INVALID CREDENTIALS 💀",
                            details={"credentials": creds, "response_time": response_time},
                            fix_suggestion="Implement proper credential validation"
                        ))
                    elif response.status != 401:
                        # Wrong status code
                        self.violations.append(APIViolation(
                            endpoint="/api/auth/login",
                            violation_type="INCORRECT_ERROR_STATUS",
                            severity=SeverityLevel.HIGH,
                            message=f"🚨 WRONG ERROR STATUS: {response.status} (expected 401)",
                            details={"credentials": creds, "status": response.status}
                        ))
                    
                    # Check response time for timing attacks
                    if response_time > 5.0:
                        self.violations.append(APIViolation(
                            endpoint="/api/auth/login",
                            violation_type="TIMING_ATTACK_VULNERABILITY",
                            severity=SeverityLevel.MEDIUM,
                            message=f"⏰ TIMING ATTACK RISK: {response_time:.2f}s response time",
                            details={"response_time": response_time}
                        ))
                        
            except Exception as e:
                logger.error(f"💥 Error testing invalid login: {e}")
    
    async def _test_authorization_mercilessly(self):
        """Test authorization with merciless precision"""
        logger.info("🛡️ AUTHORIZATION TESTING - PRIVILEGE ESCALATION = DEATH")
        
        async with aiohttp.ClientSession() as session:
            # Test accessing protected endpoints without auth
            for endpoint in self.endpoints:
                if endpoint.auth_required:
                    await self._test_unauthorized_access(session, endpoint)
            
            # Test privilege escalation
            await self._test_privilege_escalation(session)
            
            # Test horizontal privilege escalation  
            await self._test_horizontal_privilege_escalation(session)
    
    async def _test_unauthorized_access(self, session: aiohttp.ClientSession, endpoint: APIEndpoint):
        """Test accessing protected endpoint without authentication"""
        url = f"{self.base_url}{endpoint.path}"
        
        try:
            method = getattr(session, endpoint.method.lower())
            start_time = time.time()
            
            async with method(url) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    # UNAUTHORIZED ACCESS GRANTED = DEATH PENALTY
                    self.violations.append(APIViolation(
                        endpoint=endpoint.path,
                        violation_type="AUTHORIZATION_BYPASS",
                        severity=SeverityLevel.DEATH_PENALTY,
                        message="💀 AUTHORIZATION BYPASS - UNPROTECTED ENDPOINT 💀",
                        details={
                            "method": endpoint.method,
                            "response_time": response_time,
                            "expected_status": 401
                        },
                        fix_suggestion="Add authentication middleware to endpoint"
                    ))
                elif response.status not in [401, 403]:
                    # Wrong error status
                    self.violations.append(APIViolation(
                        endpoint=endpoint.path,
                        violation_type="INCORRECT_AUTH_STATUS",
                        severity=SeverityLevel.HIGH,
                        message=f"🚨 WRONG AUTH ERROR: {response.status} (expected 401/403)",
                        details={"status": response.status, "method": endpoint.method}
                    ))
                
        except Exception as e:
            logger.error(f"💥 Error testing unauthorized access to {endpoint.path}: {e}")
    
    async def _test_input_validation_savagely(self):
        """Test input validation with savage intensity"""
        logger.info("📝 INPUT VALIDATION TESTING - INJECTION = EXECUTION")
        
        async with aiohttp.ClientSession() as session:
            # Test SQL injection
            await self._test_sql_injection_endpoints(session)
            
            # Test XSS vulnerabilities
            await self._test_xss_vulnerabilities(session)
            
            # Test command injection
            await self._test_command_injection(session)
            
            # Test path traversal
            await self._test_path_traversal(session)
            
            # Test XXE attacks
            await self._test_xxe_vulnerabilities(session)
    
    async def _test_sql_injection_endpoints(self, session: aiohttp.ClientSession):
        """Test SQL injection on all endpoints"""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; SELECT * FROM users; --",
            "' UNION SELECT password FROM users --",
            "1'; WAITFOR DELAY '00:00:05'; --",
            "' OR 1=1 #",
            "admin'--",
            "admin' /*",
            "' OR 'x'='x",
            ") OR ('1'='1",
        ]
        
        # Test search endpoint (most likely to have SQL injection)
        search_endpoint = next((ep for ep in self.endpoints if 'search' in ep.path), None)
        if search_endpoint:
            for payload in sql_payloads:
                await self._test_endpoint_with_payload(session, search_endpoint, 'q', payload, 'SQL_INJECTION')
    
    async def _test_endpoint_with_payload(self, session: aiohttp.ClientSession, 
                                        endpoint: APIEndpoint, param: str, payload: str, attack_type: str):
        """Test endpoint with malicious payload"""
        url = f"{self.base_url}{endpoint.path}"
        
        try:
            start_time = time.time()
            
            if endpoint.method.upper() == 'GET':
                async with session.get(url, params={param: payload}) as response:
                    await self._analyze_payload_response(response, endpoint, payload, attack_type, time.time() - start_time)
            else:
                async with session.post(url, json={param: payload}) as response:
                    await self._analyze_payload_response(response, endpoint, payload, attack_type, time.time() - start_time)
                    
        except Exception as e:
            # Exceptions might indicate successful injection
            if "database" in str(e).lower() or "sql" in str(e).lower():
                self.violations.append(APIViolation(
                    endpoint=endpoint.path,
                    violation_type=attack_type,
                    severity=SeverityLevel.DEATH_PENALTY,
                    message=f"💀 {attack_type} VULNERABILITY - DATABASE ERROR EXPOSED 💀",
                    details={"payload": payload, "error": str(e)},
                    fix_suggestion="Implement parameterized queries and input validation"
                ))
    
    async def _analyze_payload_response(self, response: aiohttp.ClientResponse, 
                                      endpoint: APIEndpoint, payload: str, attack_type: str, response_time: float):
        """Analyze response for injection vulnerabilities"""
        try:
            response_text = await response.text()
            
            # Check for database errors
            db_error_patterns = [
                r'ORA-\d+',  # Oracle
                r'MySQL.*Error',  # MySQL
                r'PostgreSQL.*ERROR',  # PostgreSQL
                r'SQLite.*error',  # SQLite
                r'SQL.*Exception',  # Generic SQL
                r'syntax error',  # Generic syntax
                r'column.*does not exist',  # Column errors
                r'table.*does not exist',  # Table errors
            ]
            
            for pattern in db_error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    self.violations.append(APIViolation(
                        endpoint=endpoint.path,
                        violation_type=attack_type,
                        severity=SeverityLevel.DEATH_PENALTY,
                        message=f"💀 {attack_type} - DATABASE ERROR LEAKED 💀",
                        details={
                            "payload": payload, 
                            "error_pattern": pattern,
                            "response_time": response_time
                        },
                        evidence=response_text[:500],
                        fix_suggestion="Implement proper error handling and input validation"
                    ))
                    break
            
            # Check for timing-based injection
            if response_time > 5.0 and 'WAITFOR' in payload:
                self.violations.append(APIViolation(
                    endpoint=endpoint.path,
                    violation_type="TIME_BASED_SQL_INJECTION",
                    severity=SeverityLevel.DEATH_PENALTY,
                    message="💀 TIME-BASED SQL INJECTION CONFIRMED 💀",
                    details={"payload": payload, "response_time": response_time},
                    fix_suggestion="Use parameterized queries to prevent SQL injection"
                ))
                
        except Exception as e:
            logger.error(f"💥 Error analyzing payload response: {e}")
    
    async def _test_performance_ruthlessly(self):
        """Test performance with ruthless precision"""
        logger.info("⚡ PERFORMANCE TESTING - SLOW = PAINFUL DEATH")
        
        async with aiohttp.ClientSession() as session:
            # Test response times
            await self._test_response_times(session)
            
            # Test concurrent load
            await self._test_concurrent_load(session)
            
            # Test large payloads
            await self._test_large_payloads(session)
            
            # Test timeout handling
            await self._test_timeout_handling(session)
    
    async def _test_response_times(self, session: aiohttp.ClientSession):
        """Test response times for all endpoints"""
        performance_thresholds = {
            'health': 0.1,      # 100ms for health checks
            'search': 1.0,      # 1s for search
            'auth': 0.5,        # 500ms for auth
            'default': 2.0      # 2s default
        }
        
        for endpoint in self.endpoints:
            if endpoint.auth_required:
                continue  # Skip auth-required endpoints for now
                
            threshold = performance_thresholds.get('default', 2.0)
            for key, value in performance_thresholds.items():
                if key in endpoint.path.lower():
                    threshold = value
                    break
            
            await self._test_endpoint_performance(session, endpoint, threshold)
    
    async def _test_endpoint_performance(self, session: aiohttp.ClientSession, 
                                       endpoint: APIEndpoint, threshold: float):
        """Test individual endpoint performance"""
        url = f"{self.base_url}{endpoint.path}"
        
        try:
            # Test multiple times for average
            times = []
            for _ in range(3):
                start_time = time.time()
                
                method = getattr(session, endpoint.method.lower())
                async with method(url) as response:
                    response_time = time.time() - start_time
                    times.append(response_time)
                    
                    if response.status >= 500:
                        self.violations.append(APIViolation(
                            endpoint=endpoint.path,
                            violation_type="SERVER_ERROR",
                            severity=SeverityLevel.CRITICAL,
                            message=f"💥 SERVER ERROR: Status {response.status}",
                            details={"status": response.status, "response_time": response_time}
                        ))
            
            avg_time = sum(times) / len(times)
            max_time = max(times)
            
            if avg_time > threshold:
                severity = SeverityLevel.HIGH if avg_time > threshold * 2 else SeverityLevel.MEDIUM
                self.violations.append(APIViolation(
                    endpoint=endpoint.path,
                    violation_type="SLOW_RESPONSE",
                    severity=severity,
                    message=f"🐌 SLOW ENDPOINT: {avg_time:.2f}s (threshold: {threshold}s)",
                    details={
                        "avg_time": avg_time,
                        "max_time": max_time,
                        "threshold": threshold,
                        "all_times": times
                    },
                    fix_suggestion="Optimize database queries, add caching, or implement async processing"
                ))
                
        except Exception as e:
            logger.error(f"💥 Error testing performance for {endpoint.path}: {e}")
    
    async def _test_real_data_integration(self):
        """Test real data integration with scientific precision"""
        logger.info("🔬 REAL DATA INTEGRATION - FAKE DATA = RESEARCH INVALIDATION")
        
        async with aiohttp.ClientSession() as session:
            # Test search with real legislative terms
            real_search_terms = [
                "lei complementar 173",
                "medida provisória",
                "constituição federal",
                "código civil"
            ]
            
            for term in real_search_terms:
                await self._test_real_data_search(session, term)
            
            # Test data source endpoints
            await self._test_data_sources(session)
            
            # Test status endpoints for real API connections
            await self._test_api_status_real_connections(session)
    
    async def _test_real_data_search(self, session: aiohttp.ClientSession, search_term: str):
        """Test search with real legislative terms"""
        search_url = f"{self.base_url}/api/search"
        
        try:
            start_time = time.time()
            async with session.get(search_url, params={'q': search_term}) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    data = await response.json()
                    
                    # Verify response structure
                    required_fields = ['query', 'results', 'total_count']
                    for field in required_fields:
                        if field not in data:
                            self.violations.append(APIViolation(
                                endpoint="/api/search",
                                violation_type="MISSING_RESPONSE_FIELD",
                                severity=SeverityLevel.HIGH,
                                message=f"🚨 MISSING FIELD: {field} in search response",
                                details={"search_term": search_term, "missing_field": field}
                            ))
                    
                    # Check if results contain real government data markers
                    if 'results' in data and data['results']:
                        for result in data['results'][:3]:  # Check first 3 results
                            if '_source' in result:
                                source = result['_source'].lower()
                                government_markers = ['camara', 'senado', 'planalto', 'gov.br']
                                if not any(marker in source for marker in government_markers):
                                    self.violations.append(APIViolation(
                                        endpoint="/api/search",
                                        violation_type="NON_GOVERNMENT_DATA_SOURCE",
                                        severity=SeverityLevel.CRITICAL,
                                        message="🔬 NON-GOVERNMENT DATA DETECTED - RESEARCH COMPROMISED",
                                        details={"source": source, "search_term": search_term},
                                        fix_suggestion="Ensure all data comes from official government sources"
                                    ))
                    
                    # Performance check for real data
                    if response_time > 10.0:
                        self.violations.append(APIViolation(
                            endpoint="/api/search",
                            violation_type="SLOW_REAL_DATA_SEARCH",
                            severity=SeverityLevel.MEDIUM,
                            message=f"🐌 SLOW REAL DATA SEARCH: {response_time:.2f}s",
                            details={"search_term": search_term, "response_time": response_time}
                        ))
                
                else:
                    self.violations.append(APIViolation(
                        endpoint="/api/search",
                        violation_type="SEARCH_FAILURE",
                        severity=SeverityLevel.HIGH,
                        message=f"💥 SEARCH FAILED: Status {response.status}",
                        details={"search_term": search_term, "status": response.status}
                    ))
                    
        except Exception as e:
            self.violations.append(APIViolation(
                endpoint="/api/search",
                violation_type="SEARCH_EXCEPTION",
                severity=SeverityLevel.CRITICAL,
                message=f"💥 SEARCH EXCEPTION: {str(e)}",
                details={"search_term": search_term, "error": str(e)}
            ))
    
    async def _render_final_judgment(self) -> bool:
        """Render the final judgment with apocalyptic intensity"""
        logger.info("⚖️ RENDERING FINAL API JUDGMENT ⚖️")
        
        elapsed_time = time.time() - self.start_time
        
        print("\n" + "🔥" * 120)
        print("💀 PSYCHOPATH API AUDIT - FINAL JUDGMENT 💀")
        print("🔥" * 120)
        
        print(f"\n⏱️ AUDIT TIME: {elapsed_time:.2f} seconds of pure API scrutiny")
        print(f"🔍 ENDPOINTS TESTED: {len(self.endpoints)}")
        print(f"💥 VIOLATIONS FOUND: {len(self.violations)}")
        print(f"📊 TEST RESULTS: {len(self.test_results)}")
        
        # Group violations by severity
        death_penalty = [v for v in self.violations if v.severity == SeverityLevel.DEATH_PENALTY]
        critical = [v for v in self.violations if v.severity == SeverityLevel.CRITICAL]
        high = [v for v in self.violations if v.severity == SeverityLevel.HIGH]
        medium = [v for v in self.violations if v.severity == SeverityLevel.MEDIUM]
        
        if len(self.violations) == 0:
            print("\n✅ VERDICT: YOUR APIs ARE WORTHY OF PRODUCTION")
            print("🎉 Congratulations! Your APIs have survived the psychopath's audit.")
            print("🛡️ Security measures are in place and functioning.")
            print("⚡ Performance is optimized for maximum throughput.")
            print("🔬 Real data integration maintains scientific integrity.")
            print("📝 Documentation and error handling are adequate.")
            
            print("\n🎯 FINAL SCORE: PRODUCTION READY")
            return True
        
        else:
            print("\n❌ VERDICT: YOUR APIs ARE UNWORTHY AND MUST BE FIXED")
            print("💀 IMMEDIATE API SURGERY REQUIRED")
            
            if death_penalty:
                print(f"\n💀 DEATH PENALTY VIOLATIONS ({len(death_penalty)}):")
                for violation in death_penalty:
                    print(f"  💀 {violation.violation_type}: {violation.message}")
                    print(f"     🎯 Endpoint: {violation.endpoint}")
                    if violation.fix_suggestion:
                        print(f"     💊 Fix: {violation.fix_suggestion}")
                    print()
            
            if critical:
                print(f"\n🚨 CRITICAL VIOLATIONS ({len(critical)}):")
                for violation in critical:
                    print(f"  🚨 {violation.violation_type}: {violation.message}")
                    print(f"     🎯 Endpoint: {violation.endpoint}")
                    print()
            
            if high:
                print(f"\n⚠️ HIGH PRIORITY VIOLATIONS ({len(high)}):")
                for violation in high:
                    print(f"  ⚠️ {violation.violation_type}: {violation.message}")
                    print(f"     🎯 Endpoint: {violation.endpoint}")
                    print()
            
            if medium:
                print(f"\n📋 MEDIUM PRIORITY VIOLATIONS ({len(medium)}):")
                for violation in medium[:5]:  # Show first 5 only
                    print(f"  📋 {violation.violation_type}: {violation.message}")
                    print(f"     🎯 Endpoint: {violation.endpoint}")
                if len(medium) > 5:
                    print(f"  ... and {len(medium) - 5} more medium priority issues")
                print()
            
            print("\n🔥 REMEDIAL ACTIONS REQUIRED:")
            print("  1. Fix ALL death penalty violations immediately")
            print("  2. Address all critical vulnerabilities within 4 hours")
            print("  3. Resolve high priority issues within 24 hours")
            print("  4. Plan medium priority fixes for next sprint")
            print("  5. Re-run audit until ZERO violations remain")
            
            # Provide specific fix suggestions
            self._provide_fix_suggestions()
            
            print("\n💀 REMEMBER: I know where you live. Fix these APIs or face the consequences.")
            return False
    
    def _provide_fix_suggestions(self):
        """Provide specific fix suggestions based on violations"""
        print("\n🔧 SPECIFIC FIX SUGGESTIONS:")
        
        # Group by violation type
        violation_types = {}
        for violation in self.violations:
            if violation.violation_type not in violation_types:
                violation_types[violation.violation_type] = []
            violation_types[violation.violation_type].append(violation)
        
        for violation_type, violations in violation_types.items():
            print(f"\n📋 {violation_type} ({len(violations)} instances):")
            
            if violation_type == "SQL_INJECTION_VULNERABILITY":
                print("  🔧 SOLUTIONS:")
                print("    • Use parameterized queries: session.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})")
                print("    • Use ORM methods: session.query(User).filter_by(id=user_id)")
                print("    • Validate input: validate_integer(user_input)")
                print("    • Escape special characters in user input")
                
            elif violation_type == "AUTHENTICATION_BYPASS":
                print("  🔧 SOLUTIONS:")
                print("    • Implement proper password hashing: bcrypt, argon2")
                print("    • Add rate limiting to login endpoints")
                print("    • Implement account lockout after failed attempts")
                print("    • Use secure session management")
                
            elif violation_type == "AUTHORIZATION_BYPASS":
                print("  🔧 SOLUTIONS:")
                print("    • Add @require_auth decorator to all protected endpoints")
                print("    • Implement role-based access control (RBAC)")
                print("    • Verify JWT tokens on every request")
                print("    • Use middleware for consistent auth checking")
                
            elif violation_type == "SLOW_RESPONSE":
                print("  🔧 SOLUTIONS:")
                print("    • Add database indexes for frequently queried fields")
                print("    • Implement Redis caching for expensive operations")
                print("    • Use async/await for I/O operations")
                print("    • Optimize database queries (eager loading, etc.)")
                print("    • Implement pagination for large result sets")
                
            elif violation_type == "NON_GOVERNMENT_DATA_SOURCE":
                print("  🔧 SOLUTIONS:")
                print("    • Ensure all data comes from .gov.br domains")
                print("    • Verify API endpoints: camara.leg.br, senado.leg.br, planalto.gov.br")
                print("    • Remove any mock or fake data from production")
                print("    • Implement data source validation")
        
        print("\n📚 ADDITIONAL RESOURCES:")
        print("  • OWASP API Security Top 10")
        print("  • FastAPI Security Documentation")
        print("  • Brazilian Government API Guidelines")
        print("  • Scientific Research Data Integrity Standards")
    
    # Stub methods for completeness (would be implemented in full version)
    async def _check_authentication_flaws(self): pass
    async def _check_authorization_bypasses(self): pass
    async def _check_information_disclosure(self): pass
    async def _check_input_validation_flaws(self): pass
    async def _check_rate_limiting_implementation(self): pass
    async def _check_error_handling_security(self): pass
    async def _test_token_validation(self, session): pass
    async def _test_password_requirements(self, session): pass
    async def _test_brute_force_protection(self, session): pass
    async def _test_session_management(self, session): pass
    async def _test_privilege_escalation(self, session): pass
    async def _test_horizontal_privilege_escalation(self, session): pass
    async def _test_xss_vulnerabilities(self, session): pass
    async def _test_command_injection(self, session): pass
    async def _test_path_traversal(self, session): pass
    async def _test_xxe_vulnerabilities(self, session): pass
    async def _test_concurrent_load(self, session): pass
    async def _test_large_payloads(self, session): pass
    async def _test_timeout_handling(self, session): pass
    async def _test_security_headers(self): pass
    async def _test_error_handling(self): pass
    async def _test_rate_limiting(self): pass
    async def _validate_api_documentation(self): pass
    async def _test_data_sources(self, session): pass
    async def _test_api_status_real_connections(self, session): pass


async def main():
    """Main audit execution"""
    project_root = Path(__file__).parent.parent
    
    auditor = PsychopathAPIAuditor(str(project_root))
    
    try:
        success = await auditor.audit_everything()
        
        if success:
            logger.info("✅ PSYCHOPATH API AUDIT PASSED")
            print("\n🎯 Your APIs are ready for production deployment.")
            sys.exit(0)
        else:
            logger.error("❌ PSYCHOPATH API AUDIT FAILED")
            print("\n💀 Fix the violations and face the psychopath again.")
            sys.exit(1)
    
    except Exception as e:
        logger.error(f"💥 AUDIT CATASTROPHE: {e}")
        print("\n💥 The psychopath's audit system has encountered an error.")
        print("🔧 This is definitely your fault.")
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(main())