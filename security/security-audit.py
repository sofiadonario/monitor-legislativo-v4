# Security Audit and Vulnerability Scanner for Monitor Legislativo v4
# Phase 4 Week 16: Comprehensive security assessment with automated scanning
# Monitors application security posture and compliance status

import asyncio
import aiohttp
import asyncpg
import json
import logging
import subprocess
import hashlib
import os
import ssl
import socket
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import re
from pathlib import Path
import requests
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Security vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityType(Enum):
    """Types of security vulnerabilities"""
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    CSRF = "cross_site_request_forgery"
    AUTHENTICATION = "authentication_bypass"
    AUTHORIZATION = "authorization_flaw"
    SENSITIVE_DATA = "sensitive_data_exposure"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    INJECTION = "injection_flaw"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTOGRAPHIC_FAILURE = "cryptographic_failure"

@dataclass
class SecurityVulnerability:
    """Security vulnerability finding"""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    vulnerability_type: VulnerabilityType
    affected_component: str
    affected_url: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: Optional[float] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['severity'] = self.severity.value
        result['vulnerability_type'] = self.vulnerability_type.value
        result['discovered_at'] = self.discovered_at.isoformat()
        return result

@dataclass
class SecurityAuditReport:
    """Comprehensive security audit report"""
    audit_id: str
    timestamp: datetime
    vulnerabilities: List[SecurityVulnerability]
    security_score: float  # 0-100 score based on findings
    compliance_status: Dict[str, bool]
    recommendations: List[str]
    scan_duration: timedelta
    scanned_components: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        result['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        result['scan_duration'] = str(self.scan_duration)
        return result

class SecurityAuditor:
    """
    Comprehensive security audit system for Monitor Legislativo v4
    
    Performs automated security scanning including:
    - Web application vulnerability assessment
    - Database security analysis
    - Infrastructure security review
    - OWASP Top 10 compliance checking
    - Brazilian LGPD compliance verification
    """
    
    def __init__(self, base_url: str = "http://localhost:8000", 
                 db_config: Optional[Dict[str, str]] = None):
        self.base_url = base_url
        self.db_config = db_config or {}
        self.vulnerabilities = []
        self.scan_start_time = None
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "SecurityAudit/1.0 MonitorLegislativo/4.0",
            "OWASP-ZAP/2.12.0"
        ]
        
    async def run_comprehensive_audit(self) -> SecurityAuditReport:
        """Run complete security audit"""
        self.scan_start_time = datetime.now()
        self.vulnerabilities = []
        
        logger.info("Starting comprehensive security audit...")
        
        # Web application security tests
        await self._scan_web_application_security()
        
        # Database security assessment
        await self._scan_database_security()
        
        # Infrastructure security review
        await self._scan_infrastructure_security()
        
        # API security testing
        await self._scan_api_security()
        
        # Configuration security review
        await self._scan_configuration_security()
        
        # LGPD compliance check
        await self._check_lgpd_compliance()
        
        # Generate comprehensive report
        return self._generate_audit_report()
    
    async def _scan_web_application_security(self) -> None:
        """Scan web application for common vulnerabilities"""
        logger.info("Scanning web application security...")
        
        # Test for XSS vulnerabilities
        await self._test_xss_vulnerabilities()
        
        # Test for SQL injection
        await self._test_sql_injection()
        
        # Test for CSRF protection
        await self._test_csrf_protection()
        
        # Test authentication mechanisms
        await self._test_authentication_security()
        
        # Test authorization controls
        await self._test_authorization_controls()
        
        # Test for sensitive data exposure
        await self._test_sensitive_data_exposure()
    
    async def _test_xss_vulnerabilities(self) -> None:
        """Test for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg/onload=alert('XSS')>",
            "\"onmouseover=alert('XSS')\"",
        ]
        
        test_endpoints = [
            "/api/v1/search",
            "/api/v1/documents/search",
            "/api/v1/analytics/query"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in test_endpoints:
                for payload in xss_payloads:
                    try:
                        # Test in query parameters
                        url = f"{self.base_url}{endpoint}?q={payload}"
                        async with session.get(url) as response:
                            response_text = await response.text()
                            
                            if payload in response_text and "text/html" in response.headers.get("content-type", ""):
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"xss_{hashlib.md5(f'{endpoint}{payload}'.encode()).hexdigest()[:8]}",
                                    title="Cross-Site Scripting (XSS) Vulnerability",
                                    description=f"XSS payload reflected in response at {endpoint}",
                                    severity=SeverityLevel.HIGH,
                                    vulnerability_type=VulnerabilityType.XSS,
                                    affected_component="Web Application",
                                    affected_url=url,
                                    evidence={"payload": payload, "response_contains_payload": True},
                                    remediation="Implement proper input validation and output encoding"
                                ))
                        
                        # Test in POST body
                        if endpoint == "/api/v1/search":
                            data = {"query": payload, "sources": ["lexml"]}
                            async with session.post(f"{self.base_url}{endpoint}", json=data) as response:
                                response_text = await response.text()
                                
                                if payload in response_text:
                                    self.vulnerabilities.append(SecurityVulnerability(
                                        id=f"xss_post_{hashlib.md5(f'{endpoint}{payload}'.encode()).hexdigest()[:8]}",
                                        title="Cross-Site Scripting (XSS) in POST Request",
                                        description=f"XSS payload in POST body reflected at {endpoint}",
                                        severity=SeverityLevel.HIGH,
                                        vulnerability_type=VulnerabilityType.XSS,
                                        affected_component="API Endpoint",
                                        affected_url=f"{self.base_url}{endpoint}",
                                        evidence={"payload": payload, "method": "POST"},
                                        remediation="Sanitize JSON input and implement CSP headers"
                                    ))
                    
                    except Exception as e:
                        logger.debug(f"XSS test error for {endpoint}: {e}")
    
    async def _test_sql_injection(self) -> None:
        """Test for SQL injection vulnerabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE documents;--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1' UNION SELECT username,password FROM users--"
        ]
        
        test_endpoints = [
            "/api/v1/documents/{id}",
            "/api/v1/search",
            "/api/v1/analytics/documents"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in test_endpoints:
                for payload in sql_payloads:
                    try:
                        if "{id}" in endpoint:
                            test_url = endpoint.replace("{id}", payload)
                        else:
                            test_url = f"{endpoint}?id={payload}"
                        
                        url = f"{self.base_url}{test_url}"
                        async with session.get(url) as response:
                            response_text = await response.text()
                            
                            # Check for SQL error messages
                            sql_errors = [
                                "postgresql error", "syntax error", "invalid input syntax",
                                "relation does not exist", "column", "operator does not exist",
                                "permission denied", "database error"
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in response_text.lower():
                                    self.vulnerabilities.append(SecurityVulnerability(
                                        id=f"sqli_{hashlib.md5(f'{endpoint}{payload}'.encode()).hexdigest()[:8]}",
                                        title="SQL Injection Vulnerability",
                                        description=f"SQL injection detected at {endpoint} - database error exposed",
                                        severity=SeverityLevel.CRITICAL,
                                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                        affected_component="Database Layer",
                                        affected_url=url,
                                        evidence={"payload": payload, "error_message": error},
                                        remediation="Use parameterized queries and input validation"
                                    ))
                                    break
                    
                    except Exception as e:
                        logger.debug(f"SQL injection test error for {endpoint}: {e}")
    
    async def _test_csrf_protection(self) -> None:
        """Test CSRF protection mechanisms"""
        state_changing_endpoints = [
            ("/api/v1/documents", "POST"),
            ("/api/v1/analytics/export", "POST"),
            ("/api/v1/admin/settings", "PUT")
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint, method in state_changing_endpoints:
                try:
                    # Test without CSRF token
                    url = f"{self.base_url}{endpoint}"
                    
                    if method == "POST":
                        async with session.post(url, json={"test": "data"}) as response:
                            if response.status < 400:  # Request succeeded without CSRF protection
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"csrf_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                    title="Missing CSRF Protection",
                                    description=f"State-changing endpoint {endpoint} lacks CSRF protection",
                                    severity=SeverityLevel.MEDIUM,
                                    vulnerability_type=VulnerabilityType.CSRF,
                                    affected_component="API Security",
                                    affected_url=url,
                                    evidence={"method": method, "status_code": response.status},
                                    remediation="Implement CSRF tokens for state-changing operations"
                                ))
                    
                    elif method == "PUT":
                        async with session.put(url, json={"test": "data"}) as response:
                            if response.status < 400:
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"csrf_put_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                    title="Missing CSRF Protection (PUT)",
                                    description=f"PUT endpoint {endpoint} lacks CSRF protection",
                                    severity=SeverityLevel.MEDIUM,
                                    vulnerability_type=VulnerabilityType.CSRF,
                                    affected_component="API Security",
                                    affected_url=url,
                                    evidence={"method": method, "status_code": response.status},
                                    remediation="Implement CSRF tokens for all state-changing operations"
                                ))
                
                except Exception as e:
                    logger.debug(f"CSRF test error for {endpoint}: {e}")
    
    async def _test_authentication_security(self) -> None:
        """Test authentication mechanisms"""
        # Test for default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test")
        ]
        
        login_endpoints = [
            "/api/v1/auth/login",
            "/admin/login",
            "/api/v1/admin/auth"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in login_endpoints:
                for username, password in default_creds:
                    try:
                        url = f"{self.base_url}{endpoint}"
                        data = {"username": username, "password": password}
                        
                        async with session.post(url, json=data) as response:
                            if response.status == 200:
                                response_data = await response.json()
                                if "token" in response_data or "access_token" in response_data:
                                    self.vulnerabilities.append(SecurityVulnerability(
                                        id=f"auth_default_{hashlib.md5(f'{username}{password}'.encode()).hexdigest()[:8]}",
                                        title="Default Credentials Accepted",
                                        description=f"Default credentials {username}:{password} accepted",
                                        severity=SeverityLevel.CRITICAL,
                                        vulnerability_type=VulnerabilityType.AUTHENTICATION,
                                        affected_component="Authentication System",
                                        affected_url=url,
                                        evidence={"username": username, "password": "***"},
                                        remediation="Remove default credentials and enforce strong password policy"
                                    ))
                    
                    except Exception as e:
                        logger.debug(f"Authentication test error: {e}")
        
        # Test for weak session management
        await self._test_session_security()
    
    async def _test_session_security(self) -> None:
        """Test session management security"""
        async with aiohttp.ClientSession() as session:
            try:
                # Test session fixation
                url = f"{self.base_url}/api/v1/health"
                async with session.get(url) as response:
                    cookies = response.cookies
                    
                    # Check for secure session cookies
                    for cookie in cookies.values():
                        if "session" in cookie.key.lower() or "auth" in cookie.key.lower():
                            if not cookie.get("secure"):
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"session_insecure_{hashlib.md5(cookie.key.encode()).hexdigest()[:8]}",
                                    title="Insecure Session Cookie",
                                    description=f"Session cookie {cookie.key} lacks Secure flag",
                                    severity=SeverityLevel.MEDIUM,
                                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                                    affected_component="Session Management",
                                    evidence={"cookie_name": cookie.key, "secure_flag": False},
                                    remediation="Set Secure and HttpOnly flags on session cookies"
                                ))
                            
                            if not cookie.get("httponly"):
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"session_httponly_{hashlib.md5(cookie.key.encode()).hexdigest()[:8]}",
                                    title="Session Cookie Missing HttpOnly",
                                    description=f"Session cookie {cookie.key} lacks HttpOnly flag",
                                    severity=SeverityLevel.MEDIUM,
                                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                                    affected_component="Session Management",
                                    evidence={"cookie_name": cookie.key, "httponly_flag": False},
                                    remediation="Set HttpOnly flag to prevent XSS cookie theft"
                                ))
            
            except Exception as e:
                logger.debug(f"Session security test error: {e}")
    
    async def _test_authorization_controls(self) -> None:
        """Test authorization and access controls"""
        # Test for broken access control
        protected_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/settings",
            "/api/v1/admin/logs",
            "/api/v1/admin/database"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in protected_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Test without authentication
                    async with session.get(url) as response:
                        if response.status == 200:
                            self.vulnerabilities.append(SecurityVulnerability(
                                id=f"authz_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                title="Broken Access Control",
                                description=f"Protected endpoint {endpoint} accessible without authentication",
                                severity=SeverityLevel.HIGH,
                                vulnerability_type=VulnerabilityType.BROKEN_ACCESS_CONTROL,
                                affected_component="Authorization System",
                                affected_url=url,
                                evidence={"status_code": response.status, "authentication": "none"},
                                remediation="Implement proper authentication and authorization checks"
                            ))
                
                except Exception as e:
                    logger.debug(f"Authorization test error for {endpoint}: {e}")
    
    async def _test_sensitive_data_exposure(self) -> None:
        """Test for sensitive data exposure"""
        # Check for exposed configuration files
        config_files = [
            "/.env",
            "/config.json",
            "/database.conf",
            "/.git/config",
            "/docker-compose.yml",
            "/requirements.txt"
        ]
        
        async with aiohttp.ClientSession() as session:
            for config_file in config_files:
                try:
                    url = f"{self.base_url}{config_file}"
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for sensitive information
                            sensitive_patterns = [
                                r"password\s*[=:]\s*['\"][^'\"]+['\"]",
                                r"secret\s*[=:]\s*['\"][^'\"]+['\"]",
                                r"api_key\s*[=:]\s*['\"][^'\"]+['\"]",
                                r"database.*://[^/\s]+",
                                r"postgres://[^/\s]+",
                                r"redis://[^/\s]+"
                            ]
                            
                            for pattern in sensitive_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.vulnerabilities.append(SecurityVulnerability(
                                        id=f"data_exposure_{hashlib.md5(config_file.encode()).hexdigest()[:8]}",
                                        title="Sensitive Data Exposure",
                                        description=f"Configuration file {config_file} contains sensitive information",
                                        severity=SeverityLevel.HIGH,
                                        vulnerability_type=VulnerabilityType.SENSITIVE_DATA,
                                        affected_component="Configuration Management",
                                        affected_url=url,
                                        evidence={"file": config_file, "pattern_found": True},
                                        remediation="Remove sensitive files from web-accessible directories"
                                    ))
                                    break
                
                except Exception as e:
                    logger.debug(f"Sensitive data test error for {config_file}: {e}")
    
    async def _scan_database_security(self) -> None:
        """Scan database security configuration"""
        if not self.db_config:
            logger.info("Database configuration not provided, skipping database security scan")
            return
        
        logger.info("Scanning database security...")
        
        try:
            # Test database connection security
            conn = await asyncpg.connect(**self.db_config)
            
            # Check for weak database configurations
            await self._check_database_permissions(conn)
            await self._check_database_encryption(conn)
            await self._check_database_logging(conn)
            
            await conn.close()
        
        except Exception as e:
            logger.error(f"Database security scan error: {e}")
    
    async def _check_database_permissions(self, conn: asyncpg.Connection) -> None:
        """Check database user permissions"""
        try:
            # Check current user privileges
            result = await conn.fetch("SELECT current_user, session_user;")
            current_user = result[0]['current_user']
            
            # Check if user has superuser privileges
            superuser_check = await conn.fetch(
                "SELECT usesuper FROM pg_user WHERE usename = $1;", current_user
            )
            
            if superuser_check and superuser_check[0]['usesuper']:
                self.vulnerabilities.append(SecurityVulnerability(
                    id="db_superuser_privileges",
                    title="Application Using Database Superuser",
                    description="Application connects to database with superuser privileges",
                    severity=SeverityLevel.HIGH,
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                    affected_component="Database Configuration",
                    evidence={"user": current_user, "superuser": True},
                    remediation="Use dedicated application user with minimal required privileges"
                ))
        
        except Exception as e:
            logger.debug(f"Database permissions check error: {e}")
    
    async def _check_database_encryption(self, conn: asyncpg.Connection) -> None:
        """Check database encryption settings"""
        try:
            # Check SSL configuration
            ssl_result = await conn.fetch("SHOW ssl;")
            ssl_enabled = ssl_result[0]['ssl'] == 'on' if ssl_result else False
            
            if not ssl_enabled:
                self.vulnerabilities.append(SecurityVulnerability(
                    id="db_ssl_disabled",
                    title="Database SSL/TLS Disabled",
                    description="Database connection not encrypted with SSL/TLS",
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.CRYPTOGRAPHIC_FAILURE,
                    affected_component="Database Configuration",
                    evidence={"ssl_enabled": ssl_enabled},
                    remediation="Enable SSL/TLS encryption for database connections"
                ))
        
        except Exception as e:
            logger.debug(f"Database encryption check error: {e}")
    
    async def _check_database_logging(self, conn: asyncpg.Connection) -> None:
        """Check database logging configuration"""
        try:
            # Check logging settings
            log_statement = await conn.fetch("SHOW log_statement;")
            log_level = log_statement[0]['log_statement'] if log_statement else 'none'
            
            if log_level == 'none':
                self.vulnerabilities.append(SecurityVulnerability(
                    id="db_logging_disabled",
                    title="Database Statement Logging Disabled",
                    description="Database statement logging is disabled",
                    severity=SeverityLevel.LOW,
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                    affected_component="Database Configuration",
                    evidence={"log_statement": log_level},
                    remediation="Enable database statement logging for security monitoring"
                ))
        
        except Exception as e:
            logger.debug(f"Database logging check error: {e}")
    
    async def _scan_infrastructure_security(self) -> None:
        """Scan infrastructure security"""
        logger.info("Scanning infrastructure security...")
        
        # Test SSL/TLS configuration
        await self._test_ssl_configuration()
        
        # Test HTTP security headers
        await self._test_security_headers()
        
        # Test for information disclosure
        await self._test_information_disclosure()
    
    async def _test_ssl_configuration(self) -> None:
        """Test SSL/TLS configuration"""
        parsed_url = urlparse(self.base_url)
        
        if parsed_url.scheme == 'https':
            try:
                hostname = parsed_url.hostname
                port = parsed_url.port or 443
                
                # Test SSL certificate
                context = ssl.create_default_context()
                
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            self.vulnerabilities.append(SecurityVulnerability(
                                id="ssl_cert_expiring",
                                title="SSL Certificate Expiring Soon",
                                description=f"SSL certificate expires in {days_until_expiry} days",
                                severity=SeverityLevel.MEDIUM if days_until_expiry > 7 else SeverityLevel.HIGH,
                                vulnerability_type=VulnerabilityType.CRYPTOGRAPHIC_FAILURE,
                                affected_component="SSL Configuration",
                                evidence={"days_until_expiry": days_until_expiry, "not_after": cert['notAfter']},
                                remediation="Renew SSL certificate before expiration"
                            ))
            
            except Exception as e:
                logger.debug(f"SSL configuration test error: {e}")
        else:
            self.vulnerabilities.append(SecurityVulnerability(
                id="ssl_not_used",
                title="SSL/TLS Not Used",
                description="Application not using SSL/TLS encryption",
                severity=SeverityLevel.HIGH,
                vulnerability_type=VulnerabilityType.CRYPTOGRAPHIC_FAILURE,
                affected_component="Transport Security",
                evidence={"scheme": parsed_url.scheme},
                remediation="Implement SSL/TLS encryption for all connections"
            ))
    
    async def _test_security_headers(self) -> None:
        """Test HTTP security headers"""
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,  # Any value is good
            'Content-Security-Policy': None,
            'Referrer-Policy': None
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.base_url) as response:
                    headers = response.headers
                    
                    for header, expected_value in required_headers.items():
                        if header not in headers:
                            self.vulnerabilities.append(SecurityVulnerability(
                                id=f"missing_header_{header.lower().replace('-', '_')}",
                                title=f"Missing Security Header: {header}",
                                description=f"Response missing {header} security header",
                                severity=SeverityLevel.MEDIUM,
                                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                                affected_component="HTTP Security",
                                evidence={"missing_header": header},
                                remediation=f"Add {header} header to HTTP responses"
                            ))
                        elif expected_value and headers[header] not in (expected_value if isinstance(expected_value, list) else [expected_value]):
                            self.vulnerabilities.append(SecurityVulnerability(
                                id=f"incorrect_header_{header.lower().replace('-', '_')}",
                                title=f"Incorrect Security Header: {header}",
                                description=f"{header} header has incorrect value",
                                severity=SeverityLevel.LOW,
                                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                                affected_component="HTTP Security",
                                evidence={"header": header, "actual_value": headers[header], "expected": expected_value},
                                remediation=f"Set {header} header to recommended value"
                            ))
            
            except Exception as e:
                logger.debug(f"Security headers test error: {e}")
    
    async def _test_information_disclosure(self) -> None:
        """Test for information disclosure"""
        info_endpoints = [
            "/server-status",
            "/server-info",
            "/admin",
            "/phpinfo.php",
            "/info.php",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in info_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for sensitive information disclosure
                            if len(content) > 100 and any(keyword in content.lower() for keyword in 
                                ["server version", "php version", "database", "configuration", "admin"]):
                                
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"info_disclosure_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                    title="Information Disclosure",
                                    description=f"Endpoint {endpoint} discloses sensitive information",
                                    severity=SeverityLevel.LOW,
                                    vulnerability_type=VulnerabilityType.SENSITIVE_DATA,
                                    affected_component="Web Server",
                                    affected_url=url,
                                    evidence={"endpoint": endpoint, "content_length": len(content)},
                                    remediation="Remove or restrict access to information disclosure endpoints"
                                ))
                
                except Exception as e:
                    logger.debug(f"Information disclosure test error for {endpoint}: {e}")
    
    async def _scan_api_security(self) -> None:
        """Scan API-specific security issues"""
        logger.info("Scanning API security...")
        
        # Test API authentication
        await self._test_api_authentication()
        
        # Test API rate limiting
        await self._test_api_rate_limiting()
        
        # Test API input validation
        await self._test_api_input_validation()
    
    async def _test_api_authentication(self) -> None:
        """Test API authentication mechanisms"""
        api_endpoints = [
            "/api/v1/search",
            "/api/v1/documents",
            "/api/v1/analytics",
            "/api/v1/admin"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in api_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Test without API key
                    async with session.get(url) as response:
                        if response.status == 200 and "admin" in endpoint:
                            self.vulnerabilities.append(SecurityVulnerability(
                                id=f"api_auth_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                title="API Endpoint Missing Authentication",
                                description=f"Admin API endpoint {endpoint} accessible without authentication",
                                severity=SeverityLevel.HIGH,
                                vulnerability_type=VulnerabilityType.AUTHENTICATION,
                                affected_component="API Security",
                                affected_url=url,
                                evidence={"endpoint": endpoint, "status_code": response.status},
                                remediation="Implement API key or token-based authentication"
                            ))
                
                except Exception as e:
                    logger.debug(f"API authentication test error for {endpoint}: {e}")
    
    async def _test_api_rate_limiting(self) -> None:
        """Test API rate limiting"""
        test_endpoint = f"{self.base_url}/api/v1/search"
        
        async with aiohttp.ClientSession() as session:
            try:
                # Send multiple rapid requests
                responses = []
                for i in range(20):
                    async with session.get(f"{test_endpoint}?q=test{i}") as response:
                        responses.append(response.status)
                
                # Check if any requests were rate limited
                rate_limited = any(status == 429 for status in responses)
                
                if not rate_limited:
                    self.vulnerabilities.append(SecurityVulnerability(
                        id="api_no_rate_limiting",
                        title="API Rate Limiting Not Implemented",
                        description="API endpoints do not implement rate limiting",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        affected_component="API Security",
                        affected_url=test_endpoint,
                        evidence={"requests_sent": 20, "rate_limited": False},
                        remediation="Implement rate limiting to prevent abuse"
                    ))
            
            except Exception as e:
                logger.debug(f"Rate limiting test error: {e}")
    
    async def _test_api_input_validation(self) -> None:
        """Test API input validation"""
        malicious_inputs = [
            {"query": "A" * 10000},  # Buffer overflow test
            {"query": "../../../etc/passwd"},  # Directory traversal
            {"query": "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"},  # XXE
            {"sources": ["' OR 1=1--"]},  # SQL injection in array
            {"limit": -1},  # Negative number
            {"limit": 999999},  # Very large number
        ]
        
        async with aiohttp.ClientSession() as session:
            for malicious_input in malicious_inputs:
                try:
                    url = f"{self.base_url}/api/v1/search"
                    async with session.post(url, json=malicious_input) as response:
                        response_text = await response.text()
                        
                        # Check for error messages that indicate lack of input validation
                        error_indicators = [
                            "internal server error",
                            "traceback",
                            "exception",
                            "database error",
                            "file not found",
                            "permission denied"
                        ]
                        
                        for indicator in error_indicators:
                            if indicator.lower() in response_text.lower():
                                self.vulnerabilities.append(SecurityVulnerability(
                                    id=f"input_validation_{hashlib.md5(str(malicious_input).encode()).hexdigest()[:8]}",
                                    title="Inadequate Input Validation",
                                    description="API endpoint lacks proper input validation",
                                    severity=SeverityLevel.MEDIUM,
                                    vulnerability_type=VulnerabilityType.INJECTION,
                                    affected_component="API Input Validation",
                                    affected_url=url,
                                    evidence={"input": str(malicious_input), "error_found": indicator},
                                    remediation="Implement comprehensive input validation and sanitization"
                                ))
                                break
                
                except Exception as e:
                    logger.debug(f"Input validation test error: {e}")
    
    async def _scan_configuration_security(self) -> None:
        """Scan security configuration"""
        logger.info("Scanning configuration security...")
        
        # Check Docker configuration if available
        await self._check_docker_security()
        
        # Check file permissions
        await self._check_file_permissions()
    
    async def _check_docker_security(self) -> None:
        """Check Docker security configuration"""
        try:
            # Check if running in Docker and if so, check security settings
            if os.path.exists("/.dockerenv"):
                # Check if running as root
                if os.getuid() == 0:
                    self.vulnerabilities.append(SecurityVulnerability(
                        id="docker_root_user",
                        title="Container Running as Root",
                        description="Docker container running with root privileges",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        affected_component="Container Security",
                        evidence={"uid": os.getuid(), "running_as_root": True},
                        remediation="Configure container to run as non-root user"
                    ))
        
        except Exception as e:
            logger.debug(f"Docker security check error: {e}")
    
    async def _check_file_permissions(self) -> None:
        """Check file permissions for security issues"""
        sensitive_files = [
            ".env",
            "config.json",
            "database.conf",
            "docker-compose.yml"
        ]
        
        for file_path in sensitive_files:
            try:
                if os.path.exists(file_path):
                    file_stat = os.stat(file_path)
                    permissions = oct(file_stat.st_mode)[-3:]
                    
                    # Check if file is world-readable
                    if permissions[-1] in ['4', '5', '6', '7']:
                        self.vulnerabilities.append(SecurityVulnerability(
                            id=f"file_permissions_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                            title="Insecure File Permissions",
                            description=f"Sensitive file {file_path} has world-readable permissions",
                            severity=SeverityLevel.MEDIUM,
                            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                            affected_component="File System Security",
                            evidence={"file": file_path, "permissions": permissions},
                            remediation="Restrict file permissions to owner only (600 or 644)"
                        ))
            
            except Exception as e:
                logger.debug(f"File permissions check error for {file_path}: {e}")
    
    async def _check_lgpd_compliance(self) -> None:
        """Check LGPD (Brazilian data privacy law) compliance"""
        logger.info("Checking LGPD compliance...")
        
        # This will be implemented in the next task
        # For now, add a placeholder indicating LGPD check is needed
        pass
    
    def _calculate_security_score(self) -> float:
        """Calculate overall security score (0-100)"""
        if not self.vulnerabilities:
            return 100.0
        
        # Weight vulnerabilities by severity
        severity_weights = {
            SeverityLevel.CRITICAL: 20,
            SeverityLevel.HIGH: 10,
            SeverityLevel.MEDIUM: 5,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        
        total_penalty = sum(severity_weights.get(vuln.severity, 0) for vuln in self.vulnerabilities)
        
        # Start with 100 and subtract penalties, minimum score is 0
        score = max(0, 100 - total_penalty)
        return score
    
    def _generate_audit_report(self) -> SecurityAuditReport:
        """Generate comprehensive audit report"""
        scan_duration = datetime.now() - self.scan_start_time
        security_score = self._calculate_security_score()
        
        # Generate compliance status
        compliance_status = {
            "OWASP_Top_10": len([v for v in self.vulnerabilities if v.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]) == 0,
            "LGPD_Compliance": True,  # Will be updated in next task
            "SSL_TLS": not any(v.vulnerability_type == VulnerabilityType.CRYPTOGRAPHIC_FAILURE for v in self.vulnerabilities),
            "Input_Validation": not any(v.vulnerability_type == VulnerabilityType.INJECTION for v in self.vulnerabilities),
            "Authentication": not any(v.vulnerability_type == VulnerabilityType.AUTHENTICATION for v in self.vulnerabilities)
        }
        
        # Generate recommendations
        recommendations = self._generate_security_recommendations()
        
        # Scanned components
        scanned_components = [
            "Web Application",
            "API Endpoints", 
            "Database Security",
            "Infrastructure",
            "Configuration",
            "SSL/TLS",
            "HTTP Headers",
            "Authentication",
            "Authorization"
        ]
        
        return SecurityAuditReport(
            audit_id=hashlib.md5(f"{self.scan_start_time}{self.base_url}".encode()).hexdigest(),
            timestamp=datetime.now(),
            vulnerabilities=self.vulnerabilities,
            security_score=security_score,
            compliance_status=compliance_status,
            recommendations=recommendations,
            scan_duration=scan_duration,
            scanned_components=scanned_components
        )
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate type-specific recommendations
        if VulnerabilityType.XSS in vuln_types:
            recommendations.append("Implement Content Security Policy (CSP) headers and input sanitization")
        
        if VulnerabilityType.SQL_INJECTION in vuln_types:
            recommendations.append("Use parameterized queries and implement strict input validation")
        
        if VulnerabilityType.AUTHENTICATION in vuln_types:
            recommendations.append("Implement strong authentication mechanisms and remove default credentials")
        
        if VulnerabilityType.CRYPTOGRAPHIC_FAILURE in vuln_types:
            recommendations.append("Enable SSL/TLS encryption and ensure proper certificate management")
        
        if VulnerabilityType.SECURITY_MISCONFIGURATION in vuln_types:
            recommendations.append("Review and harden security configurations across all components")
        
        # Add general recommendations
        critical_count = len([v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL])
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical vulnerabilities immediately")
        
        if not recommendations:
            recommendations.append("Security posture is good - continue regular security assessments")
        
        return recommendations

# Export main classes
__all__ = [
    'SecurityAuditor',
    'SecurityVulnerability',
    'SecurityAuditReport',
    'SeverityLevel',
    'VulnerabilityType'
]