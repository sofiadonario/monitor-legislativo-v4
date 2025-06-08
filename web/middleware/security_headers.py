"""
Security Headers Middleware for FastAPI
Implements comprehensive security headers including CSP

SECURITY CRITICAL: These headers are essential defense against XSS, clickjacking, etc.
"""

import secrets
import time
from typing import Dict, Optional, Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from core.utils.enhanced_input_validator import create_csp_header
from core.monitoring.structured_logging import get_logger

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    
    Features:
    - Content Security Policy with nonce support
    - HSTS (HTTP Strict Transport Security)
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Referrer Policy
    - Permissions Policy
    - Cache control for sensitive endpoints
    """
    
    def __init__(self, app: ASGIApp, config: Dict[str, any] = None):
        """
        Initialize security headers middleware.
        
        Args:
            app: FastAPI application
            config: Optional configuration overrides
        """
        super().__init__(app)
        
        self.config = config or {}
        
        # HSTS configuration
        self.hsts_max_age = self.config.get('hsts_max_age', 31536000)  # 1 year
        self.hsts_include_subdomains = self.config.get('hsts_include_subdomains', True)
        self.hsts_preload = self.config.get('hsts_preload', True)
        
        # CSP configuration
        self.csp_enabled = self.config.get('csp_enabled', True)
        self.csp_report_uri = self.config.get('csp_report_uri', '/api/csp-report')
        
        # Frame options
        self.frame_options = self.config.get('frame_options', 'DENY')
        
        # Referrer policy
        self.referrer_policy = self.config.get('referrer_policy', 'strict-origin-when-cross-origin')
        
        # Permissions policy (formerly Feature Policy)
        self.permissions_policy = self.config.get('permissions_policy', {
            'geolocation': 'none',
            'microphone': 'none',
            'camera': 'none',
            'payment': 'none',
            'usb': 'none',
            'magnetometer': 'none',
            'gyroscope': 'none',
            'accelerometer': 'none'
        })
        
        logger.info("Security headers middleware initialized", extra={
            'csp_enabled': self.csp_enabled,
            'hsts_max_age': self.hsts_max_age
        })
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and add security headers to response.
        
        Args:
            request: Incoming request
            call_next: Next middleware in chain
            
        Returns:
            Response with security headers
        """
        # Generate CSP nonce for this request
        csp_nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = csp_nonce
        
        # Track request timing
        start_time = time.time()
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response, request, csp_nonce)
            
            # Log request completion
            process_time = time.time() - start_time
            logger.debug(f"Request processed", extra={
                'path': request.url.path,
                'method': request.method,
                'status_code': response.status_code,
                'process_time': f"{process_time:.3f}s"
            })
            
            return response
            
        except Exception as e:
            # Log error and return secure error response
            logger.error(f"Security headers middleware error: {e}", extra={
                'path': request.url.path,
                'method': request.method
            })
            
            # Return generic error to avoid information leakage
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
                headers=self._get_basic_security_headers()
            )
    
    def _add_security_headers(self, response: Response, request: Request, nonce: str):
        """Add security headers to response."""
        # HSTS (only on HTTPS)
        if request.url.scheme == 'https':
            hsts_header = f"max-age={self.hsts_max_age}"
            if self.hsts_include_subdomains:
                hsts_header += "; includeSubDomains"
            if self.hsts_preload:
                hsts_header += "; preload"
            response.headers["Strict-Transport-Security"] = hsts_header
        
        # Content Security Policy
        if self.csp_enabled:
            csp_header = create_csp_header(nonce)
            if self.csp_report_uri:
                csp_header += f"; report-uri {self.csp_report_uri}"
            response.headers["Content-Security-Policy"] = csp_header
            
            # Also set Report-Only header for monitoring
            response.headers["Content-Security-Policy-Report-Only"] = csp_header
        
        # Frame options
        response.headers["X-Frame-Options"] = self.frame_options
        
        # Content type options
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # XSS Protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = self.referrer_policy
        
        # Permissions Policy
        if self.permissions_policy:
            policy_parts = [f'{feature}=()' for feature, value in self.permissions_policy.items() if value == 'none']
            if policy_parts:
                response.headers["Permissions-Policy"] = ', '.join(policy_parts)
        
        # Remove server header if present
        response.headers.pop("Server", None)
        
        # Cache control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        # Add security headers for API responses
        if request.url.path.startswith('/api/'):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-API-Version"] = "1.0"
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint handles sensitive data."""
        sensitive_patterns = [
            '/api/auth/',
            '/api/user/',
            '/api/admin/',
            '/api/search',  # Legislative search data
            '/api/export'
        ]
        
        return any(path.startswith(pattern) for pattern in sensitive_patterns)
    
    def _get_basic_security_headers(self) -> Dict[str, str]:
        """Get basic security headers for error responses."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store, no-cache, must-revalidate, private"
        }


class CSPReportMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle Content Security Policy violation reports.
    
    This helps monitor and fix CSP violations in production.
    """
    
    def __init__(self, app: ASGIApp):
        """Initialize CSP report handler."""
        super().__init__(app)
        self.violation_count = 0
        self.last_violations = []
        self.max_stored_violations = 100
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle CSP report endpoint."""
        if request.url.path == '/api/csp-report' and request.method == 'POST':
            return await self._handle_csp_report(request)
        
        return await call_next(request)
    
    async def _handle_csp_report(self, request: Request) -> Response:
        """Process CSP violation report."""
        try:
            # Parse report
            report = await request.json()
            csp_report = report.get('csp-report', {})
            
            # Extract key information
            violation = {
                'document_uri': csp_report.get('document-uri', ''),
                'violated_directive': csp_report.get('violated-directive', ''),
                'blocked_uri': csp_report.get('blocked-uri', ''),
                'source_file': csp_report.get('source-file', ''),
                'line_number': csp_report.get('line-number', 0),
                'column_number': csp_report.get('column-number', 0),
                'timestamp': time.time()
            }
            
            # Store violation
            self.violation_count += 1
            self.last_violations.append(violation)
            
            # Limit stored violations
            if len(self.last_violations) > self.max_stored_violations:
                self.last_violations = self.last_violations[-self.max_stored_violations:]
            
            # Log violation
            logger.warning("CSP violation reported", extra=violation)
            
            # Alert on suspicious patterns
            if self._is_suspicious_violation(violation):
                logger.error("Suspicious CSP violation detected", extra=violation)
            
            return JSONResponse(status_code=204, content=None)
            
        except Exception as e:
            logger.error(f"Failed to process CSP report: {e}")
            return JSONResponse(status_code=400, content={"error": "Invalid report"})
    
    def _is_suspicious_violation(self, violation: Dict[str, any]) -> bool:
        """Check if CSP violation indicates potential attack."""
        suspicious_patterns = [
            'javascript:',
            'data:text/html',
            'vbscript:',
            'unsafe-eval',
            'unsafe-inline'
        ]
        
        blocked_uri = violation.get('blocked_uri', '').lower()
        return any(pattern in blocked_uri for pattern in suspicious_patterns)
    
    def get_violation_stats(self) -> Dict[str, any]:
        """Get CSP violation statistics."""
        if not self.last_violations:
            return {
                'total_violations': self.violation_count,
                'recent_violations': [],
                'top_violated_directives': {}
            }
        
        # Count by directive
        directive_counts = {}
        for violation in self.last_violations:
            directive = violation.get('violated_directive', 'unknown')
            directive_counts[directive] = directive_counts.get(directive, 0) + 1
        
        return {
            'total_violations': self.violation_count,
            'recent_violations': self.last_violations[-10:],
            'top_violated_directives': dict(sorted(
                directive_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])
        }


def setup_security_headers(app, config: Dict[str, any] = None):
    """
    Setup security headers middleware for FastAPI app.
    
    Args:
        app: FastAPI application instance
        config: Optional configuration
    """
    # Add security headers middleware
    app.add_middleware(SecurityHeadersMiddleware, config=config)
    
    # Add CSP report handler
    app.add_middleware(CSPReportMiddleware)
    
    logger.info("Security headers middleware configured")