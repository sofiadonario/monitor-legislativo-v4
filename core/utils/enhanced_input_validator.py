"""
Enhanced Input Validation with Professional Security Libraries
Replaces regex-based validation with battle-tested security tools

SECURITY CRITICAL: This module is the first line of defense against injection attacks.
Any vulnerability here compromises the entire system.
"""

import re
import logging
import unicodedata
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, quote

import bleach
import validators
from bleach.css_sanitizer import CSSSanitizer

logger = logging.getLogger(__name__)


class EnhancedInputValidator:
    """
    Professional input validation using security-focused libraries.
    
    Features:
    - HTML sanitization with bleach
    - URL validation with validators
    - Context-aware validation
    - Scientific research data validation
    - Comprehensive logging for security audit
    """
    
    # Allowed HTML tags for rich text (legislative descriptions)
    ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
        'blockquote', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'table', 'thead', 'tbody', 'tr', 'th', 'td',
        'a', 'abbr', 'cite', 'dfn', 'mark', 'small', 'span', 'sub', 'sup'
    ]
    
    # Allowed HTML attributes
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title', 'rel'],
        'abbr': ['title'],
        'dfn': ['title'],
        'blockquote': ['cite'],
        'cite': ['title'],
        'code': ['class'],  # For syntax highlighting
        'span': ['class'],  # For styling
        'th': ['scope', 'colspan', 'rowspan'],
        'td': ['colspan', 'rowspan']
    }
    
    # Allowed CSS properties (conservative list)
    ALLOWED_CSS_PROPERTIES = [
        'color', 'background-color', 'font-size', 'font-weight',
        'text-align', 'text-decoration', 'margin', 'padding',
        'border', 'width', 'height', 'display'
    ]
    
    # Legislative search patterns (Brazilian context)
    LEGISLATIVE_PATTERNS = {
        'lei': re.compile(r'^Lei\s+(Complementar\s+)?n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
        'pec': re.compile(r'^PEC\s+n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
        'mp': re.compile(r'^(MP|Medida\s+Provisória)\s+n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
        'decreto': re.compile(r'^Decreto(-Lei)?\s+n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
        'portaria': re.compile(r'^Portaria\s+n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
        'resolucao': re.compile(r'^Resolução\s+n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
        'instrucao': re.compile(r'^Instrução\s+Normativa\s+n?º?\s*\d+(/\d{4})?$', re.IGNORECASE),
    }
    
    def __init__(self):
        """Initialize the enhanced validator with security configurations."""
        # CSS sanitizer for style attributes
        self.css_sanitizer = CSSSanitizer(allowed_css_properties=self.ALLOWED_CSS_PROPERTIES)
        
        # Bleach cleaner for HTML sanitization
        self.cleaner = bleach.Cleaner(
            tags=self.ALLOWED_TAGS,
            attributes=self.ALLOWED_ATTRIBUTES,
            css_sanitizer=self.css_sanitizer,
            strip=True,  # Strip disallowed tags
            strip_comments=True
        )
        
        logger.info("Enhanced input validator initialized with professional security libraries")
    
    def sanitize_html(self, html_content: str, context: str = 'general') -> str:
        """
        Sanitize HTML content based on context.
        
        Args:
            html_content: Raw HTML content
            context: Context for validation ('general', 'legislative', 'comment')
            
        Returns:
            Sanitized HTML safe for storage and display
        """
        if not html_content:
            return ""
        
        # Pre-process based on context
        if context == 'legislative':
            # Legislative content may have special formatting
            html_content = self._preprocess_legislative_html(html_content)
        elif context == 'comment':
            # Comments have more restricted tags
            return self._sanitize_comment(html_content)
        
        # Use bleach to clean HTML
        cleaned = self.cleaner.clean(html_content)
        
        # Post-process
        cleaned = self._postprocess_html(cleaned)
        
        # Log suspicious content
        if self._contains_suspicious_patterns(html_content) and not self._contains_suspicious_patterns(cleaned):
            logger.warning(f"Suspicious content sanitized in {context} context", extra={
                'original_length': len(html_content),
                'cleaned_length': len(cleaned),
                'context': context
            })
        
        return cleaned
    
    def _preprocess_legislative_html(self, content: str) -> str:
        """Pre-process legislative HTML to preserve legal formatting."""
        # Preserve article/paragraph numbering
        content = re.sub(r'Art\.\s*(\d+)', r'<strong>Art. \1</strong>', content)
        content = re.sub(r'§\s*(\d+)', r'<strong>§ \1</strong>', content)
        
        return content
    
    def _sanitize_comment(self, comment: str) -> str:
        """Sanitize user comments with restricted tag set."""
        # Comments only allow basic formatting
        comment_cleaner = bleach.Cleaner(
            tags=['p', 'br', 'strong', 'em', 'a'],
            attributes={'a': ['href', 'rel']},
            strip=True,
            strip_comments=True
        )
        
        # Clean and linkify
        cleaned = comment_cleaner.clean(comment)
        cleaned = bleach.linkify(cleaned, callbacks=[self._link_callback])
        
        return cleaned
    
    def _link_callback(self, attrs, new=False):
        """Callback for linkify to add security attributes."""
        attrs[(None, 'rel')] = 'nofollow noopener noreferrer'
        if new:
            attrs[(None, 'target')] = '_blank'
        
        # Validate URL
        href = attrs.get((None, 'href'), '')
        if not self.validate_url(href, require_https=False):
            # Invalid URL, remove href
            attrs.pop((None, 'href'), None)
        
        return attrs
    
    def _postprocess_html(self, content: str) -> str:
        """Post-process cleaned HTML."""
        # Remove empty tags
        content = re.sub(r'<(\w+)(\s+[^>]*)?>(\s|&nbsp;)*</\1>', '', content)
        
        # Normalize whitespace
        content = re.sub(r'\s+', ' ', content)
        content = content.strip()
        
        return content
    
    def _contains_suspicious_patterns(self, content: str) -> bool:
        """Check if content contains suspicious patterns."""
        suspicious_patterns = [
            r'<script', r'javascript:', r'data:text/html',
            r'vbscript:', r'onclick', r'onerror', r'onload',
            r'base64', r'expression\s*\(', r'import\s*\('
        ]
        
        content_lower = content.lower()
        return any(re.search(pattern, content_lower) for pattern in suspicious_patterns)
    
    def sanitize_text(self, text: str, max_length: int = 1000, 
                     allow_newlines: bool = True) -> str:
        """
        Sanitize plain text input.
        
        Args:
            text: Input text
            max_length: Maximum allowed length
            allow_newlines: Whether to allow newline characters
            
        Returns:
            Sanitized text
        """
        if not text:
            return ""
        
        # Convert to string and limit length
        text = str(text)[:max_length]
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Normalize unicode
        text = unicodedata.normalize('NFKC', text)
        
        # Escape HTML entities
        text = bleach.clean(text, tags=[], strip=True)
        
        # Handle newlines
        if not allow_newlines:
            text = ' '.join(text.splitlines())
        
        # Remove control characters except allowed ones
        allowed_chars = '\n\r\t' if allow_newlines else '\t'
        text = ''.join(char for char in text if ord(char) >= 32 or char in allowed_chars)
        
        return text.strip()
    
    def validate_legislative_query(self, query: str) -> tuple[bool, str]:
        """
        Validate and normalize legislative search query.
        
        Args:
            query: Search query
            
        Returns:
            Tuple of (is_valid, normalized_query)
        """
        if not query or not query.strip():
            return False, "Query cannot be empty"
        
        # Basic sanitization
        query = self.sanitize_text(query, max_length=500, allow_newlines=False)
        
        # Check length
        if len(query) < 2:
            return False, "Query too short (minimum 2 characters)"
        
        if len(query) > 500:
            return False, "Query too long (maximum 500 characters)"
        
        # Check for SQL injection patterns (defense in depth)
        sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create)\b)",
            r"(--|#|;|\||&&|/\*|\*/)",
            r"(xp_|sp_|exec\s*\()",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                logger.warning(f"SQL injection attempt detected in query", extra={
                    'pattern': pattern,
                    'query_length': len(query)
                })
                return False, "Query contains invalid characters"
        
        # Normalize legislative references
        normalized = self._normalize_legislative_reference(query)
        
        return True, normalized
    
    def _normalize_legislative_reference(self, query: str) -> str:
        """Normalize legislative references to standard format."""
        # Remove extra spaces
        query = ' '.join(query.split())
        
        # Standardize number formats
        query = re.sub(r'n[º°]\s*', 'nº ', query)
        query = re.sub(r'nº\s+', 'nº ', query)
        
        # Capitalize legislative types
        legislative_types = [
            'lei', 'decreto', 'medida provisória', 'mp', 'pec',
            'portaria', 'resolução', 'instrução normativa'
        ]
        
        for leg_type in legislative_types:
            pattern = re.compile(r'\b' + leg_type + r'\b', re.IGNORECASE)
            
            # Proper capitalization
            if leg_type == 'mp':
                replacement = 'MP'
            elif leg_type == 'pec':
                replacement = 'PEC'
            else:
                replacement = leg_type.title()
            
            query = pattern.sub(replacement, query)
        
        return query
    
    def validate_url(self, url: str, require_https: bool = True, 
                    allowed_domains: List[str] = None) -> bool:
        """
        Validate URL with security checks.
        
        Args:
            url: URL to validate
            require_https: Whether to require HTTPS
            allowed_domains: List of allowed domains (None = any valid domain)
            
        Returns:
            True if URL is valid and safe
        """
        if not url:
            return False
        
        # Use validators library for basic validation
        if not validators.url(url):
            return False
        
        # Parse URL for additional checks
        try:
            parsed = urlparse(url)
            
            # Check protocol
            if require_https and parsed.scheme != 'https':
                return False
            
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check domain whitelist
            if allowed_domains:
                domain = parsed.netloc.lower()
                if not any(domain.endswith(allowed) for allowed in allowed_domains):
                    logger.warning(f"URL domain not in whitelist", extra={
                        'domain': domain,
                        'allowed_domains': allowed_domains
                    })
                    return False
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'javascript:', 'data:', 'vbscript:', 'file:',
                '%00', '%0d%0a', '../', '..\\',
                '<script', '\x00'
            ]
            
            url_lower = url.lower()
            if any(pattern in url_lower for pattern in suspicious_patterns):
                logger.warning("Suspicious URL pattern detected", extra={
                    'url_length': len(url)
                })
                return False
            
            return True
            
        except Exception as e:
            logger.debug(f"URL parsing error: {e}")
            return False
    
    def validate_email(self, email: str) -> bool:
        """
        Validate email address.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email is valid
        """
        if not email:
            return False
        
        # Normalize
        email = email.strip().lower()
        
        # Use validators library
        return validators.email(email) is True
    
    def validate_filename(self, filename: str, allowed_extensions: List[str] = None) -> tuple[bool, str]:
        """
        Validate and sanitize filename.
        
        Args:
            filename: Original filename
            allowed_extensions: List of allowed extensions (with dots)
            
        Returns:
            Tuple of (is_valid, sanitized_filename)
        """
        if not filename:
            return False, "Filename cannot be empty"
        
        # Remove path components
        filename = Path(filename).name
        
        # Remove null bytes and control characters
        filename = ''.join(char for char in filename if ord(char) >= 32)
        
        # Replace problematic characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Remove multiple dots (except for extension)
        parts = filename.split('.')
        if len(parts) > 2:
            name = '_'.join(parts[:-1])
            ext = parts[-1]
            filename = f"{name}.{ext}"
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            max_name_length = 250 - len(ext) - 1 if ext else 255
            filename = name[:max_name_length]
            if ext:
                filename = f"{filename}.{ext}"
        
        # Check extension
        if allowed_extensions:
            ext = Path(filename).suffix.lower()
            if ext not in allowed_extensions:
                logger.warning(f"Invalid file extension", extra={
                    'extension': ext,
                    'allowed': allowed_extensions
                })
                return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
        
        # Final validation
        if not filename or filename in ['.', '..']:
            return False, "Invalid filename"
        
        return True, filename
    
    def validate_government_source(self, source: str, valid_sources: Dict[str, str]) -> bool:
        """
        Validate government data source for scientific research.
        
        Args:
            source: Source identifier
            valid_sources: Dictionary of valid source IDs and names
            
        Returns:
            True if source is valid government source
        """
        if not source:
            return False
        
        # Normalize
        source = source.strip().lower()
        
        # Check against whitelist
        if source not in valid_sources:
            logger.warning(f"Invalid government source requested", extra={
                'requested_source': source,
                'valid_sources': list(valid_sources.keys())
            })
            return False
        
        # Additional validation for known government sources
        government_domains = [
            '.gov.br', '.leg.br', '.jus.br', '.mp.br',
            'camara.leg.br', 'senado.leg.br', 'planalto.gov.br',
            'in.gov.br', 'tse.jus.br', 'stf.jus.br', 'stj.jus.br'
        ]
        
        # Log for audit trail (scientific research compliance)
        logger.info(f"Government source validated for research", extra={
            'source': source,
            'source_name': valid_sources.get(source, 'Unknown')
        })
        
        return True
    
    def create_csp_header(self, nonce: str = None) -> str:
        """
        Create Content Security Policy header.
        
        Args:
            nonce: Nonce for inline scripts (if needed)
            
        Returns:
            CSP header value
        """
        directives = [
            "default-src 'self'",
            "script-src 'self' 'strict-dynamic'",
            "style-src 'self' 'unsafe-inline'",  # For legislative formatting
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self' https://*.gov.br https://*.leg.br",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ]
        
        if nonce:
            directives[1] = f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic'"
        
        return "; ".join(directives)
    
    def validate_date_range(self, start_date: str, end_date: str) -> tuple[bool, str]:
        """
        Validate date range for legislative queries.
        
        Args:
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Parse dates
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d')
            
            # Validate range
            if start > end:
                return False, "Start date must be before end date"
            
            # Validate reasonable range (not too far in past or future)
            min_date = datetime(1988, 10, 5)  # Brazilian Constitution date
            max_date = datetime.now() + timedelta(days=365)  # 1 year in future
            
            if start < min_date:
                return False, f"Start date cannot be before {min_date.strftime('%Y-%m-%d')}"
            
            if end > max_date:
                return False, f"End date cannot be after {max_date.strftime('%Y-%m-%d')}"
            
            # Validate range size (prevent DoS)
            if (end - start).days > 3650:  # 10 years
                return False, "Date range cannot exceed 10 years"
            
            return True, ""
            
        except ValueError as e:
            return False, f"Invalid date format: {str(e)}"


# Global validator instance
_validator: Optional[EnhancedInputValidator] = None


def get_validator() -> EnhancedInputValidator:
    """Get or create validator instance."""
    global _validator
    
    if _validator is None:
        _validator = EnhancedInputValidator()
    
    return _validator


# Convenience functions for backward compatibility
def sanitize_html(content: str, context: str = 'general') -> str:
    """Sanitize HTML content."""
    return get_validator().sanitize_html(content, context)


def sanitize_text(text: str, max_length: int = 1000) -> str:
    """Sanitize plain text."""
    return get_validator().sanitize_text(text, max_length)


def validate_legislative_query(query: str) -> tuple[bool, str]:
    """Validate legislative search query."""
    return get_validator().validate_legislative_query(query)


def validate_url(url: str, **kwargs) -> bool:
    """Validate URL."""
    return get_validator().validate_url(url, **kwargs)


def validate_email(email: str) -> bool:
    """Validate email."""
    return get_validator().validate_email(email)


def create_csp_header(nonce: str = None) -> str:
    """Create CSP header."""
    return get_validator().create_csp_header(nonce)