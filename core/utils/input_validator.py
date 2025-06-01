"""
Input validation and sanitization utilities
"""

import re
import html
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import unicodedata

logger = logging.getLogger(__name__)

# Regex patterns for validation
PATTERNS = {
    'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    'date': re.compile(r'^\d{4}-\d{2}-\d{2}$'),
    'username': re.compile(r'^[a-zA-Z0-9_-]{3,30}$'),
    'alphanumeric': re.compile(r'^[a-zA-Z0-9\s]+$'),
    'numeric': re.compile(r'^\d+$'),
    'url': re.compile(r'^https?://[^\s]+$'),
    'document_id': re.compile(r'^[a-zA-Z0-9_-]+$')
}

# SQL injection patterns to block
SQL_INJECTION_PATTERNS = [
    r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
    r"(--|\||;|\/\*|\*\/|@@|@)",
    r"(xp_|sp_|exec\s*\()",
    r"(cast\s*\(|convert\s*\()",
    r"(script\s*:)",
    r"(javascript\s*:)",
    r"(onload\s*=|onerror\s*=|onclick\s*=)"
]

# XSS patterns to block
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"<img[^>]*onerror[^>]*>",
    r"<svg[^>]*onload[^>]*>"
]

def sanitize_input(value: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks
    
    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not value:
        return ""
    
    # Convert to string if not already
    value = str(value)
    
    # Trim whitespace
    value = value.strip()
    
    # Limit length
    if len(value) > max_length:
        value = value[:max_length]
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Normalize unicode
    value = unicodedata.normalize('NFKC', value)
    
    # HTML escape special characters
    value = html.escape(value)
    
    # Remove dangerous patterns
    for pattern in SQL_INJECTION_PATTERNS + XSS_PATTERNS:
        value = re.sub(pattern, '', value, flags=re.IGNORECASE)
    
    # Remove control characters except newlines and tabs
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
    
    return value

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email:
        return False
    return bool(PATTERNS['email'].match(email.lower()))

def validate_date_format(date_str: str) -> bool:
    """Validate date format (YYYY-MM-DD)"""
    if not date_str:
        return False
    
    if not PATTERNS['date'].match(date_str):
        return False
    
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def validate_username(username: str) -> bool:
    """Validate username format"""
    if not username:
        return False
    return bool(PATTERNS['username'].match(username))

def validate_document_id(doc_id: str) -> bool:
    """Validate document ID format"""
    if not doc_id:
        return False
    return bool(PATTERNS['document_id'].match(doc_id))

def validate_pagination(page: int, page_size: int) -> tuple:
    """
    Validate and sanitize pagination parameters
    
    Returns:
        Tuple of (page, page_size) with safe values
    """
    # Ensure minimum values
    page = max(1, int(page))
    page_size = max(1, int(page_size))
    
    # Apply maximum limits
    page = min(page, 1000)  # Max 1000 pages
    page_size = min(page_size, 100)  # Max 100 items per page
    
    return page, page_size

def validate_search_query(query: str, min_length: int = 3, max_length: int = 500) -> str:
    """
    Validate and sanitize search query
    
    Args:
        query: Search query string
        min_length: Minimum query length
        max_length: Maximum query length
        
    Returns:
        Sanitized query string
        
    Raises:
        ValueError: If query is invalid
    """
    if not query or not query.strip():
        raise ValueError("Search query cannot be empty")
    
    query = sanitize_input(query, max_length)
    
    if len(query) < min_length:
        raise ValueError(f"Search query must be at least {min_length} characters")
    
    # Remove excessive whitespace
    query = ' '.join(query.split())
    
    return query

def validate_filters(filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and sanitize filter parameters
    
    Args:
        filters: Dictionary of filter parameters
        
    Returns:
        Sanitized filters dictionary
    """
    valid_filters = {}
    
    # Define allowed filter keys and their validators
    allowed_filters = {
        'start_date': validate_date_format,
        'end_date': validate_date_format,
        'source': lambda x: x in ['camara', 'senado', 'planalto'],
        'type': lambda x: x in ['projeto_lei', 'decreto', 'portaria', 'resolucao'],
        'status': lambda x: x in ['tramitando', 'aprovado', 'rejeitado', 'arquivado']
    }
    
    for key, value in filters.items():
        if key in allowed_filters:
            validator = allowed_filters[key]
            
            if isinstance(value, str):
                value = sanitize_input(value, 100)
            
            if validator(value):
                valid_filters[key] = value
            else:
                logger.warning(f"Invalid filter value for {key}: {value}")
    
    return valid_filters

def validate_export_format(format: str) -> str:
    """
    Validate export format
    
    Args:
        format: Export format string
        
    Returns:
        Validated format (lowercase)
        
    Raises:
        ValueError: If format is not supported
    """
    allowed_formats = ['csv', 'json', 'excel', 'pdf']
    format = format.lower().strip()
    
    if format not in allowed_formats:
        raise ValueError(f"Invalid export format. Allowed formats: {', '.join(allowed_formats)}")
    
    return format

def validate_request_data(data: Dict[str, Any], required_fields: List[str]) -> Dict[str, Any]:
    """
    Validate request data has required fields
    
    Args:
        data: Request data dictionary
        required_fields: List of required field names
        
    Returns:
        Validated data
        
    Raises:
        ValueError: If required fields are missing
    """
    if not data:
        raise ValueError("Request data is required")
    
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
    
    # Sanitize string fields
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_input(value)
        else:
            sanitized[key] = value
    
    return sanitized

def is_safe_url(url: str, allowed_hosts: List[str] = None) -> bool:
    """
    Check if URL is safe for redirection
    
    Args:
        url: URL to check
        allowed_hosts: List of allowed host names
        
    Returns:
        True if URL is safe
    """
    if not url:
        return False
    
    # Check for dangerous protocols
    dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
    for protocol in dangerous_protocols:
        if url.lower().startswith(protocol):
            return False
    
    # If allowed hosts specified, check against them
    if allowed_hosts:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc not in allowed_hosts:
            return False
    
    return True

def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename for safe storage
    
    Args:
        filename: Original filename
        max_length: Maximum allowed length
        
    Returns:
        Sanitized filename
    """
    if not filename:
        return "unnamed"
    
    # Remove path components
    filename = filename.replace('/', '').replace('\\', '')
    
    # Replace dangerous characters
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Remove multiple dots (prevent directory traversal)
    filename = re.sub(r'\.+', '.', filename)
    
    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = max_length - len(ext) - 1 if ext else max_length
        filename = name[:max_name_length] + ('.' + ext if ext else '')
    
    return filename