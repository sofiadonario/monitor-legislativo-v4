"""
Unit tests for input validation and sanitization
Critical security tests
"""

import pytest
from core.utils.input_validator import (
    sanitize_input,
    validate_email,
    validate_date_format,
    validate_search_query,
    validate_filters,
    validate_export_format,
    is_safe_url,
    sanitize_filename
)


class TestInputSanitization:
    """Test input sanitization functions"""
    
    def test_sanitize_basic_input(self):
        """Test basic input sanitization"""
        clean_input = "Hello World"
        result = sanitize_input(clean_input)
        assert result == "Hello World"
    
    def test_sanitize_html_entities(self):
        """Test HTML entity sanitization"""
        html_input = "<script>alert('xss')</script>"
        result = sanitize_input(html_input)
        assert "<script>" not in result
        assert "&lt;" in result or "script" not in result
    
    def test_sanitize_sql_injection(self):
        """Test SQL injection sanitization"""
        sql_input = "'; DROP TABLE users; --"
        result = sanitize_input(sql_input)
        assert "DROP TABLE" not in result.upper()
    
    def test_sanitize_length_limit(self):
        """Test length limitation"""
        long_input = "a" * 2000
        result = sanitize_input(long_input, max_length=100)
        assert len(result) <= 100
    
    def test_sanitize_null_bytes(self):
        """Test null byte removal"""
        input_with_null = "Hello\x00World"
        result = sanitize_input(input_with_null)
        assert "\x00" not in result
    
    def test_sanitize_control_characters(self):
        """Test control character removal"""
        input_with_control = "Hello\x01\x02World\x03"
        result = sanitize_input(input_with_control)
        assert "\x01" not in result
        assert "\x02" not in result
        assert "\x03" not in result
    
    def test_sanitize_unicode_normalization(self):
        """Test unicode normalization"""
        unicode_input = "café"
        result = sanitize_input(unicode_input)
        assert result == "café"
    
    def test_sanitize_empty_input(self):
        """Test empty input handling"""
        result = sanitize_input("")
        assert result == ""
        
        result = sanitize_input(None)
        assert result == ""


class TestEmailValidation:
    """Test email validation"""
    
    def test_valid_emails(self):
        """Test valid email formats"""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
            "123@456.com"
        ]
        
        for email in valid_emails:
            assert validate_email(email) is True
    
    def test_invalid_emails(self):
        """Test invalid email formats"""
        invalid_emails = [
            "invalid",
            "@example.com",
            "test@",
            "test..test@example.com",
            "test@example",
            ""
        ]
        
        for email in invalid_emails:
            assert validate_email(email) is False


class TestDateValidation:
    """Test date format validation"""
    
    def test_valid_dates(self):
        """Test valid date formats"""
        valid_dates = [
            "2024-01-01",
            "2024-12-31",
            "2000-02-29"  # Leap year
        ]
        
        for date in valid_dates:
            assert validate_date_format(date) is True
    
    def test_invalid_dates(self):
        """Test invalid date formats"""
        invalid_dates = [
            "2024-13-01",  # Invalid month
            "2024-01-32",  # Invalid day
            "2024/01/01",  # Wrong format
            "01-01-2024",  # Wrong format
            "2024-1-1",    # Wrong format
            "invalid",
            ""
        ]
        
        for date in invalid_dates:
            assert validate_date_format(date) is False


class TestSearchQueryValidation:
    """Test search query validation"""
    
    def test_valid_search_queries(self):
        """Test valid search queries"""
        valid_queries = [
            "data protection",
            "lei proteção dados",
            "PL 1234/2024",
            "educação AND saúde"
        ]
        
        for query in valid_queries:
            result = validate_search_query(query)
            assert len(result) >= 3
    
    def test_invalid_search_queries(self):
        """Test invalid search queries"""
        invalid_queries = [
            "",
            "ab",  # Too short
            "a" * 600,  # Too long
        ]
        
        for query in invalid_queries:
            with pytest.raises(ValueError):
                validate_search_query(query)
    
    def test_search_query_sanitization(self):
        """Test search query sanitization"""
        dangerous_query = "<script>alert('xss')</script> AND malicious"
        result = validate_search_query(dangerous_query)
        assert "<script>" not in result
    
    def test_search_query_whitespace_normalization(self):
        """Test whitespace normalization"""
        query_with_spaces = "  multiple   spaces   between   words  "
        result = validate_search_query(query_with_spaces)
        assert result == "multiple spaces between words"


class TestFiltersValidation:
    """Test filters validation"""
    
    def test_valid_filters(self):
        """Test valid filter combinations"""
        valid_filters = {
            'start_date': '2024-01-01',
            'end_date': '2024-12-31',
            'source': 'camara',
            'type': 'projeto_lei',
            'status': 'tramitando'
        }
        
        result = validate_filters(valid_filters)
        assert result == valid_filters
    
    def test_invalid_filter_values(self):
        """Test invalid filter values"""
        invalid_filters = {
            'start_date': 'invalid-date',
            'source': 'invalid_source',
            'type': 'invalid_type'
        }
        
        result = validate_filters(invalid_filters)
        
        # Invalid values should be filtered out
        assert 'start_date' not in result
        assert 'source' not in result
        assert 'type' not in result
    
    def test_unknown_filters(self):
        """Test unknown filter keys"""
        filters_with_unknown = {
            'start_date': '2024-01-01',
            'unknown_filter': 'value',
            'malicious_filter': '<script>alert("xss")</script>'
        }
        
        result = validate_filters(filters_with_unknown)
        
        # Only known filters should be kept
        assert 'start_date' in result
        assert 'unknown_filter' not in result
        assert 'malicious_filter' not in result


class TestExportFormatValidation:
    """Test export format validation"""
    
    def test_valid_formats(self):
        """Test valid export formats"""
        valid_formats = ['csv', 'json', 'excel', 'pdf']
        
        for fmt in valid_formats:
            result = validate_export_format(fmt)
            assert result == fmt.lower()
    
    def test_case_insensitive_formats(self):
        """Test case insensitive format validation"""
        formats = ['CSV', 'Json', 'EXCEL', 'Pdf']
        
        for fmt in formats:
            result = validate_export_format(fmt)
            assert result == fmt.lower()
    
    def test_invalid_formats(self):
        """Test invalid export formats"""
        invalid_formats = ['txt', 'doc', 'invalid', '']
        
        for fmt in invalid_formats:
            with pytest.raises(ValueError):
                validate_export_format(fmt)


class TestURLSafety:
    """Test URL safety validation"""
    
    def test_safe_urls(self):
        """Test safe URLs"""
        safe_urls = [
            "https://example.com",
            "http://localhost:3000",
            "/relative/path",
            "mailto:test@example.com"
        ]
        
        for url in safe_urls:
            assert is_safe_url(url) is True
    
    def test_dangerous_urls(self):
        """Test dangerous URLs"""
        dangerous_urls = [
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "vbscript:msgbox('xss')",
            "file:///etc/passwd"
        ]
        
        for url in dangerous_urls:
            assert is_safe_url(url) is False
    
    def test_url_with_allowed_hosts(self):
        """Test URL validation with allowed hosts"""
        allowed_hosts = ['example.com', 'trusted.org']
        
        assert is_safe_url('https://example.com/path', allowed_hosts) is True
        assert is_safe_url('https://untrusted.com/path', allowed_hosts) is False
    
    def test_empty_url(self):
        """Test empty URL handling"""
        assert is_safe_url('') is False
        assert is_safe_url(None) is False


class TestFilenameSanitization:
    """Test filename sanitization"""
    
    def test_basic_filename(self):
        """Test basic filename sanitization"""
        filename = "document.pdf"
        result = sanitize_filename(filename)
        assert result == "document.pdf"
    
    def test_dangerous_filename(self):
        """Test dangerous filename sanitization"""
        filename = "../../../etc/passwd"
        result = sanitize_filename(filename)
        assert "../" not in result
        assert result == "....etcpasswd"
    
    def test_filename_with_spaces(self):
        """Test filename with spaces"""
        filename = "my document with spaces.pdf"
        result = sanitize_filename(filename)
        assert result == "my_document_with_spaces.pdf"
    
    def test_filename_length_limit(self):
        """Test filename length limitation"""
        long_filename = "a" * 300 + ".pdf"
        result = sanitize_filename(long_filename, max_length=100)
        assert len(result) <= 100
        assert result.endswith(".pdf")
    
    def test_filename_with_multiple_dots(self):
        """Test filename with multiple dots"""
        filename = "document...with...dots.pdf"
        result = sanitize_filename(filename)
        assert "..." not in result
        assert result.endswith(".pdf")
    
    def test_empty_filename(self):
        """Test empty filename handling"""
        result = sanitize_filename("")
        assert result == "unnamed"
        
        result = sanitize_filename(None)
        assert result == "unnamed"


@pytest.mark.security
class TestSecurityVulnerabilities:
    """Test protection against common security vulnerabilities"""
    
    def test_xss_protection(self):
        """Test XSS protection"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "&#60;script&#62;alert('xss')&#60;/script&#62;"
        ]
        
        for payload in xss_payloads:
            sanitized = sanitize_input(payload)
            # Should not contain dangerous patterns
            assert "script" not in sanitized.lower() or "<" not in sanitized
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM users",
            "'; DELETE FROM users WHERE '1'='1",
            "admin'--"
        ]
        
        for payload in sql_payloads:
            sanitized = sanitize_input(payload)
            # Should not contain dangerous SQL keywords
            dangerous_keywords = ['DROP', 'DELETE', 'UNION', 'SELECT']
            assert not any(keyword in sanitized.upper() for keyword in dangerous_keywords)
    
    def test_path_traversal_protection(self):
        """Test path traversal protection"""
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "....//....//....//etc/passwd"
        ]
        
        for payload in path_payloads:
            sanitized = sanitize_filename(payload)
            assert "../" not in sanitized
            assert "..\\" not in sanitized
    
    def test_command_injection_protection(self):
        """Test command injection protection"""
        command_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",
            "$(id)"
        ]
        
        for payload in command_payloads:
            sanitized = sanitize_input(payload)
            dangerous_chars = [';', '|', '&', '`', '$']
            assert not any(char in sanitized for char in dangerous_chars)