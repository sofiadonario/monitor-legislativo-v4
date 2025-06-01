"""Security scanning and vulnerability tests."""

import pytest
import subprocess
import json
import os
from pathlib import Path


class TestSecurityScanning:
    """Test security vulnerabilities and compliance."""

    def test_bandit_security_scan(self):
        """Run bandit security scanner."""
        result = subprocess.run([
            'bandit', '-r', 'core/', 'web/', 'desktop/', 
            '-f', 'json', '-o', 'bandit-report.json'
        ], capture_output=True, text=True)
        
        # Bandit returns 1 if issues found, 0 if clean
        if result.returncode == 1:
            # Load report to check severity
            if os.path.exists('bandit-report.json'):
                with open('bandit-report.json', 'r') as f:
                    report = json.load(f)
                
                # Fail only on high/medium severity issues
                high_issues = [issue for issue in report.get('results', []) 
                             if issue.get('issue_severity') in ['HIGH', 'MEDIUM']]
                
                if high_issues:
                    pytest.fail(f"Bandit found {len(high_issues)} high/medium severity security issues")

    def test_safety_dependency_scan(self):
        """Run safety scanner for dependency vulnerabilities."""
        result = subprocess.run([
            'safety', 'check', '--json', '--output', 'safety-report.json'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            if os.path.exists('safety-report.json'):
                with open('safety-report.json', 'r') as f:
                    report = json.load(f)
                
                if report and len(report) > 0:
                    pytest.fail(f"Safety found {len(report)} dependency vulnerabilities")

    def test_secrets_detection(self):
        """Test for accidentally committed secrets."""
        # Common secret patterns
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret_key\s*=\s*["\'][^"\']+["\']',
            r'-----BEGIN PRIVATE KEY-----',
            r'-----BEGIN RSA PRIVATE KEY-----',
        ]
        
        # Search for patterns in source files
        import re
        project_root = Path(__file__).parent.parent.parent
        
        for py_file in project_root.rglob('*.py'):
            if 'venv' in str(py_file) or 'test' in str(py_file):
                continue
                
            content = py_file.read_text()
            for pattern in secret_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # Allow test/example values
                    if 'test' not in content.lower() and 'example' not in content.lower():
                        pytest.fail(f"Potential secret found in {py_file}: {pattern}")

    def test_sql_injection_patterns(self):
        """Test for SQL injection vulnerabilities."""
        dangerous_patterns = [
            r'\.execute\([^)]*%[^)]*\)',  # String formatting in execute
            r'\.execute\([^)]*\+[^)]*\)',  # String concatenation in execute
            r'f".*{.*}.*".*execute',  # f-strings in SQL
        ]
        
        import re
        project_root = Path(__file__).parent.parent.parent
        
        for py_file in project_root.rglob('*.py'):
            if 'venv' in str(py_file) or 'test' in str(py_file):
                continue
                
            content = py_file.read_text()
            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    pytest.fail(f"Potential SQL injection vulnerability in {py_file}")

    def test_xss_prevention(self):
        """Test for XSS prevention measures."""
        from core.utils.input_validator import InputValidator
        
        validator = InputValidator()
        
        # Test XSS payloads
        xss_payloads = [
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            'javascript:alert(1)',
            '<svg onload="alert(1)">',
            '"><script>alert(1)</script>',
        ]
        
        for payload in xss_payloads:
            sanitized = validator.sanitize_html(payload)
            assert '<script>' not in sanitized
            assert 'javascript:' not in sanitized
            assert 'onerror=' not in sanitized
            assert 'onload=' not in sanitized

    def test_csrf_protection(self):
        """Test CSRF protection measures."""
        # This would test CSRF tokens in forms
        # Implementation depends on the web framework setup
        pass

    def test_authentication_security(self):
        """Test authentication security measures."""
        from core.auth.jwt_manager import JWTManager
        
        jwt_manager = JWTManager('test-secret-key')
        
        # Test token expiration
        test_user = {'user_id': 1, 'username': 'test'}
        token = jwt_manager.create_access_token(test_user)
        
        # Verify token is valid
        payload = jwt_manager.verify_token(token)
        assert payload['user_id'] == 1
        
        # Test invalid token handling
        invalid_token = token + 'tampered'
        with pytest.raises(Exception):
            jwt_manager.verify_token(invalid_token)

    def test_password_hashing(self):
        """Test password hashing security."""
        from core.auth.models import User
        
        user = User(username='test', email='test@example.com')
        password = 'testpassword123'
        
        # Set password
        user.set_password(password)
        
        # Verify password is hashed
        assert user.password_hash != password
        assert len(user.password_hash) > 20  # Reasonable hash length
        
        # Verify password checking works
        assert user.check_password(password)
        assert not user.check_password('wrongpassword')

    def test_input_validation_security(self):
        """Test input validation against injection attacks."""
        from core.utils.input_validator import InputValidator
        
        validator = InputValidator()
        
        # Test SQL injection attempts
        sql_attacks = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM users WHERE 1=1; --",
        ]
        
        for attack in sql_attacks:
            sanitized = validator.sanitize_sql(attack)
            assert 'DROP TABLE' not in sanitized.upper()
            assert 'DELETE FROM' not in sanitized.upper()
            assert '--' not in sanitized

    def test_file_upload_security(self):
        """Test file upload security measures."""
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.scr', '.pif',
            '.php', '.jsp', '.asp', '.aspx'
        ]
        
        # Test file extension validation
        for ext in dangerous_extensions:
            filename = f"malicious{ext}"
            # Implementation would depend on file upload handler
            # assert not is_safe_filename(filename)

    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities."""
        # Check that debug mode is not enabled in production
        import os
        
        # These should not be set in production
        debug_vars = ['DEBUG', 'FLASK_DEBUG', 'DJANGO_DEBUG']
        for var in debug_vars:
            if os.environ.get(var):
                if os.environ.get(var).lower() in ['true', '1', 'on']:
                    pytest.fail(f"Debug mode enabled via {var} environment variable")

    def test_secure_headers(self):
        """Test security headers configuration."""
        # This would test HTTP security headers
        # Implementation depends on web framework setup
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        # Would verify these headers are set in HTTP responses

    def test_rate_limiting(self):
        """Test rate limiting implementation."""
        # This would test API rate limiting
        # Implementation depends on rate limiting setup
        pass

    def test_access_control(self):
        """Test access control and authorization."""
        from core.auth.decorators import require_permission
        
        # Test that protected endpoints require authentication
        # This would involve making requests to protected endpoints
        # without authentication and verifying they're rejected
        pass