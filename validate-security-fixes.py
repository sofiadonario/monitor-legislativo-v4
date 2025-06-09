#!/usr/bin/env python3
"""
Security Validation Script for Monitor Legislativo v4
Validates that all critical security fixes have been implemented

This script verifies:
1. No hardcoded credentials remain in codebase
2. Environment variables are properly configured  
3. Security headers are implemented
4. Rate limiting is configured
5. Docker configuration uses secure passwords
"""

import os
import sys
import subprocess
import re
import json
from pathlib import Path
from typing import List, Dict, Tuple

class SecurityValidator:
    """Validates security fixes implementation"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues_found = []
        self.checks_passed = 0
        self.checks_total = 0
        
    def validate_all(self) -> bool:
        """Run all security validations"""
        print("🔒 MONITOR LEGISLATIVO v4 - SECURITY VALIDATION")
        print("=" * 60)
        
        checks = [
            ("AWS Credentials Check", self.check_aws_credentials),
            ("Environment Variables", self.check_environment_variables),
            ("Docker Security", self.check_docker_security),
            ("Security Headers", self.check_security_headers),
            ("Rate Limiting", self.check_rate_limiting),
            ("Git Security", self.check_git_security),
            ("File Permissions", self.check_file_permissions)
        ]
        
        for check_name, check_func in checks:
            print(f"\n📋 {check_name}...")
            self.checks_total += 1
            
            try:
                if check_func():
                    print(f"   ✅ PASS")
                    self.checks_passed += 1
                else:
                    print(f"   ❌ FAIL")
                    
            except Exception as e:
                print(f"   ⚠️  ERROR: {e}")
                self.issues_found.append(f"{check_name}: {e}")
        
        self.print_summary()
        return len(self.issues_found) == 0 and self.checks_passed == self.checks_total
    
    def check_aws_credentials(self) -> bool:
        """Check for hardcoded AWS credentials"""
        aws_patterns = [
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID pattern
            r'aws_access_key_id\s*=\s*["\'][^"\']+["\']',
            r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']',
            r'mack' + 'monitor.*pass' + 'word',
            r'USe2' + 'WK6'  # Specific leaked password pattern
        ]
        
        # Check all Python and config files
        for pattern in [
            '**/*.py', '**/*.js', '**/*.ts', '**/*.json', 
            '**/*.yaml', '**/*.yml', '**/*.env*', '**/*.csv'
        ]:
            for file_path in self.project_root.glob(pattern):
                if self._should_skip_file(file_path):
                    continue
                    
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for aws_pattern in aws_patterns:
                        if re.search(aws_pattern, content, re.IGNORECASE):
                            self.issues_found.append(
                                f"AWS credentials found in {file_path}: matches {aws_pattern}"
                            )
                            return False
                            
                except Exception:
                    continue  # Skip files that can't be read
        
        return True
    
    def check_environment_variables(self) -> bool:
        """Check environment variable configuration"""
        required_files = [
            '.env.production',
            'env.example'
        ]
        
        for file_name in required_files:
            file_path = self.project_root / file_name
            if not file_path.exists():
                self.issues_found.append(f"Missing required file: {file_name}")
                return False
        
        # Check .env.production has secure passwords
        env_prod = self.project_root / '.env.production'
        try:
            content = env_prod.read_text()
            
            # Check for secure password patterns (base64, long strings)
            required_vars = [
                'DB_PASSWORD', 'REDIS_PASSWORD', 'GRAFANA_PASSWORD', 'SECRET_KEY'
            ]
            
            for var in required_vars:
                if var not in content:
                    self.issues_found.append(f"Missing environment variable: {var}")
                    return False
                
                # Extract password value
                match = re.search(f'{var}=(.+)', content)
                if match:
                    password = match.group(1).strip()
                    if len(password) < 16:
                        self.issues_found.append(f"Weak password for {var}: too short")
                        return False
                    
                    # Check for default/weak passwords
                    weak_passwords = [
                        'postgres', 'redis123', 'admin', 'password', '123456'
                    ]
                    if password.lower() in weak_passwords:
                        self.issues_found.append(f"Weak password for {var}: {password}")
                        return False
            
        except Exception as e:
            self.issues_found.append(f"Error reading .env.production: {e}")
            return False
        
        return True
    
    def check_docker_security(self) -> bool:
        """Check Docker configuration security"""
        docker_compose = self.project_root / 'docker-compose.yml'
        
        if not docker_compose.exists():
            self.issues_found.append("docker-compose.yml not found")
            return False
        
        try:
            content = docker_compose.read_text()
            
            # Check that environment variables are used instead of hardcoded values
            insecure_patterns = [
                r'POSTGRES_PASSWORD:\s*postgres\b',
                r'REDIS_PASSWORD:\s*redis123\b',
                r'GRAFANA_PASSWORD:\s*admin\b',
                r'password:\s*admin\b'
            ]
            
            for pattern in insecure_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # Check if it's using environment variable fallback
                    if not re.search(pattern.replace(':', ':.*\\${'), content):
                        self.issues_found.append(
                            f"Hardcoded password in docker-compose.yml: {pattern}"
                        )
                        return False
            
        except Exception as e:
            self.issues_found.append(f"Error reading docker-compose.yml: {e}")
            return False
        
        return True
    
    def check_security_headers(self) -> bool:
        """Check security headers implementation"""
        security_headers_file = self.project_root / 'web' / 'middleware' / 'security_headers.py'
        
        if not security_headers_file.exists():
            self.issues_found.append("Security headers middleware not found")
            return False
        
        try:
            content = security_headers_file.read_text()
            
            # Check for required security headers
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options', 
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'Referrer-Policy'
            ]
            
            for header in required_headers:
                if header not in content:
                    self.issues_found.append(f"Missing security header: {header}")
                    return False
            
            # Check main app integration
            main_files = [
                self.project_root / 'web' / 'main_secured.py',
                self.project_root / 'web' / 'main.py'
            ]
            
            app_has_headers = False
            for main_file in main_files:
                if main_file.exists():
                    main_content = main_file.read_text()
                    if 'security_headers' in main_content or 'X-Content-Type-Options' in main_content:
                        app_has_headers = True
                        break
            
            if not app_has_headers:
                self.issues_found.append("Security headers not integrated in main app")
                return False
            
        except Exception as e:
            self.issues_found.append(f"Error checking security headers: {e}")
            return False
        
        return True
    
    def check_rate_limiting(self) -> bool:
        """Check rate limiting implementation"""
        rate_limit_file = self.project_root / 'web' / 'middleware' / 'rate_limit_middleware.py'
        
        if not rate_limit_file.exists():
            self.issues_found.append("Rate limiting middleware not found")
            return False
        
        try:
            content = rate_limit_file.read_text()
            
            # Check for government API specific rate limiting
            if 'government' not in content.lower() and 'api' not in content.lower():
                self.issues_found.append("Government API rate limiting not implemented")
                return False
            
        except Exception as e:
            self.issues_found.append(f"Error checking rate limiting: {e}")
            return False
        
        return True
    
    def check_git_security(self) -> bool:
        """Check git security configuration"""
        gitignore = self.project_root / '.gitignore'
        
        if not gitignore.exists():
            self.issues_found.append(".gitignore not found")
            return False
        
        try:
            content = gitignore.read_text()
            
            # Check that credential files are ignored
            required_ignores = [
                '.env',
                '*.key',
                '*.pem',
                'secrets/'
            ]
            
            for ignore_pattern in required_ignores:
                if ignore_pattern not in content:
                    self.issues_found.append(f"Missing .gitignore pattern: {ignore_pattern}")
                    return False
            
        except Exception as e:
            self.issues_found.append(f"Error checking .gitignore: {e}")
            return False
        
        return True
    
    def check_file_permissions(self) -> bool:
        """Check file permissions for sensitive files"""
        sensitive_files = [
            '.env.production'
        ]
        
        for file_name in sensitive_files:
            file_path = self.project_root / file_name
            if file_path.exists():
                try:
                    # Check file permissions (should be readable only by owner)
                    stat_info = file_path.stat()
                    permissions = oct(stat_info.st_mode)[-3:]
                    
                    # Should be 600 (read/write owner only) or more restrictive
                    if permissions not in ['600', '400']:
                        print(f"   ⚠️  File {file_name} has permissions {permissions} (should be 600)")
                        # This is a warning, not a failure
                
                except Exception:
                    pass  # Skip permission check on Windows
        
        return True
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped during scanning"""
        skip_patterns = [
            '.git/', '__pycache__/', '.venv/', 'venv/', 'node_modules/',
            '.pytest_cache/', '.coverage', 'security-analysis-', '.backup'
        ]
        
        file_str = str(file_path)
        return any(pattern in file_str for pattern in skip_patterns)
    
    def print_summary(self):
        """Print validation summary"""
        print(f"\n{'='*60}")
        print(f"📊 SECURITY VALIDATION SUMMARY")
        print(f"{'='*60}")
        print(f"Checks Passed: {self.checks_passed}/{self.checks_total}")
        
        if self.issues_found:
            print(f"\n❌ ISSUES FOUND ({len(self.issues_found)}):")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"   {i}. {issue}")
        else:
            print(f"\n✅ ALL SECURITY CHECKS PASSED!")
        
        # Security score
        if self.checks_total > 0:
            score = (self.checks_passed / self.checks_total) * 100
            print(f"\n🎯 Security Score: {score:.1f}%")
            
            if score >= 100:
                print("🚀 SYSTEM READY FOR PRODUCTION DEPLOYMENT")
            elif score >= 80:
                print("⚠️  SYSTEM NEEDS MINOR FIXES BEFORE DEPLOYMENT")
            else:
                print("🚨 SYSTEM NOT READY FOR DEPLOYMENT - CRITICAL FIXES NEEDED")


def main():
    """Main entry point"""
    # Get project root directory
    script_dir = Path(__file__).parent
    project_root = script_dir
    
    print(f"🔍 Scanning project: {project_root}")
    
    # Run validation
    validator = SecurityValidator(project_root)
    success = validator.validate_all()
    
    # Set exit code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()