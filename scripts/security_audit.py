#!/usr/bin/env python3
"""
Comprehensive Security Audit Script for Monitor Legislativo v4
Performs automated security assessment across multiple domains.
"""

import os
import sys
import json
import subprocess
import re
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecurityAuditor:
    """Comprehensive security auditor for the application."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'project_root': str(self.project_root),
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
    def run_full_audit(self) -> Dict[str, Any]:
        """Run complete security audit."""
        logger.info("Starting comprehensive security audit...")
        
        # 1. Static Code Analysis
        self._analyze_static_security()
        
        # 2. Dependency Vulnerability Scan
        self._scan_dependencies()
        
        # 3. Configuration Security
        self._audit_configuration()
        
        # 4. Authentication & Authorization
        self._audit_auth_system()
        
        # 5. Input Validation
        self._audit_input_validation()
        
        # 6. Cryptography Assessment
        self._audit_cryptography()
        
        # 7. File Permissions
        self._audit_file_permissions()
        
        # 8. Environment Security
        self._audit_environment_security()
        
        # 9. Docker Security
        self._audit_docker_security()
        
        # 10. Database Security
        self._audit_database_security()
        
        # Generate summary
        self._generate_summary()
        
        # Save results
        self._save_results()
        
        return self.audit_results
    
    def _analyze_static_security(self):
        """Analyze code for security vulnerabilities."""
        logger.info("Running static security analysis...")
        
        findings = []
        
        # Run Bandit security scanner
        try:
            result = subprocess.run([
                'bandit', '-r', str(self.project_root), 
                '-f', 'json', '-o', '/tmp/bandit_results.json'
            ], capture_output=True, text=True, check=False)
            
            if os.path.exists('/tmp/bandit_results.json'):
                with open('/tmp/bandit_results.json') as f:
                    bandit_results = json.load(f)
                
                for issue in bandit_results.get('results', []):
                    findings.append({
                        'type': 'static_analysis',
                        'severity': issue.get('issue_severity', 'UNKNOWN'),
                        'description': issue.get('issue_text', ''),
                        'file': issue.get('filename', ''),
                        'line': issue.get('line_number', 0),
                        'test_id': issue.get('test_id', ''),
                        'confidence': issue.get('issue_confidence', 'UNKNOWN')
                    })
        except Exception as e:
            findings.append({
                'type': 'static_analysis',
                'severity': 'ERROR',
                'description': f"Failed to run Bandit: {e}",
                'file': '',
                'line': 0
            })
        
        # Manual pattern analysis
        self._analyze_security_patterns(findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _analyze_security_patterns(self, findings: List[Dict]):
        """Analyze code for security anti-patterns."""
        dangerous_patterns = [
            (r'exec\s*\(', 'Use of exec() can lead to code injection'),
            (r'eval\s*\(', 'Use of eval() can lead to code injection'),
            (r'shell=True', 'shell=True in subprocess can be dangerous'),
            (r'password\s*=\s*["\'][^"\']*["\']', 'Hardcoded password detected'),
            (r'api_key\s*=\s*["\'][^"\']*["\']', 'Hardcoded API key detected'),
            (r'secret\s*=\s*["\'][^"\']*["\']', 'Hardcoded secret detected'),
            (r'\.format\s*\([^)]*query', 'Potential SQL injection via string formatting'),
            (r'%.*query', 'Potential SQL injection via % formatting'),
            (r'pickle\.loads?', 'Use of pickle can lead to code execution'),
            (r'yaml\.load\(', 'unsafe yaml.load() usage'),
        ]
        
        for py_file in self.project_root.rglob('*.py'):
            if 'venv' in str(py_file) or 'test' in str(py_file):
                continue
                
            try:
                content = py_file.read_text(encoding='utf-8')
                
                for pattern, description in dangerous_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            'type': 'pattern_analysis',
                            'severity': 'MEDIUM',
                            'description': description,
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'pattern': pattern
                        })
            except Exception as e:
                logger.warning(f"Could not analyze {py_file}: {e}")
    
    def _scan_dependencies(self):
        """Scan dependencies for known vulnerabilities."""
        logger.info("Scanning dependencies for vulnerabilities...")
        
        findings = []
        
        # Run Safety scanner
        try:
            result = subprocess.run([
                'safety', 'check', '--json'
            ], capture_output=True, text=True, check=False)
            
            if result.stdout:
                safety_results = json.loads(result.stdout)
                
                for vuln in safety_results:
                    findings.append({
                        'type': 'dependency_vulnerability',
                        'severity': 'HIGH',
                        'description': vuln.get('advisory', ''),
                        'package': vuln.get('package_name', ''),
                        'version': vuln.get('analyzed_version', ''),
                        'vulnerability_id': vuln.get('vulnerability_id', ''),
                        'cve': vuln.get('cve', '')
                    })
        except Exception as e:
            findings.append({
                'type': 'dependency_scan',
                'severity': 'ERROR',
                'description': f"Failed to run Safety scanner: {e}",
                'file': 'requirements.txt'
            })
        
        # Check for outdated packages
        self._check_outdated_packages(findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _check_outdated_packages(self, findings: List[Dict]):
        """Check for outdated packages that might have security updates."""
        try:
            result = subprocess.run([
                'pip', 'list', '--outdated', '--format=json'
            ], capture_output=True, text=True, check=True)
            
            outdated = json.loads(result.stdout)
            
            for pkg in outdated:
                findings.append({
                    'type': 'outdated_dependency',
                    'severity': 'LOW',
                    'description': f"Package {pkg['name']} is outdated",
                    'package': pkg['name'],
                    'current_version': pkg['version'],
                    'latest_version': pkg['latest_version']
                })
        except Exception as e:
            logger.warning(f"Could not check outdated packages: {e}")
    
    def _audit_configuration(self):
        """Audit configuration security."""
        logger.info("Auditing configuration security...")
        
        findings = []
        
        # Check environment file security
        env_files = ['.env', '.env.example', '.env.production', '.env.development']
        
        for env_file in env_files:
            env_path = self.project_root / env_file
            if env_path.exists():
                self._audit_env_file(env_path, findings)
        
        # Check configuration files
        config_files = list(self.project_root.rglob('*config*.py'))
        config_files.extend(list(self.project_root.rglob('*config*.json')))
        
        for config_file in config_files:
            if 'venv' in str(config_file):
                continue
            self._audit_config_file(config_file, findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_env_file(self, env_path: Path, findings: List[Dict]):
        """Audit environment file security."""
        try:
            content = env_path.read_text()
            
            # Check for weak defaults
            weak_patterns = [
                (r'PASSWORD=password', 'Weak default password'),
                (r'SECRET.*=secret', 'Weak default secret'),
                (r'KEY.*=key', 'Weak default key'),
                (r'TOKEN.*=token', 'Weak default token'),
                (r'DEBUG=true', 'Debug mode enabled in production'),
            ]
            
            for pattern, description in weak_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': 'configuration',
                        'severity': 'MEDIUM',
                        'description': description,
                        'file': str(env_path.relative_to(self.project_root))
                    })
            
            # Check file permissions
            stat = env_path.stat()
            if stat.st_mode & 0o077:  # World or group readable
                findings.append({
                    'type': 'file_permissions',
                    'severity': 'HIGH',
                    'description': 'Environment file has overly permissive permissions',
                    'file': str(env_path.relative_to(self.project_root)),
                    'permissions': oct(stat.st_mode)
                })
                
        except Exception as e:
            logger.warning(f"Could not audit {env_path}: {e}")
    
    def _audit_config_file(self, config_path: Path, findings: List[Dict]):
        """Audit configuration file security."""
        try:
            content = config_path.read_text()
            
            # Look for hardcoded secrets
            secret_patterns = [
                r'password\s*[=:]\s*["\'][^"\']{3,}["\']',
                r'secret\s*[=:]\s*["\'][^"\']{10,}["\']',
                r'key\s*[=:]\s*["\'][^"\']{10,}["\']',
                r'token\s*[=:]\s*["\'][^"\']{10,}["\']',
            ]
            
            for pattern in secret_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    if 'example' not in match.group().lower() and 'placeholder' not in match.group().lower():
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            'type': 'hardcoded_secret',
                            'severity': 'HIGH',
                            'description': 'Potential hardcoded secret in configuration',
                            'file': str(config_path.relative_to(self.project_root)),
                            'line': line_num
                        })
                        
        except Exception as e:
            logger.warning(f"Could not audit {config_path}: {e}")
    
    def _audit_auth_system(self):
        """Audit authentication and authorization system."""
        logger.info("Auditing authentication and authorization...")
        
        findings = []
        
        # Check JWT implementation
        jwt_files = list(self.project_root.rglob('*jwt*.py'))
        auth_files = list(self.project_root.rglob('*auth*.py'))
        
        for auth_file in jwt_files + auth_files:
            if 'venv' in str(auth_file) or 'test' in str(auth_file):
                continue
            self._audit_auth_file(auth_file, findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_auth_file(self, auth_file: Path, findings: List[Dict]):
        """Audit authentication file."""
        try:
            content = auth_file.read_text()
            
            # Check for common auth vulnerabilities
            auth_issues = [
                (r'jwt\.decode\([^,]*,\s*verify=False', 'JWT signature verification disabled'),
                (r'password.*==.*password', 'Plain text password comparison'),
                (r'hashlib\.md5', 'Weak MD5 hashing used'),
                (r'hashlib\.sha1', 'Weak SHA1 hashing used'),
                (r'random\.random', 'Weak random number generation for security'),
                (r'time\.time\(\).*random', 'Predictable token generation'),
            ]
            
            for pattern, description in auth_issues:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'authentication',
                        'severity': 'HIGH',
                        'description': description,
                        'file': str(auth_file.relative_to(self.project_root)),
                        'line': line_num
                    })
                    
        except Exception as e:
            logger.warning(f"Could not audit {auth_file}: {e}")
    
    def _audit_input_validation(self):
        """Audit input validation mechanisms."""
        logger.info("Auditing input validation...")
        
        findings = []
        
        # Check API route files
        api_files = list(self.project_root.rglob('*route*.py'))
        api_files.extend(list(self.project_root.rglob('*api*.py'))
        
        for api_file in api_files:
            if 'venv' in str(api_file):
                continue
            self._audit_input_validation_file(api_file, findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_input_validation_file(self, api_file: Path, findings: List[Dict]):
        """Audit input validation in API files."""
        try:
            content = api_file.read_text()
            
            # Check for potential injection vulnerabilities
            injection_patterns = [
                (r'request\.args\.get\([^)]*\).*execute', 'Potential SQL injection from URL parameters'),
                (r'request\.form\.get\([^)]*\).*execute', 'Potential SQL injection from form data'),
                (r'request\.json\.get\([^)]*\).*execute', 'Potential SQL injection from JSON data'),
                (r'f".*{.*}.*".*execute', 'Potential SQL injection via f-strings'),
                (r'%.*execute', 'Potential SQL injection via string formatting'),
                (r'subprocess.*shell=True', 'Command injection risk with shell=True'),
                (r'os\.system\(.*request\.', 'Command injection via os.system'),
                (r'eval\(.*request\.', 'Code injection via eval()'),
            ]
            
            for pattern, description in injection_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'input_validation',
                        'severity': 'HIGH',
                        'description': description,
                        'file': str(api_file.relative_to(self.project_root)),
                        'line': line_num
                    })
                    
        except Exception as e:
            logger.warning(f"Could not audit {api_file}: {e}")
    
    def _audit_cryptography(self):
        """Audit cryptographic implementations."""
        logger.info("Auditing cryptography...")
        
        findings = []
        
        # Find files using cryptography
        crypto_files = []
        for py_file in self.project_root.rglob('*.py'):
            if 'venv' in str(py_file):
                continue
            try:
                content = py_file.read_text()
                if any(term in content for term in ['crypt', 'hash', 'encrypt', 'decrypt', 'jwt', 'bcrypt']):
                    crypto_files.append(py_file)
            except:
                continue
        
        for crypto_file in crypto_files:
            self._audit_crypto_file(crypto_file, findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_crypto_file(self, crypto_file: Path, findings: List[Dict]):
        """Audit cryptographic usage in file."""
        try:
            content = crypto_file.read_text()
            
            crypto_issues = [
                (r'DES\.new', 'Weak DES encryption used'),
                (r'RC4\.new', 'Weak RC4 encryption used'),
                (r'MD5\.new', 'Weak MD5 hashing used'),
                (r'SHA1\.new', 'Weak SHA1 hashing used'),
                (r'Random\.random', 'Weak random number generation'),
                (r'ssl.*verify_mode.*NONE', 'SSL certificate verification disabled'),
                (r'ssl.*check_hostname.*False', 'SSL hostname verification disabled'),
                (r'urllib3.*disable_warnings', 'SSL warnings disabled'),
            ]
            
            for pattern, description in crypto_issues:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'cryptography',
                        'severity': 'HIGH',
                        'description': description,
                        'file': str(crypto_file.relative_to(self.project_root)),
                        'line': line_num
                    })
                    
        except Exception as e:
            logger.warning(f"Could not audit {crypto_file}: {e}")
    
    def _audit_file_permissions(self):
        """Audit file permissions for security issues."""
        logger.info("Auditing file permissions...")
        
        findings = []
        
        # Check critical files
        critical_files = ['.env', 'config.py', 'secrets.json', 'private_key.pem']
        
        for file_pattern in critical_files:
            for file_path in self.project_root.rglob(file_pattern):
                if file_path.exists():
                    stat = file_path.stat()
                    mode = stat.st_mode
                    
                    # Check if file is world-readable or writable
                    if mode & 0o044:  # World-readable
                        findings.append({
                            'type': 'file_permissions',
                            'severity': 'HIGH',
                            'description': f'Sensitive file {file_path.name} is world-readable',
                            'file': str(file_path.relative_to(self.project_root)),
                            'permissions': oct(mode)
                        })
                    
                    if mode & 0o022:  # World-writable
                        findings.append({
                            'type': 'file_permissions',
                            'severity': 'CRITICAL',
                            'description': f'Sensitive file {file_path.name} is world-writable',
                            'file': str(file_path.relative_to(self.project_root)),
                            'permissions': oct(mode)
                        })
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_environment_security(self):
        """Audit environment security settings."""
        logger.info("Auditing environment security...")
        
        findings = []
        
        # Check environment variables
        insecure_env_vars = ['DEBUG=1', 'DEBUG=True', 'DEVELOPMENT=1']
        
        for env_var in insecure_env_vars:
            if env_var in os.environ:
                findings.append({
                    'type': 'environment',
                    'severity': 'MEDIUM',
                    'description': f'Insecure environment variable: {env_var}',
                    'variable': env_var
                })
        
        # Check for development servers in production
        if os.environ.get('FLASK_ENV') == 'development':
            findings.append({
                'type': 'environment',
                'severity': 'HIGH',
                'description': 'Flask development mode enabled',
                'variable': 'FLASK_ENV'
            })
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_docker_security(self):
        """Audit Docker configuration security."""
        logger.info("Auditing Docker security...")
        
        findings = []
        
        # Check Dockerfile
        dockerfile_path = self.project_root / 'Dockerfile'
        if dockerfile_path.exists():
            self._audit_dockerfile(dockerfile_path, findings)
        
        # Check docker-compose files
        for compose_file in self.project_root.glob('docker-compose*.yml'):
            self._audit_docker_compose(compose_file, findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_dockerfile(self, dockerfile_path: Path, findings: List[Dict]):
        """Audit Dockerfile security."""
        try:
            content = dockerfile_path.read_text()
            
            docker_issues = [
                (r'FROM.*:latest', 'Using latest tag is not recommended for security'),
                (r'USER root', 'Running as root user'),
                (r'sudo', 'Using sudo in container'),
                (r'chmod 777', 'Overly permissive file permissions'),
                (r'--privileged', 'Running in privileged mode'),
            ]
            
            for pattern, description in docker_issues:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'docker_security',
                        'severity': 'MEDIUM',
                        'description': description,
                        'file': str(dockerfile_path.relative_to(self.project_root)),
                        'line': line_num
                    })
                    
        except Exception as e:
            logger.warning(f"Could not audit {dockerfile_path}: {e}")
    
    def _audit_docker_compose(self, compose_path: Path, findings: List[Dict]):
        """Audit docker-compose file security."""
        try:
            content = compose_path.read_text()
            
            compose_issues = [
                (r'privileged:\s*true', 'Privileged mode enabled'),
                (r'network_mode:\s*host', 'Host network mode used'),
                (r'pid:\s*host', 'Host PID namespace used'),
                (r'user:\s*root', 'Running as root user'),
                (r'volumes:.*:/etc', 'Mounting system directories'),
            ]
            
            for pattern, description in compose_issues:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'docker_compose',
                        'severity': 'HIGH',
                        'description': description,
                        'file': str(compose_path.relative_to(self.project_root)),
                        'line': line_num
                    })
                    
        except Exception as e:
            logger.warning(f"Could not audit {compose_path}: {e}")
    
    def _audit_database_security(self):
        """Audit database security configuration."""
        logger.info("Auditing database security...")
        
        findings = []
        
        # Check for database configuration files
        db_files = list(self.project_root.rglob('*database*.py'))
        db_files.extend(list(self.project_root.rglob('*db*.py')))
        
        for db_file in db_files:
            if 'venv' in str(db_file) or 'test' in str(db_file):
                continue
            self._audit_database_file(db_file, findings)
        
        self.audit_results['findings'].extend(findings)
    
    def _audit_database_file(self, db_file: Path, findings: List[Dict]):
        """Audit database configuration file."""
        try:
            content = db_file.read_text()
            
            db_issues = [
                (r'password.*=.*["\'][^"\']*["\']', 'Hardcoded database password'),
                (r'autocommit.*=.*True', 'Autocommit enabled globally'),
                (r'echo=True', 'SQL logging enabled (may expose sensitive data)'),
                (r'trust_env.*=.*False', 'Environment variable trust disabled'),
            ]
            
            for pattern, description in db_issues:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    if 'example' not in match.group().lower():
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            'type': 'database_security',
                            'severity': 'MEDIUM',
                            'description': description,
                            'file': str(db_file.relative_to(self.project_root)),
                            'line': line_num
                        })
                        
        except Exception as e:
            logger.warning(f"Could not audit {db_file}: {e}")
    
    def _generate_summary(self):
        """Generate audit summary."""
        findings = self.audit_results['findings']
        
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_type': {},
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            finding_type = finding.get('type', 'unknown')
            
            # Count by severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
            
            # Count specific severity levels
            if severity == 'CRITICAL':
                summary['critical_issues'] += 1
            elif severity == 'HIGH':
                summary['high_issues'] += 1
            elif severity == 'MEDIUM':
                summary['medium_issues'] += 1
            elif severity == 'LOW':
                summary['low_issues'] += 1
        
        # Generate recommendations
        recommendations = []
        
        if summary['critical_issues'] > 0:
            recommendations.append("CRITICAL: Address critical security issues immediately before deployment")
        
        if summary['high_issues'] > 5:
            recommendations.append("HIGH: Multiple high-severity issues detected - prioritize remediation")
        
        if summary['by_type'].get('dependency_vulnerability', 0) > 0:
            recommendations.append("Update vulnerable dependencies using 'pip install --upgrade'")
        
        if summary['by_type'].get('hardcoded_secret', 0) > 0:
            recommendations.append("Remove hardcoded secrets and use environment variables")
        
        if summary['by_type'].get('input_validation', 0) > 0:
            recommendations.append("Implement proper input validation and parameterized queries")
        
        recommendations.extend([
            "Run security tests in CI/CD pipeline",
            "Implement regular security dependency updates",
            "Set up automated security scanning",
            "Conduct regular penetration testing",
            "Implement security headers and HTTPS",
            "Set up security monitoring and alerting"
        ])
        
        self.audit_results['summary'] = summary
        self.audit_results['recommendations'] = recommendations
    
    def _save_results(self):
        """Save audit results to file."""
        results_dir = self.project_root / 'data' / 'reports'
        results_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = results_dir / f'security_audit_{timestamp}.json'
        
        with open(results_file, 'w') as f:
            json.dump(self.audit_results, f, indent=2, default=str)
        
        logger.info(f"Security audit results saved to {results_file}")
    
    def print_summary(self):
        """Print audit summary to console."""
        summary = self.audit_results['summary']
        
        print("\n" + "="*60)
        print("SECURITY AUDIT SUMMARY")
        print("="*60)
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Critical Issues: {summary['critical_issues']}")
        print(f"High Issues: {summary['high_issues']}")
        print(f"Medium Issues: {summary['medium_issues']}")
        print(f"Low Issues: {summary['low_issues']}")
        
        print("\nFindings by Type:")
        for finding_type, count in summary['by_type'].items():
            print(f"  {finding_type}: {count}")
        
        print("\nTop Recommendations:")
        for i, rec in enumerate(self.audit_results['recommendations'][:5], 1):
            print(f"  {i}. {rec}")
        
        print("\n" + "="*60)


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    else:
        project_root = os.getcwd()
    
    auditor = SecurityAuditor(project_root)
    results = auditor.run_full_audit()
    auditor.print_summary()
    
    # Exit with error code if critical issues found
    if results['summary']['critical_issues'] > 0:
        sys.exit(1)
    elif results['summary']['high_issues'] > 10:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()