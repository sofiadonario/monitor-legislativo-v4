#!/usr/bin/env python3
"""Comprehensive security assessment for Legislative Monitoring System."""

import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

class SecurityAssessment:
    def __init__(self):
        self.vulnerabilities = []
        self.recommendations = []
        self.report_path = Path("data/reports/security_assessment.json")
        
    def run_bandit_scan(self):
        """Run Bandit security scanner on Python code."""
        print("🔒 Running Bandit security scan...")
        cmd = "bandit -r core web desktop -f json"
        success, stdout, stderr = self._run_command(cmd)
        
        if success and stdout:
            results = json.loads(stdout)
            for issue in results.get("results", []):
                self.vulnerabilities.append({
                    "tool": "bandit",
                    "severity": issue["issue_severity"],
                    "confidence": issue["issue_confidence"],
                    "file": issue["filename"],
                    "line": issue["line_number"],
                    "issue": issue["issue_text"],
                    "cwe": issue.get("issue_cwe", {}).get("id", "Unknown"),
                })
        
        return len(self.vulnerabilities)
    
    def check_secrets(self):
        """Check for hardcoded secrets and credentials."""
        print("🔑 Checking for hardcoded secrets...")
        
        secret_patterns = [
            (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'["\']?api_key["\']?\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded API key"),
            (r'["\']?secret["\']?\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded secret"),
            (r'["\']?token["\']?\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded token"),
            (r'AWS[A-Z0-9]{16,}', "AWS credentials"),
            (r'[a-zA-Z0-9/+=]{40,}', "Potential base64 encoded secret"),
        ]
        
        files_to_check = list(Path(".").rglob("*.py")) + list(Path(".").rglob("*.json"))
        
        for file_path in files_to_check:
            if "venv" in str(file_path) or "test" in str(file_path):
                continue
                
            try:
                content = file_path.read_text()
                for pattern, description in secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        self.vulnerabilities.append({
                            "tool": "secrets_scanner",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "file": str(file_path),
                            "line": line_no,
                            "issue": description,
                            "cwe": "CWE-798",
                        })
            except Exception:
                pass
    
    def check_dependencies(self):
        """Check for vulnerable dependencies."""
        print("📦 Checking dependency vulnerabilities...")
        
        # Check with safety
        cmd = "safety check --json"
        success, stdout, stderr = self._run_command(cmd)
        
        if success and stdout:
            try:
                results = json.loads(stdout)
                for vuln in results.get("vulnerabilities", []):
                    self.vulnerabilities.append({
                        "tool": "safety",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "file": "requirements.txt",
                        "line": 0,
                        "issue": f"{vuln['package_name']} {vuln['analyzed_version']} - {vuln['vulnerability']}",
                        "cwe": vuln.get("cve", "Unknown"),
                    })
            except json.JSONDecodeError:
                pass
    
    def check_api_security(self):
        """Check for common API security issues."""
        print("🌐 Checking API security...")
        
        api_patterns = [
            (r'verify\s*=\s*False', "SSL verification disabled", "CWE-295"),
            (r'debug\s*=\s*True', "Debug mode enabled", "CWE-489"),
            (r'@app\.route.*methods\s*=\s*\[["\']GET["\'],\s*["\']POST["\']]', "Mixed HTTP methods", "CWE-352"),
            (r'eval\s*\(', "Use of eval()", "CWE-95"),
            (r'pickle\.loads?\s*\(', "Unsafe deserialization", "CWE-502"),
            (r'os\.system\s*\(', "Command injection risk", "CWE-78"),
            (r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True', "Shell injection risk", "CWE-78"),
        ]
        
        for pattern, description, cwe in api_patterns:
            for file_path in Path(".").rglob("*.py"):
                if "venv" in str(file_path):
                    continue
                    
                try:
                    content = file_path.read_text()
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        self.vulnerabilities.append({
                            "tool": "api_scanner",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "file": str(file_path),
                            "line": line_no,
                            "issue": description,
                            "cwe": cwe,
                        })
                except Exception:
                    pass
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings."""
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln["severity"]] += 1
        
        self.recommendations = [
            "Implement secrets management using environment variables or vault",
            "Enable SSL certificate verification for all external API calls",
            "Add input validation and sanitization for all user inputs",
            "Implement rate limiting on all API endpoints",
            "Add authentication and authorization middleware",
            "Enable CORS with specific allowed origins",
            "Implement request/response logging with PII filtering",
            "Add security headers (CSP, HSTS, X-Frame-Options)",
            "Regular dependency updates and vulnerability scanning",
            "Implement API versioning and deprecation strategy",
        ]
        
        if severity_counts["HIGH"] > 0:
            self.recommendations.insert(0, f"⚠️  Fix {severity_counts['HIGH']} HIGH severity issues immediately")
    
    def generate_report(self):
        """Generate comprehensive security assessment report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "high_severity": len([v for v in self.vulnerabilities if v["severity"] == "HIGH"]),
                "medium_severity": len([v for v in self.vulnerabilities if v["severity"] == "MEDIUM"]),
                "low_severity": len([v for v in self.vulnerabilities if v["severity"] == "LOW"]),
            },
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.recommendations,
            "compliance_checklist": {
                "authentication": False,
                "authorization": False,
                "data_encryption": False,
                "input_validation": False,
                "error_handling": False,
                "logging_monitoring": False,
                "secure_configuration": False,
                "dependency_management": False,
            }
        }
        
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.report_path, "w") as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def _run_command(self, cmd):
        """Execute command and return results."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True
            )
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def run_assessment(self):
        """Run complete security assessment."""
        print("🛡️  Legislative Monitoring System - Security Assessment")
        print("=" * 60)
        
        # Run all security checks
        self.run_bandit_scan()
        self.check_secrets()
        self.check_dependencies()
        self.check_api_security()
        self.generate_recommendations()
        
        # Generate report
        report = self.generate_report()
        
        # Print summary
        print(f"\n📊 Security Assessment Summary:")
        print(f"Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"  - HIGH: {report['summary']['high_severity']}")
        print(f"  - MEDIUM: {report['summary']['medium_severity']}")
        print(f"  - LOW: {report['summary']['low_severity']}")
        
        print(f"\n📋 Top Recommendations:")
        for i, rec in enumerate(report['recommendations'][:5], 1):
            print(f"{i}. {rec}")
        
        print(f"\n✅ Report saved to: {self.report_path}")

if __name__ == "__main__":
    assessment = SecurityAssessment()
    assessment.run_assessment()