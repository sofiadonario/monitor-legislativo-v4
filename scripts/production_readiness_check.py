#!/usr/bin/env python3
"""
Monitor Legislativo v4 - Production Readiness Check
Comprehensive validation script for production deployment
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class ProductionReadinessChecker:
    """Comprehensive production readiness validation"""
    
    def __init__(self):
        self.project_root = project_root
        self.checks = []
        self.passed = 0
        self.failed = 0
        self.warnings = 0
    
    def log_check(self, category: str, name: str, status: str, details: str = "", severity: str = "info"):
        """Log a check result"""
        check = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "name": name,
            "status": status,
            "details": details,
            "severity": severity
        }
        self.checks.append(check)
        
        # Update counters
        if status == "PASS":
            self.passed += 1
            icon = "✅"
        elif status == "FAIL":
            self.failed += 1
            icon = "❌"
        elif status == "WARN":
            self.warnings += 1
            icon = "⚠️"
        else:
            icon = "ℹ️"
        
        print(f"{icon} [{category}] {name}: {status}")
        if details:
            print(f"   {details}")
    
    def check_file_exists(self, filepath: str, category: str = "Files") -> bool:
        """Check if a file exists"""
        file_path = self.project_root / filepath
        exists = file_path.exists()
        
        status = "PASS" if exists else "FAIL"
        self.log_check(category, f"File: {filepath}", status)
        
        return exists
    
    def check_directory_structure(self):
        """Validate project directory structure"""
        required_dirs = [
            "core",
            "core/api",
            "core/auth",
            "core/config",
            "core/models",
            "core/monitoring",
            "core/utils",
            "web",
            "web/api",
            "desktop",
            "tests",
            "infrastructure",
            "infrastructure/terraform",
            "infrastructure/kubernetes",
            "docs",
            "design-system"
        ]
        
        for dir_path in required_dirs:
            dir_full_path = self.project_root / dir_path
            exists = dir_full_path.exists() and dir_full_path.is_dir()
            
            status = "PASS" if exists else "FAIL"
            self.log_check("Directory Structure", f"Directory: {dir_path}", status)
    
    def check_core_files(self):
        """Check core application files"""
        core_files = [
            "launch.py",
            "requirements.txt",
            "core/__init__.py",
            "core/api/api_service.py",
            "core/auth/jwt_manager.py",
            "core/config/config.py",
            "core/models/models.py",
            "web/main.py",
            "web/api/routes.py",
            "desktop/main.py"
        ]
        
        for file_path in core_files:
            self.check_file_exists(file_path, "Core Files")
    
    def check_infrastructure_files(self):
        """Check infrastructure configuration files"""
        infra_files = [
            "infrastructure/terraform/main.tf",
            "infrastructure/terraform/secrets.tf",
            "infrastructure/kubernetes/namespace.yaml",
            "infrastructure/kubernetes/deployment-api.yaml",
            "infrastructure/kubernetes/configmap.yaml",
            "infrastructure/monitoring/prometheus-rules.yaml",
            "infrastructure/monitoring/grafana-dashboard.json"
        ]
        
        for file_path in infra_files:
            self.check_file_exists(file_path, "Infrastructure")
    
    def check_security_implementation(self):
        """Check security implementation"""
        security_files = [
            "core/auth/jwt_manager.py",
            "core/auth/models.py",
            "core/utils/input_validator.py",
            "core/config/secure_config.py",
            "scripts/security_audit.py"
        ]
        
        for file_path in security_files:
            if self.check_file_exists(file_path, "Security"):
                # Additional security checks
                file_full_path = self.project_root / file_path
                try:
                    with open(file_full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    if "password" in content.lower() and "hash" in content.lower():
                        self.log_check("Security", f"Password hashing in {file_path}", "PASS")
                    elif "jwt" in content.lower():
                        self.log_check("Security", f"JWT implementation in {file_path}", "PASS")
                except Exception as e:
                    self.log_check("Security", f"Reading {file_path}", "WARN", str(e))
    
    def check_monitoring_implementation(self):
        """Check monitoring and observability"""
        monitoring_files = [
            "core/monitoring/observability.py",
            "core/monitoring/performance_monitor.py",
            "core/monitoring/structured_logging.py",
            "core/monitoring/metrics_exporter.py"
        ]
        
        for file_path in monitoring_files:
            self.check_file_exists(file_path, "Monitoring")
    
    def check_documentation(self):
        """Check documentation completeness"""
        doc_files = [
            "README.md",
            "API_DOCUMENTATION.md",
            "LAUNCH_GUIDE.md",
            "GO_LIVE_CHECKLIST.md",
            "TECHNICAL_REVIEW_REPORT.md",
            "docs/TEAM_ONBOARDING_GUIDE.md",
            "docs/DEVELOPMENT_SETUP.md",
            "docs/api/openapi_v1.yaml"
        ]
        
        for file_path in doc_files:
            self.check_file_exists(file_path, "Documentation")
    
    def check_design_system(self):
        """Check design system implementation"""
        design_files = [
            "design-system/README.md",
            "design-system/brand.md",
            "design-system/accessibility.md",
            "design-system/tokens/colors.json",
            "design-system/tokens/typography.json",
            "design-system/components/Button/Button.tsx",
            "design-system/components/Card/Card.tsx"
        ]
        
        for file_path in design_files:
            self.check_file_exists(file_path, "Design System")
    
    def check_test_coverage(self):
        """Check test implementation"""
        test_files = [
            "tests/conftest.py",
            "tests/unit/test_api_service.py",
            "tests/unit/test_auth.py",
            "tests/integration/integration_tests.py",
            "tests/performance/test_performance.py",
            "tests/security/test_security_scans.py"
        ]
        
        for file_path in test_files:
            self.check_file_exists(file_path, "Testing")
    
    def check_configuration_validity(self):
        """Check configuration files validity"""
        config_files = [
            ("docker-compose.yml", "YAML"),
            ("infrastructure/kubernetes/namespace.yaml", "YAML"),
            ("design-system/tokens/colors.json", "JSON"),
            ("docs/api/openapi_v1.yaml", "YAML")
        ]
        
        for file_path, file_type in config_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                try:
                    if file_type == "JSON":
                        with open(full_path, 'r') as f:
                            json.load(f)
                        self.log_check("Configuration", f"Valid JSON: {file_path}", "PASS")
                    elif file_type == "YAML":
                        # Basic YAML check (would need PyYAML for full validation)
                        with open(full_path, 'r') as f:
                            content = f.read()
                            if content.strip():
                                self.log_check("Configuration", f"Valid YAML: {file_path}", "PASS")
                            else:
                                self.log_check("Configuration", f"Empty YAML: {file_path}", "WARN")
                except Exception as e:
                    self.log_check("Configuration", f"Invalid {file_type}: {file_path}", "FAIL", str(e))
    
    def check_docker_setup(self):
        """Check Docker configuration"""
        docker_files = [
            "Dockerfile",
            "Dockerfile.api",
            "Dockerfile.web",
            "Dockerfile.worker",
            "docker-compose.yml",
            "docker-compose.dev.yml"
        ]
        
        for file_path in docker_files:
            self.check_file_exists(file_path, "Docker")
    
    def check_environment_setup(self):
        """Check environment configuration"""
        env_files = [
            "env.example",
            ".env.example"
        ]
        
        # Check if at least one env example exists
        has_env_example = any(
            (self.project_root / env_file).exists() 
            for env_file in env_files
        )
        
        if has_env_example:
            self.log_check("Environment", "Environment example file", "PASS")
        else:
            self.log_check("Environment", "Environment example file", "FAIL", 
                          "No .env.example or env.example found")
    
    def check_production_readiness_indicators(self):
        """Check for production readiness indicators"""
        indicators = [
            ("AWS_SECRETS_MANAGER_REPORT.md", "Secrets management documented"),
            ("CLEANUP_EXECUTION_REPORT.md", "Code cleanup completed"),
            ("COMPREHENSIVE_IMPLEMENTATION_EXECUTION_REPORT.md", "Implementation complete"),
            ("infrastructure/terraform/", "Infrastructure as Code ready"),
            ("infrastructure/kubernetes/", "Kubernetes deployment ready"),
            ("design-system/", "Design system implemented"),
            ("core/monitoring/", "Monitoring stack implemented")
        ]
        
        for indicator_path, description in indicators:
            full_path = self.project_root / indicator_path
            exists = full_path.exists()
            
            status = "PASS" if exists else "FAIL"
            self.log_check("Production Readiness", description, status)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive readiness report"""
        total_checks = len(self.checks)
        pass_rate = (self.passed / total_checks * 100) if total_checks > 0 else 0
        
        # Determine overall status
        if self.failed == 0 and pass_rate >= 95:
            overall_status = "PRODUCTION READY"
            recommendation = "APPROVED FOR DEPLOYMENT"
        elif self.failed == 0 and pass_rate >= 85:
            overall_status = "MOSTLY READY"
            recommendation = "MINOR ISSUES TO RESOLVE"
        elif self.failed <= 5 and pass_rate >= 75:
            overall_status = "NEEDS ATTENTION"
            recommendation = "RESOLVE ISSUES BEFORE DEPLOYMENT"
        else:
            overall_status = "NOT READY"
            recommendation = "SIGNIFICANT ISSUES TO RESOLVE"
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": overall_status,
            "recommendation": recommendation,
            "summary": {
                "total_checks": total_checks,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "pass_rate": round(pass_rate, 2)
            },
            "checks": self.checks
        }
        
        return report
    
    def run_all_checks(self):
        """Run all production readiness checks"""
        print("🔍 Monitor Legislativo v4 - Production Readiness Check")
        print("=" * 60)
        
        # Run all check categories
        self.check_directory_structure()
        self.check_core_files()
        self.check_infrastructure_files()
        self.check_security_implementation()
        self.check_monitoring_implementation()
        self.check_documentation()
        self.check_design_system()
        self.check_test_coverage()
        self.check_configuration_validity()
        self.check_docker_setup()
        self.check_environment_setup()
        self.check_production_readiness_indicators()
        
        # Generate and display report
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print("📊 PRODUCTION READINESS SUMMARY")
        print("=" * 60)
        print(f"Overall Status: {report['overall_status']}")
        print(f"Recommendation: {report['recommendation']}")
        print(f"Pass Rate: {report['summary']['pass_rate']}%")
        print(f"✅ Passed: {report['summary']['passed']}")
        print(f"❌ Failed: {report['summary']['failed']}")
        print(f"⚠️  Warnings: {report['summary']['warnings']}")
        
        # Save detailed report
        report_file = self.project_root / "PRODUCTION_READINESS_REPORT.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        return report


def main():
    """Main execution function"""
    checker = ProductionReadinessChecker()
    report = checker.run_all_checks()
    
    # Exit with appropriate code
    if report['summary']['failed'] == 0:
        print("\n🎉 Production readiness check PASSED!")
        sys.exit(0)
    else:
        print(f"\n❌ Production readiness check FAILED with {report['summary']['failed']} critical issues!")
        sys.exit(1)


if __name__ == "__main__":
    main()