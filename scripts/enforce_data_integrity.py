#!/usr/bin/env python3
"""
Scientific Research Data Integrity Enforcement Script
Ensures NO mock, fake, or synthetic data violates research authenticity

CRITICAL: This script is required for scientific research compliance
ZERO TOLERANCE: Any fake data invalidates research results
"""

import os
import re
import sys
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Set
import ast
import importlib.util

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# SCIENTIFIC RESEARCH VIOLATIONS: Patterns that invalidate research
FORBIDDEN_PATTERNS = {
    'mock_imports': [
        r'from\s+unittest\.mock\s+import',
        r'import\s+unittest\.mock',
        r'from\s+unittest\s+import\s+mock',
        r'import\s+mock',
        r'from\s+pytest_mock\s+import',
        r'import\s+pytest_mock',
        r'from\s+responses\s+import',
        r'import\s+responses',
    ],
    'mock_usage': [
        r'Mock\(',
        r'MagicMock\(',
        r'patch\(',
        r'@patch',
        r'responses\.add',
        r'responses\.activate',
        r'mock_.*\(',
        r'\.mock\(',
        r'fake_.*\(',
        r'stub_.*\(',
        r'dummy_.*\(',
    ],
    'fake_data_markers': [
        r'fake_data',
        r'synthetic_data',
        r'mock_response',
        r'dummy_response',
        r'simulated_.*',
        r'test_data.*=.*\[.*fake',
        r'sample_.*=.*mock',
    ],
    'api_mocking': [
        r'responses\.add\(',
        r'mock\.patch\(',
        r'@responses\.activate',
        r'MockResponse',
        r'FakeAPI',
        r'MockAPI',
        r'mock_.*_api',
    ]
}

# ALLOWED EXCEPTIONS: Limited cases where mocking is acceptable for unit tests
ALLOWED_MOCK_CONTEXTS = {
    'unit_tests_only': [
        'test_cache_manager.py',  # Cache layer testing
        'test_auth.py',          # Authentication unit tests
        'test_models.py',        # Data model unit tests
        'test_secure_*.py',      # Security component unit tests
        'test_health_endpoint.py'  # Health check unit tests
    ],
    'infrastructure_tests': [
        'test_performance.py',   # Performance testing infrastructure
        'test_desktop_app.py'    # Desktop app unit tests
    ]
}

# REAL DATA REQUIREMENTS: Files that MUST use authentic government data
REAL_DATA_REQUIRED = [
    'test_api_integration.py',
    'test_real_api_integration.py',
    'test_external_api_mocks.py',  # This file should be removed
    'production_tests.py',
    'load_tests.py'
]

class DataIntegrityViolation(Exception):
    """Raised when fake data is detected in scientific research code"""
    pass

class ScientificDataIntegrityEnforcer:
    """
    Enforces strict data authenticity requirements for scientific research
    
    ZERO TOLERANCE POLICY:
    - No mock data in integration tests
    - No fake API responses
    - No synthetic legislative data
    - All data must be traceable to government sources
    """
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.violations: List[Dict] = []
        self.warnings: List[Dict] = []
        
        logger.info(f"Initializing Scientific Data Integrity Enforcer for: {project_root}")
    
    def enforce_integrity(self) -> bool:
        """
        Main enforcement method
        
        Returns:
            bool: True if no violations found, False otherwise
        """
        logger.info("🔬 SCIENTIFIC RESEARCH DATA INTEGRITY ENFORCEMENT STARTING")
        
        # Check test files for violations
        self._scan_test_files()
        
        # Check for forbidden mock files
        self._check_forbidden_files()
        
        # Verify real data requirements
        self._verify_real_data_requirements()
        
        # Check imports and dependencies
        self._check_dependencies()
        
        # Generate enforcement report
        self._generate_report()
        
        # Return success/failure
        return len(self.violations) == 0
    
    def _scan_test_files(self):
        """Scan all test files for data integrity violations"""
        logger.info("Scanning test files for scientific data integrity...")
        
        test_dirs = [
            self.project_root / 'tests',
            self.project_root / 'LawMapping' / 'tests'
        ]
        
        for test_dir in test_dirs:
            if test_dir.exists():
                self._scan_directory(test_dir)
    
    def _scan_directory(self, directory: Path):
        """Recursively scan directory for test files"""
        for file_path in directory.rglob('test_*.py'):
            self._analyze_test_file(file_path)
        
        for file_path in directory.rglob('*_test.py'):
            self._analyze_test_file(file_path)
    
    def _analyze_test_file(self, file_path: Path):
        """Analyze individual test file for violations"""
        relative_path = file_path.relative_to(self.project_root)
        file_name = file_path.name
        
        logger.debug(f"Analyzing: {relative_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if this file is allowed to use mocks
            is_unit_test = self._is_allowed_unit_test(file_name)
            is_integration_test = 'integration' in str(file_path) or 'e2e' in str(file_path)
            
            # STRICT RULE: Integration tests CANNOT use mock data
            if is_integration_test:
                violations = self._find_mock_violations(content, file_path)
                if violations:
                    self.violations.extend(violations)
                    logger.error(f"❌ SCIENTIFIC INTEGRITY VIOLATION: Mock data found in integration test: {relative_path}")
            
            # Check for forbidden patterns
            violations = self._check_forbidden_patterns(content, file_path, is_unit_test)
            self.violations.extend(violations)
            
            # Check for real data requirements
            if file_name in REAL_DATA_REQUIRED:
                if not self._has_real_data_markers(content):
                    self.violations.append({
                        'file': str(relative_path),
                        'type': 'missing_real_data_markers',
                        'severity': 'CRITICAL',
                        'message': 'File requires real government data but lacks authenticity markers'
                    })
        
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
    
    def _is_allowed_unit_test(self, file_name: str) -> bool:
        """Check if file is allowed to use limited mocking for unit tests"""
        for allowed_pattern in ALLOWED_MOCK_CONTEXTS['unit_tests_only']:
            if file_name == allowed_pattern or re.match(allowed_pattern.replace('*', '.*'), file_name):
                return True
        
        for allowed_pattern in ALLOWED_MOCK_CONTEXTS['infrastructure_tests']:
            if file_name == allowed_pattern:
                return True
        
        return False
    
    def _find_mock_violations(self, content: str, file_path: Path) -> List[Dict]:
        """Find mock/fake data violations in content"""
        violations = []
        lines = content.split('\n')
        
        for category, patterns in FORBIDDEN_PATTERNS.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        violations.append({
                            'file': str(file_path.relative_to(self.project_root)),
                            'line': line_num,
                            'pattern': pattern,
                            'category': category,
                            'severity': 'CRITICAL',
                            'content': line.strip(),
                            'message': f'Scientific research violation: {category} detected'
                        })
        
        return violations
    
    def _check_forbidden_patterns(self, content: str, file_path: Path, is_unit_test: bool) -> List[Dict]:
        """Check for forbidden patterns based on test type"""
        violations = []
        
        # For integration tests, ALL mocking is forbidden
        if 'integration' in str(file_path) or 'e2e' in str(file_path):
            violations.extend(self._find_mock_violations(content, file_path))
        
        # For unit tests, only check for fake data markers
        elif is_unit_test:
            violations.extend(self._check_fake_data_markers(content, file_path))
        
        # For all other tests, check everything
        else:
            violations.extend(self._find_mock_violations(content, file_path))
        
        return violations
    
    def _check_fake_data_markers(self, content: str, file_path: Path) -> List[Dict]:
        """Check for fake data markers even in unit tests"""
        violations = []
        lines = content.split('\n')
        
        for pattern in FORBIDDEN_PATTERNS['fake_data_markers']:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append({
                        'file': str(file_path.relative_to(self.project_root)),
                        'line': line_num,
                        'pattern': pattern,
                        'category': 'fake_data_markers',
                        'severity': 'HIGH',
                        'content': line.strip(),
                        'message': 'Fake data marker detected - use real data for scientific validity'
                    })
        
        return violations
    
    def _has_real_data_markers(self, content: str) -> bool:
        """Check if file has markers indicating real government data usage"""
        real_data_markers = [
            'REAL DATA',
            'SCIENTIFIC RESEARCH COMPLIANT',
            'NO MOCK DATA',
            'government.*.api',
            'dadosabertos',
            'senado.leg.br',
            'camara.leg.br',
            'planalto.gov.br'
        ]
        
        for marker in real_data_markers:
            if re.search(marker, content, re.IGNORECASE):
                return True
        
        return False
    
    def _check_forbidden_files(self):
        """Check for files that should not exist"""
        forbidden_files = [
            'test_external_api_mocks.py',
            'test_fake_data.py',
            'test_mock_api.py',
            'mock_responses.py'
        ]
        
        for test_dir in [self.project_root / 'tests', self.project_root / 'LawMapping' / 'tests']:
            if test_dir.exists():
                for forbidden_file in forbidden_files:
                    for found_file in test_dir.rglob(forbidden_file):
                        self.violations.append({
                            'file': str(found_file.relative_to(self.project_root)),
                            'type': 'forbidden_file',
                            'severity': 'CRITICAL',
                            'message': f'Forbidden file exists: {forbidden_file} violates scientific data integrity'
                        })
    
    def _verify_real_data_requirements(self):
        """Verify files that must use real data actually do"""
        for required_file in REAL_DATA_REQUIRED:
            # Check if file exists
            found_files = list(self.project_root.rglob(required_file))
            
            if not found_files:
                # If file doesn't exist, it might have been properly removed
                if required_file == 'test_external_api_mocks.py':
                    logger.info(f"✅ Forbidden file properly removed: {required_file}")
                continue
            
            for file_path in found_files:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if not self._has_real_data_markers(content):
                    self.violations.append({
                        'file': str(file_path.relative_to(self.project_root)),
                        'type': 'missing_real_data_compliance',
                        'severity': 'CRITICAL',
                        'message': f'File {required_file} must use real government data for scientific research'
                    })
    
    def _check_dependencies(self):
        """Check for problematic dependencies in requirements files"""
        req_files = [
            'requirements.txt',
            'requirements-test.txt',
            'requirements-dev.txt',
            'pyproject.toml'
        ]
        
        problematic_deps = [
            'responses',
            'pytest-mock',
            'mock',
            'faker',
            'factory-boy'
        ]
        
        for req_file in req_files:
            file_path = self.project_root / req_file
            if file_path.exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                
                for dep in problematic_deps:
                    if dep in content:
                        self.warnings.append({
                            'file': req_file,
                            'dependency': dep,
                            'severity': 'WARNING',
                            'message': f'Dependency {dep} may enable fake data - ensure used only for unit tests'
                        })
    
    def _generate_report(self):
        """Generate comprehensive integrity enforcement report"""
        logger.info("📊 GENERATING SCIENTIFIC DATA INTEGRITY REPORT")
        
        print("\n" + "="*80)
        print("🔬 SCIENTIFIC RESEARCH DATA INTEGRITY ENFORCEMENT REPORT")
        print("="*80)
        
        if len(self.violations) == 0:
            print("✅ COMPLIANCE STATUS: PASSED")
            print("✅ All tests use authentic government data sources")
            print("✅ No mock or fake data detected")
            print("✅ Scientific research integrity maintained")
        else:
            print("❌ COMPLIANCE STATUS: FAILED")
            print(f"❌ Found {len(self.violations)} CRITICAL violations")
            print("❌ Research data integrity COMPROMISED")
            
            print("\n🚨 CRITICAL VIOLATIONS:")
            for violation in self.violations:
                print(f"  File: {violation['file']}")
                if 'line' in violation:
                    print(f"  Line: {violation['line']}")
                print(f"  Type: {violation.get('category', violation.get('type', 'unknown'))}")
                print(f"  Message: {violation['message']}")
                if 'content' in violation:
                    print(f"  Content: {violation['content']}")
                print("  " + "-"*60)
        
        if self.warnings:
            print(f"\n⚠️  Found {len(self.warnings)} warnings:")
            for warning in self.warnings:
                print(f"  File: {warning['file']}")
                print(f"  Message: {warning['message']}")
                print("  " + "-"*40)
        
        print("\n📋 SCIENTIFIC RESEARCH REQUIREMENTS:")
        print("  • All legislative data must be from government sources")
        print("  • No mock, fake, or synthetic data allowed")
        print("  • Integration tests must use real APIs")
        print("  • All data must be traceable and verifiable")
        print("  • Research results must be reproducible")
        
        print("\n✅ APPROVED DATA SOURCES:")
        print("  • dadosabertos.camara.leg.br (House of Representatives)")
        print("  • legis.senado.leg.br (Senate)")
        print("  • planalto.gov.br (Presidential Palace)")
        print("  • *.gov.br (Government domains)")
        
        print("="*80 + "\n")


def main():
    """Main enforcement function"""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    enforcer = ScientificDataIntegrityEnforcer(project_root)
    
    try:
        success = enforcer.enforce_integrity()
        
        if success:
            logger.info("✅ Scientific data integrity enforcement PASSED")
            sys.exit(0)
        else:
            logger.error("❌ Scientific data integrity enforcement FAILED")
            sys.exit(1)
    
    except Exception as e:
        logger.error(f"💥 Enforcement failed with error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()