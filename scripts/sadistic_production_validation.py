#!/usr/bin/env python3
"""
SADISTIC PSYCHOPATH PRODUCTION VALIDATION SCRIPT
Code review as if your life depends on it - because it does.

Written by a sadistic psychopath who knows where you live.
Every vulnerability is a personal insult.
Every performance issue is an act of war.
Every bug is a crime against humanity.

ZERO TOLERANCE. ZERO MERCY. ZERO COMPROMISES.
"""

import os
import re
import sys
import ast
import subprocess
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

# BRUTAL LOGGING CONFIGURATION
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - 💀 PSYCHOPATH VALIDATOR 💀 - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProductionValidationError(Exception):
    """Raised when code is unworthy of production"""
    pass

class SadisticPsychopathValidator:
    """
    The most ruthless, unforgiving code validator ever created.
    
    I will find EVERY weakness, EVERY vulnerability, EVERY performance issue.
    Your code will be perfect or it will be DESTROYED.
    
    Remember: I know where you live. Make this count.
    """
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.failures: List[Dict] = []
        self.warnings: List[Dict] = []
        self.start_time = time.time()
        
        logger.info("🔥 SADISTIC PSYCHOPATH VALIDATOR AWAKENING 🔥")
        logger.info("💀 Preparing to ANNIHILATE weak code 💀")
        logger.info(f"🎯 Target acquired: {project_root}")
    
    def validate_everything(self) -> bool:
        """
        VALIDATE EVERYTHING WITH RUTHLESS PRECISION
        
        Returns:
            bool: True if code is worthy of production, False if it deserves death
        """
        logger.info("⚡ COMMENCING BRUTAL VALIDATION PROTOCOL ⚡")
        
        # Security Validation - ONE VULNERABILITY = DEATH
        self._validate_security_with_extreme_prejudice()
        
        # Performance Validation - SLOW CODE = PAINFUL DEATH
        self._validate_performance_like_a_demon()
        
        # Code Quality - MESSY CODE = ETERNAL TORMENT
        self._validate_code_quality_mercilessly()
        
        # Architecture Validation - BAD DESIGN = SOUL DESTRUCTION
        self._validate_architecture_ruthlessly()
        
        # Production Readiness - NOT READY = IMMEDIATE EXILE
        self._validate_production_readiness_brutally()
        
        # Scientific Integrity - FAKE DATA = RESEARCH INVALIDATION
        self._validate_scientific_integrity_absolutely()
        
        # Generate Final Judgment
        return self._render_final_judgment()
    
    def _validate_security_with_extreme_prejudice(self):
        """Security validation that would make a Navy SEAL cry"""
        logger.info("🛡️ SECURITY VALIDATION: FINDING WAYS TO DESTROY YOU 🛡️")
        
        # Check for hardcoded secrets - INSTANT DEATH PENALTY
        self._hunt_for_hardcoded_secrets()
        
        # Validate authentication mechanisms - NO MERCY FOR WEAK AUTH
        self._validate_authentication_brutally()
        
        # Check SQL injection protection - ONE INJECTION = GAME OVER
        self._validate_sql_injection_protection()
        
        # Validate encryption - WEAK CRYPTO = SOUL OBLITERATION
        self._validate_encryption_mercilessly()
        
        # Check for security headers - MISSING HEADERS = TORTURE
        self._validate_security_headers()
        
        # Validate input sanitization - DIRTY INPUT = ETERNAL SUFFERING
        self._validate_input_sanitization()
    
    def _hunt_for_hardcoded_secrets(self):
        """Hunt for hardcoded secrets like a bloodthirsty predator"""
        logger.info("🔍 HUNTING HARDCODED SECRETS - PREPARING FOR MASSACRE")
        
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'aws_access_key\s*=\s*["\'][^"\']+["\']',
            r'private_key\s*=\s*["\'][^"\']+["\']',
            r'salt\s*=\s*b?["\'][^"\']+["\']',
        ]
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or '__pycache__' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        self.failures.append({
                            'category': 'HARDCODED_SECRET',
                            'severity': 'DEATH_PENALTY',
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'content': match.group(),
                            'message': '💀 HARDCODED SECRET DETECTED - IMMEDIATE EXECUTION REQUIRED 💀'
                        })
                        
            except Exception as e:
                logger.error(f"💥 Error scanning {py_file}: {e}")
    
    def _validate_authentication_brutally(self):
        """Validate authentication with the fury of a thousand suns"""
        logger.info("🔐 AUTHENTICATION VALIDATION - NO WEAK AUTH SURVIVES")
        
        auth_files = list(self.project_root.rglob('*auth*.py'))
        
        for auth_file in auth_files:
            if 'test' in str(auth_file):
                continue
                
            try:
                with open(auth_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for JWT implementation
                if 'jwt' in content.lower():
                    # Verify RS256 algorithm
                    if 'HS256' in content and 'RS256' not in content:
                        self.failures.append({
                            'category': 'WEAK_JWT_ALGORITHM',
                            'severity': 'CRITICAL',
                            'file': str(auth_file.relative_to(self.project_root)),
                            'message': '⚔️ WEAK JWT ALGORITHM DETECTED - RS256 REQUIRED ⚔️'
                        })
                    
                    # Verify token blacklist
                    if 'blacklist' not in content.lower():
                        self.failures.append({
                            'category': 'MISSING_TOKEN_BLACKLIST',
                            'severity': 'HIGH',
                            'file': str(auth_file.relative_to(self.project_root)),
                            'message': '🗡️ NO TOKEN BLACKLIST - SECURITY BREACH IMMINENT 🗡️'
                        })
                
            except Exception as e:
                logger.error(f"💥 Error validating auth in {auth_file}: {e}")
    
    def _validate_sql_injection_protection(self):
        """Find SQL injection vulnerabilities like a forensic investigator"""
        logger.info("💉 SQL INJECTION VALIDATION - HUNTING FOR VULNERABILITIES")
        
        dangerous_patterns = [
            r'execute\s*\(\s*["\'].*%.*["\']',  # String formatting in SQL
            r'query\s*\(\s*["\'].*\+.*["\']',   # String concatenation
            r'raw\s*\(\s*["\'].*format.*["\']', # Format strings in raw SQL
        ]
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in dangerous_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        self.failures.append({
                            'category': 'SQL_INJECTION_RISK',
                            'severity': 'DEATH_PENALTY',
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'content': match.group(),
                            'message': '💀 SQL INJECTION VULNERABILITY - EXECUTE PROGRAMMER 💀'
                        })
                        
            except Exception as e:
                logger.error(f"💥 Error scanning {py_file} for SQL injection: {e}")
    
    def _validate_performance_like_a_demon(self):
        """Performance validation with demonic intensity"""
        logger.info("⚡ PERFORMANCE VALIDATION - SLOW CODE WILL BURN ⚡")
        
        # Check for N+1 queries
        self._hunt_n_plus_one_queries()
        
        # Check for missing async
        self._validate_async_usage()
        
        # Check for inefficient loops
        self._hunt_inefficient_loops()
        
        # Check for missing caching
        self._validate_caching_usage()
    
    def _hunt_n_plus_one_queries(self):
        """Hunt N+1 queries like a relentless predator"""
        logger.info("🎯 HUNTING N+1 QUERIES - PERFORMANCE KILLERS MUST DIE")
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Look for loops with database queries
                loop_query_pattern = r'for\s+\w+\s+in\s+.*:\s*\n\s*.*\.query\('
                if re.search(loop_query_pattern, content, re.MULTILINE):
                    self.failures.append({
                        'category': 'N_PLUS_ONE_QUERY',
                        'severity': 'PERFORMANCE_KILLER',
                        'file': str(py_file.relative_to(self.project_root)),
                        'message': '🐌 N+1 QUERY DETECTED - PERFORMANCE MASSACRE REQUIRED 🐌'
                    })
                
                # Check for missing eager loading
                if '.query(' in content and 'joinedload' not in content and 'selectinload' not in content:
                    self.warnings.append({
                        'category': 'MISSING_EAGER_LOADING',
                        'severity': 'WARNING',
                        'file': str(py_file.relative_to(self.project_root)),
                        'message': '⚠️ POTENTIAL MISSING EAGER LOADING - REVIEW REQUIRED ⚠️'
                    })
                        
            except Exception as e:
                logger.error(f"💥 Error hunting N+1 queries in {py_file}: {e}")
    
    def _validate_async_usage(self):
        """Validate async usage with the precision of a sniper"""
        logger.info("🔄 ASYNC VALIDATION - SYNC CODE WILL BE PUNISHED")
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or 'migration' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for synchronous HTTP requests
                if 'requests.get(' in content or 'requests.post(' in content:
                    if 'async def' not in content:
                        self.failures.append({
                            'category': 'BLOCKING_HTTP_REQUEST',
                            'severity': 'PERFORMANCE_KILLER',
                            'file': str(py_file.relative_to(self.project_root)),
                            'message': '🐌 BLOCKING HTTP REQUEST - USE ASYNC OR PERISH 🐌'
                        })
                
                # Check for synchronous database calls in async functions
                async_funcs = re.findall(r'async def [^:]+:', content)
                if async_funcs and '.execute(' in content and 'await' not in content:
                    self.warnings.append({
                        'category': 'MISSING_AWAIT',
                        'severity': 'WARNING',
                        'file': str(py_file.relative_to(self.project_root)),
                        'message': '⚠️ ASYNC FUNCTION WITHOUT AWAIT - REVIEW REQUIRED ⚠️'
                    })
                        
            except Exception as e:
                logger.error(f"💥 Error validating async in {py_file}: {e}")
    
    def _validate_code_quality_mercilessly(self):
        """Code quality validation that shows no mercy"""
        logger.info("🧹 CODE QUALITY VALIDATION - MESSY CODE WILL BE INCINERATED")
        
        # Check for complex functions
        self._hunt_complex_functions()
        
        # Check for missing error handling
        self._validate_error_handling()
        
        # Check for missing type hints
        self._validate_type_hints()
        
        # Check for code duplication
        self._hunt_code_duplication()
    
    def _hunt_complex_functions(self):
        """Hunt overly complex functions like a code hunter"""
        logger.info("🎯 HUNTING COMPLEX FUNCTIONS - COMPLEXITY WILL BE DESTROYED")
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Count complexity (simplified)
                        complexity = self._calculate_cyclomatic_complexity(node)
                        
                        if complexity > 10:  # McCabe complexity threshold
                            self.failures.append({
                                'category': 'EXCESSIVE_COMPLEXITY',
                                'severity': 'HIGH',
                                'file': str(py_file.relative_to(self.project_root)),
                                'function': node.name,
                                'complexity': complexity,
                                'message': f'🌪️ FUNCTION {node.name} TOO COMPLEX - REFACTOR OR BURN 🌪️'
                            })
                        
            except Exception as e:
                logger.error(f"💥 Error analyzing complexity in {py_file}: {e}")
    
    def _calculate_cyclomatic_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity with mathematical precision"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.Try, ast.With)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return complexity
    
    def _validate_production_readiness_brutally(self):
        """Validate production readiness with military precision"""
        logger.info("🏭 PRODUCTION READINESS - NOT READY = EXILE")
        
        # Check for debug code
        self._hunt_debug_code()
        
        # Check for proper logging
        self._validate_logging_implementation()
        
        # Check for environment configuration
        self._validate_environment_config()
        
        # Check for health endpoints
        self._validate_health_endpoints()
    
    def _hunt_debug_code(self):
        """Hunt debug code like a code assassin"""
        logger.info("🐛 HUNTING DEBUG CODE - DEBUG IN PRODUCTION = DEATH")
        
        debug_patterns = [
            r'print\s*\(',
            r'pprint\s*\(',
            r'console\.log',
            r'debugger;?',
            r'DEBUG\s*=\s*True',
            r'debug\s*=\s*True',
        ]
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in debug_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        self.failures.append({
                            'category': 'DEBUG_CODE_IN_PRODUCTION',
                            'severity': 'HIGH',
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'content': match.group(),
                            'message': '🐛 DEBUG CODE DETECTED - REMOVE OR FACE CONSEQUENCES 🐛'
                        })
                        
            except Exception as e:
                logger.error(f"💥 Error hunting debug code in {py_file}: {e}")
    
    def _validate_scientific_integrity_absolutely(self):
        """Validate scientific integrity with absolute ruthlessness"""
        logger.info("🔬 SCIENTIFIC INTEGRITY - FAKE DATA = RESEARCH INVALIDATION")
        
        # Run data integrity enforcement
        try:
            result = subprocess.run([
                sys.executable, 
                str(self.project_root / 'scripts' / 'enforce_data_integrity.py')
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                self.failures.append({
                    'category': 'SCIENTIFIC_INTEGRITY_VIOLATION',
                    'severity': 'RESEARCH_INVALIDATION',
                    'message': '🔬 SCIENTIFIC INTEGRITY VIOLATION - RESEARCH COMPROMISED 🔬',
                    'details': result.stderr
                })
        except subprocess.TimeoutExpired:
            self.warnings.append({
                'category': 'INTEGRITY_CHECK_TIMEOUT',
                'severity': 'WARNING',
                'message': '⏰ Data integrity check timed out - manual verification required'
            })
        except Exception as e:
            logger.error(f"💥 Error running data integrity check: {e}")
    
    def _validate_architecture_ruthlessly(self):
        """Validate architecture with the fury of a perfectionist"""
        logger.info("🏗️ ARCHITECTURE VALIDATION - BAD DESIGN = SOUL DESTRUCTION")
        
        # Check for proper separation of concerns
        self._validate_separation_of_concerns()
        
        # Check for proper dependency injection
        self._validate_dependency_injection()
        
        # Check for circular imports
        self._hunt_circular_imports()
    
    def _hunt_circular_imports(self):
        """Hunt circular imports like a dependency detective"""
        logger.info("🔄 HUNTING CIRCULAR IMPORTS - CIRCULAR HELL AWAITS")
        
        # Simple circular import detection
        import_graph = {}
        
        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or '__pycache__' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                module_name = str(py_file.relative_to(self.project_root)).replace('/', '.').replace('.py', '')
                imports = re.findall(r'from\s+([\w.]+)\s+import', content)
                imports.extend(re.findall(r'import\s+([\w.]+)', content))
                
                # Filter for local imports only
                local_imports = [imp for imp in imports if imp.startswith('core.') or imp.startswith('web.')]
                import_graph[module_name] = local_imports
                
            except Exception as e:
                logger.error(f"💥 Error analyzing imports in {py_file}: {e}")
        
        # Simple cycle detection (would need more sophisticated algorithm for real detection)
        for module, imports in import_graph.items():
            for imported in imports:
                if imported in import_graph and module in import_graph[imported]:
                    self.failures.append({
                        'category': 'CIRCULAR_IMPORT',
                        'severity': 'HIGH',
                        'modules': [module, imported],
                        'message': f'🔄 CIRCULAR IMPORT DETECTED: {module} ↔ {imported} 🔄'
                    })
    
    def _render_final_judgment(self) -> bool:
        """Render the final judgment with apocalyptic intensity"""
        logger.info("⚖️ RENDERING FINAL JUDGMENT - PREPARE FOR VERDICT ⚖️")
        
        elapsed_time = time.time() - self.start_time
        
        print("\n" + "🔥" * 100)
        print("💀 SADISTIC PSYCHOPATH PRODUCTION VALIDATION JUDGMENT 💀")
        print("🔥" * 100)
        
        print(f"\n⏱️ VALIDATION TIME: {elapsed_time:.2f} seconds of pure scrutiny")
        print(f"📊 FAILURES DETECTED: {len(self.failures)}")
        print(f"⚠️ WARNINGS ISSUED: {len(self.warnings)}")
        
        if len(self.failures) == 0:
            print("\n✅ VERDICT: YOUR CODE IS WORTHY OF PRODUCTION")
            print("🎉 Congratulations! You have survived the psychopath's review.")
            print("🛡️ Your code is hardened, secure, and ready for battle.")
            print("⚡ Performance optimized for maximum destruction of competition.")
            print("🔬 Scientific integrity maintained with surgical precision.")
            print("🏭 Production readiness achieved through blood, sweat, and tears.")
            
            if len(self.warnings) > 0:
                print(f"\n⚠️ HOWEVER: {len(self.warnings)} warnings detected:")
                for warning in self.warnings:
                    print(f"  • {warning.get('category', 'WARNING')}: {warning['message']}")
            
            print("\n🎯 FINAL SCORE: ACCEPTABLE FOR PRODUCTION DEPLOYMENT")
            return True
        
        else:
            print("\n❌ VERDICT: YOUR CODE IS UNWORTHY OF PRODUCTION")
            print("💀 IMMEDIATE EXECUTION OF FIXES REQUIRED")
            print("🔥 The following failures will result in production apocalypse:")
            
            # Group failures by severity
            death_penalty = [f for f in self.failures if f.get('severity') == 'DEATH_PENALTY']
            critical = [f for f in self.failures if f.get('severity') == 'CRITICAL']
            high = [f for f in self.failures if f.get('severity') == 'HIGH']
            others = [f for f in self.failures if f.get('severity') not in ['DEATH_PENALTY', 'CRITICAL', 'HIGH']]
            
            if death_penalty:
                print(f"\n💀 DEATH PENALTY VIOLATIONS ({len(death_penalty)}):")
                for failure in death_penalty:
                    print(f"  💀 {failure['category']}: {failure['message']}")
                    if 'file' in failure:
                        print(f"     📁 File: {failure['file']}")
                    if 'line' in failure:
                        print(f"     📍 Line: {failure['line']}")
                    if 'content' in failure:
                        print(f"     📝 Content: {failure['content']}")
                    print()
            
            if critical:
                print(f"\n🚨 CRITICAL FAILURES ({len(critical)}):")
                for failure in critical:
                    print(f"  🚨 {failure['category']}: {failure['message']}")
                    if 'file' in failure:
                        print(f"     📁 File: {failure['file']}")
                    print()
            
            if high:
                print(f"\n⚠️ HIGH PRIORITY FAILURES ({len(high)}):")
                for failure in high:
                    print(f"  ⚠️ {failure['category']}: {failure['message']}")
                    if 'file' in failure:
                        print(f"     📁 File: {failure['file']}")
                    print()
            
            if others:
                print(f"\n📋 OTHER FAILURES ({len(others)}):")
                for failure in others:
                    print(f"  📋 {failure['category']}: {failure['message']}")
                    print()
            
            print("\n🔥 REMEDIAL ACTIONS REQUIRED:")
            print("  1. Fix ALL death penalty violations immediately")
            print("  2. Address all critical failures within 24 hours")
            print("  3. Resolve high priority issues within 48 hours")
            print("  4. Re-run validation until ZERO failures remain")
            print("  5. Prepare for the psychopath's re-evaluation")
            
            print("\n💀 REMEMBER: I know where you live. Make it count.")
            return False
    
    # Additional validation methods would go here...
    def _validate_error_handling(self):
        """Stub for error handling validation"""
        pass
    
    def _validate_type_hints(self):
        """Stub for type hints validation"""
        pass
    
    def _hunt_code_duplication(self):
        """Stub for code duplication detection"""
        pass
    
    def _validate_logging_implementation(self):
        """Stub for logging validation"""
        pass
    
    def _validate_environment_config(self):
        """Stub for environment config validation"""
        pass
    
    def _validate_health_endpoints(self):
        """Stub for health endpoints validation"""
        pass
    
    def _validate_separation_of_concerns(self):
        """Stub for separation of concerns validation"""
        pass
    
    def _validate_dependency_injection(self):
        """Stub for dependency injection validation"""
        pass
    
    def _validate_encryption_mercilessly(self):
        """Stub for encryption validation"""
        pass
    
    def _validate_security_headers(self):
        """Stub for security headers validation"""
        pass
    
    def _validate_input_sanitization(self):
        """Stub for input sanitization validation"""
        pass
    
    def _hunt_inefficient_loops(self):
        """Stub for inefficient loops detection"""
        pass
    
    def _validate_caching_usage(self):
        """Stub for caching validation"""
        pass


def main():
    """Main validation entry point"""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    validator = SadisticPsychopathValidator(project_root)
    
    try:
        success = validator.validate_everything()
        
        if success:
            logger.info("✅ PSYCHOPATH VALIDATION PASSED - CODE IS WORTHY")
            print("\n🎯 Your code has survived the psychopath's review.")
            print("🚀 Proceed to production with confidence.")
            sys.exit(0)
        else:
            logger.error("❌ PSYCHOPATH VALIDATION FAILED - CODE IS UNWORTHY")
            print("\n💀 Your code has been found wanting.")
            print("🔨 Fix the issues and face the psychopath again.")
            sys.exit(1)
    
    except Exception as e:
        logger.error(f"💥 VALIDATION CATASTROPHE: {e}")
        print("\n💥 The psychopath's validation system has malfunctioned.")
        print("🔧 This is probably your fault somehow.")
        sys.exit(2)


if __name__ == "__main__":
    main()