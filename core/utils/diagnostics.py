"""
Comprehensive Diagnostic System for Monitor Legislativo v4
Based on transport legislation guide requirements

SPRINT 8 - TASK 8.1: Comprehensive Diagnostic System Implementation
✅ DiagnosticoSistema class with full system scanning
✅ Python version validation (3.8+ enforcement)
✅ Dependency verification (all 15+ packages)
✅ Directory structure validation
✅ Permission checking system
✅ Network connectivity testing
✅ Database connection validation
✅ Memory and disk space monitoring
✅ Automatic problem categorization (CRITICAL/HIGH/MEDIUM/LOW)
✅ Solution recommendation engine
"""

import sys
import subprocess
import platform
import importlib
import os
import shutil
import socket
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class ProblemSeverity(Enum):
    """Severity levels for detected problems."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class DiagnosticResult:
    """Result of a diagnostic check."""
    component: str
    status: str  # OK, WARNING, ERROR
    severity: ProblemSeverity
    message: str
    details: Dict[str, Any]
    solution: str = ""
    auto_fixable: bool = False


class DiagnosticoSistema:
    """
    Comprehensive system diagnostic framework with psychopath-level precision.
    
    Features:
    - Complete dependency validation
    - System resource monitoring
    - Network connectivity testing
    - Database health verification
    - Performance baseline establishment
    - Automatic problem categorization
    - Solution recommendation engine
    """
    
    def __init__(self):
        """Initialize diagnostic system."""
        self.problemas_encontrados = []
        self.avisos = []
        self.info_sistema = self._coletar_info_sistema()
        self.diagnostic_results = []
        
        # Required dependencies for transport legislation monitoring
        self.dependencias_criticas = [
            'requests', 'beautifulsoup4', 'pandas', 'sqlalchemy',
            'aiohttp', 'asyncio', 'lxml', 'xmltodict', 'psutil',
            'python-dotenv', 'pydantic', 'fastapi', 'uvicorn',
            'redis', 'celery'
        ]
        
        # Optional but recommended dependencies
        self.dependencias_opcionais = [
            'spacy', 'nltk', 'selenium', 'playwright', 'pytest',
            'black', 'ruff', 'mypy', 'coverage'
        ]
        
        # Required directories
        self.diretorios_necessarios = [
            'data', 'logs', 'cache', 'reports', 'backups', 
            'tests', 'exports', 'temp'
        ]
        
        # Minimum system requirements
        self.requisitos_minimos = {
            'python_version': (3, 8, 0),
            'memory_gb': 4,
            'disk_space_gb': 10,
            'cpu_cores': 2
        }
    
    def _coletar_info_sistema(self) -> Dict[str, Any]:
        """Collect comprehensive system information."""
        try:
            return {
                'os': platform.system(),
                'os_version': platform.version(),
                'os_release': platform.release(),
                'architecture': platform.architecture(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': sys.version,
                'python_version_info': sys.version_info,
                'python_executable': sys.executable,
                'python_path': sys.path,
                'current_directory': os.getcwd(),
                'user': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
                'home_directory': os.path.expanduser('~'),
                'environment_variables': dict(os.environ),
                'cpu_count': psutil.cpu_count() if PSUTIL_AVAILABLE else 'unknown',
                'memory_total': psutil.virtual_memory().total if PSUTIL_AVAILABLE else 'unknown',
                'disk_total': shutil.disk_usage('/').total if os.name != 'nt' else shutil.disk_usage('C:\\').total
            }
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {'error': str(e)}
    
    def executar_diagnostico_completo(self) -> Dict[str, Any]:
        """Execute comprehensive system diagnostic with military precision."""
        
        print("🔥 DIAGNÓSTICO COMPLETO DO SISTEMA - EXECUÇÃO IMPLACÁVEL 🔥")
        print("=" * 80)
        print(f"Sistema Operacional: {self.info_sistema.get('os', 'Unknown')}")
        print(f"Python: {platform.python_version()}")
        print(f"Diretório: {self.info_sistema.get('current_directory', 'Unknown')}")
        print(f"Usuário: {self.info_sistema.get('user', 'Unknown')}")
        print("=" * 80)
        
        # Execute all diagnostic checks
        self._verificar_python()
        self._verificar_dependencias()
        self._verificar_diretorios()
        self._verificar_permissoes()
        self._verificar_recursos_sistema()
        self._verificar_conectividade()
        self._verificar_apis()
        self._verificar_banco_dados()
        self._verificar_configuracao()
        self._verificar_performance()
        
        # Generate comprehensive report
        return self._gerar_relatorio_completo()
    
    def _verificar_python(self):
        """Verify Python version and installation."""
        versao_atual = sys.version_info
        versao_minima = self.requisitos_minimos['python_version']
        
        if versao_atual < versao_minima:
            self.diagnostic_results.append(DiagnosticResult(
                component="Python Version",
                status="ERROR",
                severity=ProblemSeverity.CRITICAL,
                message=f"Python {versao_atual.major}.{versao_atual.minor}.{versao_atual.micro} detectado. Necessário {versao_minima[0]}.{versao_minima[1]}+",
                details={
                    'current_version': f"{versao_atual.major}.{versao_atual.minor}.{versao_atual.micro}",
                    'required_version': f"{versao_minima[0]}.{versao_minima[1]}+",
                    'executable': sys.executable
                },
                solution="Instale Python 3.8 ou superior",
                auto_fixable=False
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="Python Version",
                status="OK",
                severity=ProblemSeverity.LOW,
                message=f"Python {versao_atual.major}.{versao_atual.minor}.{versao_atual.micro} ✓",
                details={
                    'version': f"{versao_atual.major}.{versao_atual.minor}.{versao_atual.micro}",
                    'executable': sys.executable
                }
            ))
    
    def _verificar_dependencias(self):
        """Verify all critical and optional dependencies."""
        
        # Check critical dependencies
        missing_critical = []
        for dep in self.dependencias_criticas:
            try:
                # Handle special cases for module names
                module_name = dep.replace('-', '_')
                if dep == 'beautifulsoup4':
                    module_name = 'bs4'
                elif dep == 'python-dotenv':
                    module_name = 'dotenv'
                
                importlib.import_module(module_name)
                print(f"✓ {dep}")
                
            except ImportError:
                missing_critical.append(dep)
                print(f"✗ {dep} - CRÍTICO")
        
        if missing_critical:
            self.diagnostic_results.append(DiagnosticResult(
                component="Critical Dependencies",
                status="ERROR",
                severity=ProblemSeverity.CRITICAL,
                message=f"{len(missing_critical)} dependências críticas ausentes",
                details={
                    'missing_packages': missing_critical,
                    'install_command': f"pip install {' '.join(missing_critical)}"
                },
                solution=f"Execute: pip install {' '.join(missing_critical)}",
                auto_fixable=True
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="Critical Dependencies",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Todas as dependências críticas instaladas ✓",
                details={'packages_checked': len(self.dependencias_criticas)}
            ))
        
        # Check optional dependencies
        missing_optional = []
        for dep in self.dependencias_opcionais:
            try:
                module_name = dep.replace('-', '_')
                importlib.import_module(module_name)
                print(f"✓ {dep} (opcional)")
            except ImportError:
                missing_optional.append(dep)
                print(f"- {dep} (opcional) - não instalado")
        
        if missing_optional:
            self.diagnostic_results.append(DiagnosticResult(
                component="Optional Dependencies",
                status="WARNING",
                severity=ProblemSeverity.MEDIUM,
                message=f"{len(missing_optional)} dependências opcionais ausentes",
                details={
                    'missing_packages': missing_optional,
                    'install_command': f"pip install {' '.join(missing_optional)}"
                },
                solution=f"Para funcionalidade completa: pip install {' '.join(missing_optional)}",
                auto_fixable=True
            ))
    
    def _verificar_diretorios(self):
        """Verify all required directories exist and are accessible."""
        missing_dirs = []
        permission_issues = []
        
        for diretorio in self.diretorios_necessarios:
            path = Path(diretorio)
            
            if not path.exists():
                missing_dirs.append(diretorio)
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    print(f"✓ Diretório {diretorio} criado")
                except Exception as e:
                    permission_issues.append({'dir': diretorio, 'error': str(e)})
                    print(f"✗ Falha ao criar {diretorio}: {e}")
            else:
                # Check write permissions
                try:
                    test_file = path / '.diagnostic_test'
                    test_file.write_text('test')
                    test_file.unlink()
                    print(f"✓ {diretorio} - OK")
                except Exception as e:
                    permission_issues.append({'dir': diretorio, 'error': str(e)})
                    print(f"⚠ {diretorio} - sem permissão de escrita")
        
        if missing_dirs or permission_issues:
            severity = ProblemSeverity.HIGH if permission_issues else ProblemSeverity.MEDIUM
            self.diagnostic_results.append(DiagnosticResult(
                component="Directory Structure",
                status="ERROR" if permission_issues else "WARNING",
                severity=severity,
                message=f"Problemas com diretórios: {len(missing_dirs)} ausentes, {len(permission_issues)} sem permissão",
                details={
                    'missing_directories': missing_dirs,
                    'permission_issues': permission_issues
                },
                solution="Verifique permissões do sistema e crie diretórios manualmente se necessário",
                auto_fixable=not bool(permission_issues)
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="Directory Structure",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Estrutura de diretórios OK ✓",
                details={'directories_checked': len(self.diretorios_necessarios)}
            ))
    
    def _verificar_permissoes(self):
        """Verify system permissions for critical operations."""
        permission_tests = []
        
        # Test file operations
        try:
            test_file = Path('temp_diagnostic_test.txt')
            test_file.write_text('test')
            test_file.unlink()
            permission_tests.append({'test': 'file_write', 'status': 'OK'})
        except Exception as e:
            permission_tests.append({'test': 'file_write', 'status': 'FAIL', 'error': str(e)})
        
        # Test network operations
        try:
            socket.create_connection(('8.8.8.8', 53), timeout=5)
            permission_tests.append({'test': 'network_access', 'status': 'OK'})
        except Exception as e:
            permission_tests.append({'test': 'network_access', 'status': 'FAIL', 'error': str(e)})
        
        failed_tests = [t for t in permission_tests if t['status'] == 'FAIL']
        
        if failed_tests:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Permissions",
                status="ERROR",
                severity=ProblemSeverity.HIGH,
                message=f"{len(failed_tests)} testes de permissão falharam",
                details={'failed_tests': failed_tests},
                solution="Verifique permissões de usuário e configuração do sistema",
                auto_fixable=False
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Permissions",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Permissões do sistema OK ✓",
                details={'tests_passed': len(permission_tests)}
            ))
    
    def _verificar_recursos_sistema(self):
        """Verify system resources meet minimum requirements."""
        
        if not PSUTIL_AVAILABLE:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Resources",
                status="WARNING",
                severity=ProblemSeverity.MEDIUM,
                message="psutil não disponível - verificação de recursos limitada",
                details={},
                solution="Instale psutil para verificação completa de recursos: pip install psutil",
                auto_fixable=True
            ))
            return
        
        # Memory check
        memory_gb = psutil.virtual_memory().total / (1024**3)
        memory_min = self.requisitos_minimos['memory_gb']
        
        # Disk space check
        if os.name == 'nt':
            disk_total, _, disk_free = shutil.disk_usage('C:\\')
        else:
            disk_total, _, disk_free = shutil.disk_usage('/')
        
        disk_free_gb = disk_free / (1024**3)
        disk_min = self.requisitos_minimos['disk_space_gb']
        
        # CPU check
        cpu_count = psutil.cpu_count()
        cpu_min = self.requisitos_minimos['cpu_cores']
        
        resource_issues = []
        
        if memory_gb < memory_min:
            resource_issues.append({
                'resource': 'memory',
                'current': f"{memory_gb:.1f}GB",
                'required': f"{memory_min}GB"
            })
        
        if disk_free_gb < disk_min:
            resource_issues.append({
                'resource': 'disk_space',
                'current': f"{disk_free_gb:.1f}GB",
                'required': f"{disk_min}GB"
            })
        
        if cpu_count < cpu_min:
            resource_issues.append({
                'resource': 'cpu_cores',
                'current': cpu_count,
                'required': cpu_min
            })
        
        if resource_issues:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Resources",
                status="WARNING",
                severity=ProblemSeverity.MEDIUM,
                message=f"Recursos do sistema abaixo do recomendado",
                details={
                    'memory_gb': memory_gb,
                    'disk_free_gb': disk_free_gb,
                    'cpu_count': cpu_count,
                    'issues': resource_issues
                },
                solution="Considere aumentar recursos do sistema para melhor performance",
                auto_fixable=False
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Resources",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Recursos do sistema adequados ✓",
                details={
                    'memory_gb': memory_gb,
                    'disk_free_gb': disk_free_gb,
                    'cpu_count': cpu_count
                }
            ))
    
    def _verificar_conectividade(self):
        """Verify network connectivity to critical services."""
        
        hosts_teste = [
            ('google.com', 80, 'Internet connectivity'),
            ('www.lexml.gov.br', 443, 'LexML Brasil'),
            ('dadosabertos.camara.leg.br', 443, 'Câmara dos Deputados'),
            ('legis.senado.leg.br', 80, 'Senado Federal'),
            ('www.in.gov.br', 443, 'Diário Oficial da União'),
            ('dados.antt.gov.br', 443, 'ANTT Data Portal')
        ]
        
        connectivity_issues = []
        successful_connections = 0
        
        for host, porta, descricao in hosts_teste:
            try:
                socket.create_connection((host, porta), timeout=10)
                print(f"✓ Conectividade OK com {descricao}")
                successful_connections += 1
            except Exception as e:
                connectivity_issues.append({
                    'host': host,
                    'port': porta,
                    'description': descricao,
                    'error': str(e)
                })
                print(f"✗ Falha de conectividade com {descricao}: {e}")
        
        if connectivity_issues:
            severity = ProblemSeverity.CRITICAL if successful_connections < 2 else ProblemSeverity.HIGH
            self.diagnostic_results.append(DiagnosticResult(
                component="Network Connectivity",
                status="ERROR",
                severity=severity,
                message=f"{len(connectivity_issues)} falhas de conectividade",
                details={
                    'successful_connections': successful_connections,
                    'total_tested': len(hosts_teste),
                    'failed_connections': connectivity_issues
                },
                solution="Verifique conexão com internet, firewall e configuração de rede",
                auto_fixable=False
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="Network Connectivity",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Conectividade de rede OK ✓",
                details={'successful_connections': successful_connections}
            ))
    
    def _verificar_apis(self):
        """Verify API endpoints are accessible."""
        try:
            from core.config.url_validator import URLValidator
            
            validator = URLValidator(timeout=15)
            results = validator.verify_all_urls()
            
            api_issues = []
            healthy_apis = 0
            
            for api_name, status in results.items():
                if status.status == "OK":
                    healthy_apis += 1
                    print(f"✓ API {api_name}: OK ({status.response_time_ms:.0f}ms)")
                else:
                    api_issues.append({
                        'api': api_name,
                        'status': status.status,
                        'error': status.error_message,
                        'response_time': status.response_time_ms
                    })
                    print(f"✗ API {api_name}: {status.error_message}")
            
            total_apis = len(results)
            availability_percentage = (healthy_apis / total_apis) * 100
            
            if availability_percentage < 50:
                severity = ProblemSeverity.CRITICAL
                status = "ERROR"
            elif availability_percentage < 80:
                severity = ProblemSeverity.HIGH
                status = "WARNING"
            else:
                severity = ProblemSeverity.LOW
                status = "OK"
            
            self.diagnostic_results.append(DiagnosticResult(
                component="API Endpoints",
                status=status,
                severity=severity,
                message=f"Disponibilidade das APIs: {availability_percentage:.1f}%",
                details={
                    'healthy_apis': healthy_apis,
                    'total_apis': total_apis,
                    'availability_percentage': availability_percentage,
                    'api_issues': api_issues
                },
                solution="Considere usar modo degradado ou cache local se muitas APIs estão indisponíveis",
                auto_fixable=False
            ))
            
        except ImportError:
            self.diagnostic_results.append(DiagnosticResult(
                component="API Endpoints",
                status="WARNING",
                severity=ProblemSeverity.MEDIUM,
                message="URL validator não disponível - pulando verificação de APIs",
                details={},
                solution="Instale dependências de rede para verificação completa de APIs",
                auto_fixable=False
            ))
    
    def _verificar_banco_dados(self):
        """Verify database connectivity and health."""
        try:
            import sqlite3
            
            # Test SQLite connectivity
            test_db_path = 'temp_diagnostic_test.db'
            try:
                conn = sqlite3.connect(test_db_path)
                cursor = conn.cursor()
                cursor.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
                cursor.execute("INSERT INTO test (id) VALUES (1)")
                cursor.execute("SELECT id FROM test WHERE id = 1")
                result = cursor.fetchone()
                conn.close()
                
                # Clean up
                os.remove(test_db_path)
                
                if result and result[0] == 1:
                    self.diagnostic_results.append(DiagnosticResult(
                        component="Database Connectivity",
                        status="OK",
                        severity=ProblemSeverity.LOW,
                        message="SQLite database functionality OK ✓",
                        details={'database_type': 'SQLite'}
                    ))
                else:
                    raise Exception("Database test query failed")
                    
            except Exception as e:
                self.diagnostic_results.append(DiagnosticResult(
                    component="Database Connectivity",
                    status="ERROR",
                    severity=ProblemSeverity.HIGH,
                    message=f"Falha no teste de banco de dados: {str(e)}",
                    details={'error': str(e)},
                    solution="Verifique configuração do banco de dados",
                    auto_fixable=False
                ))
                
        except ImportError:
            self.diagnostic_results.append(DiagnosticResult(
                component="Database Connectivity",
                status="ERROR",
                severity=ProblemSeverity.CRITICAL,
                message="SQLite não disponível",
                details={},
                solution="Instale sqlite3 ou configure banco de dados alternativo",
                auto_fixable=False
            ))
    
    def _verificar_configuracao(self):
        """Verify system configuration files and environment."""
        config_issues = []
        
        # Check for configuration files
        config_files = [
            '.env',
            'config.yaml',
            'requirements.txt'
        ]
        
        for config_file in config_files:
            if not Path(config_file).exists():
                config_issues.append(f"Missing configuration file: {config_file}")
        
        # Check critical environment variables
        critical_env_vars = [
            'PATH',
            'HOME' if os.name != 'nt' else 'USERPROFILE'
        ]
        
        for var in critical_env_vars:
            if not os.getenv(var):
                config_issues.append(f"Missing environment variable: {var}")
        
        if config_issues:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Configuration",
                status="WARNING",
                severity=ProblemSeverity.MEDIUM,
                message=f"{len(config_issues)} problemas de configuração",
                details={'issues': config_issues},
                solution="Verifique arquivos de configuração e variáveis de ambiente",
                auto_fixable=False
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Configuration",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Configuração do sistema OK ✓",
                details={}
            ))
    
    def _verificar_performance(self):
        """Verify system performance baseline."""
        
        # CPU performance test
        start_time = time.time()
        for _ in range(100000):
            _ = sum(range(100))
        cpu_test_time = time.time() - start_time
        
        if not PSUTIL_AVAILABLE:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Performance",
                status="WARNING",
                severity=ProblemSeverity.LOW,
                message="Verificação de performance limitada - psutil não disponível",
                details={'cpu_test_time': cpu_test_time},
                solution="Instale psutil para verificação completa: pip install psutil",
                auto_fixable=True
            ))
            return
        
        # Memory usage
        memory_usage = psutil.virtual_memory().percent
        
        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        
        performance_issues = []
        
        if cpu_test_time > 1.0:  # Should complete in less than 1 second
            performance_issues.append("CPU performance below expected")
        
        if memory_usage > 80:
            performance_issues.append(f"High memory usage: {memory_usage}%")
        
        if cpu_usage > 80:
            performance_issues.append(f"High CPU usage: {cpu_usage}%")
        
        if performance_issues:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Performance",
                status="WARNING",
                severity=ProblemSeverity.MEDIUM,
                message=f"Problemas de performance detectados",
                details={
                    'cpu_test_time': cpu_test_time,
                    'memory_usage_percent': memory_usage,
                    'cpu_usage_percent': cpu_usage,
                    'issues': performance_issues
                },
                solution="Monitore uso de recursos e otimize processos se necessário",
                auto_fixable=False
            ))
        else:
            self.diagnostic_results.append(DiagnosticResult(
                component="System Performance",
                status="OK",
                severity=ProblemSeverity.LOW,
                message="Performance do sistema OK ✓",
                details={
                    'cpu_test_time': cpu_test_time,
                    'memory_usage_percent': memory_usage,
                    'cpu_usage_percent': cpu_usage
                }
            ))
    
    def _gerar_relatorio_completo(self) -> Dict[str, Any]:
        """Generate comprehensive diagnostic report."""
        
        # Categorize results by severity
        critical_issues = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.CRITICAL]
        high_issues = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.HIGH]
        medium_issues = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.MEDIUM]
        low_issues = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.LOW]
        
        # Calculate overall system health
        total_checks = len(self.diagnostic_results)
        critical_count = len(critical_issues)
        high_count = len(high_issues)
        medium_count = len(medium_issues)
        
        if critical_count > 0:
            overall_status = "CRITICAL"
            health_score = 0
        elif high_count > 2:
            overall_status = "POOR"
            health_score = 25
        elif high_count > 0 or medium_count > 3:
            overall_status = "FAIR"
            health_score = 50
        elif medium_count > 0:
            overall_status = "GOOD"
            health_score = 75
        else:
            overall_status = "EXCELLENT"
            health_score = 100
        
        relatorio = {
            'timestamp': time.time(),
            'system_info': self.info_sistema,
            'overall_status': overall_status,
            'health_score': health_score,
            'total_checks': total_checks,
            'critical_issues': critical_count,
            'high_issues': high_count,
            'medium_issues': medium_count,
            'low_issues': len(low_issues),
            'detailed_results': [
                {
                    'component': r.component,
                    'status': r.status,
                    'severity': r.severity.value,
                    'message': r.message,
                    'details': r.details,
                    'solution': r.solution,
                    'auto_fixable': r.auto_fixable
                }
                for r in self.diagnostic_results
            ],
            'recommendations': self._gerar_recomendacoes()
        }
        
        # Print summary
        self._imprimir_resumo(relatorio)
        
        return relatorio
    
    def _gerar_recomendacoes(self) -> List[str]:
        """Generate actionable recommendations based on diagnostic results."""
        recommendations = []
        
        critical_issues = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.CRITICAL]
        high_issues = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.HIGH]
        auto_fixable = [r for r in self.diagnostic_results if r.auto_fixable and r.status == "ERROR"]
        
        if critical_issues:
            recommendations.append("🚨 AÇÃO IMEDIATA: Resolva problemas críticos antes de continuar")
            for issue in critical_issues:
                if issue.solution:
                    recommendations.append(f"   - {issue.solution}")
        
        if high_issues:
            recommendations.append("⚠️ ALTA PRIORIDADE: Problemas que afetam funcionalidade")
            for issue in high_issues:
                if issue.solution:
                    recommendations.append(f"   - {issue.solution}")
        
        if auto_fixable:
            recommendations.append("🔧 CORREÇÃO AUTOMÁTICA: Problemas que podem ser corrigidos automaticamente")
            for issue in auto_fixable:
                recommendations.append(f"   - {issue.solution}")
        
        # Add general recommendations
        api_issues = [r for r in self.diagnostic_results if r.component == "API Endpoints" and r.status != "OK"]
        if api_issues:
            recommendations.append("🌐 Configure modo degradado para operação offline se necessário")
        
        resource_issues = [r for r in self.diagnostic_results if r.component == "System Resources" and r.status == "WARNING"]
        if resource_issues:
            recommendations.append("💻 Considere aumentar recursos do sistema para melhor performance")
        
        return recommendations
    
    def _imprimir_resumo(self, relatorio: Dict[str, Any]):
        """Print diagnostic summary with psychopath-level formatting."""
        
        print("\n" + "=" * 80)
        print("🎯 RESUMO DO DIAGNÓSTICO IMPLACÁVEL")
        print("=" * 80)
        
        # Overall status with emoji
        status_emoji = {
            "EXCELLENT": "🟢",
            "GOOD": "🟡",
            "FAIR": "🟠",
            "POOR": "🔴",
            "CRITICAL": "💀"
        }
        
        print(f"\n{status_emoji.get(relatorio['overall_status'], '❓')} STATUS GERAL: {relatorio['overall_status']}")
        print(f"📊 PONTUAÇÃO DE SAÚDE: {relatorio['health_score']}/100")
        print(f"🔍 VERIFICAÇÕES REALIZADAS: {relatorio['total_checks']}")
        
        if relatorio['critical_issues'] > 0:
            print(f"\n💀 {relatorio['critical_issues']} PROBLEMAS CRÍTICOS:")
            critical_results = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.CRITICAL]
            for result in critical_results:
                print(f"   ❌ {result.message}")
                if result.solution:
                    print(f"      💡 SOLUÇÃO: {result.solution}")
        
        if relatorio['high_issues'] > 0:
            print(f"\n⚠️  {relatorio['high_issues']} PROBLEMAS ALTOS:")
            high_results = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.HIGH]
            for result in high_results:
                print(f"   🔶 {result.message}")
                if result.solution:
                    print(f"      💡 SOLUÇÃO: {result.solution}")
        
        if relatorio['medium_issues'] > 0:
            print(f"\nℹ️  {relatorio['medium_issues']} AVISOS:")
            medium_results = [r for r in self.diagnostic_results if r.severity == ProblemSeverity.MEDIUM]
            for result in medium_results:
                print(f"   🔸 {result.message}")
        
        # Print recommendations
        if relatorio['recommendations']:
            print(f"\n💡 RECOMENDAÇÕES:")
            for rec in relatorio['recommendations']:
                print(f"   {rec}")
        
        # Final verdict
        if relatorio['overall_status'] in ["EXCELLENT", "GOOD"]:
            print("\n✅ SISTEMA PRONTO PARA OPERAÇÃO!")
        else:
            print("\n❌ RESOLVA OS PROBLEMAS ACIMA ANTES DE CONTINUAR!")
        
        print("=" * 80)


# Main execution function
def executar_diagnostico_principal():
    """Main diagnostic execution function."""
    diagnostico = DiagnosticoSistema()
    return diagnostico.executar_diagnostico_completo()


if __name__ == "__main__":
    # Execute diagnostic when run directly
    executar_diagnostico_principal()