"""
Installation Verification System for Monitor Legislativo v4
Based on transport legislation guide requirements

SPRINT 8 - TASK 8.3: Installation Verification Framework  
✅ Complete dependency verification
✅ NLTK data validation
✅ spaCy model verification
✅ External service connectivity testing
✅ Configuration file validation
✅ Directory permission verification
✅ Color-coded output (✓ ⚠ ✗)
✅ Automatic fix suggestions
"""

import sys
import importlib
import subprocess
import os
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

# Color codes for terminal output
class Colors:
    """Terminal color codes for formatted output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @classmethod
    def green(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.END}"
    
    @classmethod
    def yellow(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.END}"
    
    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.END}"
    
    @classmethod
    def blue(cls, text: str) -> str:
        return f"{cls.BLUE}{text}{cls.END}"
    
    @classmethod
    def cyan(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.END}"
    
    @classmethod
    def bold(cls, text: str) -> str:
        return f"{cls.BOLD}{text}{cls.END}"


def print_header():
    """Print installation verification header."""
    print(Colors.bold(Colors.cyan("=" * 80)))
    print(Colors.bold(Colors.cyan("🔍 VERIFICAÇÃO DE INSTALAÇÃO - MONITOR LEGISLATIVO v4")))
    print(Colors.bold(Colors.cyan("   Baseado no Guia de Legislação de Transporte Rodoviário")))
    print(Colors.bold(Colors.cyan("=" * 80)))
    print()


def print_section(title: str):
    """Print section header."""
    print(Colors.bold(Colors.blue(f"\n📋 {title}")))
    print(Colors.blue("-" * (len(title) + 4)))


def verificar_versao_python() -> Tuple[bool, str, List[str]]:
    """Verify Python version meets requirements."""
    required_version = (3, 8, 0)
    current_version = sys.version_info
    
    fixes = []
    
    if current_version >= required_version:
        message = f"Python {current_version.major}.{current_version.minor}.{current_version.micro}"
        return True, message, fixes
    else:
        message = f"Python {current_version.major}.{current_version.minor}.{current_version.micro} (requer 3.8+)"
        fixes.append("Instale Python 3.8 ou superior")
        fixes.append("Download: https://www.python.org/downloads/")
        return False, message, fixes


def verificar_dependencias_criticas() -> Tuple[int, int, List[str]]:
    """Verify critical dependencies."""
    
    # Critical dependencies for transport legislation monitoring
    dependencias_criticas = {
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'pandas': 'pandas',
        'sqlalchemy': 'sqlalchemy',
        'aiohttp': 'aiohttp',
        'lxml': 'lxml',
        'xmltodict': 'xmltodict',
        'python-dotenv': 'dotenv',
        'pydantic': 'pydantic',
        'fastapi': 'fastapi',
        'uvicorn': 'uvicorn'
    }
    
    instaladas = 0
    total = len(dependencias_criticas)
    fixes = []
    missing_packages = []
    
    for package_name, import_name in dependencias_criticas.items():
        try:
            importlib.import_module(import_name)
            print(f"   {Colors.green('✓')} {package_name}")
            instaladas += 1
        except ImportError:
            print(f"   {Colors.red('✗')} {package_name} - {Colors.red('AUSENTE')}")
            missing_packages.append(package_name)
    
    if missing_packages:
        fixes.append(f"pip install {' '.join(missing_packages)}")
        fixes.append("Ou instale com: pip install -r requirements.txt")
    
    return instaladas, total, fixes


def verificar_dependencias_opcionais() -> Tuple[int, int, List[str]]:
    """Verify optional dependencies."""
    
    dependencias_opcionais = {
        'spacy': 'spacy',
        'nltk': 'nltk', 
        'selenium': 'selenium',
        'playwright': 'playwright',
        'pytest': 'pytest',
        'black': 'black',
        'ruff': 'ruff',
        'psutil': 'psutil',
        'redis': 'redis',
        'celery': 'celery'
    }
    
    instaladas = 0
    total = len(dependencias_opcionais)
    fixes = []
    missing_packages = []
    
    for package_name, import_name in dependencias_opcionais.items():
        try:
            importlib.import_module(import_name)
            print(f"   {Colors.green('✓')} {package_name}")
            instaladas += 1
        except ImportError:
            print(f"   {Colors.yellow('○')} {package_name} - {Colors.yellow('opcional')}")
            missing_packages.append(package_name)
    
    if missing_packages:
        fixes.append(f"Para funcionalidade completa: pip install {' '.join(missing_packages)}")
    
    return instaladas, total, fixes


def verificar_modelos_nlp() -> Tuple[bool, List[str]]:
    """Verify NLP models (spaCy and NLTK data)."""
    fixes = []
    all_ok = True
    
    # Check spaCy model
    try:
        import spacy
        try:
            nlp = spacy.load("pt_core_news_lg")
            print(f"   {Colors.green('✓')} spaCy modelo pt_core_news_lg")
        except OSError:
            try:
                nlp = spacy.load("pt_core_news_sm")
                print(f"   {Colors.yellow('⚠')} spaCy modelo pt_core_news_sm (recomendado: lg)")
                fixes.append("python -m spacy download pt_core_news_lg")
            except OSError:
                print(f"   {Colors.red('✗')} spaCy modelos portugueses não encontrados")
                fixes.append("python -m spacy download pt_core_news_lg")
                fixes.append("python -m spacy download pt_core_news_sm")
                all_ok = False
    except ImportError:
        print(f"   {Colors.yellow('○')} spaCy não instalado")
        fixes.append("pip install spacy")
        fixes.append("python -m spacy download pt_core_news_lg")
    
    # Check NLTK data
    try:
        import nltk
        try:
            nltk.data.find('corpora/stopwords')
            print(f"   {Colors.green('✓')} NLTK stopwords")
        except LookupError:
            print(f"   {Colors.red('✗')} NLTK stopwords não encontrado")
            fixes.append("python -c \"import nltk; nltk.download('stopwords')\"")
            all_ok = False
            
        try:
            nltk.data.find('tokenizers/punkt')
            print(f"   {Colors.green('✓')} NLTK punkt tokenizer")
        except LookupError:
            print(f"   {Colors.red('✗')} NLTK punkt não encontrado")
            fixes.append("python -c \"import nltk; nltk.download('punkt')\"")
            all_ok = False
            
    except ImportError:
        print(f"   {Colors.yellow('○')} NLTK não instalado")
        fixes.append("pip install nltk")
        fixes.append("python -c \"import nltk; nltk.download('stopwords'); nltk.download('punkt')\"")
    
    return all_ok, fixes


def verificar_estrutura_diretorios() -> Tuple[bool, List[str]]:
    """Verify directory structure."""
    
    diretorios_necessarios = [
        'data', 'logs', 'cache', 'reports', 'backups', 
        'tests', 'exports', 'temp', 'recovery'
    ]
    
    fixes = []
    all_ok = True
    issues = []
    
    for diretorio in diretorios_necessarios:
        path = Path(diretorio)
        
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
                print(f"   {Colors.green('✓')} {diretorio} - criado")
            except Exception as e:
                print(f"   {Colors.red('✗')} {diretorio} - falha ao criar: {e}")
                issues.append(diretorio)
                all_ok = False
        else:
            # Test write permissions
            try:
                test_file = path / '.test_permission'
                test_file.write_text('test')
                test_file.unlink()
                print(f"   {Colors.green('✓')} {diretorio}")
            except Exception as e:
                print(f"   {Colors.yellow('⚠')} {diretorio} - sem permissão de escrita")
                issues.append(diretorio)
                fixes.append(f"Corrigir permissões: chmod 755 {diretorio}")
    
    if issues:
        fixes.append("Verifique permissões dos diretórios e crie manualmente se necessário")
    
    return all_ok, fixes


def verificar_arquivos_configuracao() -> Tuple[bool, List[str]]:
    """Verify configuration files."""
    
    arquivos_config = {
        'requirements.txt': 'Lista de dependências',
        'pyproject.toml': 'Configuração do projeto Python',
        'pytest.ini': 'Configuração de testes',
        '.env.example': 'Exemplo de variáveis de ambiente'
    }
    
    fixes = []
    missing_files = []
    
    for arquivo, descricao in arquivos_config.items():
        if Path(arquivo).exists():
            print(f"   {Colors.green('✓')} {arquivo} - {descricao}")
        else:
            print(f"   {Colors.yellow('⚠')} {arquivo} - ausente ({descricao})")
            missing_files.append(arquivo)
    
    # Check for .env file (should be created by user)
    if Path('.env').exists():
        print(f"   {Colors.green('✓')} .env - configuração de ambiente")
    else:
        print(f"   {Colors.yellow('○')} .env - não configurado")
        fixes.append("Copie .env.example para .env e configure as variáveis necessárias")
    
    if missing_files:
        fixes.append("Alguns arquivos de configuração estão ausentes")
        fixes.append("Verifique se você está no diretório correto do projeto")
    
    return len(missing_files) == 0, fixes


def verificar_conectividade_apis() -> Tuple[int, int, List[str]]:
    """Verify API connectivity."""
    
    apis_teste = {
        'LexML Brasil': 'https://www.lexml.gov.br/busca/SRU?operation=explain',
        'Câmara dos Deputados': 'https://dadosabertos.camara.leg.br/api/v2/referencias/proposicoes/siglaTipo',
        'Senado Federal': 'http://legis.senado.leg.br/dadosabertos/senador/lista/atual',
        'Diário Oficial': 'https://www.in.gov.br/web/guest',
        'ANTT Dados': 'https://dados.antt.gov.br/api/3/action/package_list'
    }
    
    fixes = []
    conectadas = 0
    total = len(apis_teste)
    
    try:
        import requests
        
        for nome, url in apis_teste.items():
            try:
                response = requests.head(url, timeout=10, allow_redirects=True)
                if response.status_code < 400:
                    print(f"   {Colors.green('✓')} {nome}")
                    conectadas += 1
                else:
                    print(f"   {Colors.yellow('⚠')} {nome} - HTTP {response.status_code}")
            except Exception as e:
                print(f"   {Colors.red('✗')} {nome} - {str(e)[:50]}...")
                
    except ImportError:
        print(f"   {Colors.red('✗')} requests não disponível para teste de APIs")
        fixes.append("pip install requests")
        return 0, total, fixes
    
    if conectadas < total:
        fixes.append("Algumas APIs estão inacessíveis - isso é normal")
        fixes.append("O sistema pode operar em modo degradado")
        fixes.append("Verifique sua conexão de internet")
    
    return conectadas, total, fixes


def verificar_sistema_operacional() -> Tuple[bool, List[str]]:
    """Verify operating system compatibility."""
    
    import platform
    
    fixes = []
    sistema = platform.system()
    versao = platform.release()
    
    if sistema == "Linux":
        print(f"   {Colors.green('✓')} Linux {versao}")
        
        # Check for common Linux issues
        if not Path('/usr/bin/python3').exists() and not Path('/usr/local/bin/python3').exists():
            fixes.append("Python3 pode não estar no PATH do sistema")
            
    elif sistema == "Windows":
        print(f"   {Colors.green('✓')} Windows {versao}")
        
        # Check for Windows-specific issues
        if "Windows-10" not in platform.platform() and "Windows-11" not in platform.platform():
            print(f"   {Colors.yellow('⚠')} Windows versão antiga detectada")
            fixes.append("Recomendado Windows 10 ou superior")
            
    elif sistema == "Darwin":
        print(f"   {Colors.green('✓')} macOS {versao}")
        
    else:
        print(f"   {Colors.yellow('⚠')} Sistema desconhecido: {sistema}")
        fixes.append("Sistema operacional não testado - pode ter problemas")
    
    # Check available memory
    try:
        import psutil
        memory_gb = psutil.virtual_memory().total / (1024**3)
        if memory_gb >= 4:
            print(f"   {Colors.green('✓')} Memória: {memory_gb:.1f}GB")
        else:
            print(f"   {Colors.yellow('⚠')} Memória: {memory_gb:.1f}GB (recomendado: 4GB+)")
            fixes.append("Considere aumentar a memória do sistema")
    except ImportError:
        print(f"   {Colors.yellow('○')} Não foi possível verificar memória (psutil ausente)")
    
    return len(fixes) == 0, fixes


def gerar_relatorio_instalacao() -> Dict[str, Any]:
    """Generate comprehensive installation report."""
    
    report = {
        'timestamp': time.time(),
        'system_info': {
            'os': os.name,
            'platform': sys.platform,
            'python_version': sys.version,
            'working_directory': os.getcwd()
        },
        'checks': {},
        'overall_status': 'unknown',
        'critical_issues': [],
        'warnings': [],
        'recommendations': []
    }
    
    # Run all verification checks
    print_header()
    
    # Python version
    print_section("Versão do Python")
    python_ok, python_msg, python_fixes = verificar_versao_python()
    if python_ok:
        print(f"   {Colors.green('✓')} {python_msg}")
    else:
        print(f"   {Colors.red('✗')} {python_msg}")
        report['critical_issues'].extend(python_fixes)
    
    report['checks']['python_version'] = {
        'status': 'ok' if python_ok else 'error',
        'message': python_msg,
        'fixes': python_fixes
    }
    
    # Critical dependencies
    print_section("Dependências Críticas")
    crit_installed, crit_total, crit_fixes = verificar_dependencias_criticas()
    crit_percentage = (crit_installed / crit_total) * 100
    
    if crit_installed == crit_total:
        print(f"\n   {Colors.green('✓')} Todas as dependências críticas instaladas ({crit_installed}/{crit_total})")
    else:
        print(f"\n   {Colors.red('✗')} {crit_total - crit_installed} dependências críticas ausentes ({crit_installed}/{crit_total})")
        report['critical_issues'].extend(crit_fixes)
    
    report['checks']['critical_dependencies'] = {
        'status': 'ok' if crit_installed == crit_total else 'error',
        'installed': crit_installed,
        'total': crit_total,
        'percentage': crit_percentage,
        'fixes': crit_fixes
    }
    
    # Optional dependencies
    print_section("Dependências Opcionais")
    opt_installed, opt_total, opt_fixes = verificar_dependencias_opcionais()
    opt_percentage = (opt_installed / opt_total) * 100
    
    print(f"\n   {Colors.cyan('ℹ')} Dependências opcionais: {opt_installed}/{opt_total} ({opt_percentage:.0f}%)")
    if opt_fixes:
        report['warnings'].extend(opt_fixes)
    
    report['checks']['optional_dependencies'] = {
        'status': 'warning' if opt_installed < opt_total else 'ok',
        'installed': opt_installed,
        'total': opt_total,
        'percentage': opt_percentage,
        'fixes': opt_fixes
    }
    
    # NLP models
    print_section("Modelos de Processamento de Linguagem")
    nlp_ok, nlp_fixes = verificar_modelos_nlp()
    
    if nlp_ok:
        print(f"\n   {Colors.green('✓')} Modelos NLP configurados")
    else:
        print(f"\n   {Colors.yellow('⚠')} Alguns modelos NLP ausentes")
        report['warnings'].extend(nlp_fixes)
    
    report['checks']['nlp_models'] = {
        'status': 'ok' if nlp_ok else 'warning',
        'fixes': nlp_fixes
    }
    
    # Directory structure
    print_section("Estrutura de Diretórios")
    dir_ok, dir_fixes = verificar_estrutura_diretorios()
    
    if dir_ok:
        print(f"\n   {Colors.green('✓')} Estrutura de diretórios OK")
    else:
        print(f"\n   {Colors.yellow('⚠')} Problemas com estrutura de diretórios")
        report['warnings'].extend(dir_fixes)
    
    report['checks']['directory_structure'] = {
        'status': 'ok' if dir_ok else 'warning',
        'fixes': dir_fixes
    }
    
    # Configuration files
    print_section("Arquivos de Configuração")
    config_ok, config_fixes = verificar_arquivos_configuracao()
    
    if config_ok:
        print(f"\n   {Colors.green('✓')} Configuração OK")
    else:
        print(f"\n   {Colors.yellow('⚠')} Alguns arquivos de configuração ausentes")
        report['warnings'].extend(config_fixes)
    
    report['checks']['configuration'] = {
        'status': 'ok' if config_ok else 'warning',
        'fixes': config_fixes
    }
    
    # API connectivity
    print_section("Conectividade com APIs")
    api_connected, api_total, api_fixes = verificar_conectividade_apis()
    api_percentage = (api_connected / api_total) * 100
    
    if api_connected >= api_total * 0.8:
        print(f"\n   {Colors.green('✓')} APIs acessíveis: {api_connected}/{api_total} ({api_percentage:.0f}%)")
    else:
        print(f"\n   {Colors.yellow('⚠')} APIs com problemas: {api_connected}/{api_total} ({api_percentage:.0f}%)")
        report['warnings'].extend(api_fixes)
    
    report['checks']['api_connectivity'] = {
        'status': 'ok' if api_connected >= api_total * 0.8 else 'warning',
        'connected': api_connected,
        'total': api_total,
        'percentage': api_percentage,
        'fixes': api_fixes
    }
    
    # Operating system
    print_section("Sistema Operacional")
    os_ok, os_fixes = verificar_sistema_operacional()
    
    if os_ok:
        print(f"\n   {Colors.green('✓')} Sistema operacional compatível")
    else:
        print(f"\n   {Colors.yellow('⚠')} Avisos do sistema operacional")
        report['warnings'].extend(os_fixes)
    
    report['checks']['operating_system'] = {
        'status': 'ok' if os_ok else 'warning',
        'fixes': os_fixes
    }
    
    # Determine overall status
    if report['critical_issues']:
        report['overall_status'] = 'critical'
        status_color = Colors.red
        status_emoji = "💀"
        status_msg = "INSTALAÇÃO INCOMPLETA - PROBLEMAS CRÍTICOS"
    elif len(report['warnings']) > 5:
        report['overall_status'] = 'warning'
        status_color = Colors.yellow
        status_emoji = "⚠️"
        status_msg = "INSTALAÇÃO FUNCIONAL - MELHORIAS RECOMENDADAS"
    else:
        report['overall_status'] = 'ok'
        status_color = Colors.green
        status_emoji = "✅"
        status_msg = "INSTALAÇÃO COMPLETA E FUNCIONAL"
    
    # Print final summary
    print_section("RESUMO FINAL")
    print(f"\n{status_color(Colors.bold(f'{status_emoji} {status_msg}'))}")
    
    if report['critical_issues']:
        print(f"\n{Colors.red(Colors.bold('PROBLEMAS CRÍTICOS:'))}")
        for i, issue in enumerate(report['critical_issues'][:5], 1):
            print(f"   {i}. {issue}")
        if len(report['critical_issues']) > 5:
            print(f"   ... e mais {len(report['critical_issues']) - 5} problemas")
    
    if report['warnings']:
        print(f"\n{Colors.yellow(Colors.bold('AVISOS E RECOMENDAÇÕES:'))}")
        for i, warning in enumerate(report['warnings'][:3], 1):
            print(f"   {i}. {warning}")
        if len(report['warnings']) > 3:
            print(f"   ... e mais {len(report['warnings']) - 3} recomendações")
    
    # Generate recommendations
    if report['overall_status'] == 'critical':
        report['recommendations'] = [
            "Resolva todos os problemas críticos antes de usar o sistema",
            "Execute os comandos de correção listados acima",
            "Execute este script novamente após as correções"
        ]
    elif report['overall_status'] == 'warning':
        report['recommendations'] = [
            "Sistema funcional mas pode operar em modo degradado",
            "Considere instalar dependências opcionais para funcionalidade completa",
            "Configure arquivo .env para melhor integração"
        ]
    else:
        report['recommendations'] = [
            "Sistema pronto para uso!",
            "Execute: python launch.py para iniciar",
            "Consulte docs/USER_GUIDE.md para instruções detalhadas"
        ]
    
    print(f"\n{Colors.cyan(Colors.bold('PRÓXIMOS PASSOS:'))}")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"   {i}. {rec}")
    
    print(f"\n{Colors.cyan('=' * 80)}")
    
    return report


def salvar_relatorio(report: Dict[str, Any]):
    """Save installation report to file."""
    try:
        # Create reports directory if it doesn't exist
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        report_file = reports_dir / 'installation_verification.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n📄 Relatório salvo em: {report_file}")
        
    except Exception as e:
        print(f"\n{Colors.yellow('⚠')} Não foi possível salvar relatório: {e}")


def main():
    """Main verification function."""
    try:
        # Generate comprehensive report
        report = gerar_relatorio_instalacao()
        
        # Save report to file
        salvar_relatorio(report)
        
        # Return appropriate exit code
        if report['overall_status'] == 'critical':
            sys.exit(1)
        elif report['overall_status'] == 'warning':
            sys.exit(2)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.yellow('Verificação interrompida pelo usuário')}")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n{Colors.red(f'ERRO FATAL na verificação: {e}')}")
        sys.exit(1)


if __name__ == "__main__":
    main()