#!/bin/bash

# Development Environment Setup Script
# Monitor Legislativo v4
#
# Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
# Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas
# Financing: MackPesquisa - Instituto de Pesquisa Mackenzie

set -e

echo "🚀 Monitor Legislativo v4 - Development Environment Setup"
echo "Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
echo "Organization: MackIntegridade"
echo "Financing: MackPesquisa"
echo "=================================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on supported OS
check_os() {
    log "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        log "Detected Linux environment"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        log "Detected macOS environment"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        log "Detected Windows environment"
    else
        error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check Python installation
check_python() {
    log "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log "Found Python $PYTHON_VERSION"
        
        # Check if version is 3.8+
        if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
            log "Python version is compatible (3.8+)"
        else
            error "Python 3.8+ is required. Found: $PYTHON_VERSION"
            exit 1
        fi
    else
        error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
}

# Check Node.js installation (for frontend tooling)
check_nodejs() {
    log "Checking Node.js installation..."
    
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        log "Found Node.js $NODE_VERSION"
    else
        warn "Node.js not found. Some development tools may not work."
        log "Consider installing Node.js 16+ for frontend development"
    fi
}

# Check Docker installation
check_docker() {
    log "Checking Docker installation..."
    
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
        log "Found Docker $DOCKER_VERSION"
        
        # Check if Docker daemon is running
        if docker info &> /dev/null; then
            log "Docker daemon is running"
        else
            warn "Docker daemon is not running. Please start Docker."
        fi
    else
        warn "Docker not found. Container features will not be available."
        log "Consider installing Docker for containerized development"
    fi
}

# Create virtual environment
setup_virtual_environment() {
    log "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log "Created virtual environment"
    else
        log "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate || source venv/Scripts/activate
    log "Activated virtual environment"
    
    # Upgrade pip
    python -m pip install --upgrade pip
    log "Upgraded pip"
}

# Install Python dependencies
install_dependencies() {
    log "Installing Python dependencies..."
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        log "Installed production dependencies"
    else
        warn "requirements.txt not found"
    fi
    
    # Install development dependencies
    log "Installing development dependencies..."
    pip install \
        pytest \
        pytest-cov \
        pytest-asyncio \
        black \
        isort \
        flake8 \
        mypy \
        bandit \
        safety \
        pre-commit \
        mutmut \
        coverage
    
    log "Installed development dependencies"
}

# Setup pre-commit hooks
setup_pre_commit() {
    log "Setting up pre-commit hooks..."
    
    # Create pre-commit config if it doesn't exist
    if [ ! -f ".pre-commit-config.yaml" ]; then
        cat > .pre-commit-config.yaml << EOF
# Pre-commit configuration for Monitor Legislativo v4
# Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
# Organization: MackIntegridade

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=88, --extend-ignore=E203]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: [-r, .]
        exclude: ^tests/
EOF
        log "Created pre-commit configuration"
    fi
    
    # Install pre-commit hooks
    pre-commit install
    log "Installed pre-commit hooks"
}

# Setup development configuration
setup_dev_config() {
    log "Setting up development configuration..."
    
    # Create .env.development if it doesn't exist
    if [ ! -f ".env.development" ]; then
        cat > .env.development << EOF
# Development Environment Configuration
# Monitor Legislativo v4
# Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães

# Application
DEBUG=true
ENVIRONMENT=development
LOG_LEVEL=DEBUG

# Database
DATABASE_URL=sqlite:///data/dev_database.db

# Redis (for development)
REDIS_URL=redis://localhost:6379/0

# API Keys (use test keys)
CAMARA_API_KEY=test_key
SENADO_API_KEY=test_key
PLANALTO_API_KEY=test_key

# Security
SECRET_KEY=dev_secret_key_change_in_production
JWT_SECRET=dev_jwt_secret_change_in_production

# Monitoring
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000

# Attribution
PROJECT_DEVELOPERS="Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
PROJECT_ORGANIZATION="MackIntegridade"
PROJECT_FINANCING="MackPesquisa"
PROJECT_COLOR="#e1001e"
EOF
        log "Created development environment file"
    else
        log "Development environment file already exists"
    fi
}

# Setup IDE configuration
setup_ide_config() {
    log "Setting up IDE configuration..."
    
    # VSCode settings
    mkdir -p .vscode
    
    if [ ! -f ".vscode/settings.json" ]; then
        cat > .vscode/settings.json << EOF
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "python.linting.banditEnabled": true,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    },
    "files.associations": {
        "*.md": "markdown"
    },
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": [
        "tests"
    ]
}
EOF
        log "Created VSCode settings"
    fi
    
    if [ ! -f ".vscode/launch.json" ]; then
        cat > .vscode/launch.json << EOF
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Web Application",
            "type": "python",
            "request": "launch",
            "program": "web/main.py",
            "console": "integratedTerminal",
            "envFile": "\${workspaceFolder}/.env.development"
        },
        {
            "name": "Python: Desktop Application",
            "type": "python",
            "request": "launch",
            "program": "desktop/main.py",
            "console": "integratedTerminal",
            "envFile": "\${workspaceFolder}/.env.development"
        },
        {
            "name": "Python: Tests",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": ["tests/", "-v"],
            "console": "integratedTerminal"
        }
    ]
}
EOF
        log "Created VSCode launch configuration"
    fi
}

# Setup database
setup_database() {
    log "Setting up development database..."
    
    # Create data directories
    mkdir -p data/cache
    mkdir -p data/logs
    mkdir -p data/exports
    mkdir -p data/reports
    
    # Initialize database if needed
    if [ -f "core/database/schema.sql" ]; then
        log "Database schema found"
        # Note: Actual database initialization would depend on the database system
    fi
    
    log "Database directories created"
}

# Setup development scripts
setup_dev_scripts() {
    log "Setting up development scripts..."
    
    # Create development runner script
    cat > run_dev.sh << 'EOF'
#!/bin/bash
# Development Runner for Monitor Legislativo v4

echo "🚀 Starting Monitor Legislativo v4 Development Environment"

# Load environment
source .env.development

# Activate virtual environment
source venv/bin/activate || source venv/Scripts/activate

# Choose what to run
echo "Select what to run:"
echo "1) Web Application"
echo "2) Desktop Application"
echo "3) Tests"
echo "4) Code Quality Checks"
echo "5) Documentation Server"

read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        echo "Starting web application..."
        python web/main.py
        ;;
    2)
        echo "Starting desktop application..."
        python desktop/main.py
        ;;
    3)
        echo "Running tests..."
        python -m pytest tests/ -v
        ;;
    4)
        echo "Running code quality checks..."
        echo "Running Black..."
        black core/ web/ desktop/ tests/
        echo "Running isort..."
        isort core/ web/ desktop/ tests/
        echo "Running flake8..."
        flake8 core/ web/ desktop/
        echo "Running mypy..."
        mypy core/ web/ desktop/
        echo "Running bandit..."
        bandit -r core/ web/ desktop/
        ;;
    5)
        echo "Starting documentation server..."
        python -m http.server 8000 --directory docs/
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac
EOF
    
    chmod +x run_dev.sh
    log "Created development runner script"
}

# Run development checks
run_dev_checks() {
    log "Running development environment checks..."
    
    # Test imports
    python -c "import core.api.base_service; print('✅ Core API import successful')" || warn "Core API import failed"
    python -c "import core.auth.jwt_manager; print('✅ Auth import successful')" || warn "Auth import failed"
    python -c "import core.security.zero_trust; print('✅ Security import successful')" || warn "Security import failed"
    
    # Run a quick test
    if command -v pytest &> /dev/null; then
        log "Running quick test suite..."
        python -m pytest tests/ -x -q || warn "Some tests failed"
    fi
    
    log "Development environment checks completed"
}

# Main setup function
main() {
    log "Starting development environment setup..."
    
    check_os
    check_python
    check_nodejs
    check_docker
    setup_virtual_environment
    install_dependencies
    setup_pre_commit
    setup_dev_config
    setup_ide_config
    setup_database
    setup_dev_scripts
    run_dev_checks
    
    echo ""
    echo "🎉 Development environment setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Activate virtual environment: source venv/bin/activate"
    echo "2. Run development server: ./run_dev.sh"
    echo "3. Run tests: python -m pytest tests/"
    echo "4. Check code quality: pre-commit run --all-files"
    echo ""
    echo "Happy coding! 🚀"
    echo ""
    echo "Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    echo "Organization: MackIntegridade"
    echo "Financing: MackPesquisa"
}

# Run main function
main "$@"