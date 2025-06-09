#!/bin/bash
# Setup script for Legislative Monitoring System development environment

echo "🚀 Legislative Monitoring System - Environment Setup"
echo "=================================================="

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.9+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✅ Python version: $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null

# Upgrade pip
echo "📦 Upgrading pip..."
python -m pip install --upgrade pip

# Install production requirements if exists
if [ -f "requirements.txt" ]; then
    echo "📦 Installing production dependencies..."
    pip install -r requirements.txt
fi

# Install development requirements
if [ -f "requirements-dev.txt" ]; then
    echo "📦 Installing development dependencies..."
    pip install -r requirements-dev.txt
fi

# Install pre-commit hooks
if command -v pre-commit &> /dev/null; then
    echo "🔗 Installing pre-commit hooks..."
    pre-commit install
fi

# Create necessary directories
echo "📁 Creating directory structure..."
mkdir -p data/reports
mkdir -p data/cache
mkdir -p data/exports
mkdir -p data/logs
mkdir -p docs/api
mkdir -p docs/architecture
mkdir -p docs/deployment
mkdir -p docs/runbooks
mkdir -p tests/unit/core/api
mkdir -p tests/unit/core/utils
mkdir -p tests/unit/core/models
mkdir -p tests/unit/web
mkdir -p tests/unit/desktop
mkdir -p tests/integration
mkdir -p tests/security
mkdir -p tests/performance

echo ""
echo "✅ Environment setup complete!"
echo ""
echo "To activate the environment in the future, run:"
echo "  source venv/bin/activate  (Linux/Mac)"
echo "  venv\\Scripts\\activate     (Windows)"
echo ""
echo "Next steps:"
echo "1. Run assessment scripts:"
echo "   python scripts/run_coverage.py"
echo "   python scripts/security_assessment.py"
echo "   python scripts/documentation_audit.py"
echo "   python scripts/api_inventory.py"