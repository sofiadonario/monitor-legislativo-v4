#!/bin/bash
# LexML Advanced Analytics System - Installation Script

echo "🚀 Installing LexML Advanced Analytics System"
echo "============================================="

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv lexml_env
source lexml_env/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📚 Installing Python packages..."
pip install -r requirements.txt

# Install spaCy language model
echo "🌐 Installing spaCy Portuguese model..."
python -m spacy download pt_core_news_sm

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data/{raw,processed,external,models,reports}
mkdir -p logs
mkdir -p exports

# Set up environment variables
echo "⚙️ Setting up environment..."
cp .env.example .env
echo "Please edit .env file with your API keys"

echo "✅ Installation completed!"
echo "To activate the environment: source lexml_env/bin/activate"
echo "To start the dashboard: streamlit run interactive_dashboard.py"
