#!/bin/bash
# Railway build script
echo "🔨 Building Monitor Legislativo v4..."

# Update package lists
echo "📦 Updating package lists..."
apt-get update

# Install Python 3 and pip
echo "🐍 Installing Python 3..."
apt-get install -y python3 python3-pip python3-venv

# Create symlink for python command
echo "🔗 Creating python symlink..."
ln -sf /usr/bin/python3 /usr/bin/python

# Upgrade pip
echo "⬆️ Upgrading pip..."
python3 -m pip install --upgrade pip

# Install requirements
echo "📚 Installing Python dependencies..."
python3 -m pip install -r requirements.txt

echo "✅ Build complete!"