#!/bin/bash

# Database Setup Script for Monitor Legislativo v4
# This script helps configure AsyncPG and SQLAlchemy for Supabase integration

echo "=================================================="
echo "Monitor Legislativo v4 - Database Setup Assistant"
echo "=================================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo ""

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 found"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  No .env file found."
    echo "Creating .env from .env.example..."
    
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✅ Created .env file"
        echo ""
        echo "⚠️  IMPORTANT: Edit .env file with your database credentials!"
        echo "   Required: DATABASE_URL, SUPABASE_URL, SUPABASE_ANON_KEY"
        echo ""
        read -p "Press Enter after updating .env file..."
    else
        echo "❌ No .env.example file found"
        exit 1
    fi
else
    echo "✅ .env file found"
fi

echo ""
echo "Installing required dependencies..."
echo ""

# Install dependencies
pip3 install sqlalchemy[asyncio]==2.0.23 asyncpg==0.29.0 python-dotenv==1.0.0

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Dependencies installed successfully!"
else
    echo ""
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "Testing database connection..."
echo ""

# Run connection test
python3 test_database.py

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Database connection successful!"
    
    echo ""
    read -p "Would you like to initialize the database schema? (y/n): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Initializing database..."
        python3 initialize_database.py
    fi
else
    echo ""
    echo "❌ Database connection failed"
    echo ""
    echo "Please check:"
    echo "1. Your .env file has correct DATABASE_URL"
    echo "2. Your Supabase project is active"
    echo "3. Network connection to Supabase"
    exit 1
fi

echo ""
echo "=================================================="
echo "✨ Setup complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Start the backend: python3 main_app/main.py"
echo "2. Start the frontend: npm run dev"
echo "3. Check health: http://localhost:8000/api/lexml/health"
echo ""
echo "For Railway deployment:"
echo "1. Set environment variables in Railway dashboard"
echo "2. Push code: git push origin main"
echo "3. Monitor logs for database initialization"
echo ""