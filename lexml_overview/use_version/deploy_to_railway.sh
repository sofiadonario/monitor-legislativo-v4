#!/bin/bash
# Railway Deployment Script for LexML Advanced Analytics

echo "🚀 Deploying LexML Advanced Analytics to Railway"
echo "=============================================="

# Check if railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Please install it first:"
    echo "npm install -g @railway/cli"
    exit 1
fi

# Login to Railway
echo "🔐 Logging into Railway..."
railway login

# Link to project (if not already linked)
echo "🔗 Linking to Railway project..."
railway link

# Set environment variables
echo "⚙️ Setting environment variables..."
railway variables set PORT=3838
railway variables set SHINY_LOG_LEVEL=INFO
railway variables set PYTHON_PATH=/app/lexml_overview/use_version
railway variables set R_LIBS_USER=/app/R/library

# Deploy
echo "🚀 Deploying to Railway..."
railway up

# Get deployment URL
echo "🌐 Getting deployment URL..."
railway domain

echo "✅ Deployment complete!"
echo "📊 Access your dashboard at the URL above"
