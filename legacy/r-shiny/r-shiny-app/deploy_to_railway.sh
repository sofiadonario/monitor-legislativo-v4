#!/bin/bash

echo "🚀 Deploying R Shiny app to Railway..."
echo "======================================="

# Check if we're in the right directory
if [ ! -f "app.R" ]; then
    echo "❌ Error: app.R not found. Please run this script from the r-shiny-app directory."
    exit 1
fi

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Error: Railway CLI not found. Please install it first:"
    echo "   npm install -g @railway/cli"
    exit 1
fi

echo "✅ Prerequisites checked"
echo ""

# Login to Railway (if not already logged in)
echo "📝 Ensuring Railway login..."
railway whoami || railway login

echo ""
echo "🔧 Configuration files:"
echo "   - railway.toml ✅"
echo "   - Dockerfile.railway ✅"
echo "   - .Rprofile ✅"
echo "   - run_app.R ✅"
echo ""

# Deploy to Railway
echo "🚂 Starting Railway deployment..."
echo "This may take 5-10 minutes for the first deployment..."
echo ""

railway up

echo ""
echo "✅ Deployment initiated!"
echo ""
echo "📋 Next steps:"
echo "1. Monitor the build logs in Railway dashboard"
echo "2. Once deployed, get the URL with: railway domain"
echo "3. Test the health endpoint: curl https://your-app.up.railway.app/health"
echo "4. Access the app at the provided URL"
echo ""
echo "🔍 To view logs: railway logs"
echo "🌐 To get domain: railway domain"