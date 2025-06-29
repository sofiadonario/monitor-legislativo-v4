#!/bin/bash

# Railway API deployment for R Shiny service
echo "🚀 Railway API Deployment for R Shiny"
echo "====================================="

# Get Railway project info
PROJECT_ID="016d4af0-9a5a-4471-9e2e-4a3c2f165166"
SERVICE_ID="f9593955-a2c6-4606-8825-fcface62905e"
ENVIRONMENT_ID="60e8d6ba-6ce5-4246-ac4c-9680d1c3cd25"

echo "📋 Deployment Information:"
echo "Project: diligent-kindness ($PROJECT_ID)"
echo "Service: rshiny ($SERVICE_ID)"
echo "Environment: production ($ENVIRONMENT_ID)"
echo ""

echo "🔗 Manual Deployment Options:"
echo ""
echo "1. 📱 Railway Dashboard:"
echo "   https://railway.app/project/$PROJECT_ID"
echo ""
echo "2. 🐙 GitHub Integration:"
echo "   - Go to Railway dashboard"
echo "   - Click on rshiny service"
echo "   - Go to Settings > Source"
echo "   - Connect to GitHub repo: sofiadonario/monitor-legislativo-v4"
echo "   - Set Root Directory: r-shiny-minimal"
echo "   - Set Build Command: docker build -f Dockerfile ."
echo ""
echo "3. 🐳 Direct Docker Deploy:"
echo "   - Build: docker build -t rshiny-app r-shiny-minimal/"
echo "   - Tag: docker tag rshiny-app registry.railway.app/$PROJECT_ID/$SERVICE_ID"
echo "   - Push: docker push registry.railway.app/$PROJECT_ID/$SERVICE_ID"
echo ""
echo "4. 🔄 CLI Retry:"
echo "   railway redeploy --service rshiny"
echo ""

echo "💡 Recommended: Use GitHub integration via Railway dashboard"
echo "🌐 Dashboard: https://railway.app/project/$PROJECT_ID"