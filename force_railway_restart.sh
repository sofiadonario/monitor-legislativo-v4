#!/bin/bash

# Force Railway Application Restart Script
# This script forces a complete restart of the Railway application to ensure
# it picks up the updated database data

echo "🔄 Force Railway Application Restart"
echo "Time: $(date)"
echo ""

# Check if we're in the right directory
if [ ! -f "app.R" ]; then
    echo "❌ Error: app.R not found. Please run this script from the project root."
    exit 1
fi

echo "1. Checking current git status..."
git status --porcelain

echo ""
echo "2. Committing any pending changes..."
git add .
git commit -m "Force refresh database connection and add debug logging - $(date)"

echo ""
echo "3. Pushing to Railway..."
git push origin main

echo ""
echo "4. Checking Railway deployment status..."
echo "   You can monitor the deployment at: https://railway.app/dashboard"
echo "   Look for the 'monitor-legislativo-unified' service"

echo ""
echo "5. Force restart commands (run these in Railway dashboard):"
echo "   - Go to Railway dashboard"
echo "   - Find 'monitor-legislativo-unified' service"
echo "   - Click 'Deploy' to force a new deployment"
echo "   - Or click 'Restart' to restart the current deployment"

echo ""
echo "6. Expected changes after restart:"
echo "   ✅ Database connection will be refreshed"
echo "   ✅ FORCE_REFRESH flag will be enabled"
echo "   ✅ Debug logging will show actual database counts"
echo "   ✅ Should show 1,904 documents instead of 889"
echo "   ✅ Amazonas should show 3 documents instead of 0"

echo ""
echo "7. Verification steps:"
echo "   - Check the About tab for debug information"
echo "   - Look for 'Documents table total: 1904'"
echo "   - Look for 'Amazonas documents: 3'"
echo "   - Check if the map shows Amazonas with 3 documents"

echo ""
echo "🔄 Railway restart initiated!"
echo "Monitor the deployment and check the application after it's complete." 