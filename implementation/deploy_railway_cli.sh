#!/bin/bash
# Railway CLI Deployment Script

echo "🚀 Deploying corrected database via Railway CLI..."

# Install Railway CLI if not present
if ! command -v railway &> /dev/null; then
    echo "📦 Installing Railway CLI..."
    npm install -g @railway/cli
fi

# Login to Railway
echo "🔐 Login to Railway (if not already logged in)..."
railway login

# Connect to project
echo "🔗 Connecting to Railway project..."
railway link

# Execute the migration script
echo "🗄️ Executing database migration..."
railway run psql $DATABASE_URL -f production_migration_corrected.sql

# Verify deployment
echo "✅ Verifying deployment..."
railway run psql $DATABASE_URL -c "
SELECT 'Total documents' as metric, COUNT(*) as value FROM lexml_documents_corrected
UNION ALL
SELECT 'Date extraction rate' as metric, 
       ROUND((COUNT(CASE WHEN enacting_date IS NOT NULL THEN 1 END) * 100.0 / COUNT(*)), 1) || '%' as value
FROM lexml_documents_corrected
UNION ALL
SELECT 'View accessible' as metric, COUNT(*) as value FROM lexml_parsed_enhanced_fixed;
"

echo "🎉 Deployment complete! Redeploy your R Shiny service to see changes."