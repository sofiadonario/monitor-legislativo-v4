#!/bin/bash
# Background deployment script for municipality-state parsing fix

echo "🚀 Starting background deployment of municipality-state parsing fix..."
echo "Started at: $(date)" > deployment_status.log

# Set database URL
DB_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Execute SQL file with progress logging
echo "📋 Executing SQL deployment file..." >> deployment_status.log
psql "$DB_URL" -f reload_database.sql >> deployment_status.log 2>&1

# Check exit code
if [ $? -eq 0 ]; then
    echo "✅ Deployment completed successfully at $(date)" >> deployment_status.log
    
    # Verify deployment
    echo "🔍 Verifying deployment..." >> deployment_status.log
    
    # Check total count
    echo "📊 Total LexML documents:" >> deployment_status.log
    psql "$DB_URL" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML';" >> deployment_status.log 2>&1
    
    # Check municipality-state fix
    echo "📊 Documents with separated municipality-state:" >> deployment_status.log
    psql "$DB_URL" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML' AND estado != '' AND municipality != '';" >> deployment_status.log 2>&1
    
    # Check Catanduva examples
    echo "🔍 Catanduva examples:" >> deployment_status.log
    psql "$DB_URL" -c "SELECT estado, municipality, titulo FROM documents WHERE fonte = 'LexML' AND municipality ILIKE '%catanduva%' LIMIT 3;" >> deployment_status.log 2>&1
    
    echo "🎉 DEPLOYMENT AND VERIFICATION COMPLETED at $(date)" >> deployment_status.log
else
    echo "❌ Deployment failed at $(date)" >> deployment_status.log
fi

echo "📋 Deployment process finished. Check deployment_status.log for details."