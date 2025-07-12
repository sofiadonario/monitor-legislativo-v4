#!/bin/bash
# Direct PostgreSQL Deployment Script

echo "🚀 Deploying corrected database via direct PostgreSQL connection..."

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL environment variable not set"
    echo "Please set it with: export DATABASE_URL='your_railway_postgres_url'"
    exit 1
fi

# Install psql if not present (Ubuntu/Debian)
if ! command -v psql &> /dev/null; then
    echo "📦 Installing PostgreSQL client..."
    sudo apt update
    sudo apt install -y postgresql-client
fi

echo "🔗 Connecting to database..."
echo "URL: $(echo $DATABASE_URL | sed 's/:\/\/.*@/:\/\/***@/')"

# Execute the migration script
echo "🗄️ Executing database migration..."
psql "$DATABASE_URL" -f production_migration_corrected.sql

# Check if migration was successful
if [ $? -eq 0 ]; then
    echo "✅ Migration successful! Verifying..."
    
    # Verify deployment
    psql "$DATABASE_URL" -c "
    SELECT 'Total documents' as metric, COUNT(*) as value FROM lexml_documents_corrected
    UNION ALL
    SELECT 'Date extraction rate' as metric, 
           ROUND((COUNT(CASE WHEN enacting_date IS NOT NULL THEN 1 END) * 100.0 / COUNT(*)), 1) || '%' as value
    FROM lexml_documents_corrected
    UNION ALL
    SELECT 'View accessible' as metric, COUNT(*) as value FROM lexml_parsed_enhanced_fixed;
    "
    
    echo ""
    echo "🎉 Deployment complete!"
    echo "📊 Expected results: 1,904 documents, 100.0% date extraction"
    echo "🔧 Next step: Redeploy your R Shiny service in Railway dashboard"
    
else
    echo "❌ Migration failed. Check the error messages above."
    exit 1
fi