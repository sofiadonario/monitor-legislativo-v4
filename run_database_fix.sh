#!/bin/bash

# Script to fix database schema for Monitor Legislativo deployment

echo "🔧 Fixing Monitor Legislativo database schema..."

# Method 1: Using Railway CLI (if you have it installed)
if command -v railway &> /dev/null; then
    echo "✅ Railway CLI detected"
    echo "Running SQL via Railway CLI..."
    
    # Connect to the production database and run the SQL
    railway run psql -c "$(cat create_documents_view.sql)"
    
    echo "✅ Database view created via Railway CLI"
else
    echo "⚠️ Railway CLI not found"
fi

# Method 2: Using direct psql with connection string
# The connection string from your logs:
DATABASE_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

echo ""
echo "📊 Running SQL via direct connection..."
echo "Using database: nozomi.proxy.rlwy.net:44844"

# Execute the SQL file
psql "$DATABASE_URL" < create_documents_view.sql

# Check if the view was created successfully
echo ""
echo "🔍 Verifying the fix..."
psql "$DATABASE_URL" -c "SELECT COUNT(*) as total_documents FROM documents;"

echo ""
echo "✅ Database fix completed!"
echo ""
echo "Next steps:"
echo "1. Commit and push the code changes"
echo "2. Railway will automatically redeploy"
echo "3. Your app should now connect successfully"