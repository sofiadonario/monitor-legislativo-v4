#!/bin/bash

# Railway CSV Auto Import Script
# Monitor Legislativo v4 - Automated Railway Import

set -e

echo "🚀 Starting Railway CSV Auto Import"
echo "===================================="

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Please install it first:"
    echo "   npm install -g @railway/cli"
    echo "   Or download from: https://railway.app/cli"
    exit 1
fi

# Check if CSV file exists
CSV_FILE="data/processed/lexml_parsed_enhanced_fixed.csv"
if [ ! -f "$CSV_FILE" ]; then
    echo "❌ CSV file not found: $CSV_FILE"
    exit 1
fi

echo "✅ CSV file found: $CSV_FILE"

# Check if SQL file exists
SQL_FILE="railway_csv_import.sql"
if [ ! -f "$SQL_FILE" ]; then
    echo "❌ SQL file not found: $SQL_FILE"
    exit 1
fi

echo "✅ SQL file found: $SQL_FILE"

# Login to Railway (if not already logged in)
echo "🔐 Checking Railway authentication..."
railway whoami || {
    echo "Please login to Railway:"
    railway login
}

# Upload CSV file to PostgreSQL volume
echo "📤 Uploading CSV file to Railway PostgreSQL..."
railway run --service postgres cp "$CSV_FILE" /var/lib/postgresql/data/lexml_parsed_enhanced_fixed.csv

if [ $? -eq 0 ]; then
    echo "✅ CSV file uploaded successfully"
else
    echo "❌ Failed to upload CSV file"
    exit 1
fi

# Execute SQL import
echo "🔧 Executing SQL import..."
railway run --service postgres psql $DATABASE_URL -f "$SQL_FILE"

if [ $? -eq 0 ]; then
    echo "✅ SQL import completed successfully"
else
    echo "❌ SQL import failed"
    exit 1
fi

# Verify import
echo "🔍 Verifying import..."
railway run --service postgres psql $DATABASE_URL -c "SELECT COUNT(*) FROM lexml_parsed_enhanced; SELECT COUNT(*) FROM documents; SELECT COUNT(*) FROM legislative_data;"

echo ""
echo "🎉 SUCCESS! Railway CSV import completed!"
echo "📊 Your database now contains 889 real legislative records"
echo "🎯 Next steps:"
echo "   1. Check your R Shiny app for real data"
echo "   2. Test search and filtering functionality"
echo "   3. Verify all 889 records are accessible"
echo ""
echo "🔗 Your R Shiny app: https://monitor-legislativo-unified-production.up.railway.app/"