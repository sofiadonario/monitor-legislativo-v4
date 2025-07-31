#!/bin/bash

# Railway State Standardization Script
# This script adds the estado_codigo column and standardizes state data

echo "🔄 Running state standardization on Railway database..."

# Get Railway database URL and run the SQL script
railway run --service monitor-legislativo-unified psql "$DATABASE_URL" -f implementation/deploy_map_fixes.sql

echo "✅ State standardization complete!"
echo "🔄 The application should now display the map correctly."