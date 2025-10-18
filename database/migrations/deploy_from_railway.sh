#!/bin/bash
# Deploy schema from within Railway's environment
# This script is designed to run INSIDE Railway using 'railway up' or similar

set -e

echo "================================"
echo "DEPLOYING SCHEMA FROM RAILWAY"
echo "================================"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL not set"
    exit 1
fi

echo "DATABASE_URL detected (internal Railway connection)"

# Install psql if not available
if ! command -v psql &> /dev/null; then
    echo "Installing PostgreSQL client..."
    apt-get update
    apt-get install -y postgresql-client
fi

# Deploy the schema
echo "Deploying schema..."
psql "$DATABASE_URL" < database/migrations/high_performance_search_schema.sql

echo "================================"
echo "DEPLOYMENT COMPLETE"
echo "================================"
