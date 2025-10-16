#!/bin/bash
# Railway Startup Script with Database Schema Initialization
# This runs before the Shiny app starts

set -e

echo "======================================"
echo "RAILWAY STARTUP SEQUENCE"
echo "======================================"

# Run database schema initialization if DATABASE_URL is present
if [ -n "$DATABASE_URL" ]; then
    echo "✅ DATABASE_URL detected - initializing schema..."
    Rscript database/migrations/init_schema.R || {
        echo "⚠️  Schema initialization failed, but continuing startup..."
        echo "   (This is non-fatal - schema may already exist)"
    }
else
    echo "ℹ️  No DATABASE_URL - skipping schema initialization"
fi

echo ""
echo "🚀 Starting Shiny application..."
echo "======================================"

# Start the Shiny app using Railway's PORT variable
exec R -e "shiny::runApp('app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))"
