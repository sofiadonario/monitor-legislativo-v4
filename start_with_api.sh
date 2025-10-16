#!/bin/bash
# Railway Startup Script with Database Schema Initialization and API Server
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

    echo ""
    echo "📊 Initializing demographics and bills per 100k metric..."
    Rscript database/migrations/init_demographics.R || {
        echo "⚠️  Demographics initialization failed, but continuing startup..."
        echo "   (This is non-fatal - demographics may already exist)"
    }
else
    echo "ℹ️  No DATABASE_URL - skipping schema initialization"
fi

echo ""
echo "🚀 Starting API Server in background..."
echo "======================================"

# Start the API server in background
# Use PORT+1 for API (e.g., if Shiny is on 3838, API will be on 3839)
API_PORT=$((${PORT:-3838} + 1))
export API_PORT
export API_HOST="0.0.0.0"

# Start API server in background
Rscript api/start_api.R > /app/logs/api.log 2>&1 &
API_PID=$!
echo "✅ API Server started (PID: $API_PID) on port $API_PORT"

echo ""
echo "🚀 Starting Shiny application..."
echo "======================================"

# Start the Shiny app using Railway's PORT variable
exec R -e "shiny::runApp('app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))"
