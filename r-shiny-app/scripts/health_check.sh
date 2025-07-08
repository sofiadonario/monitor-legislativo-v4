#!/bin/bash
# Health check script for R Shiny application

# Check if the Shiny server is responding
PORT=${PORT:-3838}
HEALTH_ENDPOINT="http://localhost:${PORT}/health"

# Try to connect to the health endpoint
if curl -f -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" | grep -q "200"; then
    echo "Health check passed"
    exit 0
else
    # Fallback: Check if R process is running
    if pgrep -f "shiny::runApp" > /dev/null; then
        echo "R process is running but health endpoint failed"
        exit 1
    else
        echo "R process is not running"
        exit 1
    fi
fi