#!/bin/bash
# Run deployment with timeout handling

DB_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

echo "🚀 Starting deployment..."
echo "This may take several minutes due to 1,886 records..."

# Run in background with logging
nohup psql "$DB_URL" -f update_municipality_state.sql > deployment_output.log 2>&1 &
PID=$!

echo "Deployment started with PID: $PID"
echo "Check progress with: tail -f deployment_output.log"

# Wait a bit and check if it's running
sleep 5
if ps -p $PID > /dev/null; then
    echo "✅ Deployment is running in background"
    echo "Monitor with: tail -f deployment_output.log"
else
    echo "❌ Deployment may have completed or failed"
    echo "Check deployment_output.log for details"
fi