#!/bin/bash
# =============================================================================
# Check Cloud Run Logs for MackMonitor
# =============================================================================
# Quick script to check logs and diagnose issues
# =============================================================================

SERVICE_NAME="mackmonitor"
REGION="us-central1"

echo "========================================"
echo "📋 MackMonitor Cloud Run Logs"
echo "========================================"
echo ""

# Get the service URL
echo "🔗 Service URL:"
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} --region=${REGION} --format='value(status.url)' 2>/dev/null)
if [ -z "$SERVICE_URL" ]; then
    echo "   ❌ Service not found or not deployed"
    exit 1
else
    echo "   ${SERVICE_URL}"
    echo "   Health: ${SERVICE_URL}/health"
fi
echo ""

# Check service status
echo "📊 Service Status:"
gcloud run services describe ${SERVICE_NAME} --region=${REGION} --format='table(status.conditions[0].type, status.conditions[0].status, status.conditions[0].message)'
echo ""

# Get latest logs
echo "📝 Latest Logs (last 50 entries):"
echo "   Filtering for errors and startup messages..."
echo ""
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME}" \
    --limit=50 \
    --format='table(timestamp, severity, textPayload)' \
    --freshness=10m

echo ""
echo "========================================"
echo "🔍 To see more detailed logs, run:"
echo "   gcloud logging read \"resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME}\" --limit=100 --format=json"
echo ""
echo "🔍 To follow logs in real-time:"
echo "   gcloud logging tail \"resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME}\""
echo ""
echo "🔍 To filter for errors only:"
echo "   gcloud logging read \"resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME} AND severity>=ERROR\" --limit=20"
echo "========================================"
