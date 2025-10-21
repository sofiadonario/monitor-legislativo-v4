#!/bin/bash
# =============================================================================
# Deploy MackMonitor v9 to Google Cloud Run
# =============================================================================
# This script tags, pushes, and deploys the fixed shinydashboard image
# Generated: 2025-10-20
# =============================================================================

set -e  # Exit on any error

echo "========================================"
echo "🚀 Deploying MackMonitor v9 to GCP"
echo "========================================"
echo ""

# Configuration
IMAGE_NAME="mackmonitor"
VERSION="v9"
REGION="us-central1"
PROJECT_ID="mackmonitor"
REGISTRY="us-central1-docker.pkg.dev"
REPO="monitor-repo"
SERVICE_NAME="mackmonitor"

FULL_IMAGE_PATH="${REGISTRY}/${PROJECT_ID}/${REPO}/${IMAGE_NAME}:${VERSION}"

echo "📦 Image: ${FULL_IMAGE_PATH}"
echo "🌎 Region: ${REGION}"
echo "🔧 Service: ${SERVICE_NAME}"
echo ""

# Step 1: Verify local image exists
echo "1️⃣  Verifying local image exists..."
if docker image inspect ${IMAGE_NAME}:${VERSION} > /dev/null 2>&1; then
    echo "   ✅ Local image ${IMAGE_NAME}:${VERSION} found"
else
    echo "   ❌ ERROR: Local image ${IMAGE_NAME}:${VERSION} not found"
    echo "   Please build the image first with:"
    echo "   docker build --platform=linux/amd64 -t ${IMAGE_NAME}:${VERSION} ."
    exit 1
fi
echo ""

# Step 2: Tag image for Artifact Registry
echo "2️⃣  Tagging image for Artifact Registry..."
docker tag ${IMAGE_NAME}:${VERSION} ${FULL_IMAGE_PATH}
echo "   ✅ Tagged as ${FULL_IMAGE_PATH}"
echo ""

# Step 3: Push to Artifact Registry
echo "3️⃣  Pushing image to Artifact Registry..."
echo "   This may take a few minutes..."
docker push ${FULL_IMAGE_PATH}
echo "   ✅ Image pushed successfully"
echo ""

# Step 4: Deploy to Cloud Run
echo "4️⃣  Deploying to Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
  --image=${FULL_IMAGE_PATH} \
  --region=${REGION} \
  --platform=managed \
  --allow-unauthenticated \
  --port=3838 \
  --memory=2Gi \
  --cpu=2 \
  --timeout=300 \
  --max-instances=10 \
  --min-instances=0 \
  --set-env-vars="PORT=3838"

echo ""
echo "========================================"
echo "✅ DEPLOYMENT COMPLETE!"
echo "========================================"
echo ""
echo "📊 Service URL:"
gcloud run services describe ${SERVICE_NAME} --region=${REGION} --format='value(status.url)'
echo ""
echo "🔍 Check logs with:"
echo "   gcloud logging read \"resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME}\" --limit=50 --format=json"
echo ""
echo "🩺 Monitor service health:"
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} --region=${REGION} --format='value(status.url)')
echo "   Health: ${SERVICE_URL}/health"
echo "   Main App: ${SERVICE_URL}"
echo ""
