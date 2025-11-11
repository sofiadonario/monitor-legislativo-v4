#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "Populate Geographic Data from URNs"
echo "========================================"

# Build the image
echo "📦 Building Docker image..."
docker build -f Dockerfile.populate-geo -t populate-geo:latest .

# Tag for Google Container Registry
echo "🏷️  Tagging image..."
docker tag populate-geo:latest us-central1-docker.pkg.dev/mackmonitor/monitor-repo/populate-geo:latest

# Push to registry
echo "⬆️  Pushing to Google Container Registry..."
docker push us-central1-docker.pkg.dev/mackmonitor/monitor-repo/populate-geo:latest

# Run as Cloud Run job
echo "🚀 Creating Cloud Run job..."
gcloud run jobs create populate-geographic-data \
    --image=us-central1-docker.pkg.dev/mackmonitor/monitor-repo/populate-geo:latest \
    --region=southamerica-east1 \
    --set-cloudsql-instances=mackmonitor:southamerica-east1:mackmonitor-db \
    --max-retries=0 \
    --task-timeout=600 \
    --memory=512Mi \
    --cpu=1 \
    || echo "Job already exists, updating..."

# Update existing job
gcloud run jobs update populate-geographic-data \
    --image=us-central1-docker.pkg.dev/mackmonitor/monitor-repo/populate-geo:latest \
    --region=southamerica-east1

# Execute the job
echo "▶️  Executing job..."
gcloud run jobs execute populate-geographic-data --region=southamerica-east1 --wait

echo ""
echo "✅ Geographic data population completed!"
echo "📊 Check the logs above for statistics"
echo ""
echo "Next: Refresh your application to see all 134k+ documents on the map!"
