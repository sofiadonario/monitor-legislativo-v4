#!/usr/bin/env bash
# ---- USER SETTINGS ------------------------------------------------
PROJECT_ID="mackmonitor"          # already created or will be created
REGION="us-central1"              # pick any Cloud Run region you like
DB_PASSWORD="Sdonario1"           # postgres password
# -------------------------------------------------------------------
set -e

echo "⏩ Authenticating gcloud…"
gcloud auth login
gcloud config set project "$PROJECT_ID" || \
  { gcloud projects create "$PROJECT_ID"; gcloud config set project "$PROJECT_ID"; }

echo "⏩ Enabling required APIs…"
gcloud services enable run.googleapis.com \
                      artifactregistry.googleapis.com \
                      sqladmin.googleapis.com \
                      cloudbuild.googleapis.com

echo "⏩ Creating Artifact Registry (ignore AlreadyExists)…"
gcloud artifacts repositories create monitor-repo \
    --repository-format=docker --location="$REGION" || true

echo "⏩ Building and pushing Docker image to Artifact Registry…"
IMG="$REGION-docker.pkg.dev/$PROJECT_ID/monitor-repo/mackmonitor:v4"
docker build --platform=linux/amd64 -t mackmonitor:v4 .
docker tag mackmonitor:v4 "$IMG"
docker push "$IMG"

echo "⏩ Provisioning Cloud SQL (db-f1-micro)…"
gcloud sql instances create mackmonitor-db \
    --database-version=POSTGRES_13 \
    --tier=db-f1-micro \
    --region="$REGION" \
    --storage-size=10 || true

echo "   Waiting for Cloud SQL to be RUNNABLE…"
until [[ "$(gcloud sql instances describe mackmonitor-db --format='value(state)')" == "RUNNABLE" ]]; do
  sleep 20
done

gcloud sql users set-password postgres --instance mackmonitor-db --password "$DB_PASSWORD"

CONN=$(gcloud sql instances describe mackmonitor-db --format='value(connectionName)')

echo "⏩ Creating (or updating) Secret Manager entry for DB password…"
echo -n "$DB_PASSWORD" | gcloud secrets create db-password --data-file=- --replication-policy="automatic" 2>/dev/null || \
echo -n "$DB_PASSWORD" | gcloud secrets versions add db-password --data-file=-

echo "⏩ Deploying Cloud Run service…"
gcloud run deploy mackmonitor \
    --image="$IMG" \
    --platform=managed \
    --region="$REGION" \
    --port=3838 \
    --add-cloudsql-instances="$CONN" \
    --set-env-vars="DB_HOST=/cloudsql/$CONN,DB_NAME=monitor,DB_USER=postgres,PORT=3838" \
    --update-secrets="DB_PASSWORD=db-password:latest" \
    --allow-unauthenticated \
    --min-instances=0 \
    --max-instances=2 \
    --cpu=0.5 --memory=512Mi

echo "✅ Deployment finished!  The Cloud Run URL displayed above should serve your Shiny app (first cold start may take ~60 s)."