#!/bin/bash
# ==============================================================================
# CLOUD SCHEDULER SETUP - AUTOMATED REPORT DELIVERY
# ==============================================================================
# Sets up Cloud Scheduler jobs for daily and weekly legislative reports
# Week 3 - Task 3.3
#
# Author: Monitor Legislativo Team
# Date: 2025-11-27
# ==============================================================================

set -e

PROJECT_ID="mackmonitor"
REGION="southamerica-east1"
SERVICE_ACCOUNT="scheduler-reports@mackmonitor.iam.gserviceaccount.com"
CLOUD_RUN_URL="https://monitor-legislativo-v4-856381860743.southamerica-east1.run.app"

echo "🔧 Setting up Cloud Scheduler jobs for automated reports..."
echo ""

# Verify service account exists
echo "✓ Verifying service account: $SERVICE_ACCOUNT"
if ! gcloud iam service-accounts describe "$SERVICE_ACCOUNT" --project="$PROJECT_ID" &>/dev/null; then
  echo "❌ Service account not found. Creating..."
  gcloud iam service-accounts create scheduler-reports \
    --display-name="Report Scheduler Service Account" \
    --project="$PROJECT_ID"

  # Grant Cloud Run invoker role
  gcloud run services add-iam-policy-binding monitor-legislativo-v4 \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/run.invoker" \
    --region="$REGION" \
    --project="$PROJECT_ID"

  echo "✅ Service account created and permissions granted"
fi

echo ""
echo "📅 Creating daily executive report job..."
echo "   Schedule: Every day at 8:00 AM BRT (11:00 UTC)"
echo ""

# Delete existing job if it exists
if gcloud scheduler jobs describe daily-executive-report \
   --location="$REGION" \
   --project="$PROJECT_ID" &>/dev/null; then
  echo "⚠️  Job already exists. Deleting and recreating..."
  gcloud scheduler jobs delete daily-executive-report \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --quiet
fi

# Create daily executive report job
gcloud scheduler jobs create http daily-executive-report \
  --location="$REGION" \
  --schedule="0 11 * * *" \
  --time-zone="America/Sao_Paulo" \
  --uri="$CLOUD_RUN_URL/api/reports/daily-executive" \
  --http-method=POST \
  --oidc-service-account-email="$SERVICE_ACCOUNT" \
  --headers="Content-Type=application/json" \
  --message-body='{
    "report_type": "executive",
    "frequency": "daily",
    "email_recipients": ["sofiadonario@hotmail.com"],
    "include_pdf": true,
    "include_html": false
  }' \
  --project="$PROJECT_ID"

echo "✅ Daily executive report job created"
echo ""

echo "📅 Creating weekly summary report job..."
echo "   Schedule: Every Monday at 9:00 AM BRT (12:00 UTC)"
echo ""

# Delete existing job if it exists
if gcloud scheduler jobs describe weekly-summary-report \
   --location="$REGION" \
   --project="$PROJECT_ID" &>/dev/null; then
  echo "⚠️  Job already exists. Deleting and recreating..."
  gcloud scheduler jobs delete weekly-summary-report \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --quiet
fi

# Create weekly summary report job
gcloud scheduler jobs create http weekly-summary-report \
  --location="$REGION" \
  --schedule="0 12 * * MON" \
  --time-zone="America/Sao_Paulo" \
  --uri="$CLOUD_RUN_URL/api/reports/weekly-summary" \
  --http-method=POST \
  --oidc-service-account-email="$SERVICE_ACCOUNT" \
  --headers="Content-Type=application/json" \
  --message-body='{
    "report_type": "executive",
    "frequency": "weekly",
    "email_recipients": ["sofiadonario@hotmail.com"],
    "include_pdf": true,
    "include_html": true,
    "send_email": true
  }' \
  --project="$PROJECT_ID"

echo "✅ Weekly summary report job created"
echo ""

echo "📅 Creating monthly comprehensive report job..."
echo "   Schedule: First day of month at 10:00 AM BRT (13:00 UTC)"
echo ""

# Delete existing job if it exists
if gcloud scheduler jobs describe monthly-comprehensive-report \
   --location="$REGION" \
   --project="$PROJECT_ID" &>/dev/null; then
  echo "⚠️  Job already exists. Deleting and recreating..."
  gcloud scheduler jobs delete monthly-comprehensive-report \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --quiet
fi

# Create monthly comprehensive report job
gcloud scheduler jobs create http monthly-comprehensive-report \
  --location="$REGION" \
  --schedule="0 13 1 * *" \
  --time-zone="America/Sao_Paulo" \
  --uri="$CLOUD_RUN_URL/api/reports/monthly-comprehensive" \
  --http-method=POST \
  --oidc-service-account-email="$SERVICE_ACCOUNT" \
  --headers="Content-Type=application/json" \
  --message-body='{
    "report_type": "comprehensive",
    "frequency": "monthly",
    "email_recipients": ["sofiadonario@hotmail.com"],
    "include_pdf": true,
    "include_html": true,
    "send_email": true
  }' \
  --project="$PROJECT_ID"

echo "✅ Monthly comprehensive report job created"
echo ""

echo "📊 Listing all scheduler jobs..."
gcloud scheduler jobs list \
  --location="$REGION" \
  --project="$PROJECT_ID" \
  --format="table(name,schedule,state,httpTarget.uri.basename())"

echo ""
echo "✅ Cloud Scheduler setup complete!"
echo ""
echo "📝 Summary:"
echo "   • Daily Executive Report: Weekdays 8:00 AM BRT"
echo "   • Weekly Summary: Every Monday 9:00 AM BRT"
echo "   • Monthly Comprehensive: 1st of month 10:00 AM BRT"
echo ""
echo "🧪 To test a job manually:"
echo "   gcloud scheduler jobs run daily-executive-report --location=$REGION --project=$PROJECT_ID"
echo ""
echo "📋 To view job logs:"
echo "   gcloud logging read 'resource.type=\"cloud_scheduler_job\" AND resource.labels.job_id=\"daily-executive-report\"' --limit=10 --project=$PROJECT_ID"
echo ""
