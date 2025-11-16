#!/bin/bash

# Sprint 3 Batch Job Monitoring Script
# Monitor all NLP batch jobs in parallel

echo "================================================"
echo "SPRINT 3 BATCH JOB MONITORING"
echo "================================================"
echo ""

# Define build IDs
READABILITY_BUILD="d9be5e82-34bb-48c2-a172-74057597e9f1"
WORD2VEC_BUILD="538c3220-08e4-4974-8737-7b62c37809ec"
STM_BUILD="abd50e7d-d4cc-400d-ab28-9f385e6e9d0f"

PROJECT="mackmonitor"
REGION="southamerica-east1"

# Function to get build status
get_build_status() {
  local build_id=$1
  local job_name=$2
  
  echo "--- $job_name ---"
  gcloud builds describe $build_id \
    --region=$REGION \
    --project=$PROJECT \
    --format="table(id.scope(builds),status,createTime,finishTime,timeout)" \
    2>/dev/null || echo "Build $build_id not found"
  echo ""
}

# Check all build statuses
get_build_status $READABILITY_BUILD "Readability Batch"
get_build_status $WORD2VEC_BUILD "Word2Vec Training"
get_build_status $STM_BUILD "STM Topic Modeling"

# Summary
echo "================================================"
echo "SUMMARY"
echo "================================================"
gcloud builds list \
  --region=$REGION \
  --project=$PROJECT \
  --limit=5 \
  --format="table(id.scope(builds),status,createTime,timeout)"

echo ""
echo "Use: gcloud builds log BUILD_ID --region=$REGION --project=$PROJECT"
echo "To view detailed logs for any job"
