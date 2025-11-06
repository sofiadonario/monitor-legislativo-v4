#!/usr/bin/env bash
set -euo pipefail

gcloud builds submit . --config=cloudbuild-fast.yaml --project=mackmonitor --region=us-central1
