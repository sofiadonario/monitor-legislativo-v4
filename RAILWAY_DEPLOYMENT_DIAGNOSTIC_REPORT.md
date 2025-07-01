# 🚨 COMPREHENSIVE RAILWAY DEPLOYMENT DIAGNOSTIC REPORT

**Issue:** Railway Monorepo Configuration Not Respected - Services Using Wrong Build  
**Date:** December 2024  
**Repository:** https://github.com/sofiadonario/monitor-legislativo-v4

---

## 📋 Executive Summary

Despite a correctly configured `railway.json` for a monorepo setup, Railway is failing to use the specified Dockerfiles for each service. Both the `monitor-legislativo-v4` (Python/FastAPI) service and the `rshiny` (R/Shiny) service are being deployed with an identical, incorrect build, resulting in service failure for the `rshiny` app.

---

## 🔍 Evidence of the Problem

### 1. **Identical Logs Across Different Services**
Both services exhibit the same generic container startup logs, indicating neither the Python nor the R application is being started correctly:
- "Starting Container"
- "server running" 
- "finished cleaning storage units"

These appear to be platform-level logs rather than application logs.

### 2. **Service Configuration Mismatch**
- `RAILWAY_SERVICE_NAME` environment variable is correctly set for each service
- However, the underlying application code being run is wrong
- The R Shiny service appears to be running Python code or a generic container

---

## 🛠️ Configuration & Fixes Applied

### Current Project Structure
```
monitor_legislativo_v4/
├── railway.json                 # ✅ Monorepo configuration
├── main_app/
│   ├── Dockerfile              # ✅ Python service Dockerfile
│   └── main.py                 # Python FastAPI application
└── r-shiny-app/
    ├── Dockerfile              # ✅ R Shiny service Dockerfile (UPDATED)
    ├── app-minimal.R           # R Shiny application
    └── run_app_minimal.R       # R startup script
```

### Root railway.json Configuration
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "services": {
    "monitor-legislativo-v4": {
      "build": {
        "builder": "DOCKERFILE",
        "dockerfilePath": "main_app/Dockerfile"
      },
      "deploy": {
        "healthcheckPath": "/health",
        "healthcheckTimeout": 100
      }
    },
    "rshiny": {
      "build": {
        "builder": "DOCKERFILE",
        "dockerfilePath": "r-shiny-app/Dockerfile",
        "buildContext": "r-shiny-app"
      },
      "deploy": {
        "healthcheckPath": "/",
        "healthcheckTimeout": 300,
        "restartPolicyType": "ON_FAILURE",
        "restartPolicyMaxRetries": 3
      }
    }
  }
}
```

---

## 📝 Troubleshooting Steps Performed

### Phase 1: Initial Diagnosis
1. **Verified `railway.json`**
   - ✅ Present in repository root
   - ✅ Valid schema
   - ✅ Correct service definitions
   - ✅ Proper Dockerfile paths

2. **Root Dockerfile Issue**
   - **Found:** A `Dockerfile` in the repository root was causing Railway to ignore `railway.json`
   - **Action:** Deleted root `Dockerfile` and merged its logic into `main_app/Dockerfile`
   - **Result:** Issue persists

### Phase 2: Additional Issues Discovered & Fixed

3. **Conflicting Configurations**
   - **Found:** `r-shiny-app/railway.json` with different build settings
   - **Action:** ✅ DELETED - Removed conflicting nested configuration
   
4. **Multiple Dockerfiles**
   - **Found:** Multiple Dockerfiles in `r-shiny-app/`:
     - `Dockerfile` (correct one)
     - `Dockerfile.railway`
     - `Dockerfile.railway.minimal`
     - `Dockerfile.simple`
   - **Action:** Should be renamed/removed to prevent confusion

5. **PORT Environment Variable**
   - **Issue:** R Shiny Dockerfile wasn't properly handling Railway's PORT
   - **Action:** ✅ FIXED - Updated CMD to: `CMD ["sh", "-c", "PORT=${PORT:-3838} Rscript ./run_app.R"]`

6. **Git Synchronization**
   - **Status:** ✅ All changes committed and pushed
   - **Verification:** `git status` shows clean working tree
   - **Remote:** Fully synchronized with origin/main

---

## 🔴 Root Cause Analysis

### Most Likely Causes (in order of probability):

1. **Railway Build Cache**
   - Railway is using a stale build cache that ignores the new configuration
   - The cache may be from when a root Dockerfile existed
   - Evidence: Both services show identical behavior despite different configurations

2. **Monorepo Detection Bug**
   - Railway's monorepo detection may be failing for this specific structure
   - The platform might be defaulting to a generic build process
   - Evidence: Generic container logs instead of application-specific output

3. **Service Mapping Issue**
   - Internal mapping between `railway.json` services and Railway dashboard services may be broken
   - Services might be using a default or cached configuration
   - Evidence: Correct `RAILWAY_SERVICE_NAME` but wrong application code

---

## 🚀 Recommended Actions

### For You (via Railway Dashboard):

1. **Clear Build Cache & Redeploy**
   - Navigate to the `rshiny` service
   - Go to Settings → Deploy
   - Click "Clear build cache" 
   - Click "Redeploy"

2. **Nuclear Option - Recreate Service**
   - Delete the `rshiny` service entirely
   - Create a new service
   - Railway should detect it from `railway.json`
   - This forces a completely fresh build pipeline

3. **Try Service Rename**
   - In both `railway.json` and Railway dashboard
   - Rename `rshiny` to something like `shiny-analytics`
   - This can bypass cached configurations

### For Railway Support:

Please investigate:
1. Why are both services showing identical, generic container logs?
2. Is the monorepo configuration in `railway.json` being properly parsed?
3. Are there any cached builds affecting the `rshiny` service?
4. Why does the build succeed but deploy the wrong application?

---

## 📊 Service Details

### Python Service (monitor-legislativo-v4) 
- **Status:** ❓ Shows generic logs, not Python application logs
- **Expected:** FastAPI startup messages, uvicorn logs
- **Actual:** Generic container messages

### R Shiny Service (rshiny)
- **Status:** ❌ Failing - wrong application deployed
- **Expected:** R version info, Shiny server startup, "Listening on http://0.0.0.0:3838"
- **Actual:** Same generic container messages as Python service

---

## 🔧 Technical Configuration

### Working R Shiny Dockerfile (after fixes)
```dockerfile
# R Shiny Dockerfile for Railway
FROM rocker/shiny:4.3.2

WORKDIR /app

# Copy the minimal R Shiny app files
COPY app-minimal.R ./app.R
COPY run_app_minimal.R ./run_app.R

# Make run script executable
RUN chmod +x ./run_app.R

# Expose port (Railway will override with $PORT)
EXPOSE 3838

# Start R Shiny app using PORT from Railway
CMD ["sh", "-c", "PORT=${PORT:-3838} Rscript ./run_app.R"]
```

### R Startup Script (run_app_minimal.R)
```r
#!/usr/bin/env Rscript

library(shiny)

# Use Railway's PORT environment variable
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

message("Starting R Shiny app on ", host, ":", port)

# Run the app
runApp("app.R", host = host, port = port, launch.browser = FALSE)
```

---

## 📁 Repository Information

- **GitHub:** https://github.com/sofiadonario/monitor-legislativo-v4
- **Railway Project ID:** 016d4af0-9a5a-4471-9e2e-4a3c2f165166
- **Service ID (rshiny):** f9593955-a2c6-4606-8825-fcface62905e
- **Last Commit:** All fixes committed and pushed to origin/main

---

## ✅ Checklist of Fixes Applied

- [x] Removed root Dockerfile that was overriding railway.json
- [x] Deleted conflicting r-shiny-app/railway.json
- [x] Updated R Shiny Dockerfile to handle PORT correctly
- [x] Verified railway.json schema and paths
- [x] Committed and pushed all changes
- [x] Confirmed Git synchronization with remote

---

## 📞 Contact Information

**Email:** sofiadonario@hotmail.com  
**Project:** Monitor Legislativo v4 - Academic Research Platform for Brazilian Legislative Data

---

**This report demonstrates that the codebase configuration is correct. The persistence of the issue strongly indicates a platform-level problem requiring Railway support intervention.** 