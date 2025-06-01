# 🚨 URGENT: Railway Dashboard Configuration Required

## Problem
Railway keeps deploying the Python API instead of R Shiny despite environment variables.

## Solution: Manual Dashboard Configuration

### Step 1: Access Railway Dashboard
```
https://railway.app/project/016d4af0-9a5a-4471-9e2e-4a3c2f165166
```

### Step 2: Configure R Shiny Service
1. **Click on "rshiny" service**
2. **Go to Settings > Source**
3. **Disconnect current source** (if any)
4. **Connect GitHub repository**: `sofiadonario/monitor-legislativo-v4`
5. **CRITICAL SETTINGS**:
   - **Root Directory**: `r-shiny-standalone`
   - **Dockerfile Path**: `Dockerfile`
   - **Branch**: `main`
   - **Auto Deploy**: ON

### Step 3: Verify Build Settings
- **Builder**: Docker
- **Build Command**: (leave empty)
- **Start Command**: (leave empty - Docker handles it)

### Step 4: Environment Variables (Already Set)
✅ PORT=3838
✅ SERVICE_TYPE=rshiny  
✅ DISABLE_PYTHON=true
✅ R_SHINY_MODE=true

### Step 5: Deploy
- **Click "Deploy"** button
- **Monitor logs** for R installation (not Python)
- **Expected**: R Shiny server startup, not FastAPI

## Files Ready for Deployment
- ✅ `r-shiny-standalone/app.R` - Pure R Shiny app
- ✅ `r-shiny-standalone/Dockerfile` - R-only container
- ✅ `r-shiny-standalone/railway.toml` - Correct build config

## Expected Success
When configured correctly, you should see:
```
INFO: Starting R Shiny Server...
Listening on http://0.0.0.0:3838
```

NOT:
```
INFO: Started server process [1]
INFO: Uvicorn running on http://0.0.0.0:8000
```

## 🎯 The Issue
Railway CLI is having conflicts with multiple services in the same repo. 
The dashboard method allows precise control over which directory and Dockerfile to use.