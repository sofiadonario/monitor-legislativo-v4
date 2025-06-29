# 🚨 URGENT: Manual Railway Dashboard Fix Required

## The Problem
Railway's "rshiny" service is stuck using the Python Dockerfile despite our configuration. The CLI and environment variables are being ignored.

## The Solution: Manual Dashboard Configuration

### Step 1: Delete and Recreate Service
1. Go to: https://railway.app/project/016d4af0-9a5a-4471-9e2e-4a3c2f165166
2. Click on "rshiny" service
3. Go to Settings → Delete Service
4. Confirm deletion

### Step 2: Create New R Shiny Service
1. Click "New Service"
2. Choose "Empty Service"
3. Name it: "rshiny"
4. BEFORE deploying, configure it properly

### Step 3: Configure Source BEFORE First Deploy
1. Go to Settings → Source
2. Connect GitHub: `sofiadonario/monitor-legislativo-v4`
3. **CRITICAL SETTINGS**:
   - Branch: `main`
   - Root Directory: **Leave empty**
   - **Watch Paths**: `Dockerfile.rshiny,app-rshiny.R`
   
### Step 4: Set Build Command
In Settings → Build:
- **Builder**: Dockerfile
- **Dockerfile Path**: `Dockerfile.rshiny`
- **Build Context**: `.`

### Step 5: Deploy
Only after configuration is complete, click Deploy.

## Alternative: Direct Dockerfile Override
If the above doesn't work, in Railway Dashboard:
1. Go to rshiny service → Settings → Build
2. Set **Custom Build Command**:
   ```
   docker build -f Dockerfile.rshiny -t rshiny .
   ```

## Files Ready
- ✅ `Dockerfile.rshiny` - R Shiny container
- ✅ `app-rshiny.R` - R Shiny application
- ✅ Both files in root directory
- ✅ No Python dependencies

## Expected Result
When correctly configured, deployment logs should show:
```
FROM rocker/shiny:4.3.2
Installing R packages...
```

NOT:
```
FROM python:3.11-slim
COPY requirements.txt
```