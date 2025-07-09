# Fix Railway Deployment for Monitor Legislativo Unified

## Problem
The deployment is failing with error: `Dockerfile 'Dockerfile.production' does not exist`

## Solution

### Option 1: Fix in Railway Dashboard (Recommended)

1. **Go to Railway Dashboard**
   - Navigate to your project
   - Click on the "monitor-legislativo-unified" service

2. **Update Service Settings**
   - Go to Settings tab
   - Find "Root Directory" setting
   - Change it from `/` (or empty) to `r-shiny-app`
   - Save changes

3. **Trigger New Deployment**
   - Railway will automatically redeploy
   - It will now look for `Dockerfile.production` in the `r-shiny-app` directory

### Option 2: Create Root-Level Dockerfile

If you can't change the root directory, create a Dockerfile in the project root:

```bash
# In project root, create Dockerfile.production that points to the R Shiny app
cp r-shiny-app/Dockerfile.production ./Dockerfile.production
```

### Option 3: Use Different Dockerfile Name

1. In Railway Dashboard, go to service settings
2. Change "Docker File Path" from `Dockerfile.production` to `r-shiny-app/Dockerfile.production`

## Verification

After making changes:
1. Check that deployment starts building
2. Monitor build logs for successful Docker image creation
3. Verify the app deploys and health check passes

## Current Service Configuration

Your services should be configured as:

**monitor-legislativo-unified** (R Shiny App):
- Root Directory: `r-shiny-app`
- Dockerfile: `Dockerfile.production`
- Port: 3838

**backend** (FastAPI):
- Root Directory: `/` (project root)
- Builder: Nixpacks
- Port: 8000

**frontend** (React):
- Root Directory: `/` (project root)
- Builder: Nixpacks
- Build Command: `npm install && npm run build`