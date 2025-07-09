# Railway Dockerfile Debug Guide

## Current Situation
- Root Directory: `r-shiny-app` (confirmed set)
- Dockerfile exists at: `r-shiny-app/Dockerfile.production`
- Error: "Dockerfile `Dockerfile.production` does not exist"

## Things to Check in Railway Dashboard

### 1. Service Settings (monitor-legislativo-unified)
Check these exact settings:

- **Source**: Should show your GitHub repo
- **Root Directory**: `r-shiny-app` (you confirmed this is set)
- **Builder**: Should be "Dockerfile" not "Nixpacks"
- **Dockerfile Path**: Should be exactly `Dockerfile.production` (NOT `./Dockerfile.production` or `/Dockerfile.production`)

### 2. Environment Variables
Make sure no environment variable is overriding the dockerfile path:
- Check for `RAILWAY_DOCKERFILE_PATH`
- Check for `DOCKERFILE`

### 3. Build Configuration
In the service settings, under "Build Configuration":
- **Watch Patterns**: Should include the r-shiny-app directory
- **Build Command**: Should be empty (let Dockerfile handle it)

## Quick Fix Options

### Option 1: Use Default Dockerfile Name
Rename the file in the r-shiny-app directory:
```bash
cd r-shiny-app
cp Dockerfile.production Dockerfile
git add Dockerfile
git commit -m "Use default Dockerfile name for Railway"
git push
```

### Option 2: Explicit Path in Settings
In Railway Dashboard, try setting:
- **Dockerfile Path**: Leave empty (it will look for "Dockerfile" by default)

### Option 3: Create railway.toml in r-shiny-app
The r-shiny-app already has railway.toml and railway.production.toml. Make sure Railway is using the right one.

## Debugging Steps

1. **Check Recent Commits**
   - Ensure the latest commit with Dockerfile.production is pushed
   - Run: `git log --oneline -1`

2. **Force Rebuild**
   - In Railway, go to Deployments
   - Click "Redeploy" on the last deployment
   - Or make a small change and push to trigger new build

3. **Check Build Logs Carefully**
   - The full error might show more context
   - Look for any path resolution issues

## Most Likely Issue

Railway might be looking for the Dockerfile before applying the root directory setting. Try:

1. In Railway Dashboard, temporarily change:
   - **Dockerfile Path**: from `Dockerfile.production` to just `Dockerfile`
   
2. Or in the service settings, try:
   - **Builder**: Change from "Dockerfile" to "Nixpacks" and back to "Dockerfile"
   - This sometimes resets the configuration

## Alternative: Use Existing Dockerfile

Since `r-shiny-app/Dockerfile` exists, you could:
1. Update it to match Dockerfile.production
2. Use the default name Railway expects