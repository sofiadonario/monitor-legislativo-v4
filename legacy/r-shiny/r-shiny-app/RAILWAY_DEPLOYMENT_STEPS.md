# Railway Deployment Steps for R Shiny App

## Prerequisites Completed ✅
- Railway CLI installed
- All configuration files created
- Code pushed to GitHub

## Manual Deployment Steps

### 1. Login to Railway (Interactive)
Open a terminal and run:
```bash
railway login
```
This will open your browser for authentication.

### 2. Navigate to R Shiny Directory
```bash
cd /mnt/c/Users/sofia/OneDrive/Doutorado\ Stuff/MackIntegridade/monitor_legislativo_v4/r-shiny-app
```

### 3. Link to Existing Project or Create New
If you have an existing Railway project:
```bash
railway link
```

Or create a new project:
```bash
railway init
```

### 4. Deploy the Application
```bash
railway up
```

### 5. Monitor Deployment
Watch the logs:
```bash
railway logs -f
```

### 6. Get the Deployment URL
```bash
railway domain
```

## Configuration Files Created
- ✅ `.Rprofile` - R package dependencies
- ✅ `Dockerfile.railway` - Optimized Docker configuration
- ✅ `railway.toml` - Railway deployment settings
- ✅ `run_app.R` - App runner with health endpoint
- ✅ `railway.json` - Alternative Railway config

## Expected Build Time
First deployment: 5-10 minutes (installing R packages)
Subsequent deployments: 2-3 minutes

## Troubleshooting

### If build fails:
1. Check logs: `railway logs`
2. Verify R packages install correctly
3. Ensure port 3838 is exposed

### If health check fails:
1. The app includes a `/health` endpoint
2. Check that `run_app.R` is being executed
3. Verify PORT environment variable is set

### Memory issues:
- The free tier has 512MB RAM limit
- Consider upgrading if needed
- R Shiny typically needs 1-2GB RAM

## Testing the Deployment
Once deployed, test:
```bash
# Get your app URL
RSHINY_URL=$(railway domain)

# Test health endpoint
curl https://$RSHINY_URL/health

# Should return:
# {"status":"healthy","app":"monitor-legislativo-rshiny"}
```

## Integration with React Frontend
Update your React app's environment:
```
VITE_RSHINY_URL=https://your-app-name.up.railway.app
```