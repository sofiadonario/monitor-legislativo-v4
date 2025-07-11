# Railway Deployment Hanging Issue Report - Monitor Legislativo v4

## Issue Summary
The R Shiny application (`monitor-legislativo-unified`) successfully builds and deploys on Railway but hangs indefinitely during startup, resulting in an endless loading spinner. The application never becomes accessible through the Railway URL.

## Deployment Details
- **Service Name**: monitor-legislativo-unified  
- **URL**: monitor-legislativo-unified-production.up.railway.app
- **Status**: Deployment successful, but application hangs on startup
- **R Version**: 4.3.1 (rocker/shiny base image)
- **Recent Success**: All R packages including leaflet now install correctly

## Symptoms
1. ✅ Docker build completes successfully
2. ✅ All R packages install correctly (including problematic leaflet package)
3. ✅ Package verification passes
4. ❌ Application hangs after starting - infinite loading spinner
5. ❌ No response on the Railway URL
6. ❌ No error messages in deployment logs after successful build

## Root Cause Analysis

### 1. **Database Connection Hanging**
The app attempts to connect to PostgreSQL on startup:
- **File**: `r-shiny-app/R/database_connection.R`
- **Issue**: Even with timeouts added, the `dbPool()` creation might hang if the database host is unreachable
- **Evidence**: App initializes database connection immediately on startup (line 42 in app.R)

### 2. **Synchronous Blocking Operations in Initial Load**
Multiple blocking operations occur during startup:
```r
# app.R, lines 818-843
observe({
  if (database_connected) {
    values$current_documents <- cached_get_documents(50)  # Database query
    values$analytics_data <- cached_get_search_analytics()  # Database query
    updateSelectizeInput(session, "documentTypes", choices = cached_get_document_types())
    updateSelectizeInput(session, "states", choices = cached_get_states())
  }
  values$health_check_data <- perform_health_check()  # Multiple system checks
})
```

### 3. **Missing Environment Variables**
The app expects but may not have:
- `DATABASE_URL` - PostgreSQL connection string
- `PORT` - Railway assigns this dynamically
- Possible mismatch between expected and actual environment

### 4. **Port Binding Issues**
R Shiny apps need specific configuration for Railway:
- Must bind to `0.0.0.0` (not localhost)
- Must use `PORT` environment variable
- Current CMD might not be respecting Railway's PORT

## What We've Already Tried
1. ✅ Fixed leaflet installation issues with binary packages
2. ✅ Added database connection timeouts (10 seconds)
3. ✅ Added ENABLE_DATABASE flag for optional database
4. ✅ Improved error handling and logging
5. ❌ But app still hangs, suggesting the issue is elsewhere

## Potential Solutions Needed

### 1. **Verify Port Configuration**
The app might not be binding to the correct port. Current Dockerfile CMD:
```dockerfile
CMD ["R", "-e", "if(file.exists('test_version.R')) source('test_version.R'); source('app.R')"]
```

Should potentially be:
```dockerfile
CMD ["R", "-e", "options(shiny.port = as.integer(Sys.getenv('PORT', '3838')), shiny.host = '0.0.0.0'); source('app.R')"]
```

### 2. **Add Startup Logging**
Need to see what's happening during startup:
- Add timestamp logging for each initialization step
- Log when Shiny server actually starts
- Log any connection attempts

### 3. **Environment Variable Verification**
Need to confirm:
- Is `DATABASE_URL` set in Railway?
- Is `PORT` being passed correctly?
- Are there any required but missing variables?

### 4. **Async Initialization**
Move blocking operations out of startup:
- Use promises/futures for database connection
- Defer data loading until after UI renders
- Add loading states to UI

## Questions for Railway Support

1. **Logs**: Are there any additional logs available after the Docker build completes? The deployment logs seem to stop after the build phase.

2. **Port Configuration**: How should R Shiny apps properly bind to Railway's dynamic PORT? Is our current approach correct?

3. **Health Checks**: Is Railway performing health checks that might be timing out? The app has a `/health` endpoint configured.

4. **Resource Limits**: Are there any memory or CPU constraints that might cause the app to hang during initialization?

5. **Network**: Is outbound connectivity available during startup? The app tries to connect to a PostgreSQL database.

6. **Environment**: Can you verify what environment variables are actually available to the container at runtime?

## Reproduction Steps
1. Deploy the current main branch
2. Watch the build logs (successful)
3. Navigate to the app URL
4. Observe infinite loading spinner

## Additional Context
- The app works locally with the same Dockerfile
- Frontend and backend services deploy successfully on Railway
- Only the R Shiny service experiences this hanging issue
- No Redis dependencies (uses file-based caching)

## Request for Help
We need help identifying why the R Shiny application hangs after successful deployment. Specifically:
1. Access to runtime logs (not just build logs)
2. Confirmation of proper port binding for R Shiny on Railway
3. Any Railway-specific requirements for R applications we might be missing

Thank you for your assistance!