# Railway R Shiny Deployment Issue Report

## Problem Summary
R Shiny service builds successfully on Railway but containers stop immediately after showing "Listening on http://0.0.0.0:3838", preventing the service from staying online.

## Project Details
- **Project**: Monitor Legislativo v4 (Academic Research Platform)
- **Railway Project**: diligent-kindness (016d4af0-9a5a-4471-9e2e-4a3c2f165166)
- **Service**: rshiny (f9593955-a2c6-4606-8825-fcface62905e)
- **Repository**: https://github.com/sofiadonario/monitor-legislativo-v4
- **Domain**: https://rshiny-production.up.railway.app

## Architecture
This is a multi-service academic research platform:
- **Service 1**: Python FastAPI (working correctly)
- **Service 2**: R Shiny Analytics (the problematic service)
- **Frontend**: React on GitHub Pages

## Issue Timeline

### Initial Problem
Railway was incorrectly deploying Python API code to the R Shiny service despite explicit configuration.

### Configuration Attempts
1. **Environment variables set**:
   ```
   PORT=3838
   SERVICE_TYPE=rshiny
   DISABLE_PYTHON=true
   RAILWAY_DOCKERFILE_PATH=Dockerfile.rshiny
   ```

2. **Configuration files created**:
   - `railway.toml` with service-specific settings
   - `railway.json` with explicit build configuration
   - `Dockerfile.rshiny` for R Shiny container

### Current Status
- ✅ **Build Success**: Docker image builds correctly, R and Shiny packages install
- ✅ **App Starts**: R Shiny server starts and shows "Listening on http://0.0.0.0:3838"
- ❌ **Container Stops**: Immediately shows "Stopping Container" after startup

## Deployment Logs
```
R version 4.3.2 (2023-10-31) -- "Eye Holes"
> shiny::runApp('/app/app.R', host='0.0.0.0', port=3838)
Loading required package: shiny
Listening on http://0.0.0.0:3838
Stopping Container
```

## Troubleshooting Attempts

### 1. Health Check Issues
- **Problem**: Docker HEALTHCHECK was causing failures
- **Solution**: Disabled health checks in Dockerfile and Railway config
- **Result**: Still stops

### 2. Start Command Variations
Tried multiple start commands:
```bash
# Option A
R -e "shiny::runApp('/app/app.R', host='0.0.0.0', port=3838)"

# Option B  
Rscript -e "shiny::runApp('/app/app.R', host='0.0.0.0', port=3838)"

# Option C
sh -c "R -e \"shiny::runApp('/app/app.R', host='0.0.0.0', port=3838)\""

# Option D - No custom command (use Dockerfile CMD)

# Option E - With keep-alive
R -e "shiny::runApp('/app/app.R', host='0.0.0.0', port=3838); Sys.sleep(Inf)"
```
**Result**: All produce same behavior - starts then stops

### 3. Process Management
- **Created**: Dedicated startup script with `exec` and keep-alive loop
- **Dockerfile**: Uses proper CMD with shell script
- **Result**: Still investigating

## Technical Details

### Working Dockerfile.rshiny
```dockerfile
FROM rocker/shiny:4.3.2
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY app-rshiny.R /app/app.R
COPY start-rshiny.sh /app/start-rshiny.sh
RUN chmod +x /app/start-rshiny.sh
RUN R -e "install.packages('shiny', repos='https://cran.rstudio.com/')"
EXPOSE 3838
CMD ["/app/start-rshiny.sh"]
```

### R Shiny Application
Simple test application that works locally:
- Displays system information
- Shows R and Shiny versions
- Basic reactivity test
- No external dependencies

## Questions for Railway Support

1. **Container Lifecycle**: Why does Railway stop containers immediately after they show "Listening" for R applications?

2. **Process Detection**: Does Railway require specific process patterns for R/Shiny applications to be recognized as web services?

3. **Port Binding**: Are there specific requirements for how R Shiny should bind to ports on Railway?

4. **Health Checks**: What's the recommended approach for R Shiny health checks on Railway?

5. **Multi-Service**: Could the presence of a Python service in the same project be causing conflicts?

## Expected vs Actual Behavior

### Expected
- Container starts R Shiny
- Service binds to port 3838
- Railway recognizes it as a running web service
- Service stays online and accessible at the domain

### Actual  
- Container starts R Shiny correctly
- Service binds to port 3838 successfully
- Railway immediately stops the container
- Service becomes inaccessible

## Request
We need guidance on proper R Shiny deployment patterns for Railway, specifically:
- Correct process management for R applications
- Railway-specific requirements for R Shiny services
- Debugging steps for container lifecycle issues

This is an academic research platform serving Brazilian legislative data, and the R Shiny component provides critical analytics functionality.

## Files Available
All configuration files, Dockerfiles, and application code are available in the GitHub repository for Railway team review.

---
**Contact**: sofiadonario@hotmail.com  
**GitHub**: https://github.com/sofiadonario/monitor-legislativo-v4  
**Railway Project**: https://railway.app/project/016d4af0-9a5a-4471-9e2e-4a3c2f165166