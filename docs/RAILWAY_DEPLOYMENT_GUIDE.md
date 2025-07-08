# Railway Deployment Guide - Monitor Legislativo v4

## Overview

This guide provides step-by-step instructions for deploying Monitor Legislativo v4 to Railway platform using the consolidated R architecture.

## Prerequisites

- [Railway account](https://railway.app) (free tier available)
- GitHub repository with Monitor Legislativo v4 code
- Basic familiarity with environment variables

## Deployment Steps

### Step 1: Create Railway Project

1. **Login to Railway**
   - Visit [railway.app](https://railway.app)
   - Sign in with your GitHub account

2. **Create New Project**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your monitor-legislativo-v4 repository

### Step 2: Configure Services

**Main Application Service:**

1. **Service Configuration**
   - Service name: `monitor-legislativo-app`
   - Root directory: `r-shiny-app`
   - Build path: `r-shiny-app/Dockerfile.production`

2. **Environment Variables** (Required)
   ```
   PORT=3838
   R_CONFIG_ACTIVE=production
   SHINY_LOG_LEVEL=INFO
   R_MAX_MEMORY=2GB
   SHINY_MAX_SESSIONS=100
   ```

3. **Optional AI Integration** (if you have API keys)
   ```
   OPENAI_API_KEY=your_openai_key_here
   ANTHROPIC_API_KEY=your_anthropic_key_here
   ```

**Database Service:**

1. **Add PostgreSQL**
   - Click "Add Service" → "Database" → "PostgreSQL"
   - Railway will automatically create connection variables
   - The app will use `DATABASE_URL` automatically

2. **Add Redis**
   - Click "Add Service" → "Database" → "Redis"
   - Railway will provide `REDIS_URL` automatically

### Step 3: Configure Custom Domain (Optional)

1. **Add Custom Domain**
   - Go to Settings → Domains
   - Click "Add Domain"
   - Enter your domain (e.g., `monitor-legislativo.yourdomain.com`)

2. **SSL Certificate**
   - Railway automatically provides SSL certificates
   - No additional configuration needed

### Step 4: Deployment Configuration

The repository includes a `railway.toml` file that configures:
- Health checks at `/health`
- Automatic restarts on failure
- Production environment settings
- Memory and session limits

### Step 5: Environment-Specific Settings

**Development/Testing:**
```
SHINY_LOG_LEVEL=DEBUG
R_MAX_MEMORY=1GB
SHINY_MAX_SESSIONS=20
```

**Production:**
```
SHINY_LOG_LEVEL=INFO
R_MAX_MEMORY=2GB
SHINY_MAX_SESSIONS=100
```

## Post-Deployment Checklist

### ✅ Immediate Verification

1. **Health Check**
   ```bash
   curl https://your-app.railway.app/health
   ```

2. **Application Access**
   - Visit your Railway-provided URL
   - Test basic navigation and search functionality

3. **Database Connection**
   - Verify database connectivity through the app
   - Check for any connection errors in logs

### ✅ Functionality Testing

1. **Core Features**
   - [ ] LexML search functionality
   - [ ] Geographic mapping and visualization
   - [ ] Document viewing and analysis
   - [ ] Export capabilities

2. **AI Features** (if enabled)
   - [ ] Document summarization
   - [ ] Semantic search
   - [ ] Knowledge graph visualization
   - [ ] Recommendation engine

3. **Performance Verification**
   - [ ] Search response time <2s
   - [ ] Map rendering <3s
   - [ ] Document processing <5s
   - [ ] Page load time <15s

## Monitoring and Maintenance

### Built-in Railway Monitoring

Railway provides:
- **Metrics Dashboard**: CPU, memory, network usage
- **Logs Viewer**: Real-time application logs
- **Health Checks**: Automatic monitoring
- **Alerting**: Email notifications for issues

### Custom Monitoring

Access application metrics at:
- Health endpoint: `https://your-app.railway.app/health`
- Application logs: Railway dashboard → Logs tab

### Scaling Configuration

**Automatic Scaling:**
```toml
[deploy]
replicas = 1  # Start with 1 instance
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
```

**Resource Limits:**
- Memory: Up to 8GB (Railway Pro plan)
- CPU: Shared/dedicated cores available
- Storage: 100GB+ persistent volumes

## Cost Management

### Railway Pricing Tiers

**Hobby Plan (Free):**
- $0/month
- 500 hours execution time
- 1GB RAM, 1 vCPU
- Perfect for development/testing

**Pro Plan:**
- $20/month base + usage
- Unlimited execution time
- Up to 8GB RAM, 8 vCPU
- Custom domains included
- Recommended for production

### Cost Optimization

1. **Resource Right-sizing**
   ```
   R_MAX_MEMORY=1GB  # For small deployments
   SHINY_MAX_SESSIONS=50  # Adjust based on usage
   ```

2. **Environment Management**
   - Use Hobby plan for staging
   - Pro plan only for production
   - Sleep staging during off-hours

3. **Database Optimization**
   - Start with shared PostgreSQL
   - Upgrade to dedicated as needed
   - Monitor connection usage

## Troubleshooting

### Common Issues

**1. Build Failures**
```bash
# Check build logs in Railway dashboard
# Common fix: Update Dockerfile.production
```

**2. Memory Issues**
```bash
# Increase memory limit
R_MAX_MEMORY=4GB

# Reduce concurrent sessions
SHINY_MAX_SESSIONS=50
```

**3. Database Connection**
```bash
# Verify DATABASE_URL is set automatically
# Check PostgreSQL service status in Railway
```

**4. Health Check Failures**
```bash
# Verify health endpoint responds
curl https://your-app.railway.app/health

# Check application startup logs
```

### Debug Commands

**View Logs:**
- Railway Dashboard → Service → Logs
- Real-time log streaming available

**Environment Check:**
```r
# Add this to your R code for debugging
cat("Environment variables:\n")
cat("PORT:", Sys.getenv("PORT"), "\n")
cat("DATABASE_URL:", substr(Sys.getenv("DATABASE_URL"), 1, 20), "...\n")
cat("R_CONFIG_ACTIVE:", Sys.getenv("R_CONFIG_ACTIVE"), "\n")
```

## Security Best Practices

### Environment Variables
- Never commit secrets to repository
- Use Railway's environment variable interface
- Rotate API keys regularly

### Database Security
- Railway provides encrypted connections
- Database URLs include SSL parameters
- Regular backups automatically created

### Application Security
- Health checks don't expose sensitive data
- R application runs with restricted permissions
- HTTP headers configured for security

## Backup and Recovery

### Automatic Backups
Railway provides:
- Daily database backups (7-day retention)
- Point-in-time recovery
- One-click restore functionality

### Manual Backup
```bash
# Database backup (if needed)
pg_dump $DATABASE_URL > backup.sql

# Application data export
# Use built-in export functionality
```

## Performance Optimization

### Railway-Specific Optimizations

1. **Region Selection**
   - Choose region closest to users
   - US West recommended for global access

2. **Resource Allocation**
   ```
   R_MAX_MEMORY=2GB
   SHINY_MAX_SESSIONS=100
   ```

3. **Caching Strategy**
   - Redis automatically configured
   - Application-level caching enabled
   - Static assets cached by Railway CDN

### Monitoring Performance

Railway metrics show:
- Response time percentiles
- Memory and CPU usage
- Database connection count
- Error rates and status codes

## Support and Resources

### Railway Support
- [Documentation](https://docs.railway.app)
- [Discord Community](https://discord.gg/railway)
- Email support (Pro plan)

### Monitor Legislativo Support
- GitHub Issues for bugs/features
- Documentation in `/docs` folder
- Health check endpoint for monitoring

### Useful Links
- [Railway Dashboard](https://railway.app/dashboard)
- [Railway CLI](https://docs.railway.app/develop/cli)
- [Environment Variables Guide](https://docs.railway.app/deploy/variables)

---

## Quick Reference

### Essential URLs
- **Railway Dashboard**: https://railway.app/dashboard
- **Your Application**: https://your-service-name.railway.app
- **Health Check**: https://your-service-name.railway.app/health

### Key Commands
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Deploy from CLI
railway up

# View logs
railway logs

# Connect to database
railway connect postgres
```

### Environment Variables Template
```
# Required
PORT=3838
R_CONFIG_ACTIVE=production
SHINY_LOG_LEVEL=INFO

# Optional AI
OPENAI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

# Performance
R_MAX_MEMORY=2GB
SHINY_MAX_SESSIONS=100
```

Ready for production deployment on Railway! 🚀