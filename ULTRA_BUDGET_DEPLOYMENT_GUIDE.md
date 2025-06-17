# Ultra-Budget Academic Deployment Guide
## Monitor Legislativo v4 - $7-16/month Setup

**Target Cost:** $7-16/month  
**Deployment Time:** 30-45 minutes  
**Technical Level:** Intermediate  

---

## 🎯 Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitHub Pages  │    │  Railway/Render │    │  Shinyapps.io   │
│   (Frontend)    │    │   (API Backend) │    │   (R Shiny)     │
│      FREE       │    │    $7/month     │    │   FREE-$9       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
        ┌─────────────────┐     │     ┌─────────────────┐
        │   Supabase      │     │     │    Upstash      │
        │  (Database)     │─────┼─────│  (Redis Cache)  │
        │      FREE       │     │     │      FREE       │
        └─────────────────┘     │     └─────────────────┘
                                │
                    ┌─────────────────┐
                    │   CloudFlare    │
                    │     (CDN)       │
                    │      FREE       │
                    └─────────────────┘
```

---

## 📋 Prerequisites Checklist

### Required Accounts (All Free to Create)
- [ ] GitHub account
- [ ] Railway account (linked to GitHub)
- [ ] Supabase account
- [ ] Upstash account
- [ ] CloudFlare account (optional but recommended)
- [ ] Shinyapps.io account (for R component)

### Local Development Setup
- [ ] Node.js 18+ installed
- [ ] Python 3.9+ installed
- [ ] Git configured
- [ ] Code editor (VS Code recommended)

---

## 🚀 Step-by-Step Deployment

### Step 1: Setup Supabase Database (FREE)

1. **Create Supabase Project:**
   ```bash
   # Go to https://supabase.com
   # Click "New Project"
   # Choose organization and region (closest to your users)
   # Project name: "monitor-legislativo"
   # Database password: Generate strong password
   ```

2. **Get Database URL:**
   ```bash
   # In Supabase Dashboard:
   # Settings > Database > Connection String > URI
   # Copy the connection string
   # Example: postgresql://postgres:[PASSWORD]@db.[PROJECT].supabase.co:5432/postgres
   ```

3. **Initialize Database Schema:**
   ```bash
   # The application will auto-initialize schema on first run
   # Or manually run SQL in Supabase SQL Editor:
   ```

### Step 2: Setup Upstash Redis (FREE)

1. **Create Redis Database:**
   ```bash
   # Go to https://upstash.com
   # Create account and new Redis database
   # Choose region closest to your API deployment
   # Copy the Redis URL from dashboard
   ```

2. **Get Redis Connection:**
   ```bash
   # In Upstash Dashboard:
   # Copy "Redis Connect URL"
   # Example: redis://default:[PASSWORD]@[HOST]:6379
   ```

### Step 3: Deploy API Backend to Railway ($7/month)

1. **Connect GitHub Repository:**
   ```bash
   # Go to https://railway.app
   # Connect GitHub account
   # Import your repository: monitor_legislativo_v4
   ```

2. **Configure Environment Variables:**
   ```bash
   # In Railway Dashboard > Variables:
   DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[PROJECT].supabase.co:5432/postgres
   REDIS_URL=redis://default:[PASSWORD]@[HOST]:6379
   ALLOWED_ORIGINS=https://[USERNAME].github.io
   CACHE_TTL_DEFAULT=3600
   ENABLE_CACHE_WARMING=true
   PORT=8000
   ```

3. **Deploy:**
   ```bash
   # Railway will automatically deploy from your main branch
   # Monitor deployment in Railway dashboard
   # Note the deployed URL: https://[APP-NAME].railway.app
   ```

### Step 4: Setup GitHub Pages (FREE)

1. **Configure Repository:**
   ```bash
   # In your GitHub repository settings:
   # Pages > Source > GitHub Actions
   # The workflow is already configured in .github/workflows/deploy.yml
   ```

2. **Set GitHub Secrets:**
   ```bash
   # Repository > Settings > Secrets and Variables > Actions
   # Add secret: API_URL = https://[APP-NAME].railway.app
   ```

3. **Deploy:**
   ```bash
   # Push to main branch triggers automatic deployment
   git add .
   git commit -m "feat: configure ultra-budget deployment"
   git push origin main
   ```

### Step 5: Setup CloudFlare CDN (FREE - Optional)

1. **Add Domain:**
   ```bash
   # If you have a custom domain:
   # Add site to CloudFlare
   # Update DNS to CloudFlare nameservers
   ```

2. **Configure Page Rules:**
   ```bash
   # Page Rules (free tier allows 3):
   # 1. *.js, *.css, *.woff2 → Cache Level: Cache Everything, TTL: 1 year
   # 2. /api/* → Cache Level: Standard
   # 3. /assets/* → Cache Level: Cache Everything, TTL: 1 month
   ```

### Step 6: Deploy R Shiny App (FREE - $9/month)

1. **Prepare R Environment:**
   ```r
   # Install required packages
   install.packages(c("shiny", "DT", "leaflet", "plotly"))
   ```

2. **Deploy to Shinyapps.io:**
   ```r
   # Install rsconnect
   install.packages("rsconnect")
   
   # Configure account (get from shinyapps.io dashboard)
   rsconnect::setAccountInfo(
     name="your-username",
     token="your-token", 
     secret="your-secret"
   )
   
   # Deploy from r-shiny-app directory
   setwd("r-shiny-app")
   rsconnect::deployApp()
   ```

---

## ⚙️ Configuration Files Setup

### Frontend Environment (.env.production)
```bash
VITE_API_URL=https://[APP-NAME].railway.app
VITE_CACHE_ENABLED=true
VITE_OFFLINE_ENABLED=true
VITE_ACADEMIC_MODE=true
```

### Backend Environment (Railway Variables)
```bash
DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[PROJECT].supabase.co:5432/postgres
REDIS_URL=redis://default:[PASSWORD]@[HOST]:6379
ALLOWED_ORIGINS=https://[USERNAME].github.io
ENABLE_CACHE_WARMING=true
PORT=8000
```

---

## 🔍 Verification & Testing

### 1. Test API Backend
```bash
# Check health endpoint
curl https://[APP-NAME].railway.app/health

# Expected response:
{"status": "healthy", "version": "4.0.0"}
```

### 2. Test Frontend
```bash
# Visit your GitHub Pages URL
https://[USERNAME].github.io/monitor_legislativo_v4/

# Check browser console for:
# - Service worker registration
# - Cache functionality
# - API connectivity
```

### 3. Test Cache Performance
```bash
# Monitor cache headers in Network tab:
# X-Cache: HIT/MISS
# X-Cache-Time: timestamp
```

### 4. Test R Shiny Integration
```bash
# Visit your Shiny app URL
https://[USERNAME].shinyapps.io/monitor-legislativo/
```

---

## 📊 Expected Performance

### Response Times
- **Cached API calls:** <200ms
- **Fresh API calls:** <2s
- **Page load time:** <1.5s
- **Export generation:** <3s (cached), <10s (fresh)

### Cache Hit Rates
- **Static assets:** >95%
- **API responses:** >70%
- **Search results:** >60%
- **Geographic data:** >90%

### Resource Limits (Free Tiers)
- **Supabase:** 500MB database, 2GB bandwidth/month
- **Upstash:** 10,000 requests/day, 256MB storage
- **Railway:** 512MB RAM, 1GB disk, $5 free credit
- **GitHub Pages:** 1GB storage, 100GB bandwidth/month

---

## 🚨 Troubleshooting

### Common Issues

1. **API Deployment Fails:**
   ```bash
   # Check Railway logs for errors
   # Common fix: Update requirements-production.txt
   # Ensure DATABASE_URL and REDIS_URL are set
   ```

2. **Database Connection Issues:**
   ```bash
   # Verify Supabase connection string
   # Check if IP is whitelisted (should be automatic)
   # Test connection from Railway logs
   ```

3. **Cache Not Working:**
   ```bash
   # Verify Redis URL in Railway
   # Check Upstash dashboard for connection stats
   # Look for Redis errors in logs
   ```

4. **CORS Errors:**
   ```bash
   # Update ALLOWED_ORIGINS in Railway
   # Include your GitHub Pages URL
   # Format: https://username.github.io
   ```

5. **Service Worker Issues:**
   ```bash
   # Clear browser cache
   # Check HTTPS is enabled
   # Verify service-worker.js is accessible
   ```

---

## 💰 Cost Monitoring

### Monthly Costs Breakdown
- **Railway API:** $7/month (includes 512MB RAM, 1GB disk)
- **Shiny Basic:** $9/month (optional, free tier available)
- **Domain:** $10-15/year (optional)
- **Total:** $7-16/month

### Usage Monitoring
- **Railway:** Monitor in dashboard (CPU, RAM, bandwidth)
- **Supabase:** Database size and API calls
- **Upstash:** Daily request count
- **GitHub Pages:** Bandwidth usage

### Scaling Triggers
- **Upgrade Railway:** If consistently hitting 512MB RAM
- **Upgrade Shiny:** If >25 hours/month usage
- **Add CDN:** If bandwidth costs increase

---

## 🔄 Maintenance Tasks

### Daily
- [ ] Monitor error rates in Railway logs
- [ ] Check cache hit rates in application metrics

### Weekly  
- [ ] Review Supabase database size
- [ ] Clean up expired cache entries
- [ ] Monitor Upstash request quotas

### Monthly
- [ ] Analyze cost usage across all services
- [ ] Review performance metrics
- [ ] Update dependencies if needed
- [ ] Backup configuration settings

---

## 🎯 Success Criteria

### Deployment Complete When:
- [ ] All health checks pass
- [ ] Frontend loads successfully
- [ ] API responses are cached (check X-Cache headers)
- [ ] Offline mode works
- [ ] Export functionality works
- [ ] Cost is within $7-16/month target

### Performance Targets:
- [ ] Page load time <1.5s
- [ ] API response time <500ms for cached requests  
- [ ] Cache hit rate >70%
- [ ] Export generation <3s for cached results
- [ ] 99%+ uptime

---

## 🔮 Next Steps

After successful deployment:

1. **Monitor and Optimize:**
   - Set up uptime monitoring
   - Track performance metrics
   - Optimize cache TTLs based on usage

2. **Scale When Needed:**
   - Upgrade Railway plan if hitting limits
   - Add custom domain with CloudFlare
   - Implement additional optimizations

3. **Academic Enhancements:**
   - Configure institutional authentication
   - Add research collaboration features
   - Implement data export scheduling

---

**Deployment Support:** Check logs in each service dashboard  
**Performance Issues:** Monitor cache hit rates and response times  
**Cost Concerns:** Review usage in each service's billing section

**Expected Total Setup Time:** 30-45 minutes  
**Monthly Cost:** $7-16 (depending on R Shiny usage)  
**Performance:** 60-80% improvement over unoptimized deployment