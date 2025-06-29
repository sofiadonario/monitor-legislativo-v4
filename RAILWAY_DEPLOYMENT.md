# Railway Deployment Guide
## Monitor Legislativo v4 - Complete Deployment

### 🎉 **Status: READY FOR DEPLOYMENT**

All components are configured and tested for Railway deployment:

#### ✅ **Completed Setup:**
- **R Shiny**: Installed and tested (Shiny 1.11.0)
- **React Frontend**: Built successfully with R Shiny integration
- **Docker Configuration**: Multi-service setup ready
- **Environment Variables**: Production URLs configured
- **Health Monitoring**: R Shiny status component implemented

---

## 🚀 **Deployment Steps**

### **1. Install Railway CLI**
```bash
# Install Railway CLI (requires admin/sudo)
curl -fsSL https://railway.app/install.sh | sh

# Or via npm (alternative)
npm install -g @railway/cli
```

### **2. Login to Railway**
```bash
railway login
```

### **3. Deploy R Shiny Service**
```bash
# Navigate to project root
cd /path/to/monitor_legislativo_v4

# Deploy R Shiny service
railway up --service monitor-legislativo-rshiny

# Monitor deployment
railway logs --service monitor-legislativo-rshiny
```

### **4. Deploy Python API (if not already deployed)**
```bash
# Deploy main API service
railway up --service monitor-legislativo-api

# Monitor API deployment
railway logs --service monitor-legislativo-api
```

### **5. Configure Domains**
```bash
# Generate domain for R Shiny
railway domain generate --service monitor-legislativo-rshiny

# Generate domain for API (if needed)
railway domain generate --service monitor-legislativo-api

# View all domains
railway domain list
```

---

## 📋 **Service Configuration**

### **R Shiny Service:**
- **Dockerfile**: `r-shiny-app/Dockerfile`
- **Port**: 3838
- **Health Check**: `/health`
- **Expected URL**: `https://monitor-legislativo-rshiny-production.up.railway.app`

### **Python API Service:**
- **Dockerfile**: `main_app/Dockerfile`
- **Port**: 8000
- **Health Check**: `/health`
- **Current URL**: `https://monitor-legislativo-v4-production.up.railway.app`

### **React Frontend:**
- **Hosting**: GitHub Pages
- **URL**: `https://sofiadonario.github.io/monitor-legislativo-v4/`
- **Build**: Already configured for production URLs

---

## 🔧 **Environment Variables**

### **For R Shiny Service:**
```bash
railway env set SHINY_LOG_LEVEL=INFO --service monitor-legislativo-rshiny
railway env set R_LIBS_USER=/app/renv/library --service monitor-legislativo-rshiny
railway env set ENVIRONMENT=production --service monitor-legislativo-rshiny
railway env set PORT=3838 --service monitor-legislativo-rshiny
```

### **For Python API (if needed):**
```bash
railway env set DATABASE_URL=your_database_url --service monitor-legislativo-api
railway env set ENVIRONMENT=production --service monitor-legislativo-api
```

---

## 🧪 **Testing Deployment**

### **1. Health Checks**
```bash
# Test R Shiny health
curl https://monitor-legislativo-rshiny-production.up.railway.app/health

# Test API health
curl https://monitor-legislativo-v4-production.up.railway.app/health
```

### **2. React Integration**
```bash
# Open React app
open https://sofiadonario.github.io/monitor-legislativo-v4/

# Check R Shiny status indicator in dashboard
# Should show "R Shiny Available" with green status
```

### **3. Full Integration Test**
```bash
# Run comprehensive test suite
./test_full_integration.sh
```

---

## 📊 **Expected Deployment Architecture**

```
GitHub Pages (React Frontend)
       ↓
   [Internet]
       ↓
┌─────────────────────────────────────┐
│           Railway Cloud             │
│                                     │
│  ┌─────────────────┐ ┌─────────────┐│
│  │   Python API    │ │   R Shiny   ││
│  │   Port: 8000    │ │  Port: 3838 ││
│  │   FastAPI       │ │  Shiny App  ││
│  └─────────────────┘ └─────────────┘│
│           │                  │      │
│           ↓                  ↓      │
│    ┌─────────────────────────────┐  │
│    │      Supabase Database      │  │
│    │         (External)          │  │
│    └─────────────────────────────┘  │
└─────────────────────────────────────┘
```

---

## 🎯 **Key URLs After Deployment**

| Service | URL | Status |
|---------|-----|--------|
| React Frontend | https://sofiadonario.github.io/monitor-legislativo-v4/ | ✅ Deployed |
| Python API | https://monitor-legislativo-v4-production.up.railway.app | ✅ Deployed |
| R Shiny Service | https://monitor-legislativo-rshiny-production.up.railway.app | ⏳ Ready to Deploy |

---

## 🔍 **Monitoring & Logs**

### **View Logs:**
```bash
# R Shiny logs
railway logs --service monitor-legislativo-rshiny

# API logs
railway logs --service monitor-legislativo-api

# Real-time monitoring
railway logs --follow --service monitor-legislativo-rshiny
```

### **Service Status:**
```bash
# Check all services
railway status

# Service details
railway service --service monitor-legislativo-rshiny
```

---

## 💰 **Cost Estimation**

### **Railway Costs:**
- **Hobby Plan**: $5/month per service
- **R Shiny Service**: $5/month
- **Python API**: $5/month (if not already included)
- **Total**: $5-10/month

### **Resource Usage:**
- **R Shiny**: ~512MB RAM, 1 CPU
- **Python API**: ~256MB RAM, 1 CPU
- **Storage**: ~1GB per service

---

## 🚨 **Troubleshooting**

### **Common Issues:**

#### **1. R Package Installation Fails**
```bash
# Check logs for missing system dependencies
railway logs --service monitor-legislativo-rshiny | grep -i error

# Common fixes: Install system packages in Dockerfile
RUN apt-get update && apt-get install -y libfontconfig1-dev
```

#### **2. Health Check Fails**
```bash
# Check if port 3838 is properly exposed
# Verify Dockerfile EXPOSE 3838

# Check health endpoint implementation
curl -v https://your-app.up.railway.app/health
```

#### **3. React Integration Issues**
```bash
# Verify CORS settings in R Shiny app
# Check environment variables in production
# Ensure URLs match in rshiny.ts config
```

---

## ✅ **Deployment Checklist**

- [ ] Railway CLI installed
- [ ] Logged into Railway account
- [ ] Environment variables configured
- [ ] R Shiny service deployed
- [ ] Health checks passing
- [ ] React frontend updated with production URLs
- [ ] Integration tested end-to-end
- [ ] Monitoring set up

---

## 🎉 **Success Criteria**

When deployment is successful, you should see:

1. **R Shiny Status**: Green "R Shiny Available" in React dashboard
2. **Health Endpoint**: Returns 200 OK with JSON response
3. **Full Integration**: React ↔ R Shiny communication working
4. **Analytics**: Advanced R-powered analytics accessible via React

---

**Ready for deployment! All components are configured and tested.** 🚀