# 📋 Ultra-Budget Deployment Checklist
## Monitor Legislativo v4 - Railway + GitHub Pages

**Target Cost:** $7/month | **Setup Time:** 15-30 minutes

---

## ✅ Phase 1: Repository Setup

- [x] **Clean repository structure**
- [x] **Remove unnecessary documentation files** 
- [x] **Fixed remote repository URL** (`monitor-legislativo-v4`)
- [x] **Optimized `requirements.txt`** (uvicorn + FastAPI)
- [x] **`nixpacks.toml`** configured to use `venv` and `requirements.txt`
- [x] **`railway.json`** has correct `startCommand` pointing to `.venv/bin/python`
- [x] **Created proper WSGI entry point** (`wsgi.py`)
- [x] **Railway configuration** (`railway.json`, `Procfile`)

---

## 🚀 Phase 2: Deploy to Railway

### 2.1 Repository Connection
- [ ] Go to https://railway.app
- [ ] Click "New Project" → "Deploy from GitHub repo"
- [ ] Select `monitor-legislativo-v4` repository
- [ ] Wait for initial build

### 2.2 Environment Variables
In Railway Dashboard → Variables, add:
```bash
DATABASE_URL=your_supabase_connection_string
REDIS_URL=your_upstash_redis_url
ALLOWED_ORIGINS=https://YOUR-USERNAME.github.io
PORT=8000
ENABLE_CACHE_WARMING=true
DEBUG=false
```

### 2.3 Verify Deployment
- [ ] Build completes successfully
- [ ] Container starts successfully with uvicorn
- [ ] Health check passes: `https://your-app.railway.app/health`
- [ ] API docs accessible: `https://your-app.railway.app/api/docs`

---

## 🌐 Phase 3: Deploy Frontend (GitHub Pages)

### 3.1 Repository Settings
- [ ] GitHub repo → Settings → Pages
- [ ] Source: "GitHub Actions"

### 3.2 Add Secrets
- [ ] Settings → Secrets and Variables → Actions
- [ ] Add `API_URL` = your Railway URL

### 3.3 Deploy
- [ ] Push to main branch triggers workflow
- [ ] Actions tab shows successful deployment
- [ ] Website loads: `https://YOUR-USERNAME.github.io/monitor-legislativo-v4/`

---

## 🧪 Phase 4: Testing

### 4.1 Backend Tests
- [ ] `/health` returns `{"status": "healthy", "version": "4.0.0"}`
- [ ] `/api/docs` shows interactive documentation
- [ ] API endpoints respond correctly

### 4.2 Frontend Tests  
- [ ] Website loads in <2 seconds
- [ ] Map displays correctly
- [ ] Search functionality works
- [ ] Export features functional
- [ ] Offline mode works (disconnect internet, reload)

### 4.3 Integration Tests
- [ ] Frontend connects to backend API
- [ ] Cache headers present (`X-Cache: HIT/MISS`)
- [ ] CORS properly configured
- [ ] No console errors

---

## 📊 Phase 5: Performance Verification

### 5.1 Response Times
- [ ] Page load: <1.5s ✅
- [ ] API cached: <200ms ✅  
- [ ] API fresh: <2s ✅
- [ ] Export generation: <3s ✅

### 5.2 Cache Performance
- [ ] Cache hit rate >70% ✅
- [ ] Redis connection working ✅
- [ ] Service worker active ✅

---

## 💰 Phase 6: Cost Monitoring

### 6.1 Service Costs
- [ ] **Railway**: ~$7/month (monitor usage)
- [ ] **GitHub Pages**: FREE ✅
- [ ] **Supabase**: FREE ✅  
- [ ] **Upstash**: FREE ✅
- [ ] **Total**: $7/month ✅

### 6.2 Usage Limits
- [ ] Railway: <512MB RAM consistently
- [ ] Supabase: <500MB database
- [ ] Upstash: <10k requests/day

---

## 🔧 Troubleshooting Guide

### Common Issues & Solutions

**"Container failed to start - server not found"**
- ✅ **SOLVED**: Using uvicorn directly via Procfile
- ✅ **SOLVED**: Created minimal_app.py entry point
- ✅ **SOLVED**: Railway detects Procfile correctly

**"Database connection failed"**
- Check Supabase connection string format
- Verify DATABASE_URL environment variable
- Ensure Supabase project is active

**"Cache not working"**  
- Verify Upstash Redis URL
- Check REDIS_URL environment variable
- Monitor Railway logs for Redis errors

**"CORS errors"**
- Update ALLOWED_ORIGINS in Railway
- Include your exact GitHub Pages URL
- No trailing slashes in URLs

---

## 🎯 Success Criteria

### ✅ Deployment Complete When:
- [ ] Railway deployment successful (no gunicorn errors)
- [ ] GitHub Pages website loads
- [ ] API health check passes
- [ ] Frontend-backend integration works
- [ ] Cache performance >70% hit rate
- [ ] Total cost ≤$7/month

### 🏆 Performance Targets Met:
- [ ] Page load <1.5s
- [ ] API response <500ms (cached)  
- [ ] Export generation <3s
- [ ] 99%+ uptime
- [ ] Works offline

---

## 📞 Support Resources

**Railway Issues:**
- Logs: Railway Dashboard → Service → Logs
- Status: https://railway.app/status

**GitHub Pages Issues:**  
- Actions: Repository → Actions tab
- Status: https://www.githubstatus.com

**Quick Debug Commands:**
```bash
# Test API locally
curl https://your-app.railway.app/health

# Check environment variables
railway logs

# Test frontend build
npm run build
npm run preview
```

---

**🎉 DEPLOYMENT COMPLETE!**  
Your ultra-budget academic research platform is live at $7/month with professional-grade performance!