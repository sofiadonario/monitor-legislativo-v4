# 🚀 Deployment Instructions - Monitor Legislativo v4

## Step 1: Push Code to GitHub

Since authentication is required, you'll need to push the code manually:

### Option A: Using GitHub Desktop or VS Code
1. Open GitHub Desktop or VS Code
2. Push the commits to `origin/main`

### Option B: Using Command Line with PAT (Personal Access Token)
1. Create a Personal Access Token at: https://github.com/settings/tokens
2. Run: `git push -u origin main`
3. When prompted:
   - Username: `sofiadonario`
   - Password: Your Personal Access Token

### Option C: Using HTTPS with credentials
```bash
git remote set-url origin https://sofiadonario@github.com/sofiadonario/monitor-legislativo-v4.git
git push -u origin main
```

---

## Step 2: Deploy Backend to Railway

1. **Go to Railway Dashboard**: https://railway.app/dashboard

2. **Create New Project**:
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose `monitor-legislativo-v4`
   - Railway will start building automatically

3. **Add Environment Variables**:
   Go to your Railway service → Variables tab and add:
   ```
   DATABASE_URL=(your Supabase PostgreSQL URL)
   REDIS_URL=(your Upstash Redis URL)
   ALLOWED_ORIGINS=https://sofiadonario.github.io
   PORT=8000
   ENABLE_CACHE_WARMING=true
   DEBUG=false
   ```

4. **Wait for Deployment**:
   - Railway will automatically detect the Procfile
   - It will use: `python -m uvicorn minimal_app:app --host 0.0.0.0 --port $PORT`
   - Deployment should complete in 2-3 minutes

5. **Get Your API URL**:
   - Once deployed, Railway will provide a URL like: `https://monitor-legislativo-v4-production.up.railway.app`
   - Test it: `https://your-railway-url/health`

---

## Step 3: Deploy Frontend to GitHub Pages

1. **Enable GitHub Pages**:
   - Go to: https://github.com/sofiadonario/monitor-legislativo-v4/settings/pages
   - Source: Select "GitHub Actions"

2. **Add API URL Secret**:
   - Go to: https://github.com/sofiadonario/monitor-legislativo-v4/settings/secrets/actions
   - Click "New repository secret"
   - Name: `API_URL`
   - Value: Your Railway URL (from Step 2)

3. **Trigger Deployment**:
   - The push to main branch will automatically trigger the workflow
   - Or manually trigger: Actions tab → Deploy to GitHub Pages → Run workflow

4. **Access Your Site**:
   - After 5-10 minutes, visit: https://sofiadonario.github.io/monitor-legislativo-v4/

---

## Step 4: Create Free Service Accounts (if not already done)

### Supabase (Database)
1. Go to: https://supabase.com
2. Create project: "monitor-legislativo"
3. Get connection string from: Settings → Database → Connection String → URI

### Upstash (Redis Cache)
1. Go to: https://upstash.com
2. Create Redis database: "monitor-legislativo-cache"
3. Get Redis URL from dashboard

---

## Step 5: Verify Everything Works

### Backend Tests:
```bash
# Health check
curl https://your-railway-url/health
# Should return: {"status": "healthy", "version": "4.0.0"}

# API docs
https://your-railway-url/api/docs
```

### Frontend Tests:
1. Visit: https://sofiadonario.github.io/monitor-legislativo-v4/
2. Check:
   - [ ] Map loads
   - [ ] Search works
   - [ ] Export functions work
   - [ ] Offline mode works (disconnect internet, reload)
   - [ ] No console errors

### Performance Tests:
- Open DevTools Network tab
- Look for `X-Cache: HIT` headers
- Page should load in <2 seconds

---

## 🎯 Expected Results

✅ **Railway Deployment**: Clean uvicorn-based deployment  
✅ **Total Cost**: $7/month (Railway only)  
✅ **Performance**: 70%+ cache hit rate  
✅ **Availability**: 99%+ uptime  

---

## 🆘 Troubleshooting

**Railway Build Fails**:
- Check build logs in Railway dashboard
- Verify all environment variables are set
- Ensure requirements.txt has uvicorn and all dependencies

**Frontend Not Loading**:
- Check GitHub Actions logs
- Verify API_URL secret is set correctly
- Ensure ALLOWED_ORIGINS includes your GitHub Pages URL

**CORS Errors**:
- Update ALLOWED_ORIGINS in Railway to exactly: `https://sofiadonario.github.io`
- No trailing slashes!

---

## 📊 Monitor Costs

- **Railway**: Monitor usage at https://railway.app/account/usage
- **Target**: Stay under $7/month
- **Free Services**: GitHub Pages, Supabase, Upstash all on free tiers

Good luck with your deployment! 🚀