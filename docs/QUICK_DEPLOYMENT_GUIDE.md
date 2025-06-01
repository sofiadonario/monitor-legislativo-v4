# 🚀 Quick Deployment Guide - Monitor Legislativo v4

## 📋 Step 1: Configure Environment (5 minutes)

### Option A: Interactive Configuration (Recommended)
```bash
# Make the configuration script executable
chmod +x scripts/configure_environment.py

# Run the interactive configuration wizard
python scripts/configure_environment.py
```

### Option B: Manual Configuration
```bash
# Copy the template
cp .env.production.template .env.production

# Edit with your values
nano .env.production
```

## 🔑 Essential Configuration Values

### 1. **Database (Choose One)**

#### Supabase (Free - 500MB)
```env
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.xxxxx.supabase.co:5432/postgres
```
- Sign up at: https://supabase.com
- Create new project
- Copy connection string from Settings > Database

#### Neon (Free - 3GB) 
```env
DATABASE_URL=postgresql://user:password@xxx.neon.tech/dbname
```
- Sign up at: https://neon.tech
- Create new project
- Copy connection string

#### Railway PostgreSQL ($5/month)
```env
DATABASE_URL=postgresql://postgres:xxx@containers-xxx.railway.app:5432/railway
```

### 2. **Redis Cache (Choose One)**

#### Upstash (Free - 10MB)
```env
REDIS_URL=redis://default:xxx@xxx.upstash.io:6379
```
- Sign up at: https://upstash.com
- Create Redis database
- Copy REST URL

#### Redis Cloud (Free - 30MB)
```env
REDIS_URL=redis://:password@redis-xxx.c1.us-east-1-2.ec2.cloud.redislabs.com:12345
```

### 3. **Security Keys (Auto-generated)**
```bash
# Generate secure keys
openssl rand -base64 32  # For SECRET_KEY
openssl rand -base64 32  # For JWT_SECRET
```

### 4. **Domain Configuration**
```env
FRONTEND_URL=https://monitor-legislativo.gov.br  # Or your domain
BACKEND_URL=https://api.monitor-legislativo.gov.br
```

## 🏃 Step 2: Deploy Application

### For $7/month Setup (Railway + Free Services)
```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login to Railway
railway login

# 3. Create new project
railway init

# 4. Deploy backend
railway up

# 5. Add environment variables in Railway dashboard
# Copy all values from .env.production
```

### For Docker Deployment (VPS/Local)
```bash
# Make scripts executable
chmod +x scripts/deploy.sh scripts/entrypoint.sh

# Run deployment
./scripts/deploy.sh deploy
```

### For GitHub Pages (Frontend Only)
```bash
# Build frontend
npm run build

# Deploy to GitHub Pages
npm run deploy
```

## ✅ Step 3: Verify Deployment

### Health Checks
```bash
# Check backend health
curl https://your-backend-url/api/v1/health

# Check database
curl https://your-backend-url/api/v1/health/database

# Check cache
curl https://your-backend-url/api/v1/health/cache

# Test search
curl -X POST https://your-backend-url/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "transporte"}'
```

## 🆘 Troubleshooting

### Database Connection Issues
```bash
# Test connection
psql $DATABASE_URL -c "SELECT 1"

# Check logs
docker logs monitor-legislativo-backend
```

### Redis Connection Issues
```bash
# Test connection
redis-cli -u $REDIS_URL ping
```

### Port Issues
- Backend runs on port 8000
- Frontend runs on port 80/443
- Database on port 5432
- Redis on port 6379

## 📊 Monitoring URLs

After deployment, access:
- Main App: `https://your-domain.com`
- API Docs: `https://your-domain.com/api/docs`
- Health: `https://your-domain.com/api/v1/health`
- Metrics: `https://your-domain.com/metrics`

## 💰 Cost Breakdown

### Minimal ($7/month)
- Railway Backend: $7
- Supabase DB: Free
- Upstash Redis: Free
- GitHub Pages: Free

### Standard ($13/month)
- Railway Backend: $12
- Neon DB: Free
- Redis Cloud: $1
- Cloudflare: Free

### Production ($16/month)
- Render Backend: $15
- Neon DB: Free
- AWS S3: $1
- Monitoring: Free

## 🎯 Next Steps

1. **Configure DNS**
   - Point domain to your backend
   - Setup SSL certificates

2. **Enable Monitoring**
   - Access Grafana dashboards
   - Setup alerts

3. **Test Features**
   - Search functionality
   - API integrations
   - Citation generation

4. **Announce Launch**
   - Notify academic partners
   - Share with government agencies

---

**Need Help?** 
- Check logs: `docker logs monitor-legislativo-backend`
- Review docs: `/documentation` folder
- Test endpoints: Use the health check URLs above

🇧🇷 **Boa sorte com o lançamento!**