# 📋 Deployment Setup Checklist - Monitor Legislativo v4

## 🎯 Your Configuration: GitHub Pages + Free Services

I've created a `.env.production` file pre-configured for your deployment. Follow these steps to complete the setup:

## ✅ Step 1: Set Up Free Database (Supabase)

1. **Go to**: https://supabase.com
2. **Sign up** for a free account
3. **Create a new project** (name: `monitor-legislativo`)
4. **Wait** for project to initialize (~2 minutes)
5. **Get your credentials**:
   - Go to Settings → Database
   - Copy the **Connection string** (URI)
   - Note your **Database password**

6. **Update `.env.production`**:
   ```bash
   # Replace these lines with your actual values:
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.YOUR_PROJECT.supabase.co:5432/postgres
   DB_HOST=db.YOUR_PROJECT.supabase.co
   DB_PASSWORD=YOUR_PASSWORD
   ```

## ✅ Step 2: Set Up Free Redis Cache (Upstash)

1. **Go to**: https://upstash.com
2. **Sign up** for a free account
3. **Create a Redis database**:
   - Name: `monitor-legislativo-cache`
   - Region: Choose closest to you
   - Type: Regional
4. **Get your credentials**:
   - Copy the **Redis URL** from the dashboard
   
5. **Update `.env.production`**:
   ```bash
   # Replace with your Upstash Redis URL:
   REDIS_URL=redis://default:YOUR_PASSWORD@YOUR_ENDPOINT.upstash.io:6379
   ```

## ✅ Step 3: Generate Security Keys

Run these commands to generate secure keys:

```bash
# Generate SECRET_KEY (64 characters)
openssl rand -base64 48

# Generate JWT_SECRET (32 characters)
openssl rand -base64 24

# Generate SESSION_SECRET (32 characters)
openssl rand -base64 24
```

**Update `.env.production`** with the generated keys:
```bash
SECRET_KEY=YOUR_GENERATED_64_CHAR_KEY
JWT_SECRET=YOUR_GENERATED_32_CHAR_KEY
SESSION_SECRET=YOUR_GENERATED_32_CHAR_KEY
```

## ✅ Step 4: Deploy Backend to Railway

1. **Install Railway CLI**:
   ```bash
   npm install -g @railway/cli
   ```

2. **Login**:
   ```bash
   railway login
   ```

3. **Create new project**:
   ```bash
   railway init
   # Choose: Empty project
   # Name: monitor-legislativo-backend
   ```

4. **Deploy**:
   ```bash
   railway up
   ```

5. **Configure environment**:
   - Go to https://railway.app/dashboard
   - Select your project
   - Go to Variables tab
   - Click "Raw Editor"
   - Copy ALL contents from `.env.production`
   - Paste and save

6. **Get your backend URL**:
   - In Railway dashboard → Settings
   - Generate domain (e.g., `monitor-legislativo-backend.up.railway.app`)
   - Update `.env.production`:
   ```bash
   BACKEND_URL=https://YOUR-APP.up.railway.app
   API_BASE_URL=https://YOUR-APP.up.railway.app/api/v1
   ```

## ✅ Step 5: Configure Frontend

1. **Update frontend configuration**:
   ```bash
   # Edit src/config/api.ts
   export const API_BASE_URL = 'https://YOUR-BACKEND.up.railway.app/api/v1';
   ```

2. **Build frontend**:
   ```bash
   npm run build
   ```

3. **Deploy to GitHub Pages**:
   ```bash
   # Commit your changes
   git add .
   git commit -m "Configure production deployment"
   git push origin main

   # Deploy to GitHub Pages
   npm run deploy
   ```

## ✅ Step 6: Verify Deployment

### Backend Health Checks:
```bash
# Check API health
curl https://YOUR-BACKEND.up.railway.app/api/v1/health

# Check database connection
curl https://YOUR-BACKEND.up.railway.app/api/v1/health/database

# Check Redis cache
curl https://YOUR-BACKEND.up.railway.app/api/v1/health/cache
```

### Frontend Access:
- Visit: https://sofiadonario.github.io/monitor-legislativo-v4/
- Test search functionality
- Verify API connection

## 📊 Expected Costs

- **Database (Supabase)**: FREE (500MB)
- **Redis (Upstash)**: FREE (10MB)
- **Backend (Railway)**: ~$7/month
- **Frontend (GitHub Pages)**: FREE
- **Total**: ~$7/month

## 🚨 Important Notes

1. **Database Migrations**: Railway will automatically run migrations on first deploy
2. **API Keys**: Brazilian government APIs are mostly public (no keys needed)
3. **CORS**: Already configured for your GitHub Pages URL
4. **SSL**: Railway provides free SSL certificates

## 🆘 Troubleshooting

### Railway deployment fails:
```bash
# Check logs
railway logs

# Restart deployment
railway up --detach
```

### Database connection issues:
- Verify Supabase project is active
- Check connection string format
- Ensure password has no special characters that need escaping

### Redis connection issues:
- Verify Upstash database is active
- Check if Redis URL includes password
- Test with: `redis-cli -u YOUR_REDIS_URL ping`

## 📋 Final Checklist

- [ ] Supabase database created and configured
- [ ] Upstash Redis created and configured
- [ ] Security keys generated and added
- [ ] Backend deployed to Railway
- [ ] Environment variables added to Railway
- [ ] Frontend configuration updated
- [ ] Frontend deployed to GitHub Pages
- [ ] All health checks passing

---

**Ready to start?** Begin with Step 1 (Supabase setup) and work through each step. The entire process should take about 30-45 minutes.

🇧🇷 **Boa sorte!**