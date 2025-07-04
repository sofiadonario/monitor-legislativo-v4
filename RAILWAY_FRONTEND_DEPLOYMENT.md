# Railway Frontend Deployment Guide

## Overview
This guide will help you deploy the Monitor Legislativo frontend on Railway, replacing GitHub Pages deployment.

## Benefits of Railway Frontend
- No CORS issues (frontend and backend on same platform)
- Environment variables support
- Better caching control
- Proper React Router support
- Unified logging and monitoring

## Step-by-Step Deployment

### 1. Create New Railway Service

1. Go to your Railway project dashboard
2. Click "New Service"  
3. Select "Empty Service" (NOT GitHub Repo yet)
4. Name it: "frontend" or "monitor-legislativo-frontend"
5. Once created, go to Settings → Connect GitHub Repo
6. Choose your repository: `sofiadonario/monitor-legislativo-v4`

### 2. Configure Build Settings

**IMPORTANT**: Since the repository has both Python (backend) and Node.js (frontend) code, you must override the auto-detection.

In the service Settings tab:

1. **Override Build Command**:
   ```bash
   cd $RAILWAY_PROJECT_ROOT && npm ci && npm run build
   ```

2. **Override Start Command**:
   ```bash
   cd $RAILWAY_PROJECT_ROOT && node server.js
   ```

3. **Builder**: Set to NIXPACKS (default)

4. **Watch Paths** (optional):
   - `src/**`
   - `public/**`
   - `package.json`
   - `*.ts`
   - `*.tsx`

**Alternative: Use Custom Dockerfile**
- Set Dockerfile Path: `Dockerfile.frontend`
- This bypasses auto-detection issues

### 3. Set Environment Variables

Add these variables in Railway:

```bash
# Required
NODE_ENV=production
VITE_RAILWAY_ENVIRONMENT=true

# Optional (for different backend)
VITE_API_URL=https://your-backend.railway.app
```

### 4. Configure Service Settings

1. **Port**: Railway will auto-detect from Dockerfile (80)
2. **Health Check Path**: `/health`
3. **Custom Domain** (optional): Add your domain

### 5. Deploy

1. Push your changes to GitHub
2. Railway will automatically build and deploy
3. Wait for the build to complete (~3-5 minutes)

## Post-Deployment

### Update Backend CORS (if needed)

If your backend has CORS restrictions, update them to allow the new frontend URL:

```python
# In your backend main.py
origins = [
    "https://your-frontend.up.railway.app",
    "http://localhost:5173",  # Keep for local dev
]
```

### DNS Configuration (Optional)

If using a custom domain:
1. Add a CNAME record pointing to your Railway URL
2. Configure SSL in Railway settings

## Environment Configuration

The frontend will automatically:
- Use relative URLs when `VITE_RAILWAY_ENVIRONMENT=true`
- Proxy `/api/*` requests to backend through nginx
- Serve static assets with proper caching

## Monitoring

Check deployment status:
- Build logs: Shows npm install and build output
- Deploy logs: Shows nginx startup
- Runtime logs: Shows HTTP requests

## Troubleshooting

### Build Fails
- Check Node version compatibility (using Node 20)
- Verify all dependencies are in package.json
- Check for TypeScript errors

### 404 Errors
- Nginx configuration handles React Router
- All routes return index.html
- Check browser console for JS errors

### API Connection Issues
- Backend must be in same Railway project
- Check service names match nginx config
- Verify backend is running

## Rollback

To rollback to GitHub Pages:
1. Keep GitHub Pages deployment active
2. Update DNS to point back to GitHub
3. Disable Railway service

## Cost Considerations

- Frontend typically uses minimal resources
- Estimated cost: $1-3/month
- Combined with backend: ~$10/month total