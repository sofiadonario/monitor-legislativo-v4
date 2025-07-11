# Frontend Deployment Instructions

## Railway Setup with Subdirectory

### Step 1: Create Railway Service
1. Go to Railway project dashboard
2. Click **"New Service"**
3. Select **"Empty Service"**
4. Name it: **"frontend"**

### Step 2: Connect Repository
1. In the new service, go to **Settings** tab
2. Find **Source** section
3. Click **"Connect GitHub repo"**
4. Select: `sofiadonario/monitor-legislativo-v4`

### Step 3: Set Root Directory
1. Still in **Settings** tab
2. Find **Source** section
3. Set **Root Directory** to: `/frontend`
4. This tells Railway to only look at the frontend folder

### Step 4: Configure Builder
1. In **Settings** tab, find **Builder** section
2. Select **"Nixpacks"** (default)
3. Nixpacks will auto-detect package.json in /frontend directory

### Step 5: Environment Variables (Optional)
1. Go to **Variables** tab
2. Add:
   - `NODE_ENV` = `production`
   - `VITE_RAILWAY_ENVIRONMENT` = `true`

### Step 6: Deploy
1. Go to **Deployments** tab
2. Click **"Deploy"**
3. Railway will:
   - Use only files in `/frontend` directory
   - Run `npm install` and `npm run build`
   - Auto-detect start command

### Step 7: Generate Domain
1. After successful deployment
2. Go to **Settings** → **Networking**
3. Click **"Generate Domain"**
4. Your frontend will be available at the generated URL

## What This Setup Does

- **Isolates frontend code** in `/frontend` directory
- **No Python conflicts** since only frontend files are used
- **Automatic detection** of Node.js project
- **API proxying** through nginx or express server
- **Clean separation** from backend code

## File Structure
```
frontend/
├── package.json          # Node.js dependencies
├── Dockerfile            # Alternative build method
├── nginx.conf            # Nginx configuration
├── server.js             # Express server option
├── .env                  # Environment variables
├── src/                  # React source code
├── public/               # Static assets
└── DEPLOYMENT.md         # This file
```

## Alternative: Use Dockerfile
If Nixpacks has issues, you can:
1. In Railway Settings → Builder
2. Set **Dockerfile Path** to: `Dockerfile`
3. Railway will use the Dockerfile in /frontend directory