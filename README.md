# Monitor Legislativo v4
**Ultra-Budget Academic Deployment**

A comprehensive legislative monitoring system for Brazilian government APIs.

## 🚀 Features
- Real-time legislative data from Câmara, Senado, and regulatory agencies
- Interactive map visualization with offline capability
- Academic citation tools and multiple export formats
- 70%+ performance improvement through intelligent caching
- Ultra-low cost deployment ($7-16/month)

## 🏗️ Architecture
- **Frontend**: React + TypeScript (GitHub Pages - FREE)
- **Backend**: FastAPI + Python (Railway - $7/month)  
- **Database**: PostgreSQL (Supabase - FREE)
- **Cache**: Redis (Upstash - FREE)
- **CDN**: CloudFlare (FREE)
- **R Analytics**: Shiny (Shinyapps.io - FREE/optional $9)

## 📋 Quick Start

### Prerequisites
- Node.js 18+
- Python 3.11+
- Git

### Local Development
1. **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/monitor_legislativo_v4.git
    cd monitor_legislativo_v4
    ```

2. **Install dependencies:**
    ```bash
    # Backend dependencies
    pip install -r requirements.txt
    
    # Frontend dependencies
    npm install
    ```

3. **Configure environment:**
    ```bash
    # Copy environment example
    cp .env.example .env
    
    # For development with mock data (default)
    cp .env.development .env.development.local
    ```

4. **Run the application:**
```bash
# Start development servers
python launch.py  # Backend on :8000
npm run dev      # Frontend on :5173
```

### Data Service Architecture

The application uses a flexible data service layer that supports both mock data (for development/testing) and real API integration:

- **Development Mode**: Uses mock data by default (controlled by `VITE_USE_MOCK_DATA` in `.env.development`)
- **Production Mode**: Connects to the real API with automatic fallback and caching
- **API Client**: Includes retry logic, caching, and error handling
- **Type Safety**: Full TypeScript support for all data operations

### Production Deployment
Follow the deployment checklist:
1. Create accounts (GitHub, Railway, Supabase, Upstash)
2. Deploy backend to Railway
3. Deploy frontend to GitHub Pages
4. Configure environment variables
5. Test deployment

## 🎯 Performance Targets
- Page load: <1.5s
- API response: <500ms (cached)
- Cache hit rate: >70%
- Offline capability: Full functionality

## 📊 Cost Breakdown
- **Railway**: $7/month (API backend)
- **All other services**: FREE
- **Total**: $7/month for professional-grade platform

## 🔧 Environment Variables

### Backend (Railway)
```bash
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
ALLOWED_ORIGINS=https://username.github.io
PORT=8000
ENABLE_CACHE_WARMING=true
```

### Frontend (GitHub Actions)
```bash
API_URL=https://your-app.railway.app
```

## 📚 Documentation
- API Docs: `/api/docs` (Swagger UI)
- Health Check: `/health`
- Monitoring: `/api/v1/monitoring`

## 🏫 Academic Use
This system is optimized for academic research with:
- Proper citation formatting
- Multiple export formats (CSV, Excel, JSON)
- Research-grade data validation
- Institutional authentication support

---
© 2025 MackIntegridade - Academic Research Platform