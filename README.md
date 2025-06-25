# Monitor Legislativo v4
**Ultra-Budget Academic Deployment with Advanced Analytics**

A comprehensive legislative monitoring system for Brazilian government APIs featuring LexML Enhanced Research Engine integration and advanced R-powered analytics.

## 🏗️ Repository Structure

This repository is comprehensively organized for maintainability and clarity. See [`REPOSITORY_STRUCTURE.md`](./REPOSITORY_STRUCTURE.md) for detailed organization.

### Quick Navigation
- **📋 [Planning](./planning/)** - Project roadmaps, PRDs, and feature specifications
- **📚 [Documentation](./documentation/)** - Guides, deployment docs, and technical reports  
- **🔧 [Development](./development/)** - Scripts, testing tools, and research materials
- **🌐 [External](./external/)** - Third-party libraries and vendor dependencies

## 🚀 Features

### Core Capabilities
- **Real-time Legislative Data** from Câmara, Senado, and 11+ regulatory agencies
- **LexML Enhanced Research Engine** with SKOS vocabulary expansion
- **Interactive Map Visualization** with offline capability
- **Academic Citation Tools** and multiple export formats
- **Advanced R Analytics** with secure iframe integration
- **Real-time Dashboard Updates** via Server-Sent Events
- **Saved Query Management** with tag-based organization
- **Mobile-Responsive Design** with accessibility features

### Performance & Cost
- **70%+ Performance Improvement** through intelligent caching
- **Ultra-Low Cost Deployment** ($7-16/month total)
- **Budget-Efficient Architecture** using free tiers and HTTP polling

## 🏗️ Two-Tier Architecture

### Tier 1: Automated Data Collection
- **Backend**: FastAPI + Python (Railway - $7/month)
- **Database**: PostgreSQL (Supabase - FREE) 
- **Cache**: Redis (Upstash - FREE)
- **Background Jobs**: Prefect-based collection service

### Tier 2: Analytics Dashboard  
- **Frontend**: React + TypeScript (GitHub Pages - FREE)
- **R Analytics**: Shiny integration (Shinyapps.io - FREE/optional $9)
- **Real-time Updates**: Server-Sent Events with polling fallback
- **CDN**: CloudFlare (FREE)

## 📋 Quick Start

### Prerequisites
- Node.js 18+
- Python 3.11+
- Git

### Local Development

**Automated Setup** (Recommended):
```bash
git clone https://github.com/your-username/monitor_legislativo_v4.git
cd monitor_legislativo_v4

# Run comprehensive development setup
./development/scripts/dev-setup.sh

# Initialize database
python development/scripts/initialize_database.py

# Verify installation
python development/test-scripts/verify_setup.py
```

**Manual Setup**:
1. **Clone and navigate:**
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

3. **Database setup:**
    ```bash
    # Unix/Linux/Mac
    ./development/scripts/setup_database.sh
    
    # Windows
    ./development/scripts/setup_database.bat
    
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