# Monitor Legislativo v4 - Codebase Overview for New Developers

## 🎯 What is Monitor Legislativo?

Monitor Legislativo v4 is a sophisticated academic research platform for monitoring Brazilian legislative data, with a special focus on transport-related legislation. It's designed to help researchers, academics, and policy analysts track, analyze, and understand Brazilian laws and regulations through advanced search capabilities and data visualization tools.

### Key Highlights:
- **Academic Research Tool**: Built for serious legislative research with citation support
- **Real Data Only**: No mock data or placeholders - all data comes from official Brazilian government sources
- **Budget-Conscious**: Operates on $7-16/month using clever optimization and free tiers
- **Vocabulary-Aware Search**: Uses SKOS controlled vocabularies to expand searches intelligently

## 🏗️ Architecture Overview

The system follows a two-tier architecture:

### Tier 1: Data Collection Service
- Automated collection from Brazilian government APIs
- Background jobs scheduled with Prefect
- Data validation and storage in PostgreSQL (Supabase)
- Runs periodically to keep data fresh

### Tier 2: User-Facing Platform
- **Frontend**: React/TypeScript single-page application
- **Backend**: Python/FastAPI REST API
- **Analytics**: R Shiny application (optional)
- **Caching**: Redis for performance optimization

## 📁 Project Structure

```
monitor_legislativo_v4/
├── src/                    # Frontend React/TypeScript code
│   ├── components/         # Reusable UI components
│   ├── pages/             # Page-level components
│   ├── services/          # API interaction layer
│   ├── utils/             # Helper functions
│   └── config/            # Configuration files
├── backend/               # Python backend (Poetry project)
│   ├── core/             # Core business logic
│   ├── main_app/         # FastAPI application
│   ├── web/              # Additional endpoints
│   └── tests/            # Backend tests
├── r-shiny-app/          # R analytics dashboard
├── data/                 # Data storage
│   ├── raw/             # Original data files
│   ├── processed/       # Transformed data
│   └── exports/         # User-generated exports
├── scripts/              # Deployment and utility scripts
└── documentation/        # Project documentation
```

## 🔧 Technology Stack

### Frontend
- **Framework**: React 18.3.1 with TypeScript 5.7.2
- **Build Tool**: Vite 6.3.5 (fast, modern bundler)
- **Routing**: React Router DOM
- **Maps**: Leaflet for interactive visualizations
- **Data Processing**: PapaParse (CSV), D3.js (visualization)
- **Styling**: CSS modules with responsive design
- **Hosting**: GitHub Pages (free)

### Backend
- **Framework**: FastAPI 0.104.1 (async Python web framework)
- **Language**: Python 3.11
- **Database**: PostgreSQL via Supabase (free tier)
- **Cache**: Redis via Upstash (free tier)
- **HTTP Client**: aiohttp (async requests)
- **Data Processing**: pandas, BeautifulSoup4
- **Hosting**: Railway ($7/month)

### Analytics (Optional)
- **Framework**: R Shiny
- **Purpose**: Advanced statistical analysis and visualizations
- **Deployment**: Self-hosted or local

## 🚀 Key Features

### 1. LexML Enhanced Research Engine
The crown jewel of the system - provides vocabulary-aware search:
- **SKOS Vocabularies**: W3C-compliant controlled vocabularies
- **Term Expansion**: "transporte" automatically expands to 50+ related terms
- **Multi-Source Search**: Aggregates results from 11+ government sources
- **Academic Metadata**: FRBROO-compliant with automatic citations

### 2. Real-Time Legislative Monitoring
- Live updates from Câmara dos Deputados and Senado Federal
- Tracks bills, amendments, and legislative activity
- Interactive timeline visualizations

### 3. Geographic Analysis
- Interactive maps showing legislative impact by region
- Brazilian municipality data (5,570 cities)
- Spatial analysis of transport legislation

### 4. Document Analysis
- Side-by-side document comparison
- Full-text search within documents
- Quality scoring and relevance ranking
- Export in multiple formats (CSV, Excel, JSON)

### 5. Academic Tools
- Four citation formats (ABNT, APA, Vancouver, BibTeX)
- DOI integration for permanent references
- Batch export for research datasets
- Metadata preservation for reproducibility

## 🔄 Data Flow

1. **User Query** → Frontend service layer
2. **API Request** → Backend gateway router
3. **Search Processing**:
   - Vocabulary expansion via SKOS
   - Multi-source query distribution
   - Result aggregation and ranking
4. **Caching Layer**:
   - Redis for hot data
   - Database for persistent cache
   - Browser cache for static assets
5. **Response** → Frontend display

## 🛡️ Fallback Strategy

The system uses a three-tier fallback approach:

1. **Primary**: Live API calls to government services
2. **Secondary**: Cached data from Redis/PostgreSQL
3. **Tertiary**: 889 embedded CSV documents with real legislative data

This ensures the system NEVER shows mock or fake data.

## 🔑 Important Concepts

### No Mock Policy
**CRITICAL**: This is a production academic platform. Never use:
- Mock data or placeholder content
- Test stubs or fake implementations
- Simulated API responses

All data must be real and verifiable.

### Service Layer Pattern
Both frontend and backend use service layers:
- Separates API logic from business logic
- Makes testing easier
- Provides consistent error handling

### Async Everything
The backend is fully asynchronous:
- All database operations use `asyncpg`
- HTTP requests use `aiohttp`
- Enables handling many concurrent requests

### Progressive Enhancement
Core features work even when:
- JavaScript is disabled (basic search)
- APIs are down (CSV fallback)
- User is offline (service workers)

## 🚦 Getting Started

### Frontend Development
```bash
cd monitor_legislativo_v4
npm install
npm run dev  # Start development server at localhost:5173
```

### Backend Development
```bash
cd backend
poetry install
poetry run python main_app/main.py  # Start API at localhost:8000
```

### Full Stack with Docker
```bash
docker-compose up  # Starts everything including databases
```

## 📝 Code Conventions

### TypeScript/React
- Functional components only (no classes)
- Explicit type annotations required
- PascalCase for components
- camelCase for functions/variables
- Arrow functions preferred

### Python
- snake_case naming
- Type hints on all functions
- Async/await for I/O
- Dataclasses for models
- Docstrings for public functions

### General Rules
- No unnecessary comments
- Error messages must be user-friendly
- Log for debugging, never sensitive data
- Performance matters (budget constraints)

## 🔄 Common Workflows

### Adding a New Feature
1. Check if similar patterns exist
2. Use existing services/utilities
3. Follow the service layer pattern
4. Add proper error handling
5. Include CSV fallback if using APIs
6. Test with real data only

### Debugging Issues
1. Check browser console for frontend errors
2. Check FastAPI logs for backend errors
3. Verify API endpoints are accessible
4. Check Redis/PostgreSQL connectivity
5. Review fallback data loading

### Making API Calls
1. Always use the service layer
2. Include retry logic
3. Handle rate limiting
4. Provide meaningful fallbacks
5. Cache responses appropriately

## 🚀 Deployment

### Frontend (GitHub Pages)
```bash
npm run build
# Commits to main branch auto-deploy
```

### Backend (Railway)
```bash
# Push to main branch triggers deployment
git push origin main
```

## 💡 Tips for New Developers

1. **Start with the Dashboard**: It's the entry point and shows how components interact
2. **Follow existing patterns**: The codebase is consistent - copy what works
3. **Test with real data**: Use the CSV files in `/src/data/` for local testing
4. **Check the budget**: Every API call costs money - cache aggressively
5. **Read CLAUDE.md**: Contains critical project rules and conventions
6. **Use TypeScript strictly**: It catches many errors before runtime
7. **Async is not optional**: The backend will break without proper async/await

## 🐛 Common Pitfalls

1. **Mock Data**: Never create fake data - use real CSV fallbacks
2. **Synchronous Operations**: Backend must be async throughout
3. **Uncached API Calls**: Always implement caching for external APIs
4. **Missing Error Handling**: Every API call can fail - plan for it
5. **Ignoring Rate Limits**: Government APIs have strict limits
6. **Large Payloads**: Paginate results to avoid memory issues

## 📚 Where to Learn More

- `/documentation/` - Technical specifications
- `/planning/` - Architecture decisions
- `CLAUDE.md` - Development rules and standards
- API docs at `http://localhost:8000/docs` (when running)
- Frontend component stories (coming soon)

## 🤝 Contributing

1. Always check existing patterns first
2. Follow the no-mock policy strictly
3. Test with real government APIs
4. Keep changes minimal and focused
5. Document significant decisions
6. Optimize for the $7/month budget

Welcome to Monitor Legislativo v4! This codebase prioritizes real data, academic integrity, and budget-conscious engineering. When in doubt, check how existing features work and follow their patterns.