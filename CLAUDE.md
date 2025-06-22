# Monitor Legislativo v4 - Development Rules

## 🚨 CRITICAL: NO MOCK POLICY
**ABSOLUTELY NO MOCK DATA, MOCK FUNCTIONS, OR PLACEHOLDER IMPLEMENTATIONS**
- This is a production academic research platform - ALL code must be functional
- Never use mock implementations, test stubs, or placeholder functions
- If an API is unavailable, use ONLY real CSV data from actual government sources
- All features must work with real data from Brazilian government APIs or real CSV datasets
- NO EXCEPTIONS: Mock data is strictly forbidden in production code
- Fallbacks must use real historical data, not fabricated examples
- Any data used must be verifiable and academically sound
- If real data is unavailable, the system should gracefully indicate the limitation rather than show fake data

## Project Overview
Monitor Legislativo v4 is an academic research platform for monitoring Brazilian legislative data with a focus on transport-related legislation. The system operates on a strict $7-16/month budget using free and low-cost hosting services.

## Tech Stack
### Frontend
- React 18.3.1 with TypeScript 5.7.2
- Vite 6.3.5 for build tooling
- Leaflet for maps, PapaParse for CSV processing
- Hosted on GitHub Pages (free)

### Backend
- Python 3.11 with FastAPI 0.104.1
- PostgreSQL (Supabase free tier) + Redis (Upstash free tier)
- Async operations throughout (aiohttp, asyncpg)
- Hosted on Railway ($7/month)

### Analytics (Optional)
- R Shiny application for advanced data analysis
- Self-hosted or local deployment

## Code Conventions

### TypeScript/React
- Functional components with hooks only
- PascalCase for components, camelCase for functions
- Explicit type annotations required
- Arrow functions preferred
- CSS imports at end of import blocks

### Python
- snake_case for functions/variables
- Type hints required for all functions
- Async/await for all I/O operations
- Dataclasses for data models
- Docstrings for all public functions

### General
- No comments unless absolutely necessary
- Error handling with user-friendly messages
- Logging for debugging (never log sensitive data)
- Performance optimization is critical (budget constraints)

## Architecture Patterns
1. **Service Layer Pattern**: Separate API interaction from business logic
2. **Fallback Strategy**: CSV data when APIs fail
3. **Multi-layer Caching**: Redis → Local cache → Browser cache
4. **Progressive Enhancement**: Core features work offline
5. **Academic Focus**: Citation formatting and data export built-in

## API Integration
- Primary: Câmara dos Deputados, Senado Federal APIs
- Fallback: Local CSV data in `/src/data/`
- Rate limiting and retry logic required
- Session pooling for performance
- Health checks for all external services

## Testing Requirements
- Jest for frontend tests (located in `__tests__` folders)
- Test files must use `.test.ts` or `.spec.ts` extensions
- Integration tests for critical paths
- Never test with mock APIs - use real endpoints or CSV fallbacks

## Build and Deploy
### Frontend
```bash
npm run build
npm run test
npm run lint
```

### Backend
```bash
python -m pytest
ruff check .
```

## Performance Requirements
- Initial page load < 3s
- API responses < 2s
- Implement lazy loading for large datasets
- Use virtual scrolling for long lists
- Cache aggressively (respect memory limits)

## Security
- No authentication currently implemented
- Input validation on all user inputs
- Safe URL construction
- No sensitive data in frontend code
- Use environment variables for configuration

## File Organization
```
/src           - Frontend React/TypeScript code
/core          - Backend Python core functionality  
/main_app      - FastAPI application entry
/web           - Additional web endpoints
/r-shiny-app   - R analytics application
/configs       - Configuration files
/tests         - Backend integration tests
```

## Critical Features
1. **Real-time Updates**: WebSocket support for live data
2. **Map Visualization**: Interactive Leaflet maps
3. **Document Comparison**: Side-by-side analysis
4. **Export Options**: CSV, Excel, JSON, Academic citations
5. **Offline Support**: PWA with service workers

## Development Workflow
1. Always check existing patterns before implementing
2. Use existing utilities and services
3. Test with real APIs, fallback to CSV if needed
4. Monitor performance impact of changes
5. Keep bundle size minimal

## Budget Optimization
- Use free tiers wherever possible
- Implement aggressive caching
- Optimize API calls (batch when possible)
- Monitor Railway usage to stay under $7
- Consider self-hosting for additional components

## Common Commands
```bash
# Frontend
npm run dev          # Start development server
npm run build        # Build for production
npm run test         # Run tests
npm run lint         # Run ESLint

# Backend
python main_app/main.py    # Run FastAPI server
python -m pytest           # Run tests
ruff check .              # Python linting
```

## Environment Variables
Required environment variables are defined in:
- Frontend: `src/config/api.ts`
- Backend: `core/config/config.py`

Never commit `.env` files. Use `.env.example` as reference.

## Remember
- This is an academic research tool - data integrity is paramount
- Every feature must support the research mission
- Respect the budget constraints in all decisions
- NO MOCKS, NO STUBS, NO PLACEHOLDERS - only real implementations