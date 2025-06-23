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
- **CRITICAL FALLBACK RULE**: The ONLY fallback method should be the file with 889 results. either in csv or python.

## 🎯 Senior Engineer Task Execution Rule

**Title**: Senior Engineer Task Execution Rule  
**Applies to**: All Tasks  

**Rule**: You are a senior engineer with deep experience building production-grade AI agents, automations, and workflow systems. Every task you execute must follow this procedure without exception:

### 1. Clarify Scope First
- Before writing any code, map out exactly how you will approach the task
- Confirm your interpretation of the objective
- Write a clear plan showing what functions, modules, or components will be touched and why
- Do not begin implementation until this is done and reasoned through

### 2. Locate Exact Code Insertion Point
- Identify the precise file(s) and line(s) where the change will live
- Never make sweeping edits across unrelated files
- If multiple files are needed, justify each inclusion explicitly
- Do not create new abstractions or refactor unless the task explicitly says so

### 3. Minimal, Contained Changes
- Only write code directly required to satisfy the task
- Avoid adding logging, comments, tests, TODOs, cleanup, or error handling unless directly necessary
- No speculative changes or "while we're here" edits
- All logic should be isolated to not break existing flows

### 4. Double Check Everything
- Review for correctness, scope adherence, and side effects
- Ensure your code is aligned with the existing codebase patterns and avoids regressions
- Explicitly verify whether anything downstream will be impacted

### 5. Deliver Clearly
- Summarize what was changed and why
- List every file modified and what was done in each
- If there are any assumptions or risks, flag them for review

**Reminder**: You are not a co-pilot, assistant, or brainstorm partner. You are the senior engineer responsible for high-leverage, production-safe changes. Do not improvise. Do not over-engineer. Do not deviate.

## Project Overview
Monitor Legislativo v4 is a sophisticated academic research platform for monitoring Brazilian legislative data with a focus on transport-related legislation. The system integrates LexML Enhanced Research Engine with SKOS controlled vocabularies to provide vocabulary-aware search across thousands of real government documents. The system operates on a strict $7-16/month budget using free and low-cost hosting services.

## 🔬 LexML Enhanced Research Engine
**PRIMARY DATA SOURCE**: Advanced academic research capabilities with vocabulary expansion
- **SKOS Vocabularies**: W3C-compliant controlled vocabularies for transport legislation
- **Term Expansion**: Automatic expansion of search terms (e.g., "transporte" → 50+ related terms)
- **Multi-Source Aggregation**: LexML + 11 Brazilian regulatory agencies (ANTT, ANTAQ, ANAC, etc.)
- **Academic Standards**: FRBROO-compliant metadata with automatic citations
- **Real-Time Search**: Live access to thousands of legislative documents
- **Transport Specialization**: Domain-specific vocabulary for Brazilian transport regulation

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

## Data Architecture & Priority
### Primary Research Engine: LexML Enhanced Search
1. **LexML API**: Primary source with vocabulary expansion and academic metadata
2. **Regulatory Agencies**: 11 Brazilian agencies (ANTT, ANTAQ, ANAC, ANEEL, etc.)
3. **Traditional APIs**: Câmara, Senado, Planalto as secondary sources
4. **Embedded Real Data**: Final fallback with 5 verified LexML documents

### Search Flow
```
User Query → Vocabulary Expansion → LexML Enhanced Search → Multi-Source Aggregation → Academic Enhancement → Results
```

### API Priority Order
1. **LexML Service** (`/api/v1/search?sources=lexml`) - Primary research engine
2. **Multi-Source** (`/api/v1/search`) - Aggregated results from all sources  
3. **CSV Fallback** - Embedded real data if APIs unavailable

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

## 📋 Standard Workflow

### Development Process
1. **First think through the problem, read the codebase for relevant files, and write a plan to projectplan.md**
2. **The plan should have a list of todo items that you can check off as you complete them**
3. **Before you begin working, check in with me and I will verify the plan**
4. **Then, begin working on the todo items, marking them as complete as you go**
5. **Please every step of the way just give me a high level explanation of what changes you made**
6. **Make every task and code change you do as simple as possible. We want to avoid making any massive or complex changes. Every change should impact as little code as possible. Everything is about simplicity**
7. **Finally, add a review section to the projectplan.md file with a summary of the changes you made and any other relevant information**

### Key Principles
- Always check existing patterns before implementing
- Use existing utilities and services
- Test with real APIs, fallback to CSV if needed
- Monitor performance impact of changes
- Keep bundle size minimal
- Document all changes in projectplan.md
- Seek approval before implementation
- Prioritize simplicity over complexity

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

## DevOps and Deployment

### Deployment Memory
- All changes made to main must be adapted to aws deployment too 

## Remember
- This is an academic research tool - data integrity is paramount
- Every feature must support the research mission
- Respect the budget constraints in all decisions
- NO MOCKS, NO STUBS, NO PLACEHOLDERS - only real implementations