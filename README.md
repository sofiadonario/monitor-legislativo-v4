# Monitor Legislativo v4

A sophisticated academic research platform for monitoring Brazilian legislative data with transport-focused legislation analysis.

## Repository Structure

```
├── frontend/                 # React TypeScript frontend
│   ├── src/                 # React components and services
│   ├── public/              # Static assets
│   ├── package.json         # Frontend dependencies
│   └── Dockerfile           # Frontend deployment
│
├── backend/          # Python FastAPI backend
│   ├── src/                 # Backend source code
│   ├── core/                # Core functionality
│   ├── configs/             # Configuration files
│   ├── requirements.txt     # Python dependencies
│   └── nixpacks.toml        # Build configuration
│
├── r-shiny-app/            # R Shiny analytics
│   └── ...                 # R application files
│
├── docs/                   # Documentation
│   ├── deployment/         # Deployment guides
│   ├── guides/             # Integration guides
│   ├── reports/            # Technical reports
│   └── CLAUDE.md           # Development instructions
│
├── config/                 # Configuration files
│   ├── .env.*              # Environment configurations
│   ├── docker-compose.yml  # Container orchestration
│   └── *.json              # Various config files
│
├── scripts/                # Utility scripts
│   └── *.sh, *.py          # Deployment and test scripts
│
└── assets/                 # Images and static files
    └── *.png, *.jpg        # Screenshots and diagrams
```

## Quick Start

### Frontend (Railway)
```bash
cd frontend/
npm install
npm run dev
```

### Backend (Railway)
```bash
cd backend/
poetry install
poetry run uvicorn src.main:app --reload
```

## Deployment

- **Frontend**: Railway service pointing to `/frontend` directory
- **Backend**: Railway service pointing to `/backend` directory
- **Analytics**: Separate R Shiny deployment

## Key Features

- Real-time legislative document search
- Geographic analysis and mapping
- Advanced analytics dashboard
- Multi-source data integration
- Academic citation generation

## Documentation

See `docs/` directory for detailed guides:
- `docs/deployment/` - Deployment instructions
- `docs/guides/` - Integration guides
- `docs/CLAUDE.md` - Development rules and guidelines