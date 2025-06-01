# Quick Start Guide

Get up and running with the Legislative Monitoring System in minutes.

## Prerequisites

- Python 3.9+
- Docker and Docker Compose
- Git
- PostgreSQL (or use Docker)
- Redis (or use Docker)

## Quick Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/monitor-legislativo.git
cd monitor-legislativo
```

### 2. Set Up Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Configure Environment Variables

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env
```

Required configurations:
- `APP_SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
- `JWT_SECRET_KEY`: Generate similarly
- `DATABASE_URL`: Your PostgreSQL connection string

### 4. Start Services with Docker

```bash
# Start all required services
docker-compose -f docker-compose.dev.yml up -d

# Verify services are running
docker-compose ps
```

### 5. Initialize Database

```bash
# Run database migrations
alembic upgrade head

# Load initial data (optional)
python scripts/load_initial_data.py
```

### 6. Run the Application

```bash
# Start the web server
python -m web.main

# In another terminal, start the desktop app (optional)
python -m desktop.main
```

## Verify Installation

### Check API Health
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "4.0.0",
  "services": {
    "database": "connected",
    "redis": "connected",
    "camara_api": "available",
    "senado_api": "available"
  }
}
```

### Run Tests
```bash
# Run unit tests
pytest tests/unit -v

# Run with coverage
pytest --cov=core --cov=web --cov-report=html
```

## First API Request

### Get Camara Proposals
```bash
curl -X GET "http://localhost:5000/api/camara/proposicoes?ano=2025&tipo=PL" \
  -H "Accept: application/json"
```

### Search Across All Sources
```bash
curl -X POST "http://localhost:5000/api/search" \
  -H "Content-Type: application/json" \
  -d '{
    "keywords": "educação",
    "sources": ["camara", "senado"],
    "start_date": "2025-01-01",
    "limit": 10
  }'
```

## Common Issues

### Port Already in Use
```bash
# Check what's using port 5000
lsof -i :5000

# Kill the process or change the port in .env
APP_PORT=5001
```

### Database Connection Failed
- Ensure PostgreSQL is running
- Check DATABASE_URL in .env
- Verify database exists: `psql -U postgres -c "CREATE DATABASE legislativo_db;"`

### Redis Connection Failed
- Ensure Redis is running: `docker ps | grep redis`
- Check REDIS_URL in .env

## Next Steps

1. Read the [API Documentation](../api/overview.md)
2. Set up [monitoring](../operations/monitoring.md)
3. Configure [authentication](../api/authentication.md)
4. Explore [advanced features](../architecture/overview.md)

## Getting Help

- Check [troubleshooting guide](../operations/troubleshooting.md)
- Join our [Slack channel](#)
- Open an [issue on GitHub](https://github.com/your-org/monitor-legislativo/issues)