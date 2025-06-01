# Development Environment Setup Guide

## Quick Start

For experienced developers who want to get started quickly:

```bash
# Clone and setup
git clone https://github.com/mackintegridade/monitor_legislativo_v4.git
cd monitor_legislativo_v4

# Option 1: Docker (Recommended for quick setup)
docker-compose up --build

# Option 2: Local development
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env file with your settings
python manage.py migrate
python manage.py runserver

# In another terminal
cd web && npm install && npm run dev
```

## Detailed Setup Instructions

### System Requirements

- **OS**: Linux, macOS, or Windows with WSL2
- **Python**: 3.9 or higher
- **Node.js**: 18 or higher
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: 10GB free space

### 1. Install Prerequisites

#### Python & pip
```bash
# Check Python version
python --version  # Should be 3.9+

# Install pip if not available
curl https://bootstrap.pypa.io/get-pip.py | python
```

#### Node.js & npm
```bash
# Install Node.js 18 LTS
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version  # Should be v18+
npm --version
```

#### Docker (Optional but Recommended)
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

#### PostgreSQL (For local development)
```bash
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS
brew install postgresql

# Start PostgreSQL service
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

### 2. Clone Repository

```bash
git clone https://github.com/mackintegridade/monitor_legislativo_v4.git
cd monitor_legislativo_v4

# Set up git hooks (optional)
git config core.hooksPath .githooks
chmod +x .githooks/*
```

### 3. Backend Setup

#### Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows
```

#### Install Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

#### Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env  # or use your preferred editor
```

Example `.env` configuration:
```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/monitor_legislativo
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here

# External APIs
CAMARA_API_URL=https://dadosabertos.camara.leg.br/api/v2
SENADO_API_URL=https://legis.senado.leg.br/dadosabertos

# Development settings
DEBUG=True
LOG_LEVEL=DEBUG
```

#### Database Setup
```bash
# Create database
createdb monitor_legislativo

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load sample data (optional)
python manage.py loaddata fixtures/sample_data.json
```

#### Start Backend Server
```bash
# Development server
python manage.py runserver

# With specific port
python manage.py runserver 8000

# Production-like server
gunicorn core.wsgi:application --bind 0.0.0.0:8000
```

### 4. Frontend Setup

#### Install Dependencies
```bash
cd web
npm install

# Or using yarn
yarn install
```

#### Environment Configuration
```bash
# Copy environment template
cp .env.local.example .env.local

# Edit configuration
nano .env.local
```

Example `.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_SENTRY_DSN=your-sentry-dsn
```

#### Start Frontend Server
```bash
# Development server
npm run dev

# Production build
npm run build
npm start

# Type checking
npm run type-check

# Linting
npm run lint
```

### 5. Docker Setup (Alternative)

#### Using Docker Compose
```bash
# Build and start all services
docker-compose up --build

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

#### Individual Services
```bash
# Build specific service
docker-compose build api

# Start specific service
docker-compose up api

# Run commands in container
docker-compose exec api python manage.py migrate
docker-compose exec api python manage.py shell
```

### 6. Development Tools Setup

#### VS Code Configuration
Create `.vscode/settings.json`:
```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.rulers": [100],
  "typescript.preferences.importModuleSpecifier": "relative"
}
```

#### Pre-commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# Set up hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

### 7. Testing Setup

#### Backend Tests
```bash
# Install test dependencies
pip install pytest pytest-cov pytest-django

# Run tests
pytest

# With coverage
pytest --cov=core --cov-report=html

# Run specific tests
pytest tests/test_api.py::test_document_search
```

#### Frontend Tests
```bash
# Install test dependencies
npm install --save-dev jest @testing-library/react

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Run E2E tests
npm run test:e2e
```

### 8. Verification

#### Health Checks
Test these URLs to ensure everything is working:

- Backend API: http://localhost:8000/health
- API Documentation: http://localhost:8000/docs
- Frontend: http://localhost:3000
- Admin Panel: http://localhost:8000/admin

#### Test API Endpoints
```bash
# Health check
curl http://localhost:8000/api/health

# Authentication
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Search documents
curl http://localhost:8000/api/documents/search?q=lei

# WebSocket connection
wscat -c ws://localhost:8000/ws/documents/
```

## Common Issues & Solutions

### Python/pip Issues

**Issue**: `pip install` fails with permission errors
```bash
# Solution: Use user install
pip install --user -r requirements.txt

# Or fix virtual environment
deactivate && rm -rf venv && python -m venv venv && source venv/bin/activate
```

**Issue**: Import errors
```bash
# Solution: Check PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or install in development mode
pip install -e .
```

### Database Issues

**Issue**: Database connection errors
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Reset database
dropdb monitor_legislativo
createdb monitor_legislativo
python manage.py migrate
```

**Issue**: Migration conflicts
```bash
# Reset migrations
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc" -delete
python manage.py makemigrations
python manage.py migrate
```

### Node.js/npm Issues

**Issue**: npm install fails
```bash
# Clear cache and reinstall
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

**Issue**: Module not found errors
```bash
# Check Node version
node --version

# Reinstall dependencies
rm -rf node_modules
npm install
```

### Docker Issues

**Issue**: Port conflicts
```bash
# Check what's using the port
sudo lsof -i :8000

# Stop conflicting services
sudo systemctl stop apache2  # or nginx

# Use different ports
docker-compose -f docker-compose.dev.yml up
```

**Issue**: Permission errors
```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
sudo docker-compose up
```

## Performance Optimization

### Development Server
```bash
# Use faster reload
python manage.py runserver --noreload

# Disable debug toolbar
export DEBUG_TOOLBAR_CONFIG='{"SHOW_TOOLBAR_CALLBACK": lambda r: False}'
```

### Database
```bash
# Enable query logging
export DATABASE_LOG_QUERIES=true

# Use connection pooling
pip install psycopg2-pool
```

### Frontend
```bash
# Fast refresh
npm run dev

# Analyze bundle size
npm run analyze

# Enable source maps
export NEXT_PUBLIC_SOURCE_MAPS=true
```

## IDE Configuration

### PyCharm
1. Set interpreter to `./venv/bin/python`
2. Enable Django support
3. Configure code style to Black
4. Set up run configurations for manage.py

### VS Code Extensions
- Python
- Pylance
- Black Formatter
- ES7+ React/Redux/React-Native snippets
- Prettier
- GitLens

## Next Steps

After setup is complete:
1. Read the [Team Onboarding Guide](./TEAM_ONBOARDING_GUIDE.md)
2. Review the [Architecture Documentation](./ARCHITECTURE_ENHANCEMENT_PLAN.md)
3. Check the [API Documentation](./API_DOCUMENTATION.md)
4. Join the team Slack channels
5. Schedule onboarding session with team lead

## Getting Help

If you encounter issues:
1. Check this documentation
2. Search existing GitHub issues
3. Ask in #development Slack channel
4. Create a detailed issue report
5. Schedule pair programming session

---

Happy coding! 🚀