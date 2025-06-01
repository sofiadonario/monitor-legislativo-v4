# Team Onboarding Guide - Monitor Legislativo v4

## Welcome to the Team!

This guide will help you get up and running with the Monitor Legislativo v4 project. Please follow these steps in order to set up your development environment and understand our workflows.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Development Environment Setup](#development-environment-setup)
3. [Project Architecture](#project-architecture)
4. [Development Workflow](#development-workflow)
5. [Testing Guidelines](#testing-guidelines)
6. [Deployment Process](#deployment-process)
7. [Team Communication](#team-communication)
8. [Resources & Documentation](#resources--documentation)

## Prerequisites

### Required Software

- **Python 3.9+** - Main backend language
- **Node.js 18+** - Frontend and build tools
- **Docker** - Containerization
- **Git** - Version control
- **VS Code or PyCharm** - Recommended IDEs

### Accounts & Access

Please request access to:
- [ ] GitHub repository
- [ ] AWS account (development)
- [ ] Slack workspace
- [ ] Figma design files
- [ ] Grafana monitoring dashboard
- [ ] Sentry error tracking

## Development Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mackintegridade/monitor_legislativo_v4.git
cd monitor_legislativo_v4
```

### 2. Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your local configuration

# Run database migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start development server
python manage.py runserver
```

### 3. Frontend Setup

```bash
# Navigate to web directory
cd web

# Install dependencies
npm install

# Start development server
npm run dev
```

### 4. Docker Setup (Alternative)

```bash
# Build and start all services
docker-compose up --build

# Run migrations
docker-compose exec api python manage.py migrate

# Create superuser
docker-compose exec api python manage.py createsuperuser
```

### 5. Verify Installation

Visit these URLs to verify everything is working:
- Backend API: http://localhost:8000/api/health
- Frontend: http://localhost:3000
- API Documentation: http://localhost:8000/docs

## Project Architecture

### Backend Structure

```
core/
├── api/              # API services and endpoints
├── auth/             # Authentication & authorization
├── config/           # Configuration management
├── models/           # Data models
├── monitoring/       # Performance & observability
└── utils/            # Utility functions

web/
├── api/              # Web API gateway
├── components/       # React components
├── pages/            # Next.js pages
└── utils/            # Frontend utilities

infrastructure/
├── terraform/        # Infrastructure as code
├── kubernetes/       # K8s manifests
└── monitoring/       # Monitoring configs
```

### Key Technologies

- **Backend**: Python, FastAPI, SQLAlchemy, PostgreSQL
- **Frontend**: React, Next.js, TypeScript, Tailwind CSS
- **Infrastructure**: AWS, Kubernetes, Terraform
- **Monitoring**: Prometheus, Grafana, Sentry
- **Testing**: pytest, Jest, Playwright

### Data Sources

- **Câmara dos Deputados API**: Legislative data
- **Senado Federal API**: Senate data
- **Planalto**: Executive branch documents
- **Regulatory Agencies**: ANATEL, ANVISA, etc.

## Development Workflow

### 1. Branch Strategy

We use GitFlow:
- `main` - Production code
- `develop` - Integration branch
- `feature/feature-name` - New features
- `bugfix/bug-description` - Bug fixes
- `hotfix/critical-fix` - Emergency fixes

### 2. Feature Development Process

1. **Create Feature Branch**
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

2. **Development**
   - Write code following our style guidelines
   - Add tests for new functionality
   - Update documentation if needed

3. **Pre-commit Checks**
   ```bash
   # Run linting
   flake8 .
   black .
   isort .
   
   # Run tests
   pytest
   npm test
   ```

4. **Create Pull Request**
   - Fill out the PR template
   - Request review from team leads
   - Ensure CI passes

5. **Code Review**
   - Address reviewer feedback
   - Squash commits if needed
   - Merge to develop

### 3. Commit Message Convention

Use conventional commits:
```
type(scope): description

feat(api): add document search endpoint
fix(auth): resolve JWT token expiration issue
docs(readme): update installation instructions
test(api): add integration tests for search
```

## Testing Guidelines

### Backend Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=core --cov-report=html

# Run specific test file
pytest tests/test_api.py

# Run tests matching pattern
pytest -k "test_search"
```

### Frontend Testing

```bash
# Unit tests
npm test

# E2E tests
npm run test:e2e

# Visual regression tests
npm run test:visual
```

### Test Categories

1. **Unit Tests** - Test individual functions/components
2. **Integration Tests** - Test API endpoints and database
3. **E2E Tests** - Test complete user workflows
4. **Performance Tests** - Load and stress testing

### Writing Good Tests

- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Mock external dependencies
- Test edge cases and error conditions
- Keep tests fast and independent

## Deployment Process

### Development Environment

Automatic deployment on push to `develop` branch:
- Runs tests and security scans
- Deploys to dev environment
- Runs smoke tests

### Staging Environment

Manual deployment from `develop` to `staging`:
```bash
# Deploy to staging
git checkout staging
git merge develop
git push origin staging
```

### Production Environment

Deployment process:
1. Create release branch from `develop`
2. Final testing and bug fixes
3. Create PR to `main`
4. After approval, tag release
5. Deploy using GitHub Actions

### Monitoring Deployment

- Check Grafana dashboards
- Monitor error rates in Sentry
- Verify application health endpoints
- Run post-deployment tests

## Team Communication

### Channels

- **#general** - General team updates
- **#development** - Technical discussions
- **#alerts** - System alerts and incidents
- **#releases** - Release announcements
- **#random** - Non-work related chat

### Meetings

- **Daily Standup** (9:00 AM) - Progress and blockers
- **Sprint Planning** (Mondays) - Plan upcoming work
- **Sprint Review** (Fridays) - Demo completed work
- **Retrospective** (Fridays) - Process improvement

### Documentation

- Update README for new features
- Document API changes in OpenAPI spec
- Add architecture decisions to ADR folder
- Keep team wiki up to date

## Code Style Guidelines

### Python

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use meaningful variable names
- Add docstrings to functions and classes

### JavaScript/TypeScript

- Use Prettier for formatting
- Follow Airbnb style guide
- Use TypeScript strict mode
- Prefer functional components
- Use meaningful component names

### SQL

- Use uppercase for SQL keywords
- Use snake_case for table and column names
- Always use meaningful aliases
- Comment complex queries

## Security Guidelines

### General Principles

- Never commit secrets to git
- Use environment variables for configuration
- Validate all user inputs
- Use parameterized queries
- Keep dependencies updated

### Authentication

- All API endpoints require authentication
- Use JWT tokens with short expiration
- Implement proper RBAC
- Log authentication events

### Data Protection

- Encrypt sensitive data at rest
- Use HTTPS for all communications
- Sanitize data before logging
- Follow LGPD compliance requirements

## Performance Guidelines

### Backend

- Use database indexes appropriately
- Implement caching for expensive operations
- Use async/await for I/O operations
- Monitor query performance
- Implement rate limiting

### Frontend

- Optimize bundle size
- Use lazy loading for routes
- Implement virtualization for large lists
- Optimize images and assets
- Monitor Core Web Vitals

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Check DATABASE_URL in .env
   - Ensure PostgreSQL is running
   - Verify credentials

2. **Import Errors**
   - Activate virtual environment
   - Install requirements
   - Check PYTHONPATH

3. **Frontend Build Failures**
   - Clear node_modules and reinstall
   - Check Node.js version
   - Update dependencies

4. **Docker Issues**
   - Check Docker is running
   - Rebuild containers
   - Check port conflicts

### Getting Help

1. Check existing documentation
2. Search GitHub issues
3. Ask in #development channel
4. Create detailed issue report
5. Schedule pair programming session

## Resources & Documentation

### Internal Documentation

- [API Documentation](./API_DOCUMENTATION.md)
- [Architecture Overview](./ARCHITECTURE_ENHANCEMENT_PLAN.md)
- [Security Guidelines](../core/auth/README.md)
- [Design System](../design-system/README.md)

### External Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://reactjs.org/docs/)
- [PostgreSQL Guide](https://www.postgresql.org/docs/)
- [AWS Documentation](https://docs.aws.amazon.com/)

### Training Materials

- Python Best Practices Course
- React Advanced Patterns
- AWS Solutions Architect
- Security Fundamentals

## Checklist for New Team Members

### First Day
- [ ] Complete this onboarding guide
- [ ] Set up development environment
- [ ] Join team communication channels
- [ ] Schedule 1:1 with team lead
- [ ] Review codebase structure

### First Week
- [ ] Complete first small task/bug fix
- [ ] Attend all team meetings
- [ ] Review project documentation
- [ ] Set up monitoring access
- [ ] Complete security training

### First Month
- [ ] Deliver first feature
- [ ] Understand deployment process
- [ ] Contribute to team retrospective
- [ ] Write documentation improvement
- [ ] Mentor another new team member

## Contact Information

- **Team Lead**: João Silva (joao.silva@mackintegridade.com)
- **DevOps Lead**: Maria Santos (maria.santos@mackintegridade.com)
- **Frontend Lead**: Pedro Costa (pedro.costa@mackintegridade.com)
- **Product Manager**: Ana Oliveira (ana.oliveira@mackintegridade.com)

---

Welcome to the team! If you have any questions not covered in this guide, don't hesitate to reach out. We're here to help you succeed! 🚀