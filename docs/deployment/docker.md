# Docker Deployment Guide

Deploy the Legislative Monitoring System using Docker containers.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB disk space

## Quick Start

### 1. Clone and Configure

```bash
# Clone repository
git clone https://github.com/your-org/monitor-legislativo.git
cd monitor-legislativo

# Create environment file
cp .env.example .env
# Edit .env with production values
```

### 2. Build Images

```bash
# Build all services
docker-compose build

# Or build specific service
docker-compose build web
```

### 3. Start Services

```bash
# Start all services in background
docker-compose up -d

# View logs
docker-compose logs -f

# Check service status
docker-compose ps
```

## Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: Dockerfile
    image: legislativo/web:latest
    container_name: legislativo_web
    ports:
      - "80:5000"
    environment:
      - APP_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/legislativo
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./data/logs:/app/data/logs
      - ./data/exports:/app/data/exports
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  worker:
    build:
      context: .
      dockerfile: Dockerfile.worker
    image: legislativo/worker:latest
    container_name: legislativo_worker
    environment:
      - APP_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/legislativo
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./data/logs:/app/data/logs
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    container_name: legislativo_db
    environment:
      - POSTGRES_DB=legislativo
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: legislativo_redis
    command: redis-server --appendonly yes --requirepass redis_password
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    container_name: legislativo_nginx
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/certs:/etc/nginx/certs
    depends_on:
      - web
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

## Dockerfile

Create `Dockerfile` for the web service:

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/api/health || exit 1

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "web.main:app"]
```

## Environment Variables

### Required Variables

```bash
# Application
APP_ENV=production
APP_SECRET_KEY=<generate-secure-key>
JWT_SECRET_KEY=<generate-secure-key>

# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Redis
REDIS_URL=redis://:password@host:6379/0

# API Keys
CAMARA_API_KEY=<your-key>
SENADO_API_KEY=<your-key>
```

### Optional Variables

```bash
# Performance
GUNICORN_WORKERS=4
GUNICORN_TIMEOUT=120

# Monitoring
PROMETHEUS_ENABLED=true
SENTRY_DSN=<your-sentry-dsn>

# Features
FEATURE_EXPORT_SERVICE=true
FEATURE_NOTIFICATIONS=true
```

## Deployment Steps

### 1. Prepare Host

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2. Configure Firewall

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow SSH (if needed)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

### 3. SSL Certificates

```bash
# Using Let's Encrypt
docker run -it --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v /var/lib/letsencrypt:/var/lib/letsencrypt \
  certbot/certbot certonly --standalone \
  -d your-domain.com
```

### 4. Deploy Application

```bash
# Pull latest code
git pull origin main

# Build and start
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose exec web alembic upgrade head

# Create admin user
docker-compose exec web python scripts/create_admin.py
```

## Monitoring

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f web

# Last 100 lines
docker-compose logs --tail=100 web
```

### Health Checks

```bash
# Check all services
docker-compose ps

# Check specific service health
docker inspect legislativo_web --format='{{.State.Health.Status}}'

# Manual health check
curl http://localhost/api/health
```

## Backup and Restore

### Backup Database

```bash
# Create backup
docker-compose exec db pg_dump -U postgres legislativo > backup.sql

# Automated daily backup
0 2 * * * docker-compose exec -T db pg_dump -U postgres legislativo > /backups/legislativo_$(date +\%Y\%m\%d).sql
```

### Restore Database

```bash
# Restore from backup
docker-compose exec -T db psql -U postgres legislativo < backup.sql
```

## Scaling

### Horizontal Scaling

```bash
# Scale web service
docker-compose up -d --scale web=3

# With load balancer configuration
docker-compose -f docker-compose.prod.yml -f docker-compose.scale.yml up -d
```

### Resource Limits

Add to docker-compose.yml:

```yaml
services:
  web:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs web

# Check configuration
docker-compose config

# Rebuild image
docker-compose build --no-cache web
```

### Database Connection Issues

```bash
# Test connection
docker-compose exec web python -c "from core.models import db; db.create_all()"

# Check network
docker network ls
docker network inspect legislativo_default
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Inspect specific container
docker inspect legislativo_web

# Clean up
docker system prune -a
```

## Security Best Practices

1. **Use secrets management**
   ```yaml
   secrets:
     db_password:
       file: ./secrets/db_password.txt
   ```

2. **Run as non-root user**
   ```dockerfile
   USER appuser
   ```

3. **Network isolation**
   ```yaml
   networks:
     frontend:
     backend:
   ```

4. **Regular updates**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

## Next Steps

- Set up [Kubernetes deployment](./kubernetes.md) for larger scale
- Configure [monitoring](../operations/monitoring.md)
- Implement [backup strategy](../runbooks/backup-recovery.md)
- Review [security guidelines](../security/overview.md)