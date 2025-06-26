# 🚀 Monitor Legislativo v4 - Production Deployment Guide

## 📋 DEPLOYMENT OVERVIEW

This guide provides step-by-step instructions for deploying Monitor Legislativo v4 to production. The platform is a Brazilian legislative research system designed for academic excellence and government integration.

## 🏗️ INFRASTRUCTURE REQUIREMENTS

### Minimum System Requirements
- **CPU**: 8 cores (16 recommended)
- **Memory**: 32GB RAM (64GB recommended)
- **Storage**: 500GB SSD (1TB recommended)
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04 LTS or compatible

### Cloud Infrastructure (Recommended)
- **Kubernetes**: v1.24+ cluster
- **Database**: PostgreSQL 15+ cluster
- **Cache**: Redis 7+ cluster
- **Storage**: Object storage (S3, GCS, or Azure Blob)
- **CDN**: CloudFlare, AWS CloudFront, or similar
- **Load Balancer**: nginx or cloud-native LB

## 🔧 PRE-DEPLOYMENT SETUP

### 1. Environment Preparation

```bash
# Clone the repository
git clone https://github.com/sofiadonario/monitor-legislativo-v4.git
cd monitor-legislativo-v4

# Install required tools
sudo apt update
sudo apt install -y docker.io kubectl helm
```

### 2. Database Setup

```sql
-- Create production database
CREATE DATABASE monitor_legislativo_prod;
CREATE USER monitor_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE monitor_legislativo_prod TO monitor_user;

-- Enable required extensions
\c monitor_legislativo_prod
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "unaccent";
```

### 3. Environment Variables

Create production environment file:

```bash
# /etc/monitor-legislativo/production.env

# Database Configuration
DATABASE_URL=postgresql://monitor_user:secure_password@db-cluster:5432/monitor_legislativo_prod
REDIS_URL=redis://redis-cluster:6379

# Security
SECRET_KEY=your-secure-secret-key-here
JWT_SECRET=your-jwt-secret-here

# Brazilian Government APIs
CAMARA_API_URL=https://dadosabertos.camara.leg.br/api/v2
SENADO_API_URL=https://legis.senado.leg.br/dadosabertos
PLANALTO_API_URL=https://www.planalto.gov.br/ccivil_03
LEXML_API_URL=https://www.lexml.gov.br/oai

# Performance Settings
MAX_CONNECTIONS=100
CACHE_TTL=3600
RATE_LIMIT=1000

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
LOG_LEVEL=INFO

# Brazilian Specific
DEFAULT_LANGUAGE=pt-BR
TIMEZONE=America/Sao_Paulo
CURRENCY=BRL
```

## 🐳 DOCKER DEPLOYMENT

### 1. Build Images

```bash
# Build backend image
docker build -t monitor-legislativo-backend:4.0.0 -f Dockerfile.backend .

# Build frontend image
docker build -t monitor-legislativo-frontend:4.0.0 -f Dockerfile.frontend .

# Tag for registry
docker tag monitor-legislativo-backend:4.0.0 your-registry/monitor-legislativo-backend:4.0.0
docker tag monitor-legislativo-frontend:4.0.0 your-registry/monitor-legislativo-frontend:4.0.0

# Push to registry
docker push your-registry/monitor-legislativo-backend:4.0.0
docker push your-registry/monitor-legislativo-frontend:4.0.0
```

### 2. Docker Compose Deployment

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  backend:
    image: your-registry/monitor-legislativo-backend:4.0.0
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - database
      - redis
    restart: unless-stopped

  frontend:
    image: your-registry/monitor-legislativo-frontend:4.0.0
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - backend
    restart: unless-stopped

  database:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=monitor_legislativo_prod
      - POSTGRES_USER=monitor_user
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

## ☸️ KUBERNETES DEPLOYMENT

### 1. Create Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: monitor-legislativo
  labels:
    name: monitor-legislativo
```

### 2. Deploy with Helm

```bash
# Create Helm chart
helm create monitor-legislativo

# Install with custom values
helm install monitor-legislativo ./helm-chart \
  --namespace monitor-legislativo \
  --values values.prod.yaml
```

### 3. Production Values (values.prod.yaml)

```yaml
# Helm values for production
replicaCount: 5

image:
  backend:
    repository: your-registry/monitor-legislativo-backend
    tag: "4.0.0"
  frontend:
    repository: your-registry/monitor-legislativo-frontend
    tag: "4.0.0"

service:
  type: LoadBalancer
  port: 80
  targetPort: 8000

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
  hosts:
    - host: monitor-legislativo.gov.br
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: monitor-legislativo-tls
      hosts:
        - monitor-legislativo.gov.br

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 1000m
    memory: 2Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
  targetMemoryUtilizationPercentage: 80

postgresql:
  enabled: true
  primary:
    persistence:
      size: 100Gi
      storageClass: fast-ssd
  auth:
    database: monitor_legislativo_prod
    username: monitor_user

redis:
  enabled: true
  architecture: standalone
  master:
    persistence:
      size: 10Gi
```

## 🔧 NGINX CONFIGURATION

```nginx
# nginx.conf for production
upstream backend {
    server backend:8000;
}

server {
    listen 80;
    server_name monitor-legislativo.gov.br;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name monitor-legislativo.gov.br;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/monitor-legislativo.crt;
    ssl_certificate_key /etc/ssl/private/monitor-legislativo.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;

    # Frontend
    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # API Endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_timeout 60s;
    }

    # Search API (lower rate limit)
    location /api/v1/search {
        limit_req zone=search burst=10 nodelay;
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_timeout 120s;
    }

    # Health Check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

## 📊 MONITORING SETUP

### 1. Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "monitor_legislativo_rules.yml"

scrape_configs:
  - job_name: 'monitor-legislativo'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### 2. Grafana Dashboards

Import the following dashboards:
- **Application Overview**: Key metrics for Monitor Legislativo
- **Brazilian APIs**: Government API performance monitoring
- **Database Performance**: PostgreSQL metrics
- **User Analytics**: Search patterns and usage statistics

## 🔒 SECURITY CONFIGURATION

### 1. SSL/TLS Setup

```bash
# Generate SSL certificates with Let's Encrypt
certbot certonly --nginx -d monitor-legislativo.gov.br

# Or use cert-manager in Kubernetes
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.0/cert-manager.yaml
```

### 2. Security Scanning

```bash
# Run security scan before deployment
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image monitor-legislativo-backend:4.0.0

# OWASP ZAP security test
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://monitor-legislativo.gov.br
```

## 🗄️ DATABASE MIGRATION

### 1. Schema Migration

```bash
# Run database migrations
python manage.py migrate --settings=config.production

# Create Brazilian legislative indexes
psql -d monitor_legislativo_prod -f scripts/create_brazilian_indexes.sql

# Load initial data
python manage.py loaddata fixtures/brazilian_agencies.json
python manage.py loaddata fixtures/legal_vocabularies.json
```

### 2. Backup Setup

```bash
# Setup automated backups
crontab -e

# Add backup job (daily at 2 AM)
0 2 * * * /usr/local/bin/backup-monitor-legislativo.sh
```

## 🧪 DEPLOYMENT VALIDATION

### 1. Health Checks

```bash
# API Health Check
curl -f https://monitor-legislativo.gov.br/api/v1/health

# Database Health
curl -f https://monitor-legislativo.gov.br/api/v1/health/database

# Cache Health
curl -f https://monitor-legislativo.gov.br/api/v1/health/cache

# Brazilian APIs Health
curl -f https://monitor-legislativo.gov.br/api/v1/health/legislative-apis
```

### 2. Performance Testing

```bash
# Load testing with K6
k6 run --vus 100 --duration 5m scripts/load-test.js

# Brazilian legislative search test
curl -X POST https://monitor-legislativo.gov.br/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "transporte público", "filters": {"jurisdiction": "federal"}}'
```

### 3. Functional Testing

```bash
# Test Brazilian citation generation
curl -X POST https://monitor-legislativo.gov.br/api/v1/citations/generate \
  -H "Content-Type: application/json" \
  -d '{"document_id": "lei-14129-2021", "style": "abnt"}'

# Test data export
curl -X POST https://monitor-legislativo.gov.br/api/v1/export \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "query": "mobilidade urbana"}'
```

## 🔄 ROLLBACK PROCEDURES

### 1. Quick Rollback

```bash
# Kubernetes rollback
kubectl rollout undo deployment/monitor-legislativo-backend -n monitor-legislativo

# Docker Compose rollback
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up -d --scale backend=0
# Update image tags to previous version
docker-compose -f docker-compose.prod.yml up -d
```

### 2. Database Rollback

```bash
# Restore from backup
pg_restore -d monitor_legislativo_prod backup_20240101.sql

# Apply schema rollback
psql -d monitor_legislativo_prod -f rollback/rollback_to_v3.sql
```

## 📞 SUPPORT & TROUBLESHOOTING

### Common Issues

1. **High CPU Usage**
   - Check PostgreSQL query performance
   - Monitor Brazilian API response times
   - Verify cache hit rates

2. **Memory Issues**
   - Increase JVM heap size for backend
   - Optimize Redis memory usage
   - Check for memory leaks in long-running processes

3. **Slow Search Performance**
   - Rebuild PostgreSQL indexes
   - Warm cache with popular queries
   - Check Brazilian API latency

### Support Contacts

- **Technical Lead**: tech@monitor-legislativo.gov.br
- **Database Admin**: dba@monitor-legislativo.gov.br
- **Security Team**: security@monitor-legislativo.gov.br
- **Emergency**: +55 11 9999-9999

## 🎯 POST-DEPLOYMENT CHECKLIST

- [ ] SSL certificates installed and working
- [ ] All health checks passing
- [ ] Monitoring dashboards active
- [ ] Brazilian government APIs responding
- [ ] Search functionality working with Portuguese queries
- [ ] Citation generation working (ABNT format)
- [ ] Data export functionality validated
- [ ] Academic workspace accessible
- [ ] User registration and authentication working
- [ ] Support team notified and ready
- [ ] Backup procedures tested
- [ ] Performance benchmarks met
- [ ] Security scans completed
- [ ] LGPD compliance validated

---

**🚀 DEPLOYMENT COMPLETE!**

Monitor Legislativo v4 is now live and serving the Brazilian academic and government communities with world-class legislative research capabilities.

**Production URL**: https://monitor-legislativo.gov.br
**Documentation**: https://monitor-legislativo.gov.br/docs
**Support**: suporte@monitor-legislativo.gov.br