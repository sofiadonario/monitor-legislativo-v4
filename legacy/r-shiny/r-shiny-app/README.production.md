# Monitor Legislativo v4 - Production Deployment Guide

## Overview

This guide covers the production deployment of Monitor Legislativo v4 using the consolidated R architecture. The application is containerized with Docker and can be deployed on various platforms including Railway, AWS, or self-hosted environments.

## Architecture

The production setup includes:
- **Multi-stage Docker builds** for optimized images
- **Load balancing** with Nginx (2 R Shiny instances)
- **PostgreSQL** database with connection pooling
- **Redis** caching layer
- **SSL/TLS** termination
- **Health checks** and monitoring
- **Automated backups**
- **CI/CD pipeline** with GitHub Actions

## Quick Start

### 1. Environment Setup

1. Copy the environment template:
```bash
cp .env.production .env.local
```

2. Configure required variables in `.env.local`:
```bash
POSTGRES_PASSWORD=your_secure_password
OPENAI_API_KEY=your_openai_key  # Optional
ANTHROPIC_API_KEY=your_anthropic_key  # Optional
```

### 2. SSL Certificate Generation

Generate self-signed certificates for development:
```bash
./scripts/generate_ssl.sh monitor-legislativo.local
```

For production, use Let's Encrypt or your certificate provider.

### 3. Deployment

Deploy with the automated script:
```bash
./scripts/deploy.sh production
```

Or manually with Docker Compose:
```bash
docker-compose -f docker-compose.production.yml up -d
```

## Deployment Options

### Option 1: Railway (Recommended for Simplicity)

1. **Connect Repository**: Link your GitHub repository to Railway
2. **Configure Environment**: Set environment variables in Railway dashboard
3. **Deploy**: Railway will automatically build and deploy using `railway.production.toml`

**Benefits:**
- Automatic scaling
- Built-in monitoring
- Easy SSL certificates
- Database provisioning
- $5-30/month cost

### Option 2: Docker Compose (Self-hosted)

1. **Server Requirements**:
   - 4+ GB RAM
   - 2+ CPU cores
   - 20+ GB storage
   - Ubuntu 20.04+ or similar

2. **Installation**:
```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo apt install docker-compose

# Clone repository
git clone https://github.com/yourusername/monitor-legislativo-v4.git
cd monitor-legislativo-v4/r-shiny-app

# Deploy
./scripts/deploy.sh production
```

### Option 3: AWS/Cloud Provider

Use the provided Docker images with:
- **ECS/Fargate** for container orchestration
- **RDS** for PostgreSQL
- **ElastiCache** for Redis
- **ALB** for load balancing
- **CloudWatch** for monitoring

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `POSTGRES_PASSWORD` | Database password | Yes | - |
| `POSTGRES_DB` | Database name | No | monitor_legislativo |
| `REDIS_MAX_MEMORY` | Redis memory limit | No | 512mb |
| `OPENAI_API_KEY` | OpenAI API key | No | - |
| `ANTHROPIC_API_KEY` | Anthropic API key | No | - |
| `LOG_LEVEL` | Logging level | No | INFO |
| `APP_PORT` | HTTP port | No | 80 |
| `APP_SSL_PORT` | HTTPS port | No | 443 |

### Performance Tuning

**Memory Settings**:
```env
R_MAX_MEMORY=2GB
SHINY_MAX_SESSIONS=100
CACHE_TTL=3600
```

**Database Tuning**:
```env
POSTGRES_SHARED_BUFFERS=256MB
POSTGRES_MAX_CONNECTIONS=100
```

## Monitoring and Maintenance

### Health Checks

Monitor application health:
```bash
# Application health
curl http://localhost/health

# Service status
docker-compose -f docker-compose.production.yml ps

# Logs
docker-compose -f docker-compose.production.yml logs -f app1
```

### Monitoring Stack (Optional)

Enable Prometheus and Grafana:
```bash
ENABLE_MONITORING=true ./scripts/deploy.sh production
```

Access monitoring:
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

### Backups

Automated backups are configured with the deployment:
```bash
# Manual backup
./scripts/backup.sh

# Restore from backup
docker exec -i monitor_legislativo_postgres psql -U postgres < backup.sql
```

### Scaling

**Horizontal Scaling**:
1. Increase app instances in `docker-compose.production.yml`
2. Update Nginx upstream configuration
3. Redeploy with `./scripts/deploy.sh production`

**Vertical Scaling**:
1. Update resource limits in Docker Compose
2. Adjust R memory settings
3. Restart services

## Troubleshooting

### Common Issues

**1. Application Won't Start**
```bash
# Check logs
docker-compose -f docker-compose.production.yml logs app1

# Check environment variables
docker-compose -f docker-compose.production.yml config

# Verify health check
curl -v http://localhost/health
```

**2. High Memory Usage**
```bash
# Monitor resource usage
docker stats

# Adjust memory limits
# Edit docker-compose.production.yml
# Set R_MAX_MEMORY environment variable
```

**3. Database Connection Issues**
```bash
# Test database connectivity
docker exec -it monitor_legislativo_postgres psql -U postgres

# Check database logs
docker-compose -f docker-compose.production.yml logs postgres
```

**4. SSL Certificate Issues**
```bash
# Regenerate certificates
./scripts/generate_ssl.sh your-domain.com

# Check certificate validity
openssl x509 -in nginx/ssl/cert.pem -text -noout
```

### Performance Optimization

**1. Database Optimization**:
- Enable connection pooling
- Configure appropriate indexes
- Regular VACUUM and ANALYZE

**2. Caching Strategy**:
- Increase Redis memory allocation
- Implement query result caching
- Use CDN for static assets

**3. Application Tuning**:
- Optimize R package loading
- Implement lazy loading
- Configure session management

## Security

### Security Checklist

- [ ] SSL/TLS certificates configured
- [ ] Environment variables secured
- [ ] Database passwords rotated
- [ ] API keys restricted
- [ ] Network access controlled
- [ ] Regular security updates
- [ ] Backup encryption enabled

### Security Headers

The Nginx configuration includes:
- HSTS (HTTP Strict Transport Security)
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options

## CI/CD Pipeline

The GitHub Actions workflow includes:
1. **Testing**: R package tests and syntax checks
2. **Security**: Vulnerability scanning with Trivy
3. **Building**: Multi-platform Docker images
4. **Deployment**: Automated staging and production
5. **Monitoring**: Health checks and notifications

### Manual Deployment

```bash
# Build and push image
docker build -f Dockerfile.production -t monitor-legislativo:latest .
docker push your-registry/monitor-legislativo:latest

# Deploy to production
kubectl apply -f k8s/production/
```

## Cost Optimization

### Resource Planning

**Small Scale (10-50 users)**:
- 2 GB RAM, 1 CPU
- Basic PostgreSQL
- Redis cache
- Cost: $15-25/month

**Medium Scale (50-200 users)**:
- 4 GB RAM, 2 CPU
- PostgreSQL with replicas
- Enhanced caching
- Cost: $25-50/month

**Large Scale (200+ users)**:
- 8+ GB RAM, 4+ CPU
- Database clustering
- CDN integration
- Cost: $50-100/month

## Support

### Getting Help

1. **Documentation**: Check this guide and inline comments
2. **Logs**: Always check application and service logs
3. **Health Checks**: Use built-in health endpoints
4. **Monitoring**: Enable Prometheus/Grafana for insights

### Reporting Issues

When reporting issues, include:
- Environment details (Docker versions, OS)
- Complete error logs
- Steps to reproduce
- Expected vs actual behavior

## Next Steps

After successful deployment:

1. **Monitor Performance**: Watch resource usage and response times
2. **Configure Backups**: Set up automated backup schedules
3. **Security Review**: Implement additional security measures
4. **User Training**: Provide documentation for end users
5. **Scale Planning**: Monitor usage patterns for scaling decisions

---

**Monitor Legislativo v4** - Academic Research Platform for Brazilian Legislative Data