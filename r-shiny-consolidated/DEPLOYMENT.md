# Production Deployment Guide - Monitor Legislativo v4

This guide covers the complete production deployment process for Monitor Legislativo v4, including infrastructure setup, configuration, monitoring, and maintenance procedures.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Setup](#infrastructure-setup)
3. [Environment Configuration](#environment-configuration)
4. [Deployment Process](#deployment-process)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Backup and Recovery](#backup-and-recovery)
7. [Scaling and Performance](#scaling-and-performance)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)
10. [Maintenance Procedures](#maintenance-procedures)

## Prerequisites

### System Requirements

**Minimum Production Environment:**
- **CPU**: 4 cores (8+ recommended)
- **Memory**: 8GB RAM (16GB+ recommended)
- **Storage**: 100GB SSD (500GB+ recommended)
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04 LTS or newer

**Software Dependencies:**
- Docker Engine 20.10+
- Docker Compose 2.0+
- Git 2.30+
- SSL Certificate (Let's Encrypt recommended)

### External Services

**Required API Keys:**
- OpenAI API Key (for AI features)
- Anthropic Claude API Key (optional, for AI fallback)
- SMTP credentials (for notifications)

**Monitoring Services:**
- Prometheus (included in deployment)
- Grafana (included in deployment)
- AlertManager (optional)

## Infrastructure Setup

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create deployment directory
sudo mkdir -p /opt/monitor-legislativo
sudo chown $USER:$USER /opt/monitor-legislativo
```

### 2. SSL Certificate Setup

```bash
# Install Certbot
sudo apt install certbot

# Obtain SSL certificate (replace with your domain)
sudo certbot certonly --standalone -d monitor-legislativo.com

# Copy certificates to deployment directory
sudo cp /etc/letsencrypt/live/monitor-legislativo.com/fullchain.pem /opt/monitor-legislativo/ssl/cert.pem
sudo cp /etc/letsencrypt/live/monitor-legislativo.com/privkey.pem /opt/monitor-legislativo/ssl/key.pem
```

### 3. Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw allow ssh
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3000/tcp  # Grafana (restrict to admin IPs in production)
sudo ufw allow 9090/tcp  # Prometheus (restrict to admin IPs in production)
sudo ufw enable
```

## Environment Configuration

### 1. Clone Repository

```bash
cd /opt/monitor-legislativo
git clone https://github.com/your-org/monitor-legislativo-v4.git .
```

### 2. Configure Environment Variables

Create `.env` file:

```bash
# Copy example environment file
cp .env.example .env

# Edit with your configuration
nano .env
```

**Required Environment Variables:**

```bash
# Database Configuration
POSTGRES_USER=monitor_user
POSTGRES_PASSWORD=secure_password_here
POSTGRES_DB=monitor_legislativo

# AI Service API Keys
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key

# Security
JWT_SECRET=your_jwt_secret_here
SESSION_SECRET=your_session_secret_here

# Monitoring
GRAFANA_PASSWORD=admin_password_here

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_email_password

# Backup Configuration
BACKUP_S3_BUCKET=your-backup-bucket
BACKUP_S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret

# Domain Configuration
DOMAIN=monitor-legislativo.com
```

### 3. Database Initialization

```bash
# Create database initialization scripts
mkdir -p database/init

# Copy SQL initialization files if needed
cp sql/init.sql database/init/
```

## Deployment Process

### 1. Initial Deployment

```bash
# Navigate to deployment directory
cd /opt/monitor-legislativo

# Pull latest images
docker-compose -f docker-compose.prod.yml pull

# Start services
docker-compose -f docker-compose.prod.yml up -d

# Check service status
docker-compose -f docker-compose.prod.yml ps
```

### 2. Automated Deployment Script

```bash
# Make deployment script executable
chmod +x scripts/deploy.sh

# Run deployment
./scripts/deploy.sh latest
```

### 3. Health Check Verification

```bash
# Check application health
curl -f https://monitor-legislativo.com/health

# Check API health
curl -f https://monitor-legislativo.com/api/v1/health

# Check Prometheus metrics
curl -f http://localhost:9091/metrics
```

## Monitoring and Alerting

### 1. Grafana Dashboard Setup

1. Access Grafana at `https://monitor-legislativo.com:3000`
2. Login with admin credentials
3. Import pre-configured dashboards from `monitoring/grafana/dashboards/`

**Key Dashboards:**
- Application Performance
- Infrastructure Metrics
- AI Services Health
- Business Metrics
- Error Tracking

### 2. Prometheus Configuration

Metrics are automatically collected from:
- R Shiny application
- RestRserve API
- PostgreSQL database
- Redis cache
- System resources
- External APIs

### 3. Alert Configuration

Configure alerts for:
- High error rates (>5%)
- High response times (>2 seconds)
- Database connection issues
- AI service failures
- SSL certificate expiration
- Disk space warnings

## Backup and Recovery

### 1. Automated Backups

Backups run daily at 2 AM UTC:

```bash
# Manual backup
docker-compose -f docker-compose.prod.yml exec backup /backup.sh

# Restore from backup
./scripts/restore.sh backup_20240101_020000
```

### 2. Backup Strategy

**Daily Backups:**
- Database dump (compressed)
- Application data
- Configuration files
- SSL certificates

**Retention Policy:**
- Daily backups: 30 days
- Weekly backups: 12 weeks
- Monthly backups: 12 months

### 3. Disaster Recovery

**Recovery Time Objective (RTO):** 4 hours
**Recovery Point Objective (RPO):** 24 hours

**Recovery Steps:**
1. Provision new infrastructure
2. Restore latest backup
3. Update DNS records
4. Verify application functionality

## Scaling and Performance

### 1. Horizontal Scaling

Add application replicas:

```yaml
# In docker-compose.prod.yml
app:
  deploy:
    replicas: 3
    resources:
      limits:
        cpus: '2'
        memory: 4G
```

### 2. Database Scaling

**Read Replicas:**
```yaml
db-replica:
  image: postgres:15-alpine
  environment:
    POSTGRES_MASTER_SERVICE: db
    POSTGRES_REPLICA_USER: replica_user
```

**Connection Pooling:**
- PgBouncer for connection pooling
- Redis for session storage
- CDN for static assets

### 3. Performance Optimization

**Application Level:**
- R package precompilation
- Code optimization
- Memory management
- Async processing

**Infrastructure Level:**
- SSD storage
- CDN integration
- Load balancing
- Caching layers

## Security Considerations

### 1. Network Security

- SSL/TLS encryption (A+ rating)
- Firewall configuration
- VPN access for admin functions
- IP whitelisting for sensitive endpoints

### 2. Application Security

- Input validation and sanitization
- CSRF protection
- Rate limiting
- Authentication and authorization
- Security headers

### 3. Data Security

- Database encryption at rest
- Backup encryption
- Secrets management
- Audit logging
- GDPR compliance

### 4. Security Monitoring

- Log analysis with ELK stack
- Intrusion detection
- Vulnerability scanning
- Security alerts

## Troubleshooting

### Common Issues

**1. Application Won't Start**
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs app

# Check dependencies
docker-compose -f docker-compose.prod.yml ps
```

**2. Database Connection Issues**
```bash
# Test database connectivity
docker-compose -f docker-compose.prod.yml exec app R -e "source('R/database.R'); test_connection()"

# Check database logs
docker-compose -f docker-compose.prod.yml logs db
```

**3. High Memory Usage**
```bash
# Monitor memory usage
docker stats

# Restart services if needed
docker-compose -f docker-compose.prod.yml restart app
```

**4. SSL Certificate Issues**
```bash
# Check certificate expiration
openssl x509 -in ssl/cert.pem -text -noout | grep "Not After"

# Renew certificate
sudo certbot renew
```

### Log Analysis

**Application Logs:**
```bash
# View real-time logs
docker-compose -f docker-compose.prod.yml logs -f app

# Search logs for errors
docker-compose -f docker-compose.prod.yml logs app | grep ERROR
```

**System Logs:**
```bash
# Check system resources
htop
df -h
free -h

# Check Docker daemon
sudo journalctl -u docker
```

## Maintenance Procedures

### 1. Regular Maintenance

**Weekly Tasks:**
- Review monitoring alerts
- Check backup integrity
- Update security patches
- Review performance metrics

**Monthly Tasks:**
- Update application dependencies
- Security vulnerability assessment
- Capacity planning review
- Documentation updates

### 2. Update Procedures

**Application Updates:**
```bash
# Deploy new version
./scripts/deploy.sh v4.1.0

# Rollback if needed
./scripts/rollback.sh
```

**System Updates:**
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Update Docker images
docker-compose -f docker-compose.prod.yml pull
```

### 3. Performance Tuning

**Database Tuning:**
- Query optimization
- Index management
- Connection pool sizing
- Vacuum and analyze

**Application Tuning:**
- Memory optimization
- Cache configuration
- Async processing
- Load balancing

### 4. Capacity Planning

Monitor and plan for:
- User growth
- Data volume increase
- Traffic patterns
- Resource utilization

## Support and Documentation

### 1. Monitoring Dashboards

- **Grafana**: Application and infrastructure metrics
- **Kibana**: Log analysis and search
- **Prometheus**: Raw metrics and alerts

### 2. Documentation

- Architecture documentation
- API documentation
- Runbooks and procedures
- Troubleshooting guides

### 3. Contact Information

**Technical Support:**
- Email: tech-support@monitor-legislativo.com
- Slack: #monitor-legislativo-support
- On-call: +55 11 9999-9999

**Emergency Contacts:**
- DevOps Team: devops@monitor-legislativo.com
- Database Admin: dba@monitor-legislativo.com
- Security Team: security@monitor-legislativo.com

---

## Appendix

### A. Environment Variables Reference

See `config/production.yml` for complete configuration options.

### B. API Endpoints

See `docs/api.md` for complete API documentation.

### C. Database Schema

See `docs/database.md` for database schema documentation.

### D. Monitoring Metrics

See `docs/monitoring.md` for complete metrics reference.