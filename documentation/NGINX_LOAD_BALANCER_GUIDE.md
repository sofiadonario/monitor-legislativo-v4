# nginx Reverse Proxy & Load Balancer Guide
# Monitor Legislativo v4 - Phase 4 Week 13

## 🌐 Overview

This guide covers the production-grade nginx reverse proxy and load balancing implementation for Monitor Legislativo v4. The setup provides high availability, SSL termination, intelligent load balancing, and comprehensive health monitoring.

## 📋 Architecture Components

### Core Components
- **nginx Reverse Proxy**: Production-grade load balancer with SSL termination
- **Multi-instance Services**: Horizontal scaling for API, WebSocket, and R Shiny services
- **Database Clustering**: PostgreSQL master-replica with connection pooling
- **Redis Clustering**: Cache replication and failover
- **Health Monitoring**: Automated health checks with failover mechanisms

### Load Balancing Strategies
- **API Services**: Least connections with backup instances
- **R Shiny**: IP hash for session affinity
- **WebSocket**: Least connections with upgrade support
- **Database**: TCP proxy with read/write splitting

## 🔧 Configuration Files

### 1. Main nginx Configuration
**File**: `nginx-reverse-proxy.conf`

Key features:
- Multi-upstream load balancing
- SSL/TLS termination with modern security
- HTTP/2 support
- Proxy caching with intelligent invalidation
- Rate limiting and DDoS protection
- Security headers and CSP

### 2. Docker Configuration
**File**: `docker-compose.loadbalancer.yml`

Services configured:
- Load balancer (nginx)
- API instances (api1, api2, api3-backup)
- R Shiny instances (shiny1, shiny2)
- WebSocket instances (ws1, ws2)
- Database cluster (postgres, postgres-replica)
- Redis cluster (redis1, redis2)
- Monitoring stack (Prometheus, Grafana)

### 3. SSL Management
**File**: `development/ssl-generation.sh`

Features:
- Self-signed certificates for development
- Let's Encrypt integration for production
- Automatic renewal setup
- Certificate validation

### 4. Health Monitoring
**File**: `development/health-checks.sh`

Capabilities:
- Comprehensive service health checking
- Automatic failover and restart
- Alert notifications
- Interactive monitoring interface

## 🚀 Deployment Guide

### Prerequisites
```bash
# Required tools
- Docker and Docker Compose
- OpenSSL (for SSL certificates)
- curl (for health checks)

# Optional for production
- certbot (for Let's Encrypt)
- systemd (for service management)
```

### Quick Start

1. **Generate SSL Certificates**
```bash
# Development (self-signed)
./development/ssl-generation.sh self-signed

# Production (Let's Encrypt)
sudo ./development/ssl-generation.sh letsencrypt
```

2. **Configure Environment**
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
vim .env
```

Required environment variables:
```env
# Database
DB_USER=monitor_user
DB_PASSWORD=secure_password
DB_REPLICATION_USER=replication_user
DB_REPLICATION_PASSWORD=replication_password

# Monitoring
GRAFANA_PASSWORD=admin_password

# Alerts
ALERT_WEBHOOK=https://hooks.slack.com/your-webhook-url
```

3. **Deploy Load Balancer Stack**
```bash
# Start all services
docker-compose -f docker-compose.loadbalancer.yml up -d

# Check service status
docker-compose -f docker-compose.loadbalancer.yml ps

# View logs
docker-compose -f docker-compose.loadbalancer.yml logs -f loadbalancer
```

4. **Verify Deployment**
```bash
# Run health checks
./development/health-checks.sh check

# Test load balancer
curl -I https://localhost/health

# Check upstream status
curl http://localhost:9090/upstream-status
```

## 🔍 Health Monitoring

### Automated Health Checks

The health monitoring system provides:
- **Service Discovery**: Automatic detection of running services
- **Health Validation**: HTTP, PostgreSQL, and Redis health checks
- **Failure Handling**: Automatic restart and scaling
- **Alert System**: Webhook notifications for failures

### Health Check Commands
```bash
# Check all services once
./development/health-checks.sh check

# Check specific service
./development/health-checks.sh check api1

# Start continuous monitoring
./development/health-checks.sh monitor

# Interactive mode
./development/health-checks.sh interactive

# Generate health report
./development/health-checks.sh report
```

### Health Endpoints
- **Load Balancer**: `http://localhost:9090/lb-health`
- **nginx Status**: `http://localhost:9090/nginx_status`
- **Upstream Status**: `http://localhost:9090/upstream-status`
- **Service Health**: `http://localhost:8000/health` (API instances)

## ⚖️ Load Balancing Strategies

### 1. API Load Balancing
```nginx
upstream backend_api {
    least_conn;
    server api1:8000 max_fails=3 fail_timeout=30s weight=1;
    server api2:8000 max_fails=3 fail_timeout=30s weight=1;
    server api3:8000 max_fails=3 fail_timeout=30s backup;
    
    keepalive 32;
}
```

**Strategy**: Least connections with backup server
**Use Case**: Distributes API requests evenly across instances

### 2. R Shiny Load Balancing
```nginx
upstream shiny_analytics {
    ip_hash;  # Session affinity
    server shiny1:3838 max_fails=2 fail_timeout=30s;
    server shiny2:3838 max_fails=2 fail_timeout=30s;
    
    keepalive 16;
}
```

**Strategy**: IP hash for session affinity
**Use Case**: Ensures users stay on the same Shiny instance

### 3. WebSocket Load Balancing
```nginx
upstream websocket_backend {
    least_conn;
    server ws1:8001 max_fails=2 fail_timeout=30s;
    server ws2:8001 max_fails=2 fail_timeout=30s;
    
    keepalive 16;
}
```

**Strategy**: Least connections with WebSocket upgrade
**Use Case**: Real-time features like live data updates

### 4. Database Load Balancing
```nginx
# TCP stream module for database connections
upstream postgres_backend {
    least_conn;
    server db1:5432 max_fails=3 fail_timeout=30s;
    server db2:5432 max_fails=3 fail_timeout=30s backup;
}
```

**Strategy**: TCP proxy with read replica
**Use Case**: Database connection pooling and read scaling

## 🔒 SSL/TLS Configuration

### Modern SSL Configuration
```nginx
# SSL protocols and ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
ssl_ecdh_curve secp384r1;
ssl_prefer_server_ciphers off;

# Security features
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

### Security Headers
```nginx
# Essential security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Content Security Policy
```nginx
add_header Content-Security-Policy "
    default-src 'self'; 
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.shinyapps.io; 
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; 
    font-src 'self' https://fonts.gstatic.com; 
    img-src 'self' data: https://*.openstreetmap.org; 
    connect-src 'self' https://*.railway.app https://*.lexml.gov.br wss: ws:; 
    frame-src 'self' https://*.shinyapps.io;
" always;
```

## 🎯 Performance Optimization

### Caching Strategy
```nginx
# Proxy cache configuration
proxy_cache_path /var/cache/nginx/proxy 
                 levels=1:2 
                 keys_zone=api_cache:100m 
                 max_size=1g 
                 inactive=60m 
                 use_temp_path=off;

# Cache rules
proxy_cache api_cache;
proxy_cache_valid 200 302 10m;
proxy_cache_valid 404 1m;
proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
```

### Compression Settings
```nginx
# Gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_comp_level 6;
gzip_types
    text/plain text/css text/xml text/javascript
    application/javascript application/json application/xml
    image/svg+xml;
```

### Rate Limiting
```nginx
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

# Apply rate limits
location /api/ {
    limit_req zone=api burst=50 nodelay;
    # ... proxy configuration
}
```

## 📊 Monitoring and Metrics

### Prometheus Integration
Metrics collected:
- nginx request rate and response times
- Upstream server health and response times
- Cache hit rates and performance
- SSL certificate expiration
- Error rates and status codes

### Grafana Dashboards
Pre-configured dashboards for:
- **Load Balancer Overview**: Traffic, response times, error rates
- **Upstream Health**: Backend service status and performance
- **Cache Performance**: Hit rates, cache sizes, invalidation rates
- **Security Metrics**: Failed authentication attempts, blocked requests

### Log Analysis
```bash
# View access logs
tail -f /var/log/nginx/access.log

# Filter error logs
grep "ERROR" /var/log/nginx/error.log

# Analyze performance
awk '{print $9, $10}' /var/log/nginx/access.log | sort | uniq -c
```

## 🚨 Troubleshooting

### Common Issues

1. **SSL Certificate Issues**
```bash
# Check certificate validity
openssl x509 -in /etc/nginx/ssl/monitor-legislativo.crt -noout -dates

# Verify certificate chain
openssl verify -CAfile ca-bundle.crt /etc/nginx/ssl/monitor-legislativo.crt

# Test SSL configuration
curl -vI https://localhost/health
```

2. **Upstream Connection Issues**
```bash
# Check upstream status
curl http://localhost:9090/upstream-status

# Test backend connectivity
docker exec monitor-legislativo-lb curl http://api1:8000/health

# Check docker networking
docker network inspect monitor-legislativo_monitor-network
```

3. **Performance Issues**
```bash
# Check nginx status
curl http://localhost:9090/nginx_status

# Monitor resource usage
docker stats

# Analyze slow requests
grep "request_time" /var/log/nginx/access.log | awk '{if($12>1.0) print}'
```

### Debug Commands
```bash
# Test nginx configuration
nginx -t

# Reload configuration
docker-compose -f docker-compose.loadbalancer.yml exec loadbalancer nginx -s reload

# View detailed logs
docker-compose -f docker-compose.loadbalancer.yml logs -f --tail=100 loadbalancer

# Check upstream health
./development/health-checks.sh check

# Generate health report
./development/health-checks.sh report
```

## 🔄 Failover Scenarios

### Automatic Failover Triggers
1. **Service Health Check Failure**: 3 consecutive failures
2. **Response Time Threshold**: >5 seconds average
3. **Error Rate Threshold**: >5% error rate
4. **Resource Exhaustion**: Memory/CPU limits exceeded

### Failover Actions
1. **Service Restart**: Automatic container restart
2. **Backup Activation**: Switch to backup instances
3. **Service Scaling**: Launch additional instances
4. **Alert Generation**: Webhook notifications

### Manual Failover
```bash
# Force restart specific service
./development/health-checks.sh restart api1

# Scale up backup instance
docker-compose -f docker-compose.loadbalancer.yml up -d api3

# Temporarily remove upstream
# Edit nginx configuration and reload
```

## 📈 Scaling Guidelines

### Horizontal Scaling
```bash
# Add API instances
docker-compose -f docker-compose.loadbalancer.yml up -d --scale api=4

# Add Shiny instances (requires nginx config update)
docker-compose -f docker-compose.loadbalancer.yml up -d --scale shiny=3
```

### Vertical Scaling
```yaml
# Update resource limits in docker-compose.loadbalancer.yml
deploy:
  resources:
    limits:
      memory: 1G
      cpus: '2.0'
```

### Auto-scaling (Future Enhancement)
Consider implementing:
- Docker Swarm mode auto-scaling
- Kubernetes Horizontal Pod Autoscaler
- Custom scaling based on metrics

## 📋 Maintenance Tasks

### Regular Maintenance
```bash
# Certificate renewal (automated via cron)
/usr/local/bin/renew-ssl.sh

# Log rotation
logrotate /etc/logrotate.d/nginx

# Cache cleanup
find /var/cache/nginx -type f -mtime +7 -delete

# Health check validation
./development/health-checks.sh check
```

### Performance Tuning
1. **Monitor Metrics**: Check Grafana dashboards weekly
2. **Analyze Logs**: Review error patterns monthly
3. **Cache Optimization**: Adjust cache rules based on usage
4. **Resource Planning**: Monitor growth trends

## 🔐 Security Best Practices

### Implementation Status
- ✅ **SSL/TLS Configuration**: Modern protocols and ciphers
- ✅ **Security Headers**: HSTS, CSP, X-Frame-Options
- ✅ **Rate Limiting**: API and general request limits
- ✅ **Access Control**: IP-based restrictions for admin endpoints
- ✅ **Input Validation**: Request sanitization and filtering
- ✅ **Container Security**: Non-root user, read-only filesystem

### Security Monitoring
- Failed authentication attempts
- Unusual traffic patterns
- SSL certificate expiration
- Vulnerability scanning results

---

**Next Phase**: Week 14 - Database Optimization with query tuning, connection pooling, and backup strategies.

**Last Updated**: Phase 4 Week 13  
**Production Ready**: ✅ Load balancer, SSL, health checks, failover  
**Performance Target**: >99.5% uptime, <500ms response time