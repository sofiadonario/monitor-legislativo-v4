# Monitor Legislativo v4 - Deployment Guide

**Version:** 4.0.0
**Last Updated:** 2025-11-21
**Status:** Production Ready

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Environment Configuration](#environment-configuration)
4. [Database Setup](#database-setup)
5. [Application Deployment](#application-deployment)
6. [Health Checks & Monitoring](#health-checks--monitoring)
7. [Security Hardening](#security-hardening)
8. [LGPD Compliance](#lgpd-compliance)
9. [Troubleshooting](#troubleshooting)
10. [Rollback Procedures](#rollback-procedures)

---

## Overview

Monitor Legislativo v4 is a production-ready R Shiny application for Brazilian legislative document analysis with:
- ✅ **Security**: Parameterized queries, input validation, CSRF protection
- ✅ **LGPD Compliance**: Complete data protection framework
- ✅ **Monitoring**: Health checks, Prometheus metrics, alerting
- ✅ **Reliability**: Transaction support, standardized error handling
- ✅ **Performance**: Query caching, connection pooling, optimized queries

---

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended)
- **R Version**: 4.0.0 or higher
- **RAM**: Minimum 4GB, recommended 8GB+
- **CPU**: Minimum 2 cores, recommended 4+ cores
- **Disk**: 20GB+ available space

### Required R Packages

```r
# Core packages
install.packages(c(
  "shiny",           # 1.7.0+
  "DBI",             # 1.1.0+
  "RPostgres",       # 1.4.0+
  "pool",            # 1.0.0+
  "DT",              # 0.20+
  "plotly",          # 4.10.0+
  "jsonlite",        # 1.8.0+
  "shinycssloaders", # 1.0.0+
  "pryr",            # 0.1.5+ (for memory monitoring)
  "testthat"         # 3.0.0+ (for testing)
))
```

### PostgreSQL Requirements

- **Version**: PostgreSQL 12.0 or higher
- **Extensions**: None required (standard installation)
- **Size**: Minimum 10GB for 134k+ documents

---

## Environment Configuration

### Required Environment Variables

Create a `.env` file or configure the following environment variables:

```bash
# Database Configuration
PGHOST=your-postgres-host.com
PGPORT=5432
PGDATABASE=monitor_legislativo
PGUSER=monitor_user
PGPASSWORD=your-secure-password

# Application Configuration
ENVIRONMENT=production
PORT=3838
SHINY_LOG_LEVEL=INFO

# Security Configuration
SESSION_SECRET_KEY=generate-random-32-char-key
ENABLE_CSRF_PROTECTION=TRUE

# Monitoring Configuration
HEALTH_CHECK_ENABLED=TRUE
PROMETHEUS_ENABLED=TRUE

# LGPD Compliance
DPO_EMAIL=dpo@mackenzie.br
PRIVACY_POLICY_URL=https://yoursite.com/privacy
```

### Generating Secure Keys

```bash
# Generate SESSION_SECRET_KEY
openssl rand -hex 32

# Generate secure PGPASSWORD
openssl rand -base64 24
```

### Environment-Specific Configuration

**Development (.env.development)**
```bash
ENVIRONMENT=development
SHINY_LOG_LEVEL=DEBUG
CACHE_ENABLED=FALSE
```

**Staging (.env.staging)**
```bash
ENVIRONMENT=staging
SHINY_LOG_LEVEL=INFO
CACHE_ENABLED=TRUE
CACHE_TTL_SECONDS=300
```

**Production (.env.production)**
```bash
ENVIRONMENT=production
SHINY_LOG_LEVEL=WARN
CACHE_ENABLED=TRUE
CACHE_TTL_SECONDS=1800
ENABLE_RATE_LIMITING=TRUE
```

---

## Database Setup

### 1. Create Database and User

```sql
-- Connect as postgres superuser
CREATE DATABASE monitor_legislativo
    ENCODING 'UTF8'
    LC_COLLATE='pt_BR.UTF-8'
    LC_CTYPE='pt_BR.UTF-8'
    TEMPLATE=template0;

-- Create application user
CREATE USER monitor_user WITH PASSWORD 'your-secure-password';

-- Grant privileges
GRANT CONNECT ON DATABASE monitor_legislativo TO monitor_user;
\c monitor_legislativo
GRANT USAGE ON SCHEMA public TO monitor_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO monitor_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO monitor_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO monitor_user;
```

### 2. Initialize Schema

The application expects a table named `documentos_legislativos`:

```sql
CREATE TABLE IF NOT EXISTS documentos_legislativos (
    id SERIAL PRIMARY KEY,
    titulo TEXT NOT NULL,
    tipo VARCHAR(100),
    data DATE,
    estado VARCHAR(2),
    conteudo TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_documentos_titulo ON documentos_legislativos USING gin(to_tsvector('portuguese', titulo));
CREATE INDEX idx_documentos_tipo ON documentos_legislativos(tipo);
CREATE INDEX idx_documentos_data ON documentos_legislativos(data DESC);
CREATE INDEX idx_documentos_estado ON documentos_legislativos(estado);
```

### 3. Connection Pool Configuration

The application uses `pool` package with these settings:

```r
# In app_phoenix.R
db_pool <- pool::dbPool(
  RPostgres::Postgres(),
  host = Sys.getenv("PGHOST"),
  port = as.integer(Sys.getenv("PGPORT", "5432")),
  dbname = Sys.getenv("PGDATABASE"),
  user = Sys.getenv("PGUSER"),
  password = Sys.getenv("PGPASSWORD"),
  minSize = 2,      # Minimum connections
  maxSize = 10      # Maximum connections
)
```

### 4. Test Database Connection

```r
# Run this test script
source("R/database/connection.R")

# Test connection
tryCatch({
  result <- pool::dbGetQuery(db_pool, "SELECT version()")
  cat("✅ Database connected:", result$version, "\n")
}, error = function(e) {
  cat("❌ Database connection failed:", e$message, "\n")
})
```

---

## Application Deployment

### Deployment Option 1: Railway (Recommended)

**1. Install Railway CLI**
```bash
npm install -g @railway/cli
railway login
```

**2. Create Railway Project**
```bash
railway init
railway link
```

**3. Add PostgreSQL Service**
```bash
railway add --plugin postgresql
```

**4. Configure Environment**
```bash
railway env set ENVIRONMENT=production
railway env set PORT=3838
# ... add all required environment variables
```

**5. Deploy**
```bash
railway up
```

**6. Access Logs**
```bash
railway logs
```

### Deployment Option 2: Docker

**1. Build Image**
```bash
docker build -t monitor-legislativo:v4.0.0 -f Dockerfile.base .
```

**2. Run Container**
```bash
docker run -d \
  --name monitor-legislativo \
  --env-file .env.production \
  -p 3838:3838 \
  monitor-legislativo:v4.0.0
```

**3. Verify Health**
```bash
curl http://localhost:3838/health
```

### Deployment Option 3: Shiny Server

**1. Install Shiny Server**
```bash
# Ubuntu/Debian
sudo apt-get install gdebi-core
wget https://download3.rstudio.org/ubuntu-18.04/x86_64/shiny-server-1.5.20.1002-amd64.deb
sudo gdebi shiny-server-1.5.20.1002-amd64.deb
```

**2. Configure Shiny Server**
```bash
sudo nano /etc/shiny-server/shiny-server.conf
```

```conf
server {
  listen 3838;

  location /monitor-legislativo {
    app_dir /srv/shiny-server/monitor-legislativo;
    log_dir /var/log/shiny-server;

    # Connection settings
    simple_scheduler 15;

    # Timeout settings
    app_idle_timeout 1800;
    app_init_timeout 120;
  }
}
```

**3. Deploy Application**
```bash
sudo cp -r /path/to/monitor-legislativo-v4 /srv/shiny-server/monitor-legislativo
sudo chown -R shiny:shiny /srv/shiny-server/monitor-legislativo
sudo systemctl restart shiny-server
```

---

## Health Checks & Monitoring

### Health Check Endpoint

The application provides a comprehensive health check system:

**Basic Health Check**
```bash
curl http://your-app-url:3838/health
```

**Response:**
```json
{
  "timestamp": "2025-11-21 10:30:00 UTC",
  "status": "healthy",
  "version": "4.0.0",
  "uptime_seconds": 3600,
  "response_time_ms": 45.23,
  "checks": {
    "database": {
      "status": "healthy",
      "message": "Database is responsive",
      "query_time_ms": 12.5,
      "pool_free": 8,
      "pool_taken": 2,
      "active_connections": 3,
      "database_size_mb": 2048.5
    },
    "memory": {
      "status": "healthy",
      "memory_used_mb": 512.3,
      "memory_limit_mb": 8192,
      "usage_percent": 6.3
    },
    "session": {
      "status": "healthy",
      "r_version": "4.3.2",
      "platform": "x86_64-pc-linux-gnu",
      "locale": "en_US.UTF-8",
      "timezone": "UTC"
    }
  }
}
```

### Kubernetes Probes

**Liveness Probe** (checks if app is alive):
```yaml
livenessProbe:
  httpGet:
    path: /health/liveness
    port: 3838
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

**Readiness Probe** (checks if app can serve traffic):
```yaml
readinessProbe:
  httpGet:
    path: /health/readiness
    port: 3838
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

### Prometheus Metrics

**Metrics Endpoint**
```bash
curl http://your-app-url:3838/metrics
```

**Sample Metrics Output:**
```
# HELP app_uptime_seconds Application uptime in seconds
# TYPE app_uptime_seconds gauge
app_uptime_seconds 3600

# HELP app_requests_total Total number of requests
# TYPE app_requests_total counter
app_requests_total 15420

# HELP app_errors_total Total number of errors
# TYPE app_errors_total counter
app_errors_total 23

# HELP app_health_status Health check status (1=healthy, 0=unhealthy)
# TYPE app_health_status gauge
app_health_status 1

# HELP db_query_time_ms Database query response time in milliseconds
# TYPE db_query_time_ms gauge
db_query_time_ms 12.50

# HELP db_pool_free Free connections in pool
# TYPE db_pool_free gauge
db_pool_free 8

# HELP db_active_connections Active database connections
# TYPE db_active_connections gauge
db_active_connections 3
```

### Alerting Rules (Prometheus)

Create `prometheus_alerts.yml`:

```yaml
groups:
  - name: monitor_legislativo
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: rate(app_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors/second"

      - alert: DatabaseSlow
        expr: db_query_time_ms > 1000
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Database queries are slow"
          description: "Query time is {{ $value }}ms"

      - alert: AppUnhealthy
        expr: app_health_status == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Application is unhealthy"
          description: "Health check failed"
```

---

## Security Hardening

### 1. Input Validation

All user inputs are validated using `R/security/input_validation.R`:

```r
# Example validation
validate_search_term <- function(term) {
  # SQL injection patterns
  sql_patterns <- c(
    "('|(\\-\\-)|(;)|(\\|\\|)|(\\*))",  # SQL metacharacters
    "(\\bDROP\\b)|(\\bDELETE\\b)|(\\bINSERT\\b)"  # SQL keywords
  )

  # XSS patterns
  xss_patterns <- c(
    "<script",
    "javascript:",
    "onerror=",
    "onload="
  )

  # Check patterns
  # ... validation logic
}
```

**Testing Input Validation:**
```bash
# Test SQL injection prevention
curl -X POST http://your-app:3838/search \
  -H "Content-Type: application/json" \
  -d '{"query": "'; DROP TABLE users; --"}'
# Expected: Error message, query rejected
```

### 2. Parameterized Queries

All database queries use parameterized inputs:

**❌ Vulnerable (DO NOT USE):**
```r
query <- paste0("SELECT * FROM documents WHERE title LIKE '%", user_input, "%'")
```

**✅ Secure (ALWAYS USE):**
```r
query <- "SELECT * FROM documents WHERE title ILIKE $1"
result <- pool::dbGetQuery(db_pool, query, params = list(paste0("%", user_input, "%")))
```

### 3. Security Headers

Configured in `app_phoenix.R`:

```r
options(shiny.http.response.filter = function(request, response) {
  response$headers[["X-Frame-Options"]] <- "DENY"
  response$headers[["X-Content-Type-Options"]] <- "nosniff"
  response$headers[["X-XSS-Protection"]] <- "1; mode=block"
  response$headers[["Referrer-Policy"]] <- "strict-origin-when-cross-origin"
  response$headers[["Strict-Transport-Security"]] <- "max-age=31536000; includeSubDomains"
  response$headers[["Content-Security-Policy"]] <- "default-src 'self'; ..."
  response
})
```

**Testing Security Headers:**
```bash
curl -I http://your-app:3838/ | grep -E "(X-Frame|X-Content|X-XSS|Strict-Transport)"
```

### 4. HTTPS/TLS Configuration

**Using Nginx as Reverse Proxy:**

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:3838;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for Shiny
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

### 5. Rate Limiting (Nginx)

```nginx
limit_req_zone $binary_remote_addr zone=app_limit:10m rate=10r/s;

location / {
    limit_req zone=app_limit burst=20 nodelay;
    limit_req_status 429;
    # ... rest of configuration
}
```

---

## LGPD Compliance

### 1. Privacy Policy

Accessible at `/privacy` tab in the application.

**Document Location:** `docs/lgpd/privacy_policy_pt.md`

### 2. Cookie Consent

Automatically displayed on first visit with options:
- ✅ Accept Cookies (essential + analytics)
- ❌ Reject Non-Essential (essential only)

**Implementation:** `app_phoenix.R` lines 635-671

### 3. Data Subject Rights

Users can exercise LGPD rights by contacting:
- **DPO Email:** dpo@mackenzie.br
- **Response Time:** 15 business days
- **Rights:** Access, correction, deletion, portability, etc.

**Documentation:** `docs/lgpd/data_subject_rights_procedures.md`

### 4. Incident Response

Follow breach notification procedure:
- **Timeline:** Detection → Assessment → Containment → Notification (within 72h to ANPD)
- **Process:** `docs/lgpd/breach_notification_procedure.md`

### 5. Data Processing Register

Maintained at: `docs/lgpd/data_processing_register.md`

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed

**Symptoms:**
```
Error: could not connect to server
```

**Diagnosis:**
```bash
# Check environment variables
echo $PGHOST $PGPORT $PGDATABASE $PGUSER

# Test connection manually
psql -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE -c "SELECT version()"

# Check firewall
telnet $PGHOST $PGPORT
```

**Solutions:**
- Verify credentials in .env file
- Check database server is running
- Verify firewall rules allow connection
- Check SSL requirements: `sslmode=require` in connection string

#### 2. High Memory Usage

**Symptoms:**
```
Memory usage critical: 95.2%
```

**Diagnosis:**
```r
# Check memory in R
pryr::mem_used()
gc()

# System memory
free -h
```

**Solutions:**
- Increase `R_MAX_VSIZE` environment variable
- Restart application to clear memory
- Reduce query cache TTL
- Optimize data.frame sizes in reactive expressions

#### 3. Slow Queries

**Symptoms:**
```
Database query response time: 2500ms
```

**Diagnosis:**
```sql
-- Check slow queries
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state = 'active'
  AND now() - query_start > interval '1 second'
ORDER BY duration DESC;

-- Check missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE tablename = 'documentos_legislativos'
  AND n_distinct < -0.1;
```

**Solutions:**
- Add indexes on frequently queried columns
- Analyze and vacuum tables: `VACUUM ANALYZE documentos_legislativos`
- Increase cache TTL for expensive queries
- Use `EXPLAIN ANALYZE` to identify bottlenecks

#### 4. Health Check Failing

**Symptoms:**
```json
{"status": "unhealthy", "checks": {"database": {"status": "unhealthy"}}}
```

**Diagnosis:**
```r
# Run health check manually
source("R/monitoring/health_check.R")
health <- perform_health_check(db_pool, detailed = TRUE)
print(health)

# Check specific components
db_health <- check_database_health(db_pool)
mem_health <- check_memory_health()
```

**Solutions:**
- Check database connectivity
- Verify pool has free connections
- Check memory usage
- Review application logs for errors

#### 5. Transaction Rollback Errors

**Symptoms:**
```
Transaction TXN-20251121103000-5432 failed: duplicate key value
```

**Diagnosis:**
```r
# Check transaction statistics
source("R/database/transaction_support.R")
stats <- get_transaction_stats(db_pool)
print(stats)

# Check for long-running transactions
long_txns <- check_long_transactions(db_pool)
```

**Solutions:**
- Review application logic for race conditions
- Implement retry logic with exponential backoff
- Check for deadlocks: `SELECT * FROM pg_locks`
- Increase transaction timeout if appropriate

### Log Analysis

**Application Logs Location:**
- Railway: `railway logs`
- Docker: `docker logs monitor-legislativo`
- Shiny Server: `/var/log/shiny-server/`

**Key Log Patterns:**

```bash
# Find errors
grep "ERROR" app.log

# Find security incidents
grep -E "(SEC001|SEC002)" app.log

# Find slow queries
grep "query_time_ms.*[0-9]{4,}" app.log

# Find transaction rollbacks
grep "TRANSACTION ROLLBACK" app.log
```

---

## Rollback Procedures

### Rollback Checklist

1. ✅ Identify issue and impact
2. ✅ Notify stakeholders
3. ✅ Stop incoming traffic (if critical)
4. ✅ Execute rollback
5. ✅ Verify health checks
6. ✅ Resume traffic
7. ✅ Post-mortem analysis

### Railway Rollback

```bash
# List previous deployments
railway deployments

# Rollback to specific deployment
railway rollback <deployment-id>

# Verify rollback
railway logs
```

### Docker Rollback

```bash
# Stop current container
docker stop monitor-legislativo

# Remove current container
docker rm monitor-legislativo

# Start previous version
docker run -d \
  --name monitor-legislativo \
  --env-file .env.production \
  -p 3838:3838 \
  monitor-legislativo:v3.9.0  # Previous version

# Verify health
curl http://localhost:3838/health
```

### Database Rollback

**If schema changes were made:**

```sql
-- Restore from backup
pg_restore -h $PGHOST -U $PGUSER -d monitor_legislativo backup_20251120.dump

-- Verify data integrity
SELECT COUNT(*) FROM documentos_legislativos;
```

**If only data changed:**

```sql
-- Rollback transaction (if within session)
ROLLBACK;

-- Restore specific table
pg_restore -h $PGHOST -U $PGUSER -d monitor_legislativo -t documentos_legislativos backup.dump
```

---

## Maintenance

### Daily Tasks

- ✅ Check health status dashboard
- ✅ Review error logs
- ✅ Monitor Prometheus alerts
- ✅ Verify backup completion

### Weekly Tasks

- ✅ Analyze performance metrics
- ✅ Review security logs for anomalies
- ✅ Test health check endpoints
- ✅ Update documentation if needed

### Monthly Tasks

- ✅ Review and rotate logs
- ✅ Database vacuum and analyze
- ✅ Update R packages (after testing)
- ✅ Security audit review
- ✅ LGPD compliance review

---

## Support

### Contact Information

- **Technical Lead:** [email]
- **DPO (LGPD):** dpo@mackenzie.br
- **Security Issues:** security@mackenzie.br
- **General Support:** support@mackenzie.br

### Documentation

- **API Documentation:** `/docs` endpoint
- **LGPD Policies:** `docs/lgpd/`
- **Security Tests:** `tests/security/`
- **User Guide:** `docs/USER_GUIDE.md`

---

**Monitor Legislativo v4** - Production deployment ready with security, compliance, and monitoring built-in.
