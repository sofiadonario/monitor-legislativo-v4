# Monitor Legislativo v4 - Troubleshooting Guide

**Version:** 4.0.0
**Last Updated:** 2025-11-21

## Quick Reference

| Error Code | Description | Severity | Section |
|------------|-------------|----------|---------|
| DB001 | Database connection failed | CRITICAL | [Database](#database-errors) |
| DB002 | Query execution failed | ERROR | [Database](#database-errors) |
| DB003 | Transaction failed | ERROR | [Transaction](#transaction-errors) |
| DB004 | Connection pool exhausted | WARNING | [Database](#database-errors) |
| SEC001 | SQL injection attempt | CRITICAL | [Security](#security-incidents) |
| SEC002 | XSS attempt detected | CRITICAL | [Security](#security-incidents) |
| VAL001 | Data validation failed | WARNING | [Validation](#validation-errors) |
| SYS001 | Internal error | ERROR | [System](#system-errors) |

---

## Database Errors

### DB001: Database Connection Failed

**Error Message:**
```
[DB001] CRITICAL: Falha na conexão com o banco de dados
Could not connect to server: Connection refused
```

**Possible Causes:**
1. Database server is down
2. Incorrect credentials
3. Network/firewall blocking connection
4. SSL certificate issues

**Solutions:**

**1. Verify database server is running:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Or for Docker
docker ps | grep postgres

# Or for Railway
railway status
```

**2. Test connection manually:**
```bash
psql -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE

# If SSL error, try:
psql "postgresql://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE?sslmode=require"
```

**3. Check environment variables:**
```r
# In R console
Sys.getenv("PGHOST")    # Should not be empty
Sys.getenv("PGPORT")    # Usually 5432
Sys.getenv("PGUSER")    # Your database user
Sys.getenv("PGPASSWORD") # Should not be empty
```

**4. Verify firewall rules:**
```bash
# Test port connectivity
telnet $PGHOST $PGPORT
nc -zv $PGHOST $PGPORT

# Check if PostgreSQL is listening
netstat -tlnp | grep 5432
```

**5. Check PostgreSQL logs:**
```bash
# Ubuntu/Debian
sudo tail -f /var/log/postgresql/postgresql-12-main.log

# Docker
docker logs postgres-container
```

**Quick Fix:**
```r
# Restart connection pool
if (exists("db_pool")) {
  pool::poolClose(db_pool)
}
db_pool <- pool::dbPool(
  RPostgres::Postgres(),
  host = Sys.getenv("PGHOST"),
  port = as.integer(Sys.getenv("PGPORT", "5432")),
  dbname = Sys.getenv("PGDATABASE"),
  user = Sys.getenv("PGUSER"),
  password = Sys.getenv("PGPASSWORD")
)
```

---

### DB002: Query Execution Failed

**Error Message:**
```
[DB002] ERROR: Falha na execução da consulta
ERROR: column "titulo" does not exist
```

**Possible Causes:**
1. Table schema mismatch
2. Missing indexes
3. SQL syntax error
4. Insufficient permissions

**Solutions:**

**1. Verify table schema:**
```sql
\d documentos_legislativos

-- Expected columns: id, titulo, tipo, data, estado, conteudo
```

**2. Check for missing columns:**
```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'documentos_legislativos'
ORDER BY ordinal_position;
```

**3. Verify user permissions:**
```sql
SELECT grantee, privilege_type
FROM information_schema.table_privileges
WHERE table_name = 'documentos_legislativos'
  AND grantee = 'monitor_user';
```

**4. Test query isolation:**
```r
# Test query directly
result <- tryCatch({
  DBI::dbGetQuery(db_pool, "SELECT titulo FROM documentos_legislativos LIMIT 1")
}, error = function(e) {
  cat("Query failed:", e$message, "\n")
  NULL
})
```

---

### DB004: Connection Pool Exhausted

**Error Message:**
```
[DB004] WARNING: Pool de conexões esgotado
Timed out waiting for connection
```

**Possible Causes:**
1. Too many concurrent users
2. Connections not being released
3. Long-running queries blocking pool
4. Pool size too small

**Solutions:**

**1. Check pool statistics:**
```r
# Get current pool status
pool_info <- pool::dbGetInfo(db_pool)
cat("Free connections:", pool_info$free, "\n")
cat("Taken connections:", pool_info$taken, "\n")
cat("Total connections:", pool_info$free + pool_info$taken, "\n")
```

**2. Identify long-running queries:**
```sql
SELECT pid, usename, state, query, now() - query_start AS duration
FROM pg_stat_activity
WHERE state != 'idle'
  AND query NOT LIKE '%pg_stat_activity%'
ORDER BY duration DESC;
```

**3. Increase pool size (if resources allow):**
```r
# Recreate pool with larger size
pool::poolClose(db_pool)
db_pool <- pool::dbPool(
  RPostgres::Postgres(),
  # ... connection parameters ...
  minSize = 5,   # Increased from 2
  maxSize = 20   # Increased from 10
)
```

**4. Add connection timeout:**
```r
db_pool <- pool::dbPool(
  # ... parameters ...
  idleTimeout = 300000,  # 5 minutes
  validationInterval = 60000  # 1 minute
)
```

**5. Force close idle connections:**
```sql
-- Kill idle connections older than 5 minutes
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
  AND state_change < now() - interval '5 minutes'
  AND pid != pg_backend_pid();
```

---

## Transaction Errors

### DB003: Transaction Failed

**Error Message:**
```
[DB003] ERROR: Falha na transação do banco de dados
Transaction TXN-20251121103000-5432 failed: deadlock detected
```

**Possible Causes:**
1. Deadlock between transactions
2. Constraint violation (unique, foreign key)
3. Serialization failure
4. Disk full

**Solutions:**

**1. Check for deadlocks:**
```sql
-- Enable deadlock logging
ALTER SYSTEM SET deadlock_timeout = '1s';
ALTER SYSTEM SET log_lock_waits = on;
SELECT pg_reload_conf();

-- View locks
SELECT locktype, database, relation::regclass, page, tuple, transactionid, pid, mode, granted
FROM pg_locks
WHERE NOT granted;
```

**2. Review transaction isolation level:**
```r
# Use lower isolation level if appropriate
result <- execute_in_transaction(db_pool, function(conn) {
  # ... operations ...
}, isolation_level = "READ COMMITTED")  # Instead of SERIALIZABLE
```

**3. Implement retry logic:**
```r
# Retry transaction with exponential backoff
retry_transaction <- function(operation, max_attempts = 3) {
  for (attempt in 1:max_attempts) {
    result <- tryCatch({
      execute_in_transaction(db_pool, operation, log_transactions = FALSE)
    }, error = function(e) {
      if (attempt == max_attempts) {
        stop("Transaction failed after ", max_attempts, " attempts: ", e$message)
      }
      wait_time <- 2^attempt  # Exponential backoff: 2s, 4s, 8s
      cat("Transaction attempt", attempt, "failed, retrying in", wait_time, "seconds...\n")
      Sys.sleep(wait_time)
      NULL
    })

    if (!is.null(result)) {
      return(result)
    }
  }
}
```

**4. Check constraint violations:**
```sql
-- View violated constraints
SELECT conname, contype, conrelid::regclass
FROM pg_constraint
WHERE conrelid = 'documentos_legislativos'::regclass;
```

---

## Security Incidents

### SEC001: SQL Injection Attempt

**Error Message:**
```
[SEC001] CRITICAL: Tentativa de SQL injection detectada
Input: '; DROP TABLE users; --
```

**Immediate Actions:**

**1. Incident logged automatically** in audit log

**2. Verify no damage occurred:**
```sql
-- Check all tables still exist
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- Verify row counts
SELECT 'documentos_legislativos' as table_name, COUNT(*) as row_count FROM documentos_legislativos;
```

**3. Review access logs:**
```r
# Check who made the attempt (if audit logging enabled)
source("R/security/audit_logging.R")
recent_security_events <- get_audit_logs(
  action = "sql_injection_attempt",
  hours = 1
)
```

**4. Block offending IP (if repeated attempts):**
```nginx
# Add to Nginx configuration
deny 192.168.1.100;
```

**5. Notify security team:**
```r
# If incident escalation configured
source("R/security/incident_response.R")
notify_security_incident(
  type = "sql_injection",
  severity = "CRITICAL",
  details = list(ip = request_ip, payload = blocked_input)
)
```

**Prevention Verification:**

```r
# Verify all queries use parameterization
test_queries <- c(
  "'; DROP TABLE users; --",
  "1' OR '1'='1",
  "admin'--"
)

for (payload in test_queries) {
  result <- tryCatch({
    # This should be safely handled
    cached_query(
      db_pool,
      "SELECT * FROM documentos_legislativos WHERE titulo = $1 LIMIT 1",
      params = list(payload)
    )
  }, error = function(e) {
    cat("✅ Injection blocked:", e$message, "\n")
  })
}
```

---

### SEC002: XSS Attempt Detected

**Error Message:**
```
[SEC002] CRITICAL: Tentativa de XSS detectada
Input: <script>alert('xss')</script>
```

**Immediate Actions:**

**1. Verify input sanitization:**
```r
# Check if XSS payload is being escaped
test_xss <- "<script>alert('test')</script>"
sanitized <- validate_search_term(test_xss)

if (sanitized$valid) {
  cat("⚠️ XSS VULNERABILITY - payload not blocked!\n")
} else {
  cat("✅ XSS blocked:", sanitized$error, "\n")
}
```

**2. Check Content-Security-Policy:**
```bash
curl -I https://your-app.com/ | grep Content-Security-Policy
# Should include: script-src 'self'
```

**3. Review recent outputs:**
```r
# Check if any XSS made it to outputs
grep -r "<script" /var/log/shiny-server/*.log
```

**Prevention:**
- All user inputs are validated BEFORE use
- HTML outputs use `htmltools::htmlEscape()`
- CSP headers prevent inline scripts

---

## Validation Errors

### VAL001: Data Validation Failed

**Error Message:**
```
[VAL001] WARNING: Validação de dados falhou
Field 'search_term' contains invalid characters
```

**Common Scenarios:**

**Scenario 1: Special characters in search**
```r
# Input: "test & development @ 2024"
# Solution: URL encode special characters
search_term <- URLencode("test & development @ 2024")
```

**Scenario 2: Date format mismatch**
```r
# Input: "21/11/2025" (DD/MM/YYYY)
# Expected: "2025-11-21" (YYYY-MM-DD)
date_str <- "21/11/2025"
formatted_date <- format(as.Date(date_str, "%d/%m/%Y"), "%Y-%m-%d")
```

**Scenario 3: Numeric range violation**
```r
# Input: limit = -1 (invalid)
# Solution: Enforce bounds
limit <- max(1, min(as.integer(input$limit), 10000))
```

---

## System Errors

### Memory Issues

**Symptoms:**
```
Memory usage critical: 95.2%
R session may become unstable
```

**Diagnosis:**
```r
# Check current memory
pryr::mem_used()  # Current R session memory

# Check system memory
system("free -h", intern = TRUE)

# Identify memory hogs
lobstr::obj_sizes(ls())
```

**Solutions:**

**1. Force garbage collection:**
```r
gc(verbose = TRUE)
rm(list = ls()[!(ls() %in% c("db_pool"))])  # Keep pool
gc()
```

**2. Reduce cache size:**
```r
# Clear query cache
if (exists(".query_cache", envir = .GlobalEnv)) {
  cache_env <- get(".query_cache", envir = .GlobalEnv)
  rm(list = ls(cache_env), envir = cache_env)
}
```

**3. Restart application:**
```bash
# Railway
railway restart

# Docker
docker restart monitor-legislativo

# Shiny Server
sudo systemctl restart shiny-server
```

**4. Increase memory limit:**
```r
# Set in .Renviron
R_MAX_VSIZE=8G  # 8GB limit
```

---

### Performance Issues

**Symptom:** Slow page load (> 5 seconds)

**Diagnosis:**

**1. Enable profiling:**
```r
# Profile a specific operation
profvis::profvis({
  library_data <- cached_query(
    db_pool,
    "SELECT * FROM documentos_legislativos LIMIT 1000"
  )
})
```

**2. Check database performance:**
```sql
-- Find slowest queries
SELECT mean_exec_time, query
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

**3. Check network latency:**
```bash
# Measure database latency
time psql -h $PGHOST -U $PGUSER -d $PGDATABASE -c "SELECT 1"
```

**Solutions:**

**1. Add indexes:**
```sql
-- Create indexes on frequently queried columns
CREATE INDEX idx_docs_titulo_gin ON documentos_legislativos USING gin(to_tsvector('portuguese', titulo));
CREATE INDEX idx_docs_tipo ON documentos_legislativos(tipo);
CREATE INDEX idx_docs_data_desc ON documentos_legislativos(data DESC);
```

**2. Optimize queries:**
```r
# Before: Loading all columns
query <- "SELECT * FROM documentos_legislativos"

# After: Only necessary columns
query <- "SELECT id, titulo, tipo, data FROM documentos_legislativos"
```

**3. Increase cache TTL:**
```r
# Longer cache for expensive queries
CACHE_TTL <- list(
  search = 600,      # 10 minutes (was 300)
  dashboard = 1800   # 30 minutes (was 900)
)
```

**4. Use lazy loading:**
```r
# Load data on demand, not on startup
library_data <- reactive({
  req(input$apply_filters)  # Only load when button clicked
  # ... query logic
})
```

---

## Health Check Issues

### Health Check Returning "unhealthy"

**Full Diagnosis Script:**

```r
source("R/monitoring/health_check.R")

# Detailed health check
health <- perform_health_check(db_pool, detailed = TRUE)

# Check each component
cat("\n=== HEALTH CHECK RESULTS ===\n")
cat("Overall Status:", health$status, "\n\n")

cat("Database:\n")
cat("  Status:", health$checks$database$status, "\n")
cat("  Message:", health$checks$database$message, "\n")
if (!is.null(health$checks$database$query_time_ms)) {
  cat("  Query Time:", health$checks$database$query_time_ms, "ms\n")
}

cat("\nMemory:\n")
cat("  Status:", health$checks$memory$status, "\n")
cat("  Used:", health$checks$memory$memory_used_mb, "MB\n")
if (!is.null(health$checks$memory$usage_percent)) {
  cat("  Usage:", health$checks$memory$usage_percent, "%\n")
}

cat("\nSession:\n")
cat("  Status:", health$checks$session$status, "\n")
cat("  R Version:", health$checks$session$r_version, "\n")

# Get active alerts
alerts <- get_active_alerts(db_pool)
if (length(alerts) > 0) {
  cat("\n=== ACTIVE ALERTS ===\n")
  for (alert in alerts) {
    cat(sprintf("[%s] %s: %s\n",
      toupper(alert$severity),
      alert$component,
      alert$message))
  }
}
```

**Common Fixes:**

**If database unhealthy:**
```r
# Test database manually
DBI::dbGetQuery(db_pool, "SELECT 1 as test")
```

**If memory critical:**
```r
gc()
# Or restart application
```

**If disk full:**
```bash
df -h
# Clean up old logs
find /var/log -name "*.log" -mtime +30 -delete
```

---

## Error Code Reference

### Full Error Code Catalog

```r
# Load error codes
source("R/utils/error_handling.R")

# Display all error codes
for (error_name in names(ERROR_CODES)) {
  error <- ERROR_CODES[[error_name]]
  cat(sprintf("\n%s (%s - %s)\n",
    error_name,
    error$code,
    error$severity))
  cat("  Message:", error$message, "\n")
  cat("  User Message:", error$user_message, "\n")
}
```

---

## Emergency Procedures

### Complete Application Reset

**WARNING: This will clear all caches and restart connections**

```r
# 1. Clear caches
if (exists(".query_cache", envir = .GlobalEnv)) {
  rm(".query_cache", envir = .GlobalEnv)
}
if (exists(".app_metrics", envir = .GlobalEnv)) {
  rm(".app_metrics", envir = .GlobalEnv)
}

# 2. Close database pool
if (exists("db_pool")) {
  pool::poolClose(db_pool)
}

# 3. Force garbage collection
gc(full = TRUE)

# 4. Restart Shiny session
session$reload()
```

### Database Recovery

**If database is corrupted:**

```bash
# 1. Stop application
railway stop  # or docker stop / systemctl stop

# 2. Backup current database
pg_dump -h $PGHOST -U $PGUSER $PGDATABASE > backup_$(date +%Y%m%d_%H%M%S).sql

# 3. Restore from last good backup
pg_restore -h $PGHOST -U $PGUSER -d $PGDATABASE backup_20251120.dump

# 4. Verify integrity
psql -h $PGHOST -U $PGUSER -d $PGDATABASE -c "SELECT COUNT(*) FROM documentos_legislativos"

# 5. Restart application
railway start  # or docker start / systemctl start
```

---

## Support Contacts

### Escalation Path

1. **Level 1**: Check this troubleshooting guide
2. **Level 2**: Review logs and error codes
3. **Level 3**: Contact technical support: support@mackenzie.br
4. **Level 4**: Security incidents: security@mackenzie.br
5. **Level 5**: LGPD/Privacy: dpo@mackenzie.br

### Incident Report Template

```markdown
**Incident Report**

Date/Time: [YYYY-MM-DD HH:MM UTC]
Severity: [CRITICAL / HIGH / MEDIUM / LOW]
Error Code: [e.g., DB001, SEC001]
Environment: [production / staging / development]

**Description:**
[What happened]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Error occurs]

**Impact:**
- Users affected: [number]
- Services down: [list]
- Data integrity: [OK / COMPROMISED]

**Actions Taken:**
1. [Action 1]
2. [Action 2]

**Current Status:** [RESOLVED / IN PROGRESS / MONITORING]

**Root Cause:** [If known]

**Prevention:** [Future steps]
```

---

**Last Updated:** 2025-11-21
**Document Version:** 4.0.0
