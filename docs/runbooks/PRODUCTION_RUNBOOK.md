# 🚨 LEGISLATIVE MONITOR V4 - PRODUCTION RUNBOOK

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Criticality**: PRODUCTION CRITICAL  
**On-Call Rotation**: 24/7 Coverage Required  

## 📋 TABLE OF CONTENTS

1. [Emergency Contacts](#emergency-contacts)
2. [System Overview](#system-overview)
3. [Critical Alerts](#critical-alerts)
4. [Incident Response Procedures](#incident-response-procedures)
5. [Common Issues & Solutions](#common-issues--solutions)
6. [Escalation Matrix](#escalation-matrix)
7. [Recovery Procedures](#recovery-procedures)
8. [Post-Incident Process](#post-incident-process)

---

## 🚨 EMERGENCY CONTACTS

### Primary On-Call
- **Phone**: [REDACTED] 
- **Slack**: #legislative-monitor-oncall
- **PagerDuty**: legislative-monitor-primary

### Escalation Path
1. **L1 - Primary On-Call**: Response within 5 minutes
2. **L2 - Secondary On-Call**: Response within 10 minutes
3. **L3 - Team Lead**: Response within 15 minutes
4. **L4 - Engineering Manager**: Response within 30 minutes
5. **L5 - CTO**: Response within 1 hour

### External Dependencies
- **AWS Support**: Premium Support Plan - Case Priority: CRITICAL
- **Government API Contacts**: 
  - Câmara: suporte@dadosabertos.camara.leg.br
  - Senado: dadosabertos@senado.leg.br
  - Planalto: Contact via official channels only

---

## 🏗️ SYSTEM OVERVIEW

### Architecture Components
```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   CloudFront    │────▶│  ALB/Nginx   │────▶│   FastAPI       │
│      (CDN)      │     │(Load Balancer)│     │   (API Layer)   │
└─────────────────┘     └──────────────┘     └─────────────────┘
                                                      │
                                ┌─────────────────────┴─────────────────────┐
                                │                                           │
                          ┌─────▼──────┐                            ┌──────▼──────┐
                          │   Redis     │                            │  PostgreSQL  │
                          │  (Cache)    │                            │  (Primary)   │
                          └─────────────┘                            └──────────────┘
                                                                            │
                                                                     ┌──────▼──────┐
                                                                     │  Read       │
                                                                     │  Replicas   │
                                                                     └─────────────┘
```

### Key Metrics Thresholds
- **API Response Time**: p50 < 100ms, p99 < 1s
- **Error Rate**: < 0.1%
- **Database Connections**: < 80% of pool
- **Memory Usage**: < 80% of allocated
- **CPU Usage**: < 70% sustained

### Health Check Endpoints
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe (includes dependencies)
- `/health/detailed` - Full system analysis

---

## 🚨 CRITICAL ALERTS

### P0 - IMMEDIATE ACTION REQUIRED (Page immediately)

#### 1. Complete Service Outage
**Alert**: `legislative_monitor_down`
```bash
# Immediate Actions:
1. Check CloudWatch dashboard
2. Verify ALB target health
3. Check ECS task status
4. Review recent deployments

# Quick Fix:
kubectl rollout undo deployment/api -n production
```

#### 2. Database Connection Exhaustion
**Alert**: `database_connections_critical`
```sql
-- Check active connections
SELECT count(*) FROM pg_stat_activity;

-- Kill idle connections
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'idle' 
AND state_change < current_timestamp - interval '10 minutes';
```

#### 3. Government API Complete Failure
**Alert**: `external_api_all_down`
```python
# Enable fallback mode
curl -X POST http://internal-api/admin/fallback/enable \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### P1 - URGENT (Respond within 15 minutes)

#### 4. High Error Rate (>5%)
**Alert**: `error_rate_high`
```bash
# Check error logs
kubectl logs -n production -l app=api --tail=1000 | grep ERROR

# Check circuit breaker status
curl http://internal-api/admin/circuit-breakers
```

#### 5. Cache Miss Rate >50%
**Alert**: `cache_performance_degraded`
```bash
# Check Redis status
redis-cli info stats
redis-cli --latency

# Warm cache if needed
python scripts/warm_cache.py --priority=critical
```

---

## 📋 INCIDENT RESPONSE PROCEDURES

### 🔥 PHASE 1: DETECTION & TRIAGE (0-5 minutes)

1. **Acknowledge Alert**
   ```bash
   # Via PagerDuty CLI
   pd acknowledge -i <incident_id>
   ```

2. **Initial Assessment**
   - Check primary dashboard: https://grafana.internal/d/legislative-monitor
   - Verify customer impact: https://status.legislative-monitor.gov.br
   - Check recent changes: https://deployments.internal/recent

3. **Severity Classification**
   - **SEV1**: Complete outage, data loss risk
   - **SEV2**: Partial outage, degraded performance
   - **SEV3**: Minor issues, no customer impact

### 🛠️ PHASE 2: MITIGATION (5-30 minutes)

#### For API Issues:
```bash
# 1. Scale up immediately
kubectl scale deployment api -n production --replicas=10

# 2. Enable rate limiting
curl -X POST http://internal-api/admin/rate-limit/emergency \
  -d '{"requests_per_minute": 100}'

# 3. Check for memory leaks
kubectl top pods -n production
```

#### For Database Issues:
```sql
-- 1. Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- 2. Kill long-running queries
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'active' 
AND query_start < current_timestamp - interval '5 minutes';

-- 3. Emergency connection limit
ALTER DATABASE legislative_monitor 
SET connection_limit = 50;
```

#### For External API Issues:
```python
# 1. Enable circuit breakers for all external APIs
for api in ['camara', 'senado', 'planalto']:
    requests.post(f'http://internal-api/admin/circuit-breaker/{api}/open')

# 2. Switch to cached-only mode
requests.post('http://internal-api/admin/mode/cached-only')

# 3. Alert users via status page
requests.post('https://status-api/incidents', json={
    'title': 'Limited data availability',
    'severity': 'partial_outage',
    'message': 'Operating on cached data due to government API issues'
})
```

### 🔍 PHASE 3: INVESTIGATION (Parallel with mitigation)

1. **Gather Evidence**
   ```bash
   # Create incident directory
   mkdir /tmp/incident-$(date +%Y%m%d-%H%M%S)
   cd /tmp/incident-*
   
   # Collect logs
   kubectl logs -n production -l app=api --since=1h > api.log
   kubectl logs -n production -l app=worker --since=1h > worker.log
   
   # Collect metrics
   curl http://prometheus:9090/api/v1/query_range?query=up > metrics.json
   
   # Database state
   psql -h $DB_HOST -U $DB_USER -d legislative_monitor \
     -c "\copy (SELECT * FROM pg_stat_activity) TO 'db_activity.csv' CSV HEADER"
   ```

2. **Identify Root Cause**
   - Check deployment timeline
   - Review recent PRs
   - Analyze error patterns
   - Check dependency status

### ✅ PHASE 4: RESOLUTION (30+ minutes)

1. **Implement Fix**
   - Create hotfix branch
   - Apply minimal change
   - Fast-track review
   - Deploy to staging first

2. **Verify Resolution**
   ```bash
   # Monitor key metrics
   watch -n 5 'curl -s http://internal-api/metrics | grep -E "(error_rate|response_time)"'
   
   # Check circuit breakers are closing
   curl http://internal-api/admin/circuit-breakers | jq '.[] | select(.state != "closed")'
   
   # Verify external APIs recovering
   for api in camara senado planalto; do
     echo "Checking $api..."
     curl -s http://internal-api/health/dependencies | jq ".${api}"
   done
   ```

---

## 🔧 COMMON ISSUES & SOLUTIONS

### Issue 1: "Too Many Connections" Database Error

**Symptoms**: 
- Error: `FATAL: remaining connection slots are reserved`
- Slow API responses
- Connection pool exhaustion alerts

**Root Cause**: Connection leak or thundering herd

**Solution**:
```bash
# 1. Immediate relief - restart specific pods
kubectl delete pod -n production -l app=api,version=old

# 2. Increase connection limit temporarily
psql -c "ALTER SYSTEM SET max_connections = 500;"
psql -c "SELECT pg_reload_conf();"

# 3. Fix connection leak
# Check for missing connection.close() in code
# Deploy fix with connection timeout:
DATABASE_URL="postgresql://...?connect_timeout=5&command_timeout=5"
```

### Issue 2: Redis Memory Full

**Symptoms**:
- Error: `OOM command not allowed when used memory > 'maxmemory'`
- Cache miss rate 100%
- API timeouts

**Solution**:
```bash
# 1. Emergency flush old keys
redis-cli --scan --pattern "cache:old:*" | xargs redis-cli DEL

# 2. Increase memory limit
aws elasticache modify-cache-cluster \
  --cache-cluster-id prod-redis \
  --cache-node-type cache.r6g.xlarge

# 3. Fix TTL settings
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### Issue 3: Government API Rate Limit

**Symptoms**:
- 429 errors from external APIs
- Circuit breakers opening frequently
- Incomplete search results

**Solution**:
```python
# 1. Reduce request rate
curl -X PUT http://internal-api/admin/config \
  -d '{"external_api_rate_limit": 10}'  # requests per second

# 2. Enable request coalescing
curl -X POST http://internal-api/admin/features/request-coalescing/enable

# 3. Implement exponential backoff
# Already in enhanced_circuit_breaker.py
```

### Issue 4: Memory Leak in API Pods

**Symptoms**:
- Gradual memory increase
- OOMKilled pods
- Response time degradation

**Solution**:
```bash
# 1. Emergency restart with memory limits
kubectl set resources deployment/api -n production \
  --limits=memory=2Gi --requests=memory=1Gi

# 2. Enable memory profiling
kubectl set env deployment/api -n production \
  PYTHONMALLOC=malloc MALLOC_TRIM_THRESHOLD_=100000

# 3. Schedule periodic restarts until fix
kubectl patch cronjob/api-restarter -n production \
  --patch '{"spec":{"schedule":"0 */6 * * *"}}'
```

### Issue 5: Deployment Failure

**Symptoms**:
- Health checks failing on new version
- Rollout stuck
- Mixed versions serving traffic

**Solution**:
```bash
# 1. Pause rollout
kubectl rollout pause deployment/api -n production

# 2. Check failing pods
kubectl describe pod -n production -l app=api,version=new

# 3. Rollback if needed
kubectl rollout undo deployment/api -n production

# 4. Fix and retry with canary
kubectl set image deployment/api-canary -n production \
  api=legislative-monitor:fixed-version
```

---

## 📊 ESCALATION MATRIX

| Time Elapsed | Severity | Action Required | Escalate To |
|--------------|----------|-----------------|-------------|
| 0-5 min | ALL | Acknowledge & Triage | Primary On-Call |
| 5-15 min | SEV1 | Implement Mitigation | Secondary On-Call |
| 15-30 min | SEV1 | No Progress | Team Lead + Manager |
| 30-60 min | SEV1 | Still Unresolved | Director + CTO |
| 60+ min | SEV1 | Major Outage | Executive Team |
| 0-30 min | SEV2 | Work on Fix | Primary On-Call |
| 30-60 min | SEV2 | Need Help | Team Lead |
| 0-2 hours | SEV3 | Monitor & Fix | Primary On-Call |

### Communication Requirements

**SEV1 - Complete Outage**:
- Status page update within 5 minutes
- Slack #incidents channel
- Email to stakeholders every 30 minutes
- Executive briefing if > 1 hour

**SEV2 - Partial Outage**:
- Status page update within 15 minutes  
- Slack #incidents channel
- Email to stakeholders every hour

**SEV3 - Minor Issue**:
- Slack #incidents channel
- Status page if customer visible

---

## 🔄 RECOVERY PROCEDURES

### 1. Full System Recovery (After Complete Outage)

```bash
#!/bin/bash
# recovery_sequence.sh

echo "Starting full system recovery..."

# 1. Verify infrastructure
echo "Checking infrastructure..."
aws rds describe-db-instances --db-instance-identifier prod-legislative
aws elasticache describe-cache-clusters
aws eks describe-cluster --name prod-cluster

# 2. Start core services
echo "Starting database..."
kubectl scale statefulset postgres -n production --replicas=1
kubectl wait --for=condition=ready pod -l app=postgres -n production

echo "Starting cache..."
kubectl scale deployment redis -n production --replicas=3
kubectl wait --for=condition=ready pod -l app=redis -n production

# 3. Start application layer
echo "Starting API (minimal)..."
kubectl scale deployment api -n production --replicas=2
kubectl wait --for=condition=ready pod -l app=api -n production

# 4. Verify health
echo "Checking health..."
curl http://api.legislative-monitor.internal/health/ready

# 5. Gradual scale up
echo "Scaling up..."
kubectl scale deployment api -n production --replicas=5
kubectl scale deployment worker -n production --replicas=3

# 6. Enable external traffic
echo "Enabling traffic..."
kubectl patch service api -n production \
  -p '{"spec":{"selector":{"app":"api","version":"stable"}}}'

# 7. Clear circuit breakers
curl -X POST http://internal-api/admin/circuit-breakers/reset-all

echo "Recovery complete!"
```

### 2. Database Recovery

```sql
-- 1. Check replication status
SELECT client_addr, state, sync_state, replay_lag 
FROM pg_stat_replication;

-- 2. Promote standby if needed
SELECT pg_promote();

-- 3. Rebuild indexes
REINDEX DATABASE legislative_monitor CONCURRENTLY;

-- 4. Update statistics
ANALYZE;

-- 5. Check data integrity
SELECT COUNT(*) FROM propositions;
SELECT MAX(created_at) FROM propositions;
```

### 3. Cache Recovery

```bash
# 1. Check Redis cluster health
redis-cli cluster info
redis-cli cluster nodes

# 2. Warm critical cache
python scripts/cache_warmer.py \
  --priority critical \
  --keys "search:*,propositions:recent:*"

# 3. Verify cache performance
redis-cli info stats | grep -E "(hits|misses)"
```

---

## 📝 POST-INCIDENT PROCESS

### Immediate (Within 2 hours)
1. **Update status page** - Mark incident as resolved
2. **All-clear message** - Notify stakeholders
3. **Preserve evidence** - Upload logs to S3

### Within 24 hours
1. **Create incident ticket** 
2. **Schedule post-mortem** (if SEV1 or SEV2)
3. **Update runbook** with new findings

### Within 48 hours
1. **Complete post-mortem document**
   - Timeline
   - Root cause
   - Impact assessment
   - Action items
2. **Share with team**
3. **Create follow-up tickets**

### Post-Mortem Template
```markdown
# Incident Post-Mortem: [INCIDENT-ID]

**Date**: [DATE]
**Duration**: [START] - [END]  
**Severity**: SEV[1-3]
**Author**: [NAME]

## Summary
[1-2 sentences describing what happened]

## Impact
- Customer impact: [#affected users, features impacted]
- Data impact: [any data loss or corruption]
- Revenue impact: [if applicable]

## Timeline
- HH:MM - Alert triggered
- HH:MM - On-call acknowledged  
- HH:MM - Initial mitigation applied
- HH:MM - Root cause identified
- HH:MM - Fix deployed
- HH:MM - Incident resolved

## Root Cause
[Detailed explanation of what caused the incident]

## Resolution
[How the incident was resolved]

## Lessons Learned
### What went well
- 
### What went poorly
- 
### Where we got lucky
-

## Action Items
| Action | Owner | Due Date | Ticket |
|--------|-------|----------|---------|
| | | | |

## Supporting Data
[Links to graphs, logs, etc.]
```

---

## 🛡️ PREVENTIVE MEASURES

### Daily Checks (Business Hours)
```bash
# Run daily health check
./scripts/daily_health_check.sh

# Check for warning signs
- Error rate trending up
- Response time increasing  
- Connection pool usage >60%
- Disk usage >70%
- Certificate expiration <30 days
```

### Weekly Tasks
1. Review performance dashboards
2. Check security alerts
3. Verify backup completion
4. Test monitoring alerts
5. Update dependencies

### Monthly Tasks  
1. Disaster recovery drill
2. Security scan
3. Performance load test
4. Runbook review
5. On-call rotation update

---

## 🔐 SECURITY INCIDENT ADDENDUM

### If Security Breach Suspected:
1. **DO NOT** attempt to fix alone
2. **IMMEDIATELY** contact Security Team
3. **PRESERVE** all evidence
4. **ISOLATE** affected systems
5. **DOCUMENT** everything

### Security Contacts
- Security Team: security@legislative-monitor
- CISO: [REDACTED]
- Legal: legal@legislative-monitor
- PR: communications@legislative-monitor

---

**Remember**: In production, slow is smooth, smooth is fast. Take a breath, follow the runbook, and ask for help when needed.

**This document is CONFIDENTIAL and for internal use only.**