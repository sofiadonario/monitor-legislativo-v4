# Incident Response Runbook
## Legislative Monitoring System V4

### Overview
This runbook provides step-by-step procedures for responding to incidents in the Legislative Monitoring System. Follow these procedures to quickly diagnose, contain, and resolve issues.

---

## Incident Classification

### Severity Levels

#### Critical (P0)
- System completely down
- Data corruption or loss
- Security breach
- **Response Time**: Immediate (< 15 minutes)
- **Notification**: All stakeholders

#### High (P1)
- Major functionality unavailable
- Performance severely degraded
- External API completely down
- **Response Time**: < 1 hour
- **Notification**: Technical team + management

#### Medium (P2)
- Minor functionality issues
- Performance issues affecting some users
- Non-critical service degradation
- **Response Time**: < 4 hours
- **Notification**: Technical team

#### Low (P3)
- Cosmetic issues
- Non-urgent improvements
- Documentation issues
- **Response Time**: < 24 hours
- **Notification**: Development team

---

## General Incident Response Process

### 1. Detection and Alert
```
┌─ Alert Received ─┐
│                  │
│ 1. Acknowledge   │
│ 2. Assess        │
│ 3. Classify      │
│ 4. Notify        │
└─────────────────┘
```

**Actions:**
1. **Acknowledge** the alert in monitoring system
2. **Assess** the situation using dashboards
3. **Classify** severity level (P0-P3)
4. **Notify** appropriate stakeholders

### 2. Initial Response (First 15 minutes)
- [ ] Check system status dashboard
- [ ] Verify alert is not false positive
- [ ] Create incident ticket
- [ ] Assemble response team
- [ ] Begin initial investigation

### 3. Investigation and Diagnosis
- [ ] Review logs and metrics
- [ ] Check recent deployments
- [ ] Verify external dependencies
- [ ] Identify root cause
- [ ] Document findings

### 4. Resolution and Recovery
- [ ] Implement fix or workaround
- [ ] Verify system functionality
- [ ] Monitor for stability
- [ ] Update stakeholders
- [ ] Document resolution

### 5. Post-Incident Review
- [ ] Conduct blameless post-mortem
- [ ] Update documentation
- [ ] Implement preventive measures
- [ ] Share lessons learned

---

## Quick Reference Commands

### System Health Check
```bash
# Check all services
docker-compose ps

# Check service logs
docker-compose logs -f web
docker-compose logs -f worker

# Check system resources
docker stats

# Health check endpoint
curl http://localhost:5000/api/health
```

### Database Issues
```bash
# Check database connectivity
docker-compose exec db psql -U postgres -d legislativo -c "SELECT 1;"

# Check database performance
docker-compose exec db psql -U postgres -d legislativo -c "
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY total_time DESC LIMIT 10;"

# Check database size
docker-compose exec db psql -U postgres -d legislativo -c "
SELECT pg_size_pretty(pg_database_size('legislativo'));"
```

### Cache Issues
```bash
# Check Redis connectivity
docker-compose exec redis redis-cli ping

# Check Redis memory usage
docker-compose exec redis redis-cli info memory

# Clear cache (use with caution)
docker-compose exec redis redis-cli flushall
```

---

## Specific Incident Scenarios

### Scenario 1: Application Down (P0)

#### Symptoms
- Health check endpoint returns 503
- Users cannot access the application
- High error rate in logs

#### Investigation Steps
1. **Check service status**
   ```bash
   docker-compose ps
   curl -f http://localhost:5000/api/health || echo "Health check failed"
   ```

2. **Review application logs**
   ```bash
   docker-compose logs --tail=100 web
   docker-compose logs --tail=100 worker
   ```

3. **Check resource usage**
   ```bash
   docker stats --no-stream
   df -h
   free -h
   ```

#### Common Causes & Solutions

**Database Connection Issues**
```bash
# Check database connectivity
docker-compose exec web python -c "
from core.models import db
try:
    db.engine.execute('SELECT 1')
    print('Database OK')
except Exception as e:
    print(f'Database Error: {e}')
"
```

**Out of Memory**
```bash
# Check memory usage
free -h
# Restart services if needed
docker-compose restart web worker
```

**Configuration Issues**
```bash
# Check environment variables
docker-compose exec web printenv | grep -E "(DATABASE|REDIS|API_KEY)"
```

#### Resolution Steps
1. **Restart services**
   ```bash
   docker-compose restart web worker
   ```

2. **Scale up if needed**
   ```bash
   docker-compose up -d --scale web=3
   ```

3. **Verify recovery**
   ```bash
   curl http://localhost:5000/api/health
   ```

### Scenario 2: High Response Times (P1)

#### Symptoms
- API response times > 2 seconds
- User complaints about slow performance
- High CPU/memory usage

#### Investigation Steps
1. **Check performance metrics**
   - Open Grafana dashboard
   - Review response time graphs
   - Check resource utilization

2. **Identify bottlenecks**
   ```bash
   # Check slow queries
   docker-compose exec db psql -U postgres -d legislativo -c "
   SELECT query, calls, total_time, mean_time 
   FROM pg_stat_statements 
   WHERE mean_time > 1000 
   ORDER BY total_time DESC;"
   ```

3. **Check external API status**
   ```bash
   # Test external APIs
   curl -w "%{time_total}\n" -o /dev/null -s https://dadosabertos.camara.leg.br/api/v2
   curl -w "%{time_total}\n" -o /dev/null -s https://legis.senado.leg.br/dadosabertos
   ```

#### Resolution Steps
1. **Enable caching** (if not already)
2. **Optimize database queries**
3. **Scale application** if needed
4. **Review external API usage**

### Scenario 3: External API Failures (P1)

#### Symptoms
- Circuit breakers open
- External API errors in logs
- Partial functionality loss

#### Investigation Steps
1. **Check circuit breaker status**
   ```bash
   curl http://localhost:5000/api/metrics | jq '.circuit_breakers'
   ```

2. **Test external APIs directly**
   ```bash
   # Test Camara API
   curl -i https://dadosabertos.camara.leg.br/api/v2/proposicoes?pagina=1&itens=1
   
   # Test Senado API
   curl -i https://legis.senado.leg.br/dadosabertos/materia/pesquisa/lista
   ```

3. **Check API documentation** for service announcements

#### Resolution Steps
1. **Verify API status** on provider websites
2. **Adjust circuit breaker settings** if temporary issue
3. **Implement fallback mechanisms**
4. **Notify users** of limited functionality

### Scenario 4: Database Issues (P0/P1)

#### Symptoms
- Database connection errors
- Slow queries
- Lock timeouts

#### Investigation Steps
1. **Check database status**
   ```bash
   docker-compose exec db pg_isready -U postgres
   ```

2. **Check for locks**
   ```bash
   docker-compose exec db psql -U postgres -d legislativo -c "
   SELECT blocked_locks.pid AS blocked_pid,
          blocked_activity.usename AS blocked_user,
          blocking_locks.pid AS blocking_pid,
          blocking_activity.usename AS blocking_user,
          blocked_activity.query AS blocked_statement,
          blocking_activity.query AS current_statement_in_blocking_process
   FROM pg_catalog.pg_locks blocked_locks
   JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
   JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
   JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
   WHERE NOT blocked_locks.granted;"
   ```

3. **Check disk space**
   ```bash
   docker-compose exec db df -h /var/lib/postgresql/data
   ```

#### Resolution Steps
1. **Kill long-running queries** if needed
2. **Restart database** if corrupted
3. **Restore from backup** if data loss

### Scenario 5: Security Incident (P0)

#### Symptoms
- Unusual access patterns
- Security alerts triggered
- Suspicious log entries

#### Immediate Actions
1. **Isolate affected systems**
   ```bash
   # Stop external access
   docker-compose stop nginx
   ```

2. **Preserve evidence**
   ```bash
   # Copy logs
   docker-compose logs > incident_logs_$(date +%Y%m%d_%H%M%S).txt
   ```

3. **Notify security team**
4. **Begin forensic investigation**

---

## Monitoring and Alerting

### Key Metrics to Monitor
- Response time (95th percentile)
- Error rate
- System availability
- Resource utilization
- External API status

### Alert Thresholds
```yaml
Critical Alerts:
  - System down (health check fails)
  - Error rate > 5%
  - Response time > 5 seconds
  - Disk space < 10%

Warning Alerts:
  - Error rate > 1%
  - Response time > 2 seconds
  - CPU usage > 80%
  - Memory usage > 85%
```

### Alert Channels
- **Critical**: SMS + Email + Slack
- **Warning**: Email + Slack
- **Info**: Slack only

---

## Communication Templates

### Initial Incident Notification
```
INCIDENT ALERT - [SEVERITY]

System: Legislative Monitoring System
Time: [TIMESTAMP]
Severity: [P0/P1/P2/P3]
Summary: [Brief description]
Impact: [User/system impact]
Status: Investigating

Incident Commander: [NAME]
Next Update: [TIME]
```

### Status Update
```
INCIDENT UPDATE - [INCIDENT_ID]

Summary: [Current status]
Actions Taken: [What's been done]
Next Steps: [What's planned]
ETA: [Estimated resolution time]
Next Update: [TIME]
```

### Resolution Notification
```
INCIDENT RESOLVED - [INCIDENT_ID]

Summary: [What happened]
Resolution: [How it was fixed]
Duration: [Total time]
Prevention: [Steps to prevent recurrence]

Post-mortem: [Date/time]
```

---

## Contact Information

### On-Call Rotation
| Day | Primary | Secondary |
|-----|---------|-----------|
| Mon | DevOps Lead | Senior Dev 1 |
| Tue | Senior Dev 1 | DevOps Lead |
| Wed | Senior Dev 2 | QA Lead |
| Thu | QA Lead | Senior Dev 2 |
| Fri | DevOps Lead | Senior Dev 1 |
| Sat | On-call rotation | |
| Sun | On-call rotation | |

### Escalation Contacts
- **Technical Lead**: +55 11 99999-1111
- **Product Manager**: +55 11 99999-2222
- **Infrastructure Team**: +55 11 99999-3333
- **Security Team**: +55 11 99999-4444

### External Contacts
- **Cloud Provider Support**: [Support ticket system]
- **Database Support**: [Vendor contact]
- **Network Operations**: [NOC contact]

---

## Tools and Resources

### Monitoring Dashboards
- **Grafana**: http://monitoring.legislativo.gov.br:3000
- **Prometheus**: http://monitoring.legislativo.gov.br:9090
- **Logs**: http://logs.legislativo.gov.br

### Documentation
- **System Architecture**: /docs/architecture/
- **API Documentation**: /docs/api/
- **Deployment Guide**: /docs/deployment/

### Recovery Tools
```bash
# Backup and restore scripts
/scripts/backup_database.sh
/scripts/restore_database.sh

# Health check scripts
/scripts/health_check.sh
/scripts/performance_check.sh
```

---

## Post-Incident Checklist

### Immediate (< 1 hour after resolution)
- [ ] Verify system stability
- [ ] Update stakeholders
- [ ] Document timeline
- [ ] Close incident ticket

### Short-term (< 24 hours)
- [ ] Schedule post-mortem meeting
- [ ] Prepare incident report
- [ ] Review monitoring/alerting
- [ ] Update runbooks if needed

### Long-term (< 1 week)
- [ ] Implement preventive measures
- [ ] Update documentation
- [ ] Share lessons learned
- [ ] Review incident response process

---

## Revision History

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-01-30 | 1.0 | Initial version | DevOps Team |