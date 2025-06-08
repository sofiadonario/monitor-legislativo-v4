# 🔒 SECURITY RUNBOOK - Legislative Monitor v4

**Classification**: CONFIDENTIAL  
**Version**: 1.0.0  
**Last Updated**: January 6, 2025  
**Next Review**: January 13, 2025  

## 🚨 EMERGENCY CONTACTS

| Role | Primary | Secondary | Escalation |
|------|---------|-----------|------------|
| **Security Lead** | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | CTO |
| **On-Call Engineer** | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | DevOps Lead |
| **Incident Commander** | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | VP Engineering |

## 📋 INCIDENT CLASSIFICATION

### P0 - CRITICAL (Immediate Response)
- **Data breach or unauthorized access**
- **System compromise with active attacker**
- **Key cryptographic compromise**
- **Complete service outage due to security**

### P1 - HIGH (15 minute response)
- **Multiple authentication failures indicating brute force**
- **Successful privilege escalation**
- **Malware detection**
- **DDoS attack in progress**

### P2 - MEDIUM (1 hour response)
- **Suspicious access patterns**
- **Rate limiting being exceeded**
- **Failed injection attempts**
- **Abnormal data access patterns**

### P3 - LOW (4 hour response)
- **Minor security violations**
- **Policy violations**
- **Configuration drift**
- **Non-critical monitoring alerts**

---

## 🔍 DETECTION AND MONITORING

### Security Event Sources
- **Security Monitor**: `core/monitoring/security_monitor.py`
- **Rate Limiter**: Real-time blocking and alerting
- **Authentication System**: Failed logins, token revocation
- **Input Validation**: Injection attempt detection
- **Infrastructure**: WAF, IDS/IPS, SIEM

### Alert Channels
- **Critical**: PagerDuty + SMS + Phone
- **High**: Slack #security-alerts + Email
- **Medium**: Email + Slack
- **Low**: Daily digest email

### Key Metrics to Monitor

```python
# Security Dashboard Metrics
security_events_per_minute > 100     # Possible attack
failed_auth_rate > 10%               # Credential stuffing
rate_limit_blocks > 1000/hour        # DDoS attempt
blocked_ips_count > 500              # Distributed attack
new_user_registrations > 50/hour     # Account creation abuse
data_export_volume > 10GB/hour       # Data exfiltration
geo_anomaly_score > 8.0              # Geographic anomaly
risk_score_average > 7.0             # Overall threat level
```

---

## 🚨 INCIDENT RESPONSE PROCEDURES

### STEP 1: INITIAL RESPONSE (0-5 minutes)

#### For P0/P1 Incidents:

1. **IMMEDIATE ACTIONS**:
   ```bash
   # Check security status
   kubectl exec -it security-monitor -- python -c "
   from core.monitoring.security_monitor import get_security_monitor
   monitor = get_security_monitor()
   print(monitor.get_stats())
   "
   
   # Check for active attacks
   grep "CRITICAL\|EMERGENCY" /var/log/security/security.log | tail -50
   
   # Check blocked entities
   redis-cli keys "blacklist:*" | wc -l
   ```

2. **THREAT ASSESSMENT**:
   - Determine attack vector and scope
   - Identify compromised systems/accounts
   - Assess data at risk
   - Estimate impact and urgency

3. **CONTAINMENT** (if confirmed attack):
   ```python
   # Emergency IP blocking
   from core.security.rate_limiter import get_rate_limiter
   limiter = get_rate_limiter()
   limiter.add_to_blacklist(ip_address="ATTACKER_IP")
   
   # Emergency user blocking
   from core.auth.models import User
   user = session.query(User).filter_by(id="COMPROMISED_USER").first()
   user.is_locked = True
   user.lock_reason = "Security incident"
   session.commit()
   
   # Revoke all tokens for user
   from core.auth.jwt_manager import jwt_manager
   jwt_manager.revoke_all_user_tokens("COMPROMISED_USER")
   ```

### STEP 2: INVESTIGATION (5-30 minutes)

#### Evidence Collection:

1. **System Logs**:
   ```bash
   # Security events
   tail -1000 /var/log/security/security.log > incident_${INCIDENT_ID}_security.log
   
   # Application logs
   kubectl logs deployment/api --since=1h > incident_${INCIDENT_ID}_api.log
   
   # Database audit logs
   psql -c "SELECT * FROM security_events WHERE timestamp > NOW() - INTERVAL '1 hour';" \
        > incident_${INCIDENT_ID}_db.log
   ```

2. **Network Analysis**:
   ```bash
   # Check current connections
   netstat -an | grep :443 | head -50
   
   # Check for suspicious IPs
   grep "blocked" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -nr
   
   # GeoIP analysis
   python3 -c "
   import geoip2.database
   with geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
       response = reader.city('SUSPICIOUS_IP')
       print(f'Country: {response.country.name}')
       print(f'City: {response.city.name}')
   "
   ```

3. **Data Access Audit**:
   ```sql
   -- Check for data access anomalies
   SELECT user_id, COUNT(*), AVG(search_time_ms)
   FROM search_logs 
   WHERE timestamp > NOW() - INTERVAL '1 hour'
   GROUP BY user_id 
   HAVING COUNT(*) > 100;
   
   -- Check for bulk exports
   SELECT user_id, endpoint, COUNT(*)
   FROM security_events 
   WHERE event_type = 'data.bulk_export' 
   AND timestamp > NOW() - INTERVAL '6 hours'
   GROUP BY user_id, endpoint;
   ```

### STEP 3: ERADICATION (30 minutes - 2 hours)

#### Remove Threats:

1. **Malware/Backdoors**:
   ```bash
   # Scan for suspicious files
   find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|exec" {} \;
   
   # Check for unauthorized cron jobs
   crontab -l -u www-data
   
   # Verify file integrity
   debsums -c
   ```

2. **Compromised Accounts**:
   ```python
   # Force password reset for all users
   from core.auth.models import User
   users = session.query(User).filter_by(is_active=True).all()
   for user in users:
       user.force_password_reset = True
       user.password_reset_token = secrets.token_urlsafe(32)
   session.commit()
   
   # Invalidate all active sessions
   from core.auth.jwt_manager import jwt_manager
   jwt_manager.revoke_all_tokens()
   ```

3. **System Hardening**:
   ```bash
   # Update security rules
   kubectl apply -f k8s/security/network-policies.yaml
   
   # Rotate API keys
   python3 -c "
   from core.security.secrets_manager import get_secrets_manager
   manager = get_secrets_manager()
   manager.rotate_all_api_keys()
   "
   
   # Update WAF rules
   curl -X POST https://waf-api/rules \
        -H "Authorization: Bearer $WAF_TOKEN" \
        -d '{"rule": "block_suspicious_patterns", "enabled": true}'
   ```

### STEP 4: RECOVERY (2-8 hours)

#### Service Restoration:

1. **System Verification**:
   ```bash
   # Run security scans
   nmap -sS -O localhost
   nikto -h https://api.legislativo.com
   
   # Verify certificates
   openssl s_client -connect api.legislativo.com:443 -servername api.legislativo.com
   
   # Check database integrity
   python3 -c "
   from core.database.models import Base, engine
   from sqlalchemy import inspect
   inspector = inspect(engine)
   print('Tables:', inspector.get_table_names())
   "
   ```

2. **Gradual Service Restoration**:
   ```bash
   # Start with limited traffic
   kubectl scale deployment/api --replicas=1
   
   # Monitor for 30 minutes, then scale up
   kubectl scale deployment/api --replicas=3
   
   # Full restoration
   kubectl scale deployment/api --replicas=5
   ```

3. **User Communication**:
   ```python
   # Send security notification
   from core.utils.notifications import send_security_notification
   send_security_notification(
       template="security_incident_resolved",
       users=affected_users,
       details={
           "incident_id": incident_id,
           "resolution_time": datetime.now(),
           "actions_taken": ["password_reset", "token_revocation"]
       }
   )
   ```

---

## 🔧 COMMON ATTACK SCENARIOS

### SQL Injection Attack

**Detection**:
```python
# Check for SQL injection attempts
grep "sql_injection" /var/log/security/security.log | tail -20
```

**Response**:
```python
# Block attacking IP immediately
limiter.add_to_blacklist(ip_address="ATTACKER_IP")

# Check database for unauthorized changes
SELECT * FROM information_schema.processlist;
SELECT * FROM security_events WHERE event_type = 'attack.sql_injection';
```

**Prevention**:
- All queries use parameterized statements
- Input validation with enhanced_input_validator.py
- WAF rules blocking SQL patterns

### Brute Force Attack

**Detection**:
```bash
# Check failed authentication attempts
grep "auth.failure" /var/log/security/security.log | wc -l
```

**Response**:
```python
# Check for blocked accounts
from core.monitoring.security_monitor import get_security_monitor
monitor = get_security_monitor()
recent_events = monitor.get_recent_events(
    event_type=SecurityEventType.AUTH_FAILURE,
    minutes=60
)
print(f"Failed auth attempts: {len(recent_events)}")
```

### DDoS Attack

**Detection**:
```bash
# Check request rates
tail -1000 /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
```

**Response**:
```bash
# Emergency rate limiting
redis-cli set "emergency_rate_limit" "true" EX 3600

# Block attack sources
for ip in $(cat attacking_ips.txt); do
    iptables -A INPUT -s $ip -j DROP
done
```

### Data Exfiltration

**Detection**:
```sql
-- Check for unusual data access
SELECT user_id, COUNT(*) as searches, 
       SUM(CASE WHEN result_count > 100 THEN 1 ELSE 0 END) as large_results
FROM search_logs 
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY user_id 
HAVING COUNT(*) > 50 OR SUM(CASE WHEN result_count > 100 THEN 1 ELSE 0 END) > 10;
```

**Response**:
```python
# Check for data export anomalies
from core.monitoring.security_monitor import SecurityEventType
monitor.get_recent_events(
    event_type=SecurityEventType.BULK_DATA_EXPORT,
    minutes=360  # 6 hours
)
```

---

## 🔑 KEY MANAGEMENT PROCEDURES

### Emergency Key Rotation

```python
# Rotate all keys immediately
from core.security.key_rotation_service import get_key_rotation_service
service = get_key_rotation_service()

# Rotate JWT signing keys
service.rotate_key('jwt_signing', reason='security_incident')

# Rotate master encryption keys
service.rotate_key('master', reason='security_incident')

# Rotate API keys
service.rotate_key('api_key', reason='security_incident')
```

### Key Compromise Response

```python
# Mark key as compromised
service.mark_compromised('key_id_here', 'evidence_of_compromise')

# Emergency generation of new keys
new_key_id, _ = service.generate_key('jwt_signing')
print(f"Emergency key generated: {new_key_id}")
```

---

## 📊 FORENSICS AND EVIDENCE COLLECTION

### Log Collection

```bash
#!/bin/bash
# incident_collection.sh

INCIDENT_ID=$1
COLLECTION_DIR="/tmp/incident_${INCIDENT_ID}"
mkdir -p $COLLECTION_DIR

# System logs
journalctl --since="1 hour ago" > $COLLECTION_DIR/system.log

# Application logs
kubectl logs deployment/api --since=1h > $COLLECTION_DIR/api.log
kubectl logs deployment/worker --since=1h > $COLLECTION_DIR/worker.log

# Security logs
cp /var/log/security/*.log $COLLECTION_DIR/

# Database snapshot
pg_dump legislativo_db > $COLLECTION_DIR/database_snapshot.sql

# Redis snapshot
redis-cli --rdb $COLLECTION_DIR/redis_snapshot.rdb

# Network capture (if attack is ongoing)
tcpdump -i eth0 -w $COLLECTION_DIR/network_capture.pcap &
TCPDUMP_PID=$!
sleep 300  # Capture for 5 minutes
kill $TCPDUMP_PID

# Create archive
tar -czf incident_${INCIDENT_ID}_evidence.tar.gz $COLLECTION_DIR
rm -rf $COLLECTION_DIR

echo "Evidence collected: incident_${INCIDENT_ID}_evidence.tar.gz"
```

### Memory Analysis

```bash
# Capture memory dump (if system is compromised)
dd if=/dev/mem of=/tmp/memory_dump.bin bs=1M

# Process analysis
ps aux > /tmp/processes.txt
netstat -tulpn > /tmp/network_connections.txt
lsof > /tmp/open_files.txt
```

---

## 🔄 POST-INCIDENT PROCEDURES

### Incident Report Template

```markdown
# Security Incident Report - ${INCIDENT_ID}

## Summary
- **Incident ID**: ${INCIDENT_ID}
- **Classification**: P${PRIORITY}
- **Detection Time**: ${DETECTION_TIME}
- **Resolution Time**: ${RESOLUTION_TIME}
- **Total Duration**: ${DURATION}

## Timeline
| Time | Action | Result |
|------|--------|--------|
| ${TIME1} | Initial detection | Alert triggered |
| ${TIME2} | Investigation started | Threat confirmed |
| ${TIME3} | Containment deployed | Attack stopped |
| ${TIME4} | Eradication completed | System cleaned |
| ${TIME5} | Service restored | Normal operations |

## Root Cause
${ROOT_CAUSE_ANALYSIS}

## Impact Assessment
- **Users Affected**: ${USER_COUNT}
- **Data Compromised**: ${DATA_DETAILS}
- **Service Downtime**: ${DOWNTIME_DURATION}
- **Financial Impact**: ${COST_ESTIMATE}

## Lessons Learned
${LESSONS_LEARNED}

## Action Items
- [ ] ${ACTION_ITEM_1}
- [ ] ${ACTION_ITEM_2}
- [ ] ${ACTION_ITEM_3}
```

### Improvement Actions

1. **Update Security Controls**:
   ```python
   # Update detection rules based on incident
   from core.monitoring.security_monitor import get_security_monitor
   monitor = get_security_monitor()
   
   # Add new detection patterns
   monitor.add_detection_rule({
       'name': 'incident_based_rule',
       'pattern': 'new_attack_pattern',
       'severity': 'HIGH'
   })
   ```

2. **Team Training**:
   - Schedule incident response drill
   - Update runbook based on lessons learned
   - Security awareness training for development team

3. **Infrastructure Hardening**:
   - Update security configurations
   - Implement additional monitoring
   - Review and update access controls

---

## 📱 CONTACT ESCALATION MATRIX

### Internal Escalation
1. **Security Engineer** → **Security Lead** (15 min)
2. **Security Lead** → **DevOps Lead** (30 min)
3. **DevOps Lead** → **CTO** (1 hour)
4. **CTO** → **CEO** (2 hours for P0)

### External Contacts
- **Law Enforcement**: [Contact for data breaches]
- **Legal Team**: [Contact for compliance issues]
- **PR Team**: [Contact for public communication]
- **Cyber Insurance**: [Contact for claims]

---

## 🔍 TESTING AND VALIDATION

### Monthly Security Drills

```bash
# Simulate attack scenarios
python3 security_drill.py --scenario brute_force
python3 security_drill.py --scenario sql_injection
python3 security_drill.py --scenario ddos

# Test incident response
security_team_drill.sh --incident-type P1 --duration 30m
```

### Quarterly Security Reviews

- [ ] Review and update this runbook
- [ ] Test all emergency procedures
- [ ] Validate contact information
- [ ] Update threat intelligence
- [ ] Review security metrics and trends

---

**Document Owner**: Security Team  
**Review Schedule**: Monthly  
**Distribution**: Security Team, DevOps, Engineering Leadership  

---

*This document contains sensitive security information. Treat as CONFIDENTIAL.*