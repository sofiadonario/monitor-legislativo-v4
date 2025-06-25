# Monitoring & Alerting Guide
# Monitor Legislativo v4 - Phase 4 Week 15

## 📊 Overview

This guide covers the comprehensive monitoring and alerting system for Monitor Legislativo v4, including Prometheus metrics collection, Grafana dashboards, log aggregation with Loki, and automated SLA tracking. The system provides real-time visibility into all platform components with intelligent alerting for proactive issue resolution.

## 📋 Architecture Components

### Core Monitoring Stack
- **Prometheus**: Metrics collection and time-series database
- **Grafana**: Visualization dashboards and alerting interface
- **Loki**: Log aggregation and analysis
- **Promtail**: Log collection and shipping
- **Alertmanager**: Alert routing and notification management
- **SLA Monitor**: Custom SLA tracking and compliance monitoring

### Monitored Components
- **Frontend**: React application, nginx load balancer, CDN performance
- **Backend**: FastAPI services, connection pools, business metrics
- **Database**: PostgreSQL performance, connection health, query analysis
- **Cache**: Redis performance, hit rates, memory usage
- **External APIs**: Brazilian government APIs, LexML service availability
- **Infrastructure**: Container metrics, system resources, network performance

## 🔧 Implementation Components

### 1. Prometheus Configuration
**File**: `monitoring/prometheus-config.yml`

Key features:
- **Service Discovery**: Automatic detection of Monitor Legislativo services
- **Brazilian API Monitoring**: Government data source health checks
- **Business Metrics**: Custom application-specific measurements
- **High Availability**: Remote write configuration for long-term storage
- **Performance Optimization**: Efficient scraping with proper intervals

### 2. Alert Rules
**File**: `monitoring/alert_rules.yml`

Comprehensive alerting for:
- **Critical System Alerts**: API down, database failures, high error rates
- **Performance Monitoring**: Response time degradation, resource usage
- **Brazilian Government APIs**: LexML, Câmara, Senado availability
- **Data Collection**: Collection failures, processing backlogs
- **Business Logic**: User activity, search performance, data freshness

### 3. Grafana Dashboard
**File**: `monitoring/grafana/dashboards/monitor-legislativo-overview.json`

Dashboard sections:
- **System Overview**: Service status, alerts, uptime metrics
- **Government Data Sources**: Brazilian API status and collection rates
- **Database Performance**: Connection pools, query times, cache performance
- **Business Metrics**: Document counts, searches, user activity, data freshness

### 4. Log Aggregation
**Files**: `monitoring/loki-config.yml`, `monitoring/promtail-config.yml`

Features:
- **Centralized Logging**: All application and infrastructure logs
- **Intelligent Parsing**: Component-specific log parsing and labeling
- **Retention Policies**: Different retention for various log types
- **Performance Optimization**: Compressed storage, efficient indexing

### 5. SLA Monitoring
**File**: `monitoring/sla-monitor.py`

Capabilities:
- **Comprehensive SLA Tracking**: 10 key service level objectives
- **Automated Alerting**: Breach detection with business impact assessment
- **Trend Analysis**: Performance trends and predictive insights
- **Compliance Reporting**: Detailed SLA compliance reports

## 🎯 Key Metrics and SLAs

### Service Level Objectives

#### API Performance
```yaml
- API Availability: 99.5% uptime
- API Response Time: <2s (95th percentile)
- Error Rate: <1% HTTP 5xx errors
- Search Performance: <5s for complex queries
```

#### Data Reliability
```yaml
- Data Freshness: <24 hours maximum age
- Collection Success Rate: >95% from government APIs
- LexML API Availability: >95% (external dependency)
- Backup Reliability: <24 hours since last successful backup
```

#### System Performance
```yaml
- Database Response Time: <1s average queries
- Cache Hit Rate: >80% Redis performance
- CPU Usage: <80% sustained load
- Memory Usage: <85% of allocated resources
```

### Prometheus Metrics Collection

#### Application Metrics
```yaml
# API Performance
http_request_duration_seconds_bucket{job="backend-api"}
http_requests_total{job="backend-api",status=~"5.."}
monitor_legislativo_search_duration_seconds_bucket

# Business Metrics  
monitor_legislativo_total_documents
monitor_legislativo_search_requests_total
monitor_legislativo_active_users
monitor_legislativo_data_freshness_timestamp

# Collection Metrics
monitor_legislativo_collection_attempts_total
monitor_legislativo_collection_failures_total
monitor_legislativo_processing_queue_size
```

#### Infrastructure Metrics
```yaml
# Database
postgresql_connections_active
postgresql_query_duration_seconds_sum
postgresql_slow_queries_total

# Cache
redis_keyspace_hits_total
redis_keyspace_misses_total
redis_memory_used_bytes

# System
node_memory_MemAvailable_bytes
node_cpu_seconds_total
container_memory_usage_bytes
```

#### External Dependencies
```yaml
# Government APIs
probe_success{job="government-apis"}
probe_success{instance="https://www.lexml.gov.br"}
probe_ssl_earliest_cert_expiry

# Network Performance
probe_http_duration_seconds
probe_http_status_code
```

## 🚨 Alerting Strategy

### Alert Severity Levels

#### Critical Alerts (Immediate Response)
```yaml
- APIServiceDown: API instance unavailable >30s
- DatabaseConnectionFailure: DB connection issues
- HighAPIErrorRate: >5% error rate for 2+ minutes
- LoadBalancerDown: nginx unavailable >30s
- BackupFailure: No successful backup >24h
- SSLCertificateExpired: Certificate has expired
```

#### Warning Alerts (Monitor Closely)
```yaml
- SlowAPIResponseTime: >2s 95th percentile for 3+ minutes
- HighMemoryUsage: >85% memory utilization for 5+ minutes
- HighCPUUsage: >80% CPU for 10+ minutes
- LexMLAPIDown: External API unavailable >10 minutes
- HighCollectionFailureRate: >20% failure rate for 30+ minutes
- SlowDatabaseQueries: >10 slow queries/second for 5+ minutes
```

#### Business Impact Alerts
```yaml
- NoRecentDataCollection: No collection activity >4 hours
- DocumentProcessingBacklog: >1000 documents queued >15 minutes
- NoRecentUserActivity: No user interactions >30 minutes
- StaleDataDetected: Data not updated >24 hours
- MultipleGovAPIsDown: ≥2 government APIs unavailable
```

### Alert Routing and Notifications

#### Slack Integration
```yaml
# Critical alerts to #alerts channel
- API service failures
- Database connection issues
- Security certificate problems

# Warning alerts to #monitoring channel  
- Performance degradation
- External API issues
- Resource usage warnings
```

#### Email Notifications
```yaml
# Executive summary (daily)
- SLA compliance report
- System health summary
- Trending issues

# Engineering alerts (immediate)
- Critical system failures
- Security incidents
- Data collection issues
```

## 📊 Dashboard Organization

### Main Overview Dashboard
- **System Health**: Service status, alert counts, overall uptime
- **Performance Metrics**: Response times, error rates, throughput
- **Business KPIs**: Document counts, search activity, user engagement
- **External Dependencies**: Government API status, collection success

### Detailed Component Dashboards

#### API Performance Dashboard
```yaml
Panels:
- Request rate and response times by endpoint
- Error rate breakdown by status code
- Connection pool utilization
- Geographic request distribution
- Slow query analysis
```

#### Database Performance Dashboard
```yaml
Panels:
- Connection pool status and utilization
- Query performance and slow query analysis
- Index usage and table statistics
- Replication lag and backup status
- Cache hit rates and performance
```

#### Brazilian Government Data Dashboard
```yaml
Panels:
- LexML API availability and response times
- Government API status matrix (Câmara, Senado, etc.)
- Collection success rates by source
- Data freshness by content type
- Regional data distribution
```

#### Infrastructure Dashboard
```yaml
Panels:
- Container resource usage (CPU, memory, disk)
- Network performance and connectivity
- Load balancer metrics and upstream health
- SSL certificate expiration monitoring
- Security metrics and failed access attempts
```

## 📝 Log Analysis and Aggregation

### Log Collection Strategy

#### Application Logs
```yaml
API Logs:
- Request/response logging with correlation IDs
- Error tracking with stack traces
- Performance metrics and slow query detection
- User activity and search analytics

Database Logs:
- Connection events and authentication
- Slow query logs with execution plans
- Error logs and transaction failures
- Replication status and backup events
```

#### Infrastructure Logs
```yaml
nginx Logs:
- Access logs with performance metrics
- Error logs with client and upstream context
- Security events and blocked requests
- Load balancing decisions and health checks

System Logs:
- Container lifecycle events
- Resource allocation and limits
- Network connectivity issues
- Security events and system changes
```

### Log Parsing and Enrichment

#### Intelligent Log Parsing
```yaml
# API request logs with structured data extraction
- Request ID correlation across services
- User session tracking and behavior analysis
- Search query analysis and performance metrics
- Error categorization and root cause analysis

# Database query analysis
- Slow query identification and optimization hints
- Connection pool analysis and optimization
- Transaction analysis and deadlock detection
- Performance trend analysis and capacity planning
```

#### Brazilian Government Context
```yaml
# Government API interaction logs
- Source identification (LexML, Câmara, Senado)
- Collection attempt tracking and failure analysis
- Data quality validation and error detection
- Regional data distribution analysis
```

### Log Retention and Compliance
```yaml
Retention Policies:
- Error logs: 90 days (compliance requirement)
- API access logs: 30 days (performance analysis)
- nginx logs: 7 days (operational monitoring)
- Debug logs: 3 days (troubleshooting)

Privacy Compliance:
- PII data sanitization in logs
- User session anonymization
- LGPD compliance for Brazilian users
- Audit trail for data access and modifications
```

## 🔍 SLA Monitoring and Compliance

### SLA Target Definitions

#### User Experience SLAs
```python
API_AVAILABILITY = SLATarget(
    name="api_availability",
    target_value=99.5,  # 99.5% uptime
    warning_threshold=99.0,
    critical_threshold=98.0,
    business_impact="high"
)

API_RESPONSE_TIME = SLATarget(
    name="api_response_time", 
    target_value=2.0,  # 2 seconds
    warning_threshold=1.5,
    critical_threshold=3.0,
    business_impact="high"
)
```

#### Data Quality SLAs
```python
DATA_FRESHNESS = SLATarget(
    name="data_freshness",
    target_value=24.0,  # 24 hours maximum
    warning_threshold=12.0,
    critical_threshold=48.0,
    business_impact="medium"
)

COLLECTION_SUCCESS = SLATarget(
    name="collection_success_rate",
    target_value=95.0,  # 95% success rate
    warning_threshold=90.0,
    critical_threshold=80.0,
    business_impact="medium"
)
```

### Automated SLA Reporting

#### Real-time Compliance Tracking
```python
# Continuous monitoring every 60 seconds
await sla_monitor.start_monitoring(check_interval=60)

# Automated breach detection and alerting
measurement = await sla_monitor._measure_sla_target(session, target)
if measurement.status in [SLAStatus.WARNING, SLAStatus.CRITICAL]:
    await sla_monitor._trigger_sla_alert(measurement, target)
```

#### Periodic Compliance Reports
```python
# Generate comprehensive 24-hour compliance report
report = await sla_monitor.generate_comprehensive_report(period_hours=24)

# Report includes:
# - Overall compliance percentage
# - Individual SLA target performance
# - Breach analysis and root causes
# - Performance trends and recommendations
# - Business impact assessment
```

## 🚀 Deployment and Configuration

### Monitoring Stack Deployment
```bash
# Deploy complete monitoring stack
docker-compose -f docker-compose.monitoring.yml up -d

# Verify Prometheus targets
curl http://prometheus:9090/api/v1/targets

# Check Grafana dashboard access
curl http://grafana:3000/api/health

# Validate Loki log ingestion
curl http://loki:3100/ready
```

### Configuration Management
```bash
# Prometheus configuration
docker-compose exec prometheus promtool check config /etc/prometheus/prometheus.yml

# Alert rules validation
docker-compose exec prometheus promtool check rules /etc/prometheus/alert_rules.yml

# Grafana dashboard import
curl -X POST http://admin:admin@grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @monitoring/grafana/dashboards/monitor-legislativo-overview.json
```

### SLA Monitor Integration
```python
# Initialize SLA monitoring
from monitoring.sla_monitor import create_sla_monitor

sla_monitor = await create_sla_monitor(
    prometheus_url="http://prometheus:9090",
    alertmanager_url="http://alertmanager:9093"
)

# Start continuous monitoring
await sla_monitor.start_monitoring(check_interval=60)

# Get current status
status = await sla_monitor.get_current_status()
```

## 🔧 Operational Procedures

### Daily Monitoring Tasks
```bash
# Check system health dashboard
curl -s http://grafana:3000/api/dashboards/uid/monitor-legislativo-overview

# Review overnight alerts
curl -s http://alertmanager:9093/api/v1/alerts

# Verify SLA compliance
python -c "
import asyncio
from monitoring.sla_monitor import create_sla_monitor
async def check_sla():
    monitor = await create_sla_monitor()
    status = await monitor.get_current_status()
    print(f'SLA Status: {len([s for s in status.values() if s.get(\"current_measurement\", {}).get(\"status\") == \"healthy\"])}/{len(status)} targets healthy')
asyncio.run(check_sla())
"
```

### Weekly Analysis Tasks
```bash
# Generate SLA compliance report
python -c "
import asyncio, json
from monitoring.sla_monitor import create_sla_monitor
async def weekly_report():
    monitor = await create_sla_monitor()
    report = await monitor.generate_comprehensive_report(period_hours=168)
    print(json.dumps(report.to_dict(), indent=2))
asyncio.run(weekly_report())
"

# Analyze performance trends
curl -s "http://prometheus:9090/api/v1/query_range?query=rate(http_request_duration_seconds_sum[5m])/rate(http_request_duration_seconds_count[5m])&start=$(date -d '7 days ago' +%s)&end=$(date +%s)&step=3600"
```

### Monthly Optimization
```bash
# Review alert effectiveness
curl -s http://alertmanager:9093/api/v1/alerts | jq '.data[] | select(.status.state == "suppressed")'

# Analyze log storage usage
curl -s http://loki:3100/loki/api/v1/label/__name__/values | jq '.data[]' | sort | uniq -c

# Database performance review
curl -s "http://prometheus:9090/api/v1/query?query=postgresql_slow_queries_total"
```

## 🚨 Troubleshooting

### Common Monitoring Issues

#### Prometheus Target Discovery Issues
```bash
# Check service discovery
curl http://prometheus:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up")'

# Verify network connectivity
docker-compose exec prometheus nc -zv api1 8000

# Check firewall rules
docker-compose exec prometheus netstat -tlnp
```

#### Grafana Dashboard Problems
```bash
# Verify datasource connectivity
curl http://grafana:3000/api/datasources/proxy/1/api/v1/query?query=up

# Check dashboard import errors
docker-compose logs grafana | grep -i error

# Validate dashboard JSON
jq . < monitoring/grafana/dashboards/monitor-legislativo-overview.json
```

#### Log Aggregation Issues
```bash
# Check Loki ingestion
curl http://loki:3100/metrics | grep loki_ingester_streams

# Verify Promtail connectivity  
curl http://promtail:9080/metrics | grep promtail_targets_active_total

# Test log parsing
docker-compose exec promtail promtail -config.file=/etc/promtail/config.yml -dry-run
```

### Performance Optimization
```bash
# Optimize Prometheus retention
# Edit prometheus.yml: retention.time: 15d, retention.size: 10GB

# Tune Grafana query performance
# Enable query caching in grafana.ini

# Optimize Loki storage
# Configure retention policies per log stream
```

## 📈 Metrics and KPIs

### System Performance KPIs
- **Overall System Availability**: >99.5%
- **Mean Time to Recovery (MTTR)**: <15 minutes
- **Alert Noise Ratio**: <5% false positives
- **Monitoring Coverage**: 100% of critical services

### Business Intelligence KPIs
- **Data Collection Success Rate**: >95%
- **Search Performance**: <5s average response time
- **User Engagement**: Daily active users, search frequency
- **Content Freshness**: <24 hours data age

### Operational Efficiency KPIs
- **Alert Response Time**: <5 minutes to acknowledge
- **Incident Resolution Time**: <30 minutes average
- **Capacity Utilization**: 60-80% resource usage
- **Cost Efficiency**: <$0.50 per monitored service per day

---

**Next Phase**: Week 16 - Security & Compliance with comprehensive security audit, vulnerability scanning, and LGPD compliance implementation.

**Last Updated**: Phase 4 Week 15  
**Production Ready**: ✅ Comprehensive monitoring, alerting, SLA tracking, log aggregation  
**Coverage**: 100% system components, 10 SLA targets, 50+ alert rules