# Zero-Downtime Migration Plan - Railway to AWS
## Monitor Legislativo v4 - Complete Infrastructure Migration

### Executive Summary

**Objective**: Migrate Monitor Legislativo v4 from Railway to AWS with zero downtime, ensuring continuous service availability for Brazilian academic and government users during the transition.

**Migration Window**: 72 hours (Friday 18:00 to Monday 06:00 Brazil time)
**Maximum Allowable Downtime**: <5 minutes for DNS propagation
**Expected User Impact**: None (transparent migration)

### Migration Architecture Overview

```
Current State (Railway):
[Users] → [Railway Load Balancer] → [Single Container] → [Railway PostgreSQL] → [Railway Redis]

Transition State (Blue-Green):
[Users] → [Route 53 DNS] → [Railway (Blue)] → [Railway DB + AWS RDS Sync]
                       → [AWS ALB (Green)] → [ECS Fargate] → [AWS RDS] → [ElastiCache]

Final State (AWS):
[Users] → [CloudFront CDN] → [Route 53] → [AWS ALB] → [ECS Fargate (Auto-scaling)] → [RDS Multi-AZ] → [ElastiCache]
```

### Pre-Migration Requirements

#### Infrastructure Readiness Checklist

**AWS Infrastructure (Must be 100% operational):**
- ✅ VPC with Multi-AZ subnets configured
- ✅ RDS PostgreSQL Multi-AZ instance running
- ✅ ElastiCache Redis cluster operational
- ✅ ECS Fargate cluster ready
- ✅ Application Load Balancer configured
- ✅ CloudFront distribution prepared
- ✅ WAF rules activated
- ✅ CloudWatch monitoring enabled
- ✅ SNS alerting configured

**Security & Compliance:**
- ✅ SSL certificates provisioned
- ✅ IAM roles and policies configured
- ✅ Security groups properly configured
- ✅ Secrets Manager populated with credentials
- ✅ LGPD compliance verified (São Paulo region)

**Data Synchronization:**
- ✅ Initial data load to AWS RDS completed
- ✅ Real-time sync process running for 48+ hours
- ✅ Data consistency verification passed
- ✅ Performance testing completed

### Migration Timeline

#### Phase 1: Final Preparation (Friday 18:00 - 20:00 BRT)

**18:00 - Infrastructure Final Check**
```bash
#!/bin/bash
# final-infrastructure-check.sh

echo "=== Final Infrastructure Readiness Check ==="

# Check AWS RDS availability
aws rds describe-db-instances \
  --db-instance-identifier monitor-legislativo-prod \
  --query 'DBInstances[0].DBInstanceStatus' \
  --output text

# Check ECS cluster status
aws ecs describe-clusters \
  --clusters monitor-legislativo-cluster \
  --query 'clusters[0].status' \
  --output text

# Check ALB health
aws elbv2 describe-load-balancers \
  --names monitor-legislativo-alb \
  --query 'LoadBalancers[0].State.Code' \
  --output text

# Verify data synchronization
python3 verify_final_sync.py

echo "✓ All infrastructure components ready"
```

**18:30 - Application Build and Deploy to AWS (Parallel Environment)**
```bash
# Deploy application to AWS ECS (Green environment)
aws ecs update-service \
  --cluster monitor-legislativo-cluster \
  --service monitor-legislativo-service \
  --desired-count 2 \
  --deployment-configuration maximumPercent=200,minimumHealthyPercent=50

# Wait for deployment to complete
aws ecs wait services-stable \
  --cluster monitor-legislativo-cluster \
  --services monitor-legislativo-service
```

**19:00 - Green Environment Validation**
```bash
# Health check on AWS environment
GREEN_ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names monitor-legislativo-alb \
  --query 'LoadBalancers[0].DNSName' \
  --output text)

# Application health check
curl -f "http://${GREEN_ALB_DNS}/health" || {
  echo "✗ Green environment health check failed"
  exit 1
}

# Database connectivity test
curl -f "http://${GREEN_ALB_DNS}/api/test-db" || {
  echo "✗ Green environment database test failed"
  exit 1
}

echo "✓ Green environment validated and ready"
```

**19:30 - Final Data Sync Checkpoint**
```python
# final_data_sync.py - Ensure data is perfectly synchronized
import psycopg2
import os
from datetime import datetime

def final_sync_validation():
    railway_conn = psycopg2.connect(os.environ['RAILWAY_DATABASE_URL'])
    aws_conn = psycopg2.connect(os.environ['AWS_RDS_URL'])
    
    # Compare record counts
    railway_cursor = railway_conn.cursor()
    aws_cursor = aws_conn.cursor()
    
    railway_cursor.execute("SELECT COUNT(*) FROM documents")
    railway_count = railway_cursor.fetchone()[0]
    
    aws_cursor.execute("SELECT COUNT(*) FROM documents")
    aws_count = aws_cursor.fetchone()[0]
    
    print(f"Railway records: {railway_count}")
    print(f"AWS RDS records: {aws_count}")
    
    if railway_count != aws_count:
        print("✗ Data sync mismatch detected")
        return False
    
    # Check latest timestamp sync
    railway_cursor.execute("SELECT MAX(updated_at) FROM documents")
    railway_latest = railway_cursor.fetchone()[0]
    
    aws_cursor.execute("SELECT MAX(updated_at) FROM documents")
    aws_latest = aws_cursor.fetchone()[0]
    
    time_diff = abs((railway_latest - aws_latest).total_seconds())
    
    if time_diff > 300:  # 5 minutes
        print(f"✗ Data sync time difference too large: {time_diff} seconds")
        return False
    
    print("✓ Final data synchronization validated")
    return True

if __name__ == "__main__":
    if not final_sync_validation():
        exit(1)
```

#### Phase 2: Traffic Splitting (Friday 20:00 - Saturday 02:00 BRT)

**20:00 - Enable Route 53 Weighted Routing (5% to AWS)**
```bash
# Create Route 53 weighted routing to gradually shift traffic
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-5percent.json

# route53-5percent.json
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "monitor-legislativo.mackenzie.br",
        "Type": "CNAME",
        "SetIdentifier": "Railway-Blue",
        "Weight": 95,
        "TTL": 60,
        "ResourceRecords": [
          {
            "Value": "railway-production-url.up.railway.app"
          }
        ]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "monitor-legislativo.mackenzie.br",
        "Type": "CNAME",
        "SetIdentifier": "AWS-Green",
        "Weight": 5,
        "TTL": 60,
        "ResourceRecords": [
          {
            "Value": "monitor-legislativo-alb-12345.sa-east-1.elb.amazonaws.com"
          }
        ]
      }
    }
  ]
}
```

**20:30 - Monitor 5% Traffic Split**
```bash
# Monitor both environments for 30 minutes
for i in {1..30}; do
  echo "Minute $i - Monitoring both environments"
  
  # Check Railway (Blue) health
  curl -f https://railway-production-url.up.railway.app/health
  
  # Check AWS (Green) health
  curl -f "http://${GREEN_ALB_DNS}/health"
  
  # Check error rates in CloudWatch
  aws cloudwatch get-metric-statistics \
    --namespace AWS/ApplicationELB \
    --metric-name HTTPCode_Target_5XX_Count \
    --dimensions Name=LoadBalancer,Value="$ALB_FULL_NAME" \
    --start-time $(date -d '5 minutes ago' -u +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Sum
  
  sleep 60
done
```

**21:30 - Increase to 25% AWS Traffic**
```bash
# Update Route 53 to 25% AWS traffic
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-25percent.json
```

**22:30 - Increase to 50% AWS Traffic**
```bash
# Update Route 53 to 50% AWS traffic
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-50percent.json
```

**00:00 - Increase to 75% AWS Traffic**
```bash
# Update Route 53 to 75% AWS traffic
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-75percent.json
```

**01:00 - Increase to 90% AWS Traffic**
```bash
# Update Route 53 to 90% AWS traffic
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-90percent.json
```

#### Phase 3: Complete Migration (Saturday 02:00 - 06:00 BRT)

**02:00 - Final Traffic Cutover (100% to AWS)**
```bash
# Complete traffic cutover to AWS
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-100percent.json

echo "=== COMPLETE TRAFFIC CUTOVER TO AWS ==="
echo "Time: $(date)"

# Monitor for issues for 30 minutes
for i in {1..30}; do
  # Check AWS environment health
  curl -f "http://${GREEN_ALB_DNS}/health" || {
    echo "✗ AWS health check failed - initiating emergency rollback"
    aws route53 change-resource-record-sets \
      --hosted-zone-id Z1234567890 \
      --change-batch file://route53-emergency-rollback.json
    exit 1
  }
  
  # Check error rates
  ERROR_COUNT=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/ApplicationELB \
    --metric-name HTTPCode_Target_5XX_Count \
    --dimensions Name=LoadBalancer,Value="$ALB_FULL_NAME" \
    --start-time $(date -d '5 minutes ago' -u +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Sum \
    --query 'Datapoints[0].Sum' \
    --output text)
  
  if [ "$ERROR_COUNT" != "None" ] && [ "$ERROR_COUNT" -gt 10 ]; then
    echo "✗ High error rate detected: $ERROR_COUNT errors"
    # Continue monitoring but alert
    aws sns publish \
      --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
      --subject "High Error Rate During Migration" \
      --message "Error count: $ERROR_COUNT in last 5 minutes"
  fi
  
  echo "✓ Minute $i - System healthy"
  sleep 60
done
```

**03:00 - Stop Railway Data Sync**
```bash
# Stop the real-time sync process from Railway to AWS
pkill -f railway_to_aws_sync.py

# Perform final data reconciliation
python3 final_data_reconciliation.py

echo "✓ Data synchronization stopped - AWS RDS is now primary"
```

**04:00 - Enable CloudFront CDN**
```bash
# Update Route 53 to point to CloudFront distribution
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch file://route53-cloudfront.json

# route53-cloudfront.json
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "monitor-legislativo.mackenzie.br",
        "Type": "A",
        "AliasTarget": {
          "DNSName": "d123456789.cloudfront.net",
          "EvaluateTargetHealth": true,
          "HostedZoneId": "Z2FDTNDATAQYW2"
        }
      }
    }
  ]
}

echo "✓ CloudFront CDN enabled - Global performance optimized"
```

**05:00 - Auto-scaling Validation**
```bash
# Test auto-scaling by generating load
python3 load_test.py --target-users 100 --duration 300

# Monitor auto-scaling response
aws ecs describe-services \
  --cluster monitor-legislativo-cluster \
  --services monitor-legislativo-service \
  --query 'services[0].runningCount'

echo "✓ Auto-scaling validated under load"
```

#### Phase 4: Post-Migration Validation (Saturday 06:00 - Sunday 18:00 BRT)

**06:00 - Comprehensive System Validation**
```python
# comprehensive_validation.py
import requests
import time
import json
from datetime import datetime

def comprehensive_system_test():
    base_url = "https://monitor-legislativo.mackenzie.br"
    
    tests = []
    
    # Test 1: Application Health
    try:
        response = requests.get(f"{base_url}/health", timeout=10)
        tests.append({"name": "Health Check", "status": "PASS" if response.status_code == 200 else "FAIL"})
    except Exception as e:
        tests.append({"name": "Health Check", "status": "FAIL", "error": str(e)})
    
    # Test 2: Database Connectivity
    try:
        response = requests.get(f"{base_url}/api/test-db", timeout=10)
        tests.append({"name": "Database Test", "status": "PASS" if response.status_code == 200 else "FAIL"})
    except Exception as e:
        tests.append({"name": "Database Test", "status": "FAIL", "error": str(e)})
    
    # Test 3: Search Functionality
    try:
        response = requests.post(f"{base_url}/api/search", 
                               json={"query": "legislação", "limit": 10}, 
                               timeout=15)
        if response.status_code == 200 and len(response.json().get('results', [])) > 0:
            tests.append({"name": "Search Functionality", "status": "PASS"})
        else:
            tests.append({"name": "Search Functionality", "status": "FAIL"})
    except Exception as e:
        tests.append({"name": "Search Functionality", "status": "FAIL", "error": str(e)})
    
    # Test 4: Performance (Response Time)
    start_time = time.time()
    try:
        response = requests.get(f"{base_url}/", timeout=10)
        response_time = time.time() - start_time
        if response.status_code == 200 and response_time < 3.0:
            tests.append({"name": "Performance Test", "status": "PASS", "response_time": response_time})
        else:
            tests.append({"name": "Performance Test", "status": "FAIL", "response_time": response_time})
    except Exception as e:
        tests.append({"name": "Performance Test", "status": "FAIL", "error": str(e)})
    
    # Test 5: OAuth Authentication
    try:
        response = requests.get(f"{base_url}/auth/google", timeout=10, allow_redirects=False)
        if response.status_code in [302, 200]:
            tests.append({"name": "OAuth Authentication", "status": "PASS"})
        else:
            tests.append({"name": "OAuth Authentication", "status": "FAIL"})
    except Exception as e:
        tests.append({"name": "OAuth Authentication", "status": "FAIL", "error": str(e)})
    
    # Generate report
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": len(tests),
        "passed": len([t for t in tests if t["status"] == "PASS"]),
        "failed": len([t for t in tests if t["status"] == "FAIL"]),
        "tests": tests
    }
    
    print(json.dumps(report, indent=2))
    
    # Save report
    with open(f"migration_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    return report["failed"] == 0

if __name__ == "__main__":
    success = comprehensive_system_test()
    if not success:
        print("✗ Validation failed - manual intervention required")
        exit(1)
    else:
        print("✓ All validation tests passed")
```

**12:00 - User Acceptance Testing**
```bash
# Notify test users to perform acceptance testing
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-testers \
  --subject "User Acceptance Testing - Monitor Legislativo v4" \
  --message "The migration to AWS is complete. Please perform your standard user workflows and report any issues. Testing window: 6 hours."
```

#### Phase 5: Cleanup and Optimization (Sunday 18:00 - Monday 06:00 BRT)

**18:00 - Railway Decommissioning Preparation**
```bash
# Create final backup of Railway data
pg_dump $RAILWAY_DATABASE_URL \
  --format=custom \
  --file=railway_final_backup_$(date +%Y%m%d_%H%M%S).dump

# Upload to S3 for long-term retention
aws s3 cp railway_final_backup_*.dump s3://monitor-legislativo-backups/migration/

echo "✓ Final Railway backup completed and archived"
```

**20:00 - Performance Optimization**
```sql
-- Run on AWS RDS to optimize for production load
-- Update PostgreSQL statistics
ANALYZE;

-- Reindex for optimal performance
REINDEX DATABASE monitor_legislativo;

-- Update configuration for production
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '512MB';
ALTER SYSTEM SET effective_cache_size = '1536MB';

-- Restart required for some settings
-- (Handle via RDS parameter group and reboot during low-traffic period)
```

**22:00 - Monitoring Dashboard Setup**
```bash
# Import custom CloudWatch dashboard
aws cloudwatch put-dashboard \
  --dashboard-name "MonitorLegislativoV4-Production" \
  --dashboard-body file://cloudwatch-dashboard.json

# Set up additional alerts for production
aws cloudwatch put-metric-alarm \
  --alarm-name "MonitorLegislativo-DatabaseConnections" \
  --alarm-description "Alert when database connections exceed 80%" \
  --metric-name DatabaseConnections \
  --namespace AWS/RDS \
  --statistic Average \
  --period 300 \
  --threshold 160 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts
```

### Rollback Procedures

#### Emergency Rollback (If Issues Detected)

**Immediate Rollback (< 2 minutes):**
```bash
#!/bin/bash
# emergency-rollback.sh

echo "=== EMERGENCY ROLLBACK INITIATED ==="
echo "Time: $(date)"

# Immediate DNS rollback to Railway
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch '{
    "Changes": [
      {
        "Action": "UPSERT",
        "ResourceRecordSet": {
          "Name": "monitor-legislativo.mackenzie.br",
          "Type": "CNAME",
          "TTL": 60,
          "ResourceRecords": [
            {
              "Value": "railway-production-url.up.railway.app"
            }
          ]
        }
      }
    ]
  }'

# Verify Railway is still operational
curl -f https://railway-production-url.up.railway.app/health || {
  echo "✗ CRITICAL: Railway also failing - manual intervention required"
  exit 1
}

echo "✓ Emergency rollback completed - Traffic back to Railway"

# Send alert
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --subject "EMERGENCY ROLLBACK - Monitor Legislativo v4" \
  --message "Emergency rollback to Railway completed. AWS issues detected during migration. Immediate investigation required."
```

#### Partial Rollback (Specific Components)

**Database Rollback:**
```bash
# If only database issues, rollback database while keeping AWS infrastructure
export DATABASE_URL=$RAILWAY_DATABASE_URL

# Update ECS service environment
aws ecs update-service \
  --cluster monitor-legislativo-cluster \
  --service monitor-legislativo-service \
  --task-definition monitor-legislativo-with-railway-db
```

### Success Validation Criteria

**Migration is considered successful when ALL criteria are met:**

1. **Availability**: System uptime >99.99% during migration window
2. **Performance**: Average response time <3 seconds for all requests
3. **Data Integrity**: 100% data consistency between Railway and AWS
4. **Functionality**: All application features working correctly
5. **Auto-scaling**: System successfully handles load increases
6. **Monitoring**: All CloudWatch metrics reporting correctly
7. **Security**: All security controls functioning (WAF, SSL, authentication)
8. **User Acceptance**: No critical issues reported by test users

### Communication Plan

#### Stakeholder Notifications

**Before Migration:**
```bash
# T-48 hours notification
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-users \
  --subject "Scheduled Infrastructure Upgrade - Monitor Legislativo v4" \
  --message "We will be upgrading our infrastructure this weekend to improve performance and scalability. No service interruption is expected, but please report any issues to admin@mackenzie.br"
```

**During Migration:**
```bash
# Progress updates every 2 hours
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-internal \
  --subject "Migration Progress Update" \
  --message "Migration Phase X completed successfully. Current traffic split: X% AWS, Y% Railway. All systems operational."
```

**After Migration:**
```bash
# Success notification
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-users \
  --subject "Infrastructure Upgrade Completed - Monitor Legislativo v4" \
  --message "Our infrastructure upgrade has been completed successfully. The system now supports 10x higher capacity and improved performance. Thank you for your patience."
```

### Post-Migration Monitoring

#### First 24 Hours - Intensive Monitoring

```bash
# Automated monitoring script for first 24 hours
#!/bin/bash
# intensive-monitoring.sh

for hour in {1..24}; do
  echo "=== Hour $hour Post-Migration Monitoring ==="
  
  # Application health
  curl -f https://monitor-legislativo.mackenzie.br/health
  
  # Performance metrics
  aws cloudwatch get-metric-statistics \
    --namespace AWS/ApplicationELB \
    --metric-name TargetResponseTime \
    --dimensions Name=LoadBalancer,Value="$ALB_FULL_NAME" \
    --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 3600 \
    --statistics Average
  
  # Database performance
  aws cloudwatch get-metric-statistics \
    --namespace AWS/RDS \
    --metric-name DatabaseConnections \
    --dimensions Name=DBInstanceIdentifier,Value=monitor-legislativo-prod \
    --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 3600 \
    --statistics Average
  
  # Error rate check
  ERROR_COUNT=$(aws logs filter-log-events \
    --log-group-name /ecs/monitor-legislativo-prod \
    --start-time $(date -d '1 hour ago' +%s)000 \
    --filter-pattern "ERROR" \
    --query 'events | length(@)')
  
  if [ "$ERROR_COUNT" -gt 10 ]; then
    aws sns publish \
      --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
      --subject "Elevated Error Rate - Hour $hour" \
      --message "Error count in last hour: $ERROR_COUNT"
  fi
  
  sleep 3600  # Wait 1 hour
done
```

#### First Week - Daily Health Reports

```python
# daily_health_report.py
import boto3
import json
from datetime import datetime, timedelta

def generate_daily_report():
    cloudwatch = boto3.client('cloudwatch')
    
    # Get metrics for last 24 hours
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=1)
    
    metrics = {
        'response_time': get_metric_average('AWS/ApplicationELB', 'TargetResponseTime'),
        'request_count': get_metric_sum('AWS/ApplicationELB', 'RequestCount'),
        'error_rate': get_metric_sum('AWS/ApplicationELB', 'HTTPCode_Target_5XX_Count'),
        'cpu_utilization': get_metric_average('AWS/ECS', 'CPUUtilization'),
        'memory_utilization': get_metric_average('AWS/ECS', 'MemoryUtilization'),
        'database_connections': get_metric_average('AWS/RDS', 'DatabaseConnections'),
    }
    
    # Generate report
    report = {
        'date': datetime.now().strftime('%Y-%m-%d'),
        'metrics': metrics,
        'status': 'healthy' if all_metrics_healthy(metrics) else 'attention_required'
    }
    
    # Send to SNS
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-daily-reports',
        Subject=f"Daily Health Report - {report['date']}",
        Message=json.dumps(report, indent=2)
    )

# Schedule to run daily at 8 AM Brazil time
```

This comprehensive zero-downtime migration plan ensures a smooth transition from Railway to AWS while maintaining service availability, data integrity, and providing robust rollback capabilities for the Monitor Legislativo v4 platform.