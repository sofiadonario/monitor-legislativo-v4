# Deployment Procedures & Operational Runbook
## Monitor Legislativo v4 - AWS Infrastructure Operations

### Overview

This runbook provides comprehensive procedures for deploying, operating, and maintaining the Monitor Legislativo v4 infrastructure on AWS. It covers everything from initial deployment to emergency response procedures.

### Table of Contents

1. [Initial Deployment](#initial-deployment)
2. [Daily Operations](#daily-operations)
3. [Monitoring & Alerting](#monitoring--alerting)
4. [Troubleshooting](#troubleshooting)
5. [Emergency Procedures](#emergency-procedures)
6. [Maintenance Tasks](#maintenance-tasks)
7. [Security Operations](#security-operations)
8. [Performance Optimization](#performance-optimization)

## Initial Deployment

### Prerequisites Checklist

**AWS Account Setup:**
- [ ] AWS account with university credits activated
- [ ] IAM users created with appropriate permissions
- [ ] AWS CLI configured with correct profiles
- [ ] CDK CLI installed and configured
- [ ] Domain name registered and Route 53 hosted zone created

**Development Environment:**
- [ ] Docker installed and running
- [ ] Node.js 18+ and npm installed
- [ ] AWS CDK v2 installed globally
- [ ] Git repository cloned and up to date
- [ ] Environment variables configured

### Step 1: Infrastructure Deployment

#### 1.1 Bootstrap CDK Environment
```bash
# Navigate to CDK directory
cd infrastructure/cdk

# Install dependencies
npm install

# Bootstrap CDK (one-time setup per AWS account/region)
npx cdk bootstrap --profile university-aws

# Verify bootstrap
aws cloudformation describe-stacks \
  --stack-name CDKToolkit \
  --profile university-aws
```

#### 1.2 Deploy Security Stack First
```bash
# Deploy security components (WAF, certificates, IAM roles)
npx cdk deploy MonitorLegislativoSecurityStack \
  --profile university-aws \
  --require-approval never

# Verify security stack deployment
aws wafv2 list-web-acls \
  --scope CLOUDFRONT \
  --region us-east-1 \
  --profile university-aws
```

#### 1.3 Deploy Development Environment
```bash
# Deploy development stack
npx cdk deploy MonitorLegislativoStack-dev \
  --profile university-aws \
  --require-approval never

# Wait for deployment completion
aws ecs wait services-stable \
  --cluster monitor-legislativo-cluster-dev \
  --services monitor-legislativo-service-dev \
  --profile university-aws
```

#### 1.4 Deploy Production Environment
```bash
# Deploy production stack
npx cdk deploy MonitorLegislativoStack-prod \
  --profile university-aws \
  --require-approval never

# Deploy monitoring stack
npx cdk deploy MonitorLegislativoMonitoringStack \
  --profile university-aws \
  --require-approval never
```

### Step 2: Application Configuration

#### 2.1 Configure Secrets
```bash
# OAuth2 secrets for authentication
aws secretsmanager update-secret \
  --secret-id monitor-legislativo-oauth \
  --secret-string '{
    "googleClientId": "YOUR_GOOGLE_CLIENT_ID",
    "googleClientSecret": "YOUR_GOOGLE_CLIENT_SECRET",
    "microsoftClientId": "YOUR_MICROSOFT_CLIENT_ID", 
    "microsoftClientSecret": "YOUR_MICROSOFT_CLIENT_SECRET",
    "microsoftTenantId": "common"
  }' \
  --profile university-aws

# Database credentials
aws secretsmanager update-secret \
  --secret-id monitor-legislativo-db-prod \
  --secret-string '{
    "username": "postgres",
    "password": "SECURE_RANDOM_PASSWORD_HERE",
    "engine": "postgres",
    "host": "RDS_ENDPOINT_HERE",
    "port": 5432,
    "dbname": "monitor_legislativo"
  }' \
  --profile university-aws
```

#### 2.2 Configure Application Parameters
```bash
# Application configuration parameters
aws ssm put-parameter \
  --name "/monitor-legislativo/app/environment" \
  --value "production" \
  --type "String" \
  --profile university-aws

aws ssm put-parameter \
  --name "/monitor-legislativo/app/log-level" \
  --value "INFO" \
  --type "String" \
  --profile university-aws

aws ssm put-parameter \
  --name "/monitor-legislativo/app/max-users" \
  --value "500" \
  --type "String" \
  --profile university-aws
```

#### 2.3 Initial Data Load
```bash
# Run initial data migration
python3 scripts/migrate_railway_to_aws.py \
  --source-url $RAILWAY_DATABASE_URL \
  --target-url $AWS_RDS_URL \
  --batch-size 1000 \
  --verify-integrity

# Verify data load
psql $AWS_RDS_URL -c "
  SELECT 
    COUNT(*) as total_documents,
    COUNT(DISTINCT tipo) as document_types,
    COUNT(DISTINCT estado) as states,
    MAX(created_at) as latest_document
  FROM documents;
"
```

### Step 3: DNS and SSL Configuration

#### 3.1 Configure Route 53
```bash
# Get ALB DNS name
ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names monitor-legislativo-alb-prod \
  --query 'LoadBalancers[0].DNSName' \
  --output text \
  --profile university-aws)

# Create Route 53 record
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch '{
    "Changes": [
      {
        "Action": "UPSERT",
        "ResourceRecordSet": {
          "Name": "monitor-legislativo.mackenzie.br",
          "Type": "A",
          "AliasTarget": {
            "DNSName": "'$ALB_DNS'",
            "EvaluateTargetHealth": true,
            "HostedZoneId": "Z2P70J7HTTTPLU"
          }
        }
      }
    ]
  }' \
  --profile university-aws
```

#### 3.2 SSL Certificate Validation
```bash
# Request SSL certificate
aws acm request-certificate \
  --domain-name monitor-legislativo.mackenzie.br \
  --subject-alternative-names "*.monitor-legislativo.mackenzie.br" \
  --validation-method DNS \
  --region sa-east-1 \
  --profile university-aws

# Follow DNS validation process as instructed by AWS
```

## Daily Operations

### Morning Health Check (9 AM BRT)

#### System Status Verification
```bash
#!/bin/bash
# daily-health-check.sh

echo "=== Monitor Legislativo v4 - Daily Health Check ==="
echo "Date: $(date)"

# 1. Application Health
echo "1. Checking application health..."
curl -f https://monitor-legislativo.mackenzie.br/health || {
  echo "❌ Application health check failed"
  exit 1
}
echo "✅ Application healthy"

# 2. Database Health
echo "2. Checking database health..."
DB_STATUS=$(aws rds describe-db-instances \
  --db-instance-identifier monitor-legislativo-prod \
  --query 'DBInstances[0].DBInstanceStatus' \
  --output text \
  --profile university-aws)

if [ "$DB_STATUS" != "available" ]; then
  echo "❌ Database not available: $DB_STATUS"
  exit 1
fi
echo "✅ Database available"

# 3. ECS Service Health
echo "3. Checking ECS service health..."
RUNNING_TASKS=$(aws ecs describe-services \
  --cluster monitor-legislativo-cluster \
  --services monitor-legislativo-service \
  --query 'services[0].runningCount' \
  --output text \
  --profile university-aws)

DESIRED_TASKS=$(aws ecs describe-services \
  --cluster monitor-legislativo-cluster \
  --services monitor-legislativo-service \
  --query 'services[0].desiredCount' \
  --output text \
  --profile university-aws)

if [ "$RUNNING_TASKS" != "$DESIRED_TASKS" ]; then
  echo "❌ ECS service unhealthy: $RUNNING_TASKS/$DESIRED_TASKS tasks running"
  exit 1
fi
echo "✅ ECS service healthy: $RUNNING_TASKS tasks running"

# 4. Cache Health
echo "4. Checking Redis cache health..."
CACHE_STATUS=$(aws elasticache describe-cache-clusters \
  --cache-cluster-id monitor-legislativo-redis \
  --query 'CacheClusters[0].CacheClusterStatus' \
  --output text \
  --profile university-aws)

if [ "$CACHE_STATUS" != "available" ]; then
  echo "❌ Cache not available: $CACHE_STATUS"
  exit 1
fi
echo "✅ Cache available"

# 5. Performance Check
echo "5. Checking performance metrics..."
RESPONSE_TIME=$(aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name TargetResponseTime \
  --dimensions Name=LoadBalancer,Value="$ALB_FULL_NAME" \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Average \
  --query 'Datapoints[0].Average' \
  --output text \
  --profile university-aws)

if (( $(echo "$RESPONSE_TIME > 3.0" | bc -l) )); then
  echo "⚠️ High response time: ${RESPONSE_TIME}s"
else
  echo "✅ Response time good: ${RESPONSE_TIME}s"
fi

echo "=== Daily health check completed ==="
```

### Cost Monitoring
```bash
#!/bin/bash
# daily-cost-check.sh

# Get yesterday's cost
YESTERDAY_COST=$(aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 day ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[0].Total.BlendedCost.Amount' \
  --output text \
  --profile university-aws)

echo "Yesterday's cost: $${YESTERDAY_COST}"

# Check if exceeding budget
if (( $(echo "$YESTERDAY_COST > 5.0" | bc -l) )); then
  aws sns publish \
    --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
    --subject "Daily Cost Alert - Monitor Legislativo" \
    --message "Yesterday's cost: $${YESTERDAY_COST} exceeded daily budget of $5.00" \
    --profile university-aws
fi
```

## Monitoring & Alerting

### Key Metrics to Monitor

#### Application Metrics
```bash
# Response Time
aws cloudwatch put-metric-alarm \
  --alarm-name "MonitorLegislativo-HighResponseTime" \
  --alarm-description "Alert when response time > 3 seconds" \
  --metric-name TargetResponseTime \
  --namespace AWS/ApplicationELB \
  --statistic Average \
  --period 300 \
  --threshold 3.0 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --profile university-aws

# Error Rate
aws cloudwatch put-metric-alarm \
  --alarm-name "MonitorLegislativo-HighErrorRate" \
  --alarm-description "Alert when 5XX errors > 10 per 5 minutes" \
  --metric-name HTTPCode_Target_5XX_Count \
  --namespace AWS/ApplicationELB \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --profile university-aws
```

#### Infrastructure Metrics
```bash
# CPU Utilization
aws cloudwatch put-metric-alarm \
  --alarm-name "MonitorLegislativo-HighCPU" \
  --alarm-description "Alert when ECS CPU > 85%" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 85 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 3 \
  --dimensions Name=ServiceName,Value=monitor-legislativo-service Name=ClusterName,Value=monitor-legislativo-cluster \
  --alarm-actions arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --profile university-aws

# Database Connections
aws cloudwatch put-metric-alarm \
  --alarm-name "MonitorLegislativo-HighDBConnections" \
  --alarm-description "Alert when RDS connections > 160" \
  --metric-name DatabaseConnections \
  --namespace AWS/RDS \
  --statistic Average \
  --period 300 \
  --threshold 160 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=DBInstanceIdentifier,Value=monitor-legislativo-prod \
  --alarm-actions arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --profile university-aws
```

### Log Analysis
```bash
# Search for errors in application logs
aws logs filter-log-events \
  --log-group-name /ecs/monitor-legislativo-prod \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --filter-pattern "ERROR" \
  --profile university-aws

# Search for specific issues
aws logs filter-log-events \
  --log-group-name /ecs/monitor-legislativo-prod \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --filter-pattern "database connection failed" \
  --profile university-aws
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: High Response Times

**Symptoms:**
- Response time alarms triggered
- Users reporting slow page loads
- CloudWatch showing >3 second response times

**Diagnosis:**
```bash
# Check ECS task CPU/Memory usage
aws ecs describe-services \
  --cluster monitor-legislativo-cluster \
  --services monitor-legislativo-service \
  --profile university-aws

# Check database performance
aws rds describe-db-instances \
  --db-instance-identifier monitor-legislativo-prod \
  --profile university-aws

# Check for database locks
psql $AWS_RDS_URL -c "
  SELECT 
    pid, state, query_start, query
  FROM pg_stat_activity 
  WHERE state != 'idle' 
  ORDER BY query_start ASC;
"
```

**Solutions:**
```bash
# Scale up ECS service immediately
aws ecs update-service \
  --cluster monitor-legislativo-cluster \
  --service monitor-legislativo-service \
  --desired-count 6 \
  --profile university-aws

# Restart application if needed
aws ecs update-service \
  --cluster monitor-legislativo-cluster \
  --service monitor-legislativo-service \
  --force-new-deployment \
  --profile university-aws
```

#### Issue 2: Database Connection Errors

**Symptoms:**
- Application returning 500 errors
- Database connection alarms
- "Max connections reached" in logs

**Diagnosis:**
```bash
# Check current connections
psql $AWS_RDS_URL -c "
  SELECT 
    count(*) as total_connections,
    state,
    application_name
  FROM pg_stat_activity 
  GROUP BY state, application_name;
"

# Check connection limits
psql $AWS_RDS_URL -c "SHOW max_connections;"
```

**Solutions:**
```bash
# Kill idle connections if needed
psql $AWS_RDS_URL -c "
  SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
  WHERE state = 'idle in transaction'
  AND query_start < NOW() - INTERVAL '10 minutes';
"

# Scale up database if needed
aws rds modify-db-instance \
  --db-instance-identifier monitor-legislativo-prod \
  --db-instance-class db.t3.medium \
  --apply-immediately \
  --profile university-aws
```

#### Issue 3: Auto-scaling Not Working

**Symptoms:**
- High CPU/memory but no new tasks starting
- Manual scaling required frequently
- Auto-scaling events not in CloudWatch

**Diagnosis:**
```bash
# Check auto-scaling configuration
aws application-autoscaling describe-scalable-targets \
  --service-namespace ecs \
  --resource-ids service/monitor-legislativo-cluster/monitor-legislativo-service \
  --profile university-aws

# Check scaling policies
aws application-autoscaling describe-scaling-policies \
  --service-namespace ecs \
  --resource-id service/monitor-legislativo-cluster/monitor-legislativo-service \
  --profile university-aws
```

**Solutions:**
```bash
# Re-register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/monitor-legislativo-cluster/monitor-legislativo-service \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 2 \
  --max-capacity 16 \
  --profile university-aws

# Recreate scaling policy
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/monitor-legislativo-cluster/monitor-legislativo-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name cpu-scaling-policy \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleOutCooldown": 300,
    "ScaleInCooldown": 300
  }' \
  --profile university-aws
```

## Emergency Procedures

### Incident Response Playbook

#### Severity 1: Complete Service Outage

**Response Time**: Immediate (0-15 minutes)

**Actions:**
1. **Immediate Assessment**
   ```bash
   # Check all critical components
   curl -f https://monitor-legislativo.mackenzie.br/health
   aws ecs describe-services --cluster monitor-legislativo-cluster --services monitor-legislativo-service
   aws rds describe-db-instances --db-instance-identifier monitor-legislativo-prod
   ```

2. **Emergency Rollback (if recent deployment)**
   ```bash
   # Rollback to previous task definition
   aws ecs update-service \
     --cluster monitor-legislativo-cluster \
     --service monitor-legislativo-service \
     --task-definition monitor-legislativo-prod:PREVIOUS_REVISION
   ```

3. **Scale Up Immediately**
   ```bash
   # Force scale to maximum capacity
   aws ecs update-service \
     --cluster monitor-legislativo-cluster \
     --service monitor-legislativo-service \
     --desired-count 8
   ```

4. **Database Emergency Actions**
   ```bash
   # Check database status
   aws rds describe-db-instances --db-instance-identifier monitor-legislativo-prod
   
   # Failover if Multi-AZ (if needed)
   aws rds reboot-db-instance \
     --db-instance-identifier monitor-legislativo-prod \
     --force-failover
   ```

#### Severity 2: Performance Degradation

**Response Time**: 15-30 minutes

**Actions:**
1. **Performance Tuning**
   ```bash
   # Scale up service
   aws ecs update-service \
     --cluster monitor-legislativo-cluster \
     --service monitor-legislativo-service \
     --desired-count 6
   
   # Check for slow queries
   psql $AWS_RDS_URL -c "
     SELECT query, calls, total_time, mean_time
     FROM pg_stat_statements
     ORDER BY total_time DESC
     LIMIT 10;
   "
   ```

2. **Cache Optimization**
   ```bash
   # Restart Redis if needed
   aws elasticache reboot-cache-cluster \
     --cache-cluster-id monitor-legislativo-redis
   ```

### Communication Templates

#### Incident Notification
```bash
# Send incident notification
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-users \
  --subject "Service Issue - Monitor Legislativo v4" \
  --message "We are currently experiencing technical difficulties. Our team is working to resolve the issue. Updates will be provided every 15 minutes." \
  --profile university-aws
```

#### Resolution Notification
```bash
# Send resolution notification
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-users \
  --subject "Service Restored - Monitor Legislativo v4" \
  --message "The technical issue has been resolved. All services are now operating normally. We apologize for any inconvenience." \
  --profile university-aws
```

## Maintenance Tasks

### Weekly Maintenance (Sundays 2 AM BRT)

#### Database Maintenance
```bash
#!/bin/bash
# weekly-db-maintenance.sh

# Update database statistics
psql $AWS_RDS_URL -c "ANALYZE;"

# Check for unused indexes
psql $AWS_RDS_URL -c "
  SELECT 
    schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
  FROM pg_stat_user_indexes
  WHERE idx_tup_read = 0 AND idx_tup_fetch = 0;
"

# Vacuum large tables
psql $AWS_RDS_URL -c "VACUUM ANALYZE documents;"

# Check database size and growth
psql $AWS_RDS_URL -c "
  SELECT 
    pg_size_pretty(pg_database_size('monitor_legislativo')) as database_size,
    pg_size_pretty(pg_total_relation_size('documents')) as documents_table_size;
"
```

#### Log Rotation and Cleanup
```bash
# Clean up old CloudWatch logs (older than 30 days)
aws logs delete-log-group \
  --log-group-name /ecs/monitor-legislativo-old-logs \
  --profile university-aws

# Export important logs to S3 for long-term storage
aws logs create-export-task \
  --log-group-name /ecs/monitor-legislativo-prod \
  --from $(date -d '7 days ago' +%s)000 \
  --to $(date +%s)000 \
  --destination monitor-legislativo-log-archive \
  --profile university-aws
```

### Monthly Maintenance

#### Security Updates
```bash
# Update ECS task definition with latest base image
aws ecs register-task-definition \
  --family monitor-legislativo-prod \
  --container-definitions file://task-definition.json \
  --profile university-aws

# Deploy updated task definition
aws ecs update-service \
  --cluster monitor-legislativo-cluster \
  --service monitor-legislativo-service \
  --task-definition monitor-legislativo-prod:LATEST \
  --profile university-aws
```

#### Cost Review
```bash
# Generate monthly cost report
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 month ago' +%Y-%m-01),End=$(date +%Y-%m-01) \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --profile university-aws > monthly-cost-report.json

# Check for unused resources
aws ec2 describe-volumes \
  --filters Name=status,Values=available \
  --profile university-aws

aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query 'DBSnapshots[?SnapshotCreateTime<`2024-01-01`]' \
  --profile university-aws
```

This comprehensive operational runbook provides all the necessary procedures for successfully deploying, monitoring, and maintaining the Monitor Legislativo v4 infrastructure on AWS, ensuring reliable service for 500+ concurrent users while optimizing costs through university AWS credits.