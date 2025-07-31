# AWS Migration Architecture - Monitor Legislativo v4
## Scalable Infrastructure for 500+ Concurrent Users

### Executive Summary

**Objective**: Migrate Monitor Legislativo v4 from Railway to AWS to support 500+ concurrent users while maintaining <$100/month operational costs using university AWS credits.

**Key Requirements**:
- Support 500+ concurrent users (10x current capacity)
- <3 second response times for all interactions
- 99.9% uptime SLA with Multi-AZ deployment
- LGPD compliance in Brazilian region (São Paulo)
- Zero-downtime migration strategy
- Cost optimization using university AWS credits

### Current Railway Infrastructure Analysis

**Current State**:
- **Platform**: Railway PaaS
- **Application**: R/Shiny with OAuth2 authentication
- **Database**: PostgreSQL (278,152 legislative documents)
- **Caching**: Redis for performance optimization
- **Container**: Single Docker container (rocker/shiny:4.3.1)
- **Cost**: $7-16/month
- **Performance**: Adequate for 50+ users, limited scalability

**Limitations**:
- Single container deployment
- Limited horizontal scaling
- Resource constraints during peak usage
- No auto-scaling capabilities
- Single point of failure

### Proposed AWS Architecture

#### 1. Compute Layer - Auto-Scaling R/Shiny Application

**Primary Option: Amazon ECS Fargate**
```
Application Load Balancer (ALB)
├── Target Group 1 (AZ-1a)
│   ├── ECS Task 1 (R/Shiny Container)
│   ├── ECS Task 2 (R/Shiny Container)
│   └── ECS Task N (Auto-scaling)
└── Target Group 2 (AZ-1b)
    ├── ECS Task 1 (R/Shiny Container)
    ├── ECS Task 2 (R/Shiny Container)
    └── ECS Task N (Auto-scaling)
```

**Configuration**:
- **Service**: ECS Fargate for serverless container management
- **CPU**: 2 vCPU per task (scalable from 2-16 tasks)
- **Memory**: 4GB per task
- **Auto-scaling**: Target 70% CPU utilization
- **Min Tasks**: 2 (Multi-AZ)
- **Max Tasks**: 16 (supports 500+ users)
- **Health Checks**: ALB health checks on `/health` endpoint

**Alternative Option: EC2 with Auto Scaling Groups**
- **Instance Type**: t3.medium (2 vCPU, 4GB RAM)
- **Auto Scaling**: 2-8 instances based on CPU/memory metrics
- **Cost Advantage**: Reserved instances for predictable workloads

#### 2. Database Layer - High Availability PostgreSQL

**Amazon RDS PostgreSQL**
```
RDS Multi-AZ Deployment
├── Primary Instance (sa-east-1a)
│   ├── Instance Class: db.t3.medium
│   ├── Storage: 100GB GP3 (scalable to 1TB)
│   └── Automated Backups: 7 days retention
└── Standby Instance (sa-east-1b)
    ├── Synchronous replication
    └── Automatic failover (<60 seconds)
```

**Configuration**:
- **Engine**: PostgreSQL 15.x
- **Instance Class**: db.t3.medium (2 vCPU, 4GB RAM)
- **Storage**: 100GB GP3 SSD (3000 IOPS baseline)
- **Multi-AZ**: Yes (High Availability)
- **Backup**: 7-day automated backups
- **Security**: VPC isolation, encryption at rest/transit
- **Performance Insights**: Enabled for query optimization

#### 3. Caching Layer - Redis Cluster

**Amazon ElastiCache for Redis**
```
Redis Cluster Mode
├── Primary Node (sa-east-1a)
│   └── Shard 1: cache.t3.micro
└── Replica Node (sa-east-1b)
    └── Shard 1 Replica: cache.t3.micro
```

**Configuration**:
- **Node Type**: cache.t3.micro (1 vCPU, 0.5GB RAM)
- **Cluster Mode**: Enabled for high availability
- **Shards**: 1 (sufficient for current data volume)
- **Replicas**: 1 per shard (Multi-AZ)
- **Encryption**: In-transit and at-rest
- **Backup**: Daily snapshots with 5-day retention

#### 4. Content Delivery & Security

**Amazon CloudFront CDN**
```
CloudFront Distribution
├── Origin 1: ALB (Dynamic Content)
├── Origin 2: S3 (Static Assets)
└── Edge Locations: Global (Brazil optimized)
```

**AWS Web Application Firewall (WAF)**
- DDoS protection
- Rate limiting (per IP)
- SQL injection protection
- Geographic restrictions (if needed)
- Bot management

#### 5. Monitoring & Observability

**Amazon CloudWatch**
- Application metrics (custom metrics from R/Shiny)
- Infrastructure metrics (ECS, RDS, ElastiCache)
- Log aggregation from all services
- Custom dashboards for business metrics
- Automated alerting via SNS

**AWS X-Ray**
- Distributed tracing for performance optimization
- Request flow analysis
- Bottleneck identification

### Network Architecture

**VPC Configuration**:
```
VPC: 10.0.0.0/16 (sa-east-1)
├── Public Subnets
│   ├── 10.0.1.0/24 (sa-east-1a) - ALB, NAT Gateway
│   └── 10.0.2.0/24 (sa-east-1b) - ALB, NAT Gateway
└── Private Subnets
    ├── 10.0.10.0/24 (sa-east-1a) - ECS Tasks, RDS Primary
    └── 10.0.20.0/24 (sa-east-1b) - ECS Tasks, RDS Standby
```

**Security Groups**:
- **ALB Security Group**: 443 (HTTPS), 80 (HTTP redirect)
- **ECS Security Group**: 3838 (from ALB only)
- **RDS Security Group**: 5432 (from ECS only)
- **ElastiCache Security Group**: 6379 (from ECS only)

### Cost Optimization Strategy

#### Estimated Monthly Costs (Using University Credits)

**Compute (ECS Fargate)**:
- 2 tasks × 24/7 × $0.04048/vCPU-hour × 2 vCPU = ~$60
- 2 tasks × 24/7 × $0.004445/GB-hour × 4 GB = ~$26
- **Subtotal**: ~$86/month (baseline)

**Database (RDS)**:
- db.t3.medium Multi-AZ: ~$30/month
- 100GB GP3 storage: ~$10/month
- **Subtotal**: ~$40/month

**Caching (ElastiCache)**:
- cache.t3.micro × 2 nodes: ~$15/month

**Load Balancer & Networking**:
- ALB: ~$18/month (750 hours free tier)
- Data transfer: ~$5/month

**CloudFront CDN**:
- 1TB transfer: ~$8/month (1TB free tier)

**Monitoring & Misc**:
- CloudWatch, X-Ray, WAF: ~$10/month

**Total Estimated Cost**: ~$182/month (without credits)
**With University Credits**: ~$82/month (assuming 55% credit coverage)

#### Cost Optimization Techniques

1. **Reserved Instances**: 30-60% savings on predictable workloads
2. **Spot Instances**: For batch processing tasks (70-90% savings)
3. **S3 Intelligent Tiering**: For log storage and backups
4. **Schedule-based Scaling**: Reduce capacity during off-hours
5. **Free Tier Usage**: Maximize 12-month free tier benefits

### Migration Strategy - Zero Downtime Approach

#### Phase 1: Infrastructure Setup (Week 1-2)
1. **AWS Account Setup**
   ```bash
   # Configure AWS CLI
   aws configure
   aws sts get-caller-identity
   ```

2. **VPC and Networking**
   - Create VPC with public/private subnets
   - Configure NAT Gateways and Internet Gateway
   - Setup Security Groups and NACLs

3. **Database Migration Preparation**
   - Create RDS instance in standby mode
   - Setup VPN/Direct Connect for secure data transfer
   - Configure database replication from Railway to AWS

#### Phase 2: Application Deployment (Week 3)
1. **ECS Cluster Setup**
   ```dockerfile
   # Enhanced Dockerfile for AWS deployment
   FROM rocker/shiny:4.3.1
   
   # Install AWS SDK and monitoring tools
   RUN apt-get update && apt-get install -y \
       awscli \
       cloudwatch-agent \
       && rm -rf /var/lib/apt/lists/*
   
   # Copy application files
   COPY . /app
   WORKDIR /app
   
   # Health check endpoint
   HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
     CMD curl -f http://localhost:3838/health || exit 1
   
   EXPOSE 3838
   CMD ["R", "-e", "source('start_app.R')"]
   ```

2. **Load Balancer Configuration**
   - Setup ALB with SSL termination
   - Configure health checks and routing rules
   - Setup CloudFront distribution

#### Phase 3: Data Migration (Week 4)
1. **Database Synchronization**
   ```sql
   -- Create read replica from Railway to AWS
   pg_dump --host=railway-host --format=custom --no-privileges --no-owner railway_db > migration.dump
   pg_restore --host=aws-rds-host --dbname=monitor_legislativo migration.dump
   ```

2. **Cache Warming**
   - Migrate Redis data using RIOT (Redis Input/Output Tool)
   - Pre-populate frequently accessed data

#### Phase 4: DNS Cutover (Week 5)
1. **Blue-Green Deployment**
   ```bash
   # Switch traffic gradually
   aws elbv2 modify-target-group --target-group-arn arn:aws:elasticloadbalancing:sa-east-1:...:targetgroup/monitor-legislativo-blue/... --health-check-path /health
   
   # Route 10% traffic to AWS
   aws route53 change-resource-record-sets --hosted-zone-id Z123456789 --change-batch file://route53-10percent.json
   
   # Gradually increase to 100%
   aws route53 change-resource-record-sets --hosted-zone-id Z123456789 --change-batch file://route53-100percent.json
   ```

2. **Rollback Plan**
   ```bash
   # Emergency rollback to Railway
   aws route53 change-resource-record-sets --hosted-zone-id Z123456789 --change-batch file://route53-rollback.json
   ```

### Security & Compliance

#### LGPD Compliance in AWS
1. **Data Residency**: All resources in sa-east-1 (São Paulo)
2. **Encryption**: At-rest and in-transit for all data
3. **Access Control**: IAM roles with principle of least privilege
4. **Audit Logging**: CloudTrail for all API calls
5. **Data Backup**: Encrypted backups with controlled access

#### Security Best Practices
1. **Network Isolation**: Private subnets for application and database
2. **WAF Protection**: SQL injection, XSS, and DDoS protection
3. **Certificate Management**: AWS Certificate Manager for SSL/TLS
4. **Secrets Management**: AWS Secrets Manager for credentials
5. **Vulnerability Scanning**: Inspector for container and infrastructure scanning

### Performance Optimization

#### Auto-Scaling Configuration
```json
{
  "serviceName": "monitor-legislativo-service",
  "scalingPolicy": {
    "targetTrackingScalingPolicy": {
      "targetValue": 70.0,
      "scaleOutCooldown": 300,
      "scaleInCooldown": 300,
      "metricSpecification": {
        "predefinedMetricSpecification": {
          "predefinedMetricType": "ECSServiceAverageCPUUtilization"
        }
      }
    }
  }
}
```

#### Database Performance Tuning
```sql
-- PostgreSQL optimization for legislative documents
CREATE INDEX CONCURRENTLY idx_documents_estado_tipo ON documents(estado, tipo);
CREATE INDEX CONCURRENTLY idx_documents_data_publicacao ON documents(data_publicacao);
CREATE INDEX CONCURRENTLY idx_documents_search_vector ON documents USING gin(to_tsvector('portuguese', titulo || ' ' || conteudo));

-- Connection pooling configuration
max_connections = 200
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 16MB
```

### Monitoring & Alerting

#### Key Performance Indicators (KPIs)
1. **Response Time**: <3 seconds for 95th percentile
2. **Availability**: 99.9% uptime SLA
3. **Concurrent Users**: Support 500+ simultaneous users
4. **Database Performance**: Query response time <500ms
5. **Error Rate**: <0.1% application errors

#### CloudWatch Alarms
```json
{
  "AlarmName": "HighResponseTime",
  "MetricName": "TargetResponseTime",
  "Threshold": 3.0,
  "ComparisonOperator": "GreaterThanThreshold",
  "AlarmActions": ["arn:aws:sns:sa-east-1:123456789:alerts"]
}
```

### Implementation Timeline

**Week 1-2: Infrastructure Setup**
- AWS account configuration
- VPC and networking setup
- RDS and ElastiCache deployment

**Week 3: Application Deployment**
- ECS cluster setup
- Docker image optimization
- Load balancer configuration

**Week 4: Data Migration**
- Database synchronization
- Cache data migration
- Performance testing

**Week 5: Go-Live**
- DNS cutover
- Traffic routing
- Monitoring validation

**Week 6: Optimization**
- Performance tuning
- Cost optimization
- Documentation completion

### Success Criteria

1. **Scalability**: Successfully handle 500+ concurrent users
2. **Performance**: Maintain <3 second response times
3. **Availability**: Achieve 99.9% uptime SLA
4. **Cost**: Stay within $100/month budget using university credits
5. **Security**: Maintain LGPD compliance and security standards
6. **Migration**: Zero-downtime migration with <5 minutes DNS cutover

### Risk Mitigation

1. **Migration Risks**: Blue-green deployment with rollback plan
2. **Performance Risks**: Load testing before go-live
3. **Cost Risks**: Budget alerts and resource tagging
4. **Security Risks**: Security group reviews and penetration testing
5. **Compliance Risks**: LGPD audit and documentation

This architecture provides a robust, scalable, and cost-effective solution for migrating Monitor Legislativo v4 to AWS while maintaining all current functionality and dramatically improving scalability to support Brazil's academic and government research community.