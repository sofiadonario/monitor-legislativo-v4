# Monitor Legislativo v4 - Production Deployment Checklist

## Current Status Summary

### ✅ Completed Tasks
- [x] Sprint 11 integration tests reviewed
- [x] Git status checked (namespace.yaml is new/uncommitted)
- [x] GO_LIVE_CHECKLIST validated
- [x] LAUNCH_GUIDE reviewed
- [x] Docker configurations prepared (Dockerfile, Dockerfile.api, docker-compose.yml)
- [x] Deployment script created (scripts/deploy_production.sh)
- [x] Terraform configurations created:
  - [x] RDS Aurora PostgreSQL (rds.tf)
  - [x] ElastiCache Redis (elasticache.tf)
  - [x] OpenSearch/Elasticsearch (opensearch.tf)
  - [x] EKS Cluster (eks.tf)

### ✅ Recently Completed
- [x] Kubernetes cluster configuration setup
- [x] All Kubernetes manifests created (secrets, deployments, services, ingress)
- [x] Terraform main configuration (main.tf)
- [x] Terraform secrets management (secrets.tf)
- [x] Production environment configuration example (.env.production.example)

### 🚀 Ready for Deployment
- [x] All infrastructure code is ready
- [x] All Kubernetes configurations are complete
- [x] Security configurations are in place
- [x] Monitoring stack is configured

## Infrastructure Components

### 1. Docker Images
- **API Service**: Dockerfile.api
- **Web Service**: Dockerfile.web
- **Worker Service**: Dockerfile.worker
- **Base Image**: Python 3.11-slim with security hardening

### 2. Kubernetes Resources
- **Namespace**: monitor-legislativo-production
- **Deployments**: api-service, web-service, worker-service
- **Services**: LoadBalancer for API, ClusterIP for internal
- **Ingress**: NGINX with SSL termination
- **ConfigMaps**: Application configuration
- **Secrets**: Database, Redis, API keys
- **HPA**: Auto-scaling based on CPU/Memory
- **PDB**: Pod Disruption Budget for high availability

### 3. AWS Resources
- **EKS Cluster**: Production-grade Kubernetes
- **RDS Aurora**: PostgreSQL 15.4, Multi-AZ, encrypted
- **ElastiCache**: Redis 7.0, cluster mode, Multi-AZ
- **OpenSearch**: 2.9, 3 dedicated masters, encrypted
- **S3**: Static assets and backups
- **CloudFront**: CDN for global distribution
- **WAF**: Web Application Firewall
- **Secrets Manager**: Secure credential storage
- **KMS**: Encryption keys management

### 4. Monitoring Stack
- **Prometheus**: Metrics collection
- **Grafana**: Dashboards and visualization
- **CloudWatch**: AWS native monitoring
- **Sentry**: Error tracking
- **ELK Stack**: Log aggregation

## Deployment Steps

### Phase 1: Infrastructure Setup
1. **AWS Account Setup**
   ```bash
   aws configure
   export AWS_REGION=us-east-1
   export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
   ```

2. **Create S3 Backend for Terraform**
   ```bash
   aws s3 mb s3://monitor-legislativo-terraform-state
   ```

3. **Deploy Infrastructure with Terraform**
   ```bash
   cd infrastructure/terraform
   terraform init
   terraform plan -out=tfplan
   terraform apply tfplan
   ```

### Phase 2: Build and Push Images
1. **Build Docker Images**
   ```bash
   docker build -f Dockerfile.api -t monitor-legislativo-api:latest .
   docker build -f Dockerfile.web -t monitor-legislativo-web:latest .
   docker build -f Dockerfile.worker -t monitor-legislativo-worker:latest .
   ```

2. **Push to ECR**
   ```bash
   ./scripts/deploy_production.sh
   ```

### Phase 3: Deploy to Kubernetes
1. **Configure kubectl**
   ```bash
   aws eks update-kubeconfig --name monitor-legislativo-production --region us-east-1
   ```

2. **Apply Kubernetes Resources**
   ```bash
   kubectl apply -f k8s/production/namespace.yaml
   kubectl apply -f k8s/production/secrets.yaml
   kubectl apply -f k8s/production/api-deployment.yaml
   kubectl apply -f k8s/production/web-deployment.yaml
   kubectl apply -f k8s/production/ingress.yaml
   kubectl apply -f k8s/production/monitoring.yaml
   ```

### Phase 4: Post-Deployment
1. **Run Database Migrations**
   ```bash
   kubectl exec -it deployment/api-service -- python -m alembic upgrade head
   ```

2. **Verify Services**
   ```bash
   kubectl get pods -n monitor-legislativo-production
   kubectl get services -n monitor-legislativo-production
   kubectl get ingress -n monitor-legislativo-production
   ```

3. **Test Endpoints**
   ```bash
   curl https://api.monitor-legislativo.gov.br/health
   curl https://api.monitor-legislativo.gov.br/api/v1/status
   ```

## Security Checklist
- [ ] All secrets in AWS Secrets Manager
- [ ] Network policies applied
- [ ] WAF rules configured
- [ ] SSL certificates valid
- [ ] Security groups properly configured
- [ ] IAM roles follow least privilege
- [ ] Container images scanned for vulnerabilities
- [ ] RBAC configured in Kubernetes

## Monitoring Checklist
- [ ] Prometheus scraping all services
- [ ] Grafana dashboards imported
- [ ] Alerts configured in AlertManager
- [ ] CloudWatch alarms set
- [ ] Log aggregation working
- [ ] APM traces visible

## Rollback Plan
1. **Quick Rollback** (< 5 minutes)
   ```bash
   kubectl rollout undo deployment/api-service -n monitor-legislativo-production
   kubectl rollout undo deployment/web-service -n monitor-legislativo-production
   ```

2. **Full Rollback** (< 30 minutes)
   - Restore from previous Terraform state
   - Restore database from snapshot
   - Redeploy previous image versions

## Contact Information
- **DevOps Lead**: [Name] - [Phone]
- **Tech Lead**: Sofia Donario & Lucas Guimarães
- **AWS Support**: Case #[XXXXX]
- **On-Call Engineer**: [Rotation Schedule]

## Final Validation
- [x] Infrastructure code complete
- [x] Kubernetes manifests ready
- [x] Security configurations in place
- [x] Monitoring stack configured
- [x] Documentation updated
- [ ] Infrastructure provisioning pending
- [ ] Application deployment pending

## Deployment Summary
All infrastructure code and configurations have been successfully created:
- ✅ Terraform infrastructure code (VPC, EKS, RDS, ElastiCache, OpenSearch)
- ✅ Kubernetes manifests (deployments, services, ingress, monitoring)
- ✅ Security configurations (secrets, network policies, RBAC)
- ✅ Production environment configuration template
- ✅ Deployment automation scripts

The system is now ready for infrastructure provisioning and application deployment.

---
**Last Updated**: January 6, 2025
**Version**: 1.1.0
**Status**: READY FOR INFRASTRUCTURE PROVISIONING