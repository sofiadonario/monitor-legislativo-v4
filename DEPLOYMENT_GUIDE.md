# Monitor Legislativo v4 - Infrastructure Provisioning & Deployment Guide

## Prerequisites

Before starting, ensure you have:
- AWS CLI installed and configured
- Terraform installed (>= 1.0)
- kubectl installed
- Docker installed
- Helm installed
- AWS account with appropriate permissions

## Step 1: AWS Setup

### 1.1 Configure AWS CLI
```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Default region: us-east-1
# Default output format: json
```

### 1.2 Verify AWS Access
```bash
aws sts get-caller-identity
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "AWS Account ID: $AWS_ACCOUNT_ID"
```

### 1.3 Create S3 Backend for Terraform State
```bash
# Create S3 bucket for Terraform state
aws s3 mb s3://monitor-legislativo-terraform-state --region us-east-1

# Create DynamoDB table for state locking
aws dynamodb create-table \
    --table-name monitor-legislativo-terraform-locks \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1
```

## Step 2: Terraform Infrastructure Provisioning

### 2.1 Initialize Terraform
```bash
cd infrastructure/terraform

# Initialize Terraform
terraform init
```

### 2.2 Review and Plan
```bash
# Review the infrastructure plan
terraform plan -out=tfplan

# Save the plan summary
terraform show -no-color tfplan > tfplan.txt
```

### 2.3 Apply Infrastructure
```bash
# Apply the infrastructure (this will take 15-30 minutes)
terraform apply tfplan

# Save outputs
terraform output -json > terraform-outputs.json
```

## Step 3: Configure kubectl for EKS

### 3.1 Update kubeconfig
```bash
# Get the cluster name from Terraform output
CLUSTER_NAME=$(terraform output -raw cluster_name)

# Configure kubectl
aws eks update-kubeconfig --name $CLUSTER_NAME --region us-east-1

# Verify connection
kubectl get nodes
```

## Step 4: Build and Push Docker Images

### 4.1 Create ECR Repositories
```bash
# Create ECR repositories
aws ecr create-repository --repository-name monitor-legislativo/api --region us-east-1
aws ecr create-repository --repository-name monitor-legislativo/web --region us-east-1
aws ecr create-repository --repository-name monitor-legislativo/worker --region us-east-1

# Get ECR login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
```

### 4.2 Build and Push Images
```bash
# Build images
docker build -f Dockerfile.api -t monitor-legislativo/api:latest .
docker build -f Dockerfile.web -t monitor-legislativo/web:latest .
docker build -f Dockerfile.worker -t monitor-legislativo/worker:latest .

# Tag images
docker tag monitor-legislativo/api:latest $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/api:latest
docker tag monitor-legislativo/web:latest $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/web:latest
docker tag monitor-legislativo/worker:latest $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/worker:latest

# Push images
docker push $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/api:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/web:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/worker:latest
```

## Step 5: Deploy to Kubernetes

### 5.1 Install External Secrets Operator
```bash
# Add External Secrets helm repo
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

# Install External Secrets Operator
helm install external-secrets \
    external-secrets/external-secrets \
    -n external-secrets-system \
    --create-namespace \
    --set installCRDs=true
```

### 5.2 Update Image References
```bash
# Update the image placeholders in deployments
export ECR_REGISTRY="$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com"

# Update API deployment
sed -i "s|PLACEHOLDER_API_IMAGE|$ECR_REGISTRY/monitor-legislativo/api:latest|g" k8s/production/api-deployment.yaml

# Update Web deployment
sed -i "s|monitor-legislativo/web:latest|$ECR_REGISTRY/monitor-legislativo/web:latest|g" k8s/production/web-deployment.yaml
```

### 5.3 Create AWS Secrets
```bash
# Create secrets in AWS Secrets Manager
aws secretsmanager create-secret --name monitor-legislativo/production/database \
    --secret-string '{"password":"GENERATE_STRONG_PASSWORD"}'

aws secretsmanager create-secret --name monitor-legislativo/production/redis \
    --secret-string '{"password":"GENERATE_STRONG_PASSWORD"}'

aws secretsmanager create-secret --name monitor-legislativo/production/jwt \
    --secret-string '{"secret":"GENERATE_STRONG_SECRET"}'

# Add more secrets as needed...
```

### 5.4 Deploy Kubernetes Resources
```bash
# Create namespace
kubectl apply -f k8s/production/namespace.yaml

# Deploy secrets (External Secrets will sync from AWS)
kubectl apply -f k8s/production/secrets.yaml

# Deploy API service
kubectl apply -f k8s/production/api-deployment.yaml

# Deploy Web service
kubectl apply -f k8s/production/web-deployment.yaml

# Deploy Ingress
kubectl apply -f k8s/production/ingress.yaml

# Deploy Monitoring
kubectl apply -f k8s/production/monitoring.yaml
```

## Step 6: Post-Deployment Configuration

### 6.1 Run Database Migrations
```bash
# Get a pod name
API_POD=$(kubectl get pods -n monitor-legislativo-production -l app=api-service -o jsonpath='{.items[0].metadata.name}')

# Run migrations
kubectl exec -it $API_POD -n monitor-legislativo-production -- python -m alembic upgrade head

# Create initial admin user (if needed)
kubectl exec -it $API_POD -n monitor-legislativo-production -- python -m core.cli create-admin
```

### 6.2 Configure DNS
```bash
# Get the Load Balancer URL
LB_URL=$(kubectl get ingress -n monitor-legislativo-production monitor-legislativo-ingress -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "Load Balancer URL: $LB_URL"

# Update Route53 records (or your DNS provider)
# Point monitor-legislativo.gov.br and api.monitor-legislativo.gov.br to the LB
```

### 6.3 Install SSL Certificate
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer for Let's Encrypt
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@monitor-legislativo.gov.br
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

## Step 7: Verification

### 7.1 Check Pod Status
```bash
kubectl get pods -n monitor-legislativo-production
kubectl get services -n monitor-legislativo-production
kubectl get ingress -n monitor-legislativo-production
```

### 7.2 Check Application Health
```bash
# Check API health
curl -k https://api.monitor-legislativo.gov.br/health

# Check Web health
curl -k https://monitor-legislativo.gov.br/health
```

### 7.3 Check Monitoring
```bash
# Port-forward to Grafana
kubectl port-forward -n monitoring svc/grafana-service 3000:3000

# Access Grafana at http://localhost:3000
# Default credentials are in the secrets
```

## Step 8: Enable Auto-scaling and Monitoring

### 8.1 Install Metrics Server
```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

### 8.2 Verify HPA
```bash
kubectl get hpa -n monitor-legislativo-production
```

## Troubleshooting

### Common Issues:

1. **Pods not starting**: Check logs
   ```bash
   kubectl logs -n monitor-legislativo-production <pod-name>
   ```

2. **Database connection issues**: Verify security groups and credentials
   ```bash
   kubectl describe secret -n monitor-legislativo-production monitor-legislativo-secrets
   ```

3. **Ingress not working**: Check ingress controller
   ```bash
   kubectl get pods -n ingress-nginx
   ```

4. **SSL certificate issues**: Check cert-manager logs
   ```bash
   kubectl logs -n cert-manager deployment/cert-manager
   ```

## Rollback Procedure

If needed, rollback deployments:
```bash
# Rollback deployment
kubectl rollout undo deployment/api-service -n monitor-legislativo-production
kubectl rollout undo deployment/web-service -n monitor-legislativo-production

# Destroy infrastructure (CAUTION!)
# terraform destroy
```

## Security Checklist

- [ ] All secrets are in AWS Secrets Manager
- [ ] Network policies are applied
- [ ] SSL certificates are valid
- [ ] WAF rules are configured
- [ ] Security groups are properly configured
- [ ] IAM roles follow least privilege
- [ ] Container images are scanned
- [ ] RBAC is properly configured

## Next Steps

1. Configure monitoring alerts
2. Set up backup automation
3. Configure CI/CD pipeline
4. Perform load testing
5. Document runbooks
6. Train operations team

---
**Important**: Keep this guide updated as the infrastructure evolves.