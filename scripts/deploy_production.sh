#!/bin/bash

# Monitor Legislativo v4 - Production Deployment Script
# This script handles the complete production deployment process

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="monitor-legislativo"
AWS_REGION="us-east-1"
ECR_REGISTRY=""  # To be set after login
ENVIRONMENT="production"

# Function to print colored output
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install kubectl first."
        exit 1
    fi
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    # Check Helm (optional but recommended)
    if ! command -v helm &> /dev/null; then
        warning "Helm is not installed. Some features may not be available."
    fi
    
    log "All prerequisites satisfied."
}

# Build Docker images
build_images() {
    log "Building Docker images..."
    
    # Build API image
    log "Building API image..."
    docker build -f Dockerfile.api -t ${PROJECT_NAME}-api:latest .
    
    # Build Web image
    log "Building Web image..."
    docker build -f Dockerfile.web -t ${PROJECT_NAME}-web:latest .
    
    # Build Worker image
    log "Building Worker image..."
    docker build -f Dockerfile.worker -t ${PROJECT_NAME}-worker:latest .
    
    log "Docker images built successfully."
}

# Tag and push images to ECR
push_to_ecr() {
    log "Logging into AWS ECR..."
    
    # Get ECR login token
    aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}
    
    # Create repositories if they don't exist
    for repo in api web worker; do
        aws ecr describe-repositories --repository-names ${PROJECT_NAME}-${repo} --region ${AWS_REGION} || \
        aws ecr create-repository --repository-name ${PROJECT_NAME}-${repo} --region ${AWS_REGION}
    done
    
    # Tag and push images
    for service in api web worker; do
        log "Pushing ${service} image to ECR..."
        docker tag ${PROJECT_NAME}-${service}:latest ${ECR_REGISTRY}/${PROJECT_NAME}-${service}:latest
        docker push ${ECR_REGISTRY}/${PROJECT_NAME}-${service}:latest
    done
    
    log "Images pushed to ECR successfully."
}

# Create Kubernetes namespace
create_namespace() {
    log "Creating Kubernetes namespace..."
    
    kubectl apply -f k8s/production/namespace.yaml
    
    log "Namespace created."
}

# Deploy secrets
deploy_secrets() {
    log "Deploying secrets..."
    
    # Check if secrets.yaml has placeholders
    if grep -q "PLACEHOLDER" k8s/production/secrets.yaml; then
        error "secrets.yaml contains placeholders. Please update with actual values."
        exit 1
    fi
    
    kubectl apply -f k8s/production/secrets.yaml
    
    log "Secrets deployed."
}

# Deploy database
deploy_database() {
    log "Setting up RDS Aurora PostgreSQL..."
    
    # This would typically use Terraform or AWS CLI
    # For now, we'll assume RDS is provisioned separately
    
    warning "Please ensure RDS Aurora is properly configured with:"
    echo "  - Multi-AZ deployment"
    echo "  - Automated backups"
    echo "  - Encryption at rest"
    echo "  - VPC security groups"
    
    log "Database configuration noted."
}

# Deploy Redis
deploy_redis() {
    log "Setting up ElastiCache Redis..."
    
    # This would typically use Terraform or AWS CLI
    warning "Please ensure ElastiCache Redis is configured with:"
    echo "  - Cluster mode enabled"
    echo "  - Multi-AZ with automatic failover"
    echo "  - Encryption in transit and at rest"
    
    log "Redis configuration noted."
}

# Deploy Elasticsearch
deploy_elasticsearch() {
    log "Setting up OpenSearch/Elasticsearch..."
    
    warning "Please ensure OpenSearch is configured with:"
    echo "  - Multi-AZ deployment"
    echo "  - Dedicated master nodes"
    echo "  - Encryption at rest"
    echo "  - Fine-grained access control"
    
    log "Elasticsearch configuration noted."
}

# Deploy applications
deploy_applications() {
    log "Deploying applications to Kubernetes..."
    
    # Update image references in deployment files
    sed -i "s|PLACEHOLDER_API_IMAGE|${ECR_REGISTRY}/${PROJECT_NAME}-api:latest|g" k8s/production/api-deployment.yaml
    sed -i "s|PLACEHOLDER_WEB_IMAGE|${ECR_REGISTRY}/${PROJECT_NAME}-web:latest|g" k8s/production/web-deployment.yaml
    
    # Apply deployments
    kubectl apply -f k8s/production/api-deployment.yaml
    kubectl apply -f k8s/production/web-deployment.yaml
    
    # Wait for rollout
    kubectl rollout status deployment/api-service -n monitor-legislativo-production
    kubectl rollout status deployment/web-service -n monitor-legislativo-production
    
    log "Applications deployed."
}

# Deploy ingress
deploy_ingress() {
    log "Deploying ingress controller..."
    
    kubectl apply -f k8s/production/ingress.yaml
    
    log "Ingress deployed."
}

# Deploy monitoring
deploy_monitoring() {
    log "Deploying monitoring stack..."
    
    kubectl apply -f k8s/production/monitoring.yaml
    
    # Deploy Prometheus and Grafana
    if command -v helm &> /dev/null; then
        # Add Prometheus community repo
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
        helm repo update
        
        # Install Prometheus Operator
        helm install prometheus prometheus-community/kube-prometheus-stack \
            --namespace monitoring \
            --create-namespace \
            --values monitoring/prometheus-values.yaml
    else
        warning "Helm not installed. Please deploy Prometheus manually."
    fi
    
    log "Monitoring deployed."
}

# Run database migrations
run_migrations() {
    log "Running database migrations..."
    
    # Create a migration job
    kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: db-migration-$(date +%s)
  namespace: monitor-legislativo-production
spec:
  template:
    spec:
      containers:
      - name: migration
        image: ${ECR_REGISTRY}/${PROJECT_NAME}-api:latest
        command: ["python", "-m", "alembic", "upgrade", "head"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: url
      restartPolicy: Never
  backoffLimit: 3
EOF
    
    log "Migration job created."
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Check pod status
    kubectl get pods -n monitor-legislativo-production
    
    # Check services
    kubectl get services -n monitor-legislativo-production
    
    # Get ingress URL
    INGRESS_URL=$(kubectl get ingress -n monitor-legislativo-production -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}')
    
    log "Deployment verification complete."
    log "Application URL: https://${INGRESS_URL}"
}

# Main deployment flow
main() {
    log "Starting production deployment for Monitor Legislativo v4..."
    
    # Check prerequisites
    check_prerequisites
    
    # Get AWS account ID and ECR registry
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    
    # Build and push images
    build_images
    push_to_ecr
    
    # Deploy infrastructure
    create_namespace
    deploy_secrets
    deploy_database
    deploy_redis
    deploy_elasticsearch
    
    # Deploy applications
    deploy_applications
    deploy_ingress
    deploy_monitoring
    
    # Run migrations
    run_migrations
    
    # Verify deployment
    verify_deployment
    
    log "Production deployment completed successfully!"
    log "Please verify all services are running correctly."
}

# Run main function
main "$@"