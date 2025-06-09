#!/bin/bash

set -euo pipefail

# Deploy script for Monitor Legislativo production environment
# This script handles the complete deployment process including infrastructure and application

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${1:-production}"
REGION="${AWS_REGION:-us-east-1}"
CLUSTER_NAME="monitor-legislativo-${ENVIRONMENT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check required tools
    command -v aws >/dev/null 2>&1 || error "AWS CLI not found. Please install AWS CLI."
    command -v kubectl >/dev/null 2>&1 || error "kubectl not found. Please install kubectl."
    command -v terraform >/dev/null 2>&1 || error "Terraform not found. Please install Terraform."
    command -v helm >/dev/null 2>&1 || error "Helm not found. Please install Helm."
    
    # Check AWS credentials
    aws sts get-caller-identity >/dev/null 2>&1 || error "AWS credentials not configured or invalid."
    
    # Check Docker is running
    docker info >/dev/null 2>&1 || error "Docker daemon not running. Please start Docker."
    
    success "Prerequisites check passed"
}

build_and_push_images() {
    log "Building and pushing Docker images..."
    
    # Build API image
    log "Building API image..."
    docker build -t monitor-legislativo/api:latest -f Dockerfile.api "$PROJECT_ROOT"
    
    # Build Web image
    log "Building Web image..."
    docker build -t monitor-legislativo/web:latest -f Dockerfile.web "$PROJECT_ROOT"
    
    # Tag and push to ECR
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local ecr_registry="${account_id}.dkr.ecr.${REGION}.amazonaws.com"
    
    # Login to ECR
    aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ecr_registry"
    
    # Tag and push API image
    docker tag monitor-legislativo/api:latest "${ecr_registry}/monitor-legislativo/api:latest"
    docker tag monitor-legislativo/api:latest "${ecr_registry}/monitor-legislativo/api:$(git rev-parse --short HEAD)"
    docker push "${ecr_registry}/monitor-legislativo/api:latest"
    docker push "${ecr_registry}/monitor-legislativo/api:$(git rev-parse --short HEAD)"
    
    # Tag and push Web image
    docker tag monitor-legislativo/web:latest "${ecr_registry}/monitor-legislativo/web:latest"
    docker tag monitor-legislativo/web:latest "${ecr_registry}/monitor-legislativo/web:$(git rev-parse --short HEAD)"
    docker push "${ecr_registry}/monitor-legislativo/web:latest"
    docker push "${ecr_registry}/monitor-legislativo/web:$(git rev-parse --short HEAD)"
    
    success "Docker images built and pushed successfully"
}

deploy_infrastructure() {
    log "Deploying infrastructure with Terraform..."
    
    cd "$PROJECT_ROOT/infrastructure/terraform"
    
    # Initialize Terraform
    terraform init
    
    # Plan deployment
    terraform plan -var="environment=${ENVIRONMENT}" -var="region=${REGION}" -out=tfplan
    
    # Apply infrastructure
    terraform apply tfplan
    
    # Update kubeconfig
    aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME"
    
    success "Infrastructure deployed successfully"
}

setup_kubernetes_addons() {
    log "Setting up Kubernetes add-ons..."
    
    # Install AWS Load Balancer Controller
    helm repo add eks https://aws.github.io/eks-charts
    helm repo update
    
    helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
        -n kube-system \
        --set clusterName="$CLUSTER_NAME" \
        --set serviceAccount.create=false \
        --set serviceAccount.name=aws-load-balancer-controller
    
    # Install NGINX Ingress Controller
    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
    helm repo update
    
    helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
        -n ingress-nginx \
        --create-namespace \
        --set controller.service.type=LoadBalancer
    
    # Install cert-manager
    helm repo add jetstack https://charts.jetstack.io
    helm repo update
    
    helm upgrade --install cert-manager jetstack/cert-manager \
        -n cert-manager \
        --create-namespace \
        --set installCRDs=true
    
    # Install external-secrets operator
    helm repo add external-secrets https://charts.external-secrets.io
    helm repo update
    
    helm upgrade --install external-secrets external-secrets/external-secrets \
        -n external-secrets-system \
        --create-namespace
    
    success "Kubernetes add-ons installed successfully"
}

deploy_application() {
    log "Deploying application to Kubernetes..."
    
    # Create namespace
    kubectl create namespace monitor-legislativo-production --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply Kubernetes manifests
    kubectl apply -f "$PROJECT_ROOT/k8s/production/"
    
    # Wait for deployments to be ready
    log "Waiting for deployments to be ready..."
    kubectl wait --for=condition=available --timeout=600s deployment/api-service -n monitor-legislativo-production
    kubectl wait --for=condition=available --timeout=600s deployment/web-service -n monitor-legislativo-production
    
    # Create monitoring namespace and deploy monitoring stack
    kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -f "$PROJECT_ROOT/k8s/production/monitoring.yaml"
    
    success "Application deployed successfully"
}

run_post_deployment_checks() {
    log "Running post-deployment checks..."
    
    # Check pod status
    kubectl get pods -n monitor-legislativo-production
    kubectl get pods -n monitoring
    
    # Check service endpoints
    kubectl get svc -n monitor-legislativo-production
    kubectl get ingress -n monitor-legislativo-production
    
    # Wait for ingress to get external IP
    log "Waiting for ingress to get external IP..."
    for i in {1..30}; do
        external_ip=$(kubectl get ingress monitor-legislativo-ingress -n monitor-legislativo-production -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")
        if [[ -n "$external_ip" ]]; then
            success "Ingress external hostname: $external_ip"
            break
        fi
        log "Waiting for external IP... (attempt $i/30)"
        sleep 10
    done
    
    # Test health endpoints
    log "Testing health endpoints..."
    local api_url="http://$(kubectl get svc api-service -n monitor-legislativo-production -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'):80"
    
    if curl -f "$api_url/health" >/dev/null 2>&1; then
        success "API health check passed"
    else
        warning "API health check failed or not yet ready"
    fi
    
    success "Post-deployment checks completed"
}

cleanup() {
    log "Cleaning up temporary files..."
    rm -f "$PROJECT_ROOT/infrastructure/terraform/tfplan"
}

main() {
    log "Starting deployment for environment: $ENVIRONMENT"
    
    trap cleanup EXIT
    
    check_prerequisites
    build_and_push_images
    deploy_infrastructure
    setup_kubernetes_addons
    deploy_application
    run_post_deployment_checks
    
    success "Deployment completed successfully!"
    log "Application should be available at the ingress hostname shown above"
    log "Monitoring dashboard: kubectl port-forward -n monitoring svc/grafana-service 3000:3000"
    log "Prometheus: kubectl port-forward -n monitoring svc/prometheus-service 9090:9090"
}

# Show usage if no arguments provided
if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [environment]"
    echo "Environment: production (default)"
    echo ""
    echo "Example: $0 production"
    exit 1
fi

main "$@"