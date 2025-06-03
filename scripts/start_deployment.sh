#!/bin/bash
# Monitor Legislativo v4 - Infrastructure Deployment Quick Start
# This script helps you start the deployment process

set -e

echo "================================================"
echo "Monitor Legislativo v4 - Infrastructure Deployment"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

echo ""
echo "Checking prerequisites..."
echo ""

# Check AWS CLI
if command_exists aws; then
    print_status "AWS CLI is installed"
    AWS_VERSION=$(aws --version | cut -d' ' -f1 | cut -d'/' -f2)
    echo "   Version: $AWS_VERSION"
else
    print_error "AWS CLI is not installed"
    echo "   Please install: https://aws.amazon.com/cli/"
    exit 1
fi

# Check Terraform
if command_exists terraform; then
    print_status "Terraform is installed"
    TF_VERSION=$(terraform version | head -n1 | cut -d' ' -f2)
    echo "   Version: $TF_VERSION"
else
    print_error "Terraform is not installed"
    echo "   Please install: https://www.terraform.io/downloads"
    exit 1
fi

# Check kubectl
if command_exists kubectl; then
    print_status "kubectl is installed"
    KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null | cut -d' ' -f3)
    echo "   Version: $KUBECTL_VERSION"
else
    print_error "kubectl is not installed"
    echo "   Please install: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

# Check Docker
if command_exists docker; then
    print_status "Docker is installed"
    DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | sed 's/,$//')
    echo "   Version: $DOCKER_VERSION"
else
    print_error "Docker is not installed"
    echo "   Please install: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Helm
if command_exists helm; then
    print_status "Helm is installed"
    HELM_VERSION=$(helm version --short | cut -d' ' -f1)
    echo "   Version: $HELM_VERSION"
else
    print_error "Helm is not installed"
    echo "   Please install: https://helm.sh/docs/intro/install/"
    exit 1
fi

echo ""
echo "Checking AWS credentials..."
echo ""

# Check AWS credentials
if aws sts get-caller-identity >/dev/null 2>&1; then
    print_status "AWS credentials are configured"
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    AWS_USER=$(aws sts get-caller-identity --query Arn --output text | cut -d'/' -f2)
    AWS_REGION=$(aws configure get region)
    echo "   Account ID: $AWS_ACCOUNT_ID"
    echo "   User/Role: $AWS_USER"
    echo "   Region: $AWS_REGION"
else
    print_error "AWS credentials are not configured"
    echo "   Please run: aws configure"
    exit 1
fi

echo ""
echo "================================================"
echo "Pre-deployment checklist:"
echo "================================================"
echo ""

# Check if required files exist
REQUIRED_FILES=(
    "infrastructure/terraform/main.tf"
    "infrastructure/terraform/variables.tf"
    "infrastructure/terraform/secrets.tf"
    "k8s/production/namespace.yaml"
    "k8s/production/api-deployment.yaml"
    "k8s/production/web-deployment.yaml"
    "Dockerfile.api"
    "Dockerfile.web"
)

ALL_FILES_EXIST=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_status "Found: $file"
    else
        print_error "Missing: $file"
        ALL_FILES_EXIST=false
    fi
done

if [ "$ALL_FILES_EXIST" = false ]; then
    echo ""
    print_error "Some required files are missing. Please ensure all files are present."
    exit 1
fi

echo ""
echo "================================================"
echo "Ready to start deployment!"
echo "================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Create Terraform backend:"
echo "   ${GREEN}./scripts/start_deployment.sh setup-backend${NC}"
echo ""
echo "2. Deploy infrastructure:"
echo "   ${GREEN}./scripts/start_deployment.sh deploy-infra${NC}"
echo ""
echo "3. Build and push Docker images:"
echo "   ${GREEN}./scripts/start_deployment.sh build-images${NC}"
echo ""
echo "4. Deploy to Kubernetes:"
echo "   ${GREEN}./scripts/start_deployment.sh deploy-k8s${NC}"
echo ""

# Handle command arguments
case "$1" in
    setup-backend)
        echo "Setting up Terraform backend..."
        echo ""
        
        # Create S3 bucket
        BUCKET_NAME="monitor-legislativo-terraform-state"
        if aws s3 ls "s3://$BUCKET_NAME" 2>&1 | grep -q 'NoSuchBucket'; then
            print_status "Creating S3 bucket: $BUCKET_NAME"
            aws s3 mb "s3://$BUCKET_NAME" --region us-east-1
            aws s3api put-bucket-versioning --bucket "$BUCKET_NAME" --versioning-configuration Status=Enabled
            aws s3api put-bucket-encryption --bucket "$BUCKET_NAME" \
                --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
        else
            print_warning "S3 bucket already exists: $BUCKET_NAME"
        fi
        
        # Create DynamoDB table
        TABLE_NAME="monitor-legislativo-terraform-locks"
        if aws dynamodb describe-table --table-name "$TABLE_NAME" 2>&1 | grep -q 'ResourceNotFoundException'; then
            print_status "Creating DynamoDB table: $TABLE_NAME"
            aws dynamodb create-table \
                --table-name "$TABLE_NAME" \
                --attribute-definitions AttributeName=LockID,AttributeType=S \
                --key-schema AttributeName=LockID,KeyType=HASH \
                --billing-mode PAY_PER_REQUEST \
                --region us-east-1
        else
            print_warning "DynamoDB table already exists: $TABLE_NAME"
        fi
        
        echo ""
        print_status "Terraform backend setup complete!"
        ;;
        
    deploy-infra)
        echo "Deploying infrastructure with Terraform..."
        echo ""
        cd infrastructure/terraform
        
        print_status "Initializing Terraform..."
        terraform init
        
        print_status "Planning infrastructure..."
        terraform plan -out=tfplan
        
        echo ""
        read -p "Do you want to apply this plan? (yes/no): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Applying infrastructure..."
            terraform apply tfplan
            
            print_status "Saving outputs..."
            terraform output -json > terraform-outputs.json
            
            echo ""
            print_status "Infrastructure deployment complete!"
        else
            print_warning "Infrastructure deployment cancelled."
        fi
        cd ../..
        ;;
        
    build-images)
        echo "Building and pushing Docker images..."
        echo ""
        
        # Create ECR repositories
        print_status "Creating ECR repositories..."
        aws ecr create-repository --repository-name monitor-legislativo/api --region us-east-1 2>/dev/null || print_warning "API repository already exists"
        aws ecr create-repository --repository-name monitor-legislativo/web --region us-east-1 2>/dev/null || print_warning "Web repository already exists"
        aws ecr create-repository --repository-name monitor-legislativo/worker --region us-east-1 2>/dev/null || print_warning "Worker repository already exists"
        
        # Login to ECR
        print_status "Logging into ECR..."
        aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com"
        
        # Build images
        print_status "Building Docker images..."
        docker build -f Dockerfile.api -t monitor-legislativo/api:latest .
        docker build -f Dockerfile.web -t monitor-legislativo/web:latest .
        
        # Tag images
        print_status "Tagging images..."
        docker tag monitor-legislativo/api:latest "$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/api:latest"
        docker tag monitor-legislativo/web:latest "$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/web:latest"
        
        # Push images
        print_status "Pushing images to ECR..."
        docker push "$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/api:latest"
        docker push "$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/web:latest"
        
        echo ""
        print_status "Docker images built and pushed successfully!"
        ;;
        
    deploy-k8s)
        echo "Deploying to Kubernetes..."
        echo ""
        
        # Update kubeconfig
        CLUSTER_NAME=$(cd infrastructure/terraform && terraform output -raw cluster_name)
        print_status "Configuring kubectl for cluster: $CLUSTER_NAME"
        aws eks update-kubeconfig --name "$CLUSTER_NAME" --region us-east-1
        
        # Update image references
        print_status "Updating image references..."
        sed -i.bak "s|PLACEHOLDER_API_IMAGE|$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/api:latest|g" k8s/production/api-deployment.yaml
        sed -i.bak "s|monitor-legislativo/web:latest|$AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/monitor-legislativo/web:latest|g" k8s/production/web-deployment.yaml
        
        # Deploy
        print_status "Deploying Kubernetes resources..."
        kubectl apply -f k8s/production/namespace.yaml
        kubectl apply -f k8s/production/secrets.yaml
        kubectl apply -f k8s/production/api-deployment.yaml
        kubectl apply -f k8s/production/web-deployment.yaml
        kubectl apply -f k8s/production/ingress.yaml
        kubectl apply -f k8s/production/monitoring.yaml
        
        echo ""
        print_status "Kubernetes deployment complete!"
        
        # Show status
        echo ""
        echo "Checking deployment status..."
        kubectl get pods -n monitor-legislativo-production
        ;;
        
    *)
        echo "Usage: $0 {setup-backend|deploy-infra|build-images|deploy-k8s}"
        echo ""
        echo "Run without arguments to see the pre-deployment checklist."
        ;;
esac