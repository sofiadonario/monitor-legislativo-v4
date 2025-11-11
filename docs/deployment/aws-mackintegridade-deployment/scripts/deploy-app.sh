#!/bin/bash
# Deploy Monitor Legislativo v4 to AWS ECS as part of Mackintegridade
# Usage: ./deploy-app.sh [environment]

set -e

# Configuration
ENVIRONMENT=${1:-production}
AWS_REGION="us-east-1"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REPOSITORY="mackintegridade-transport-monitor/api"
ECS_CLUSTER="mackintegridade-cluster"
ECS_SERVICE="transport-monitor-api"
STACK_NAME="mackintegridade-transport-monitor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Monitor Legislativo to Mackintegridade Platform${NC}"
echo -e "Environment: ${YELLOW}${ENVIRONMENT}${NC}"
echo -e "URL: ${YELLOW}https://www.mackenzie.br/mackintegridade/energia/transporte${NC}"

# Step 1: Build Docker image
echo -e "\n${GREEN}📦 Building Docker image...${NC}"
cd ../..
docker build -t ${ECR_REPOSITORY}:${ENVIRONMENT} -f aws-mackintegridade-deployment/docker/Dockerfile .

# Step 2: Tag for ECR
echo -e "\n${GREEN}🏷️  Tagging image for ECR...${NC}"
docker tag ${ECR_REPOSITORY}:${ENVIRONMENT} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${ENVIRONMENT}
docker tag ${ECR_REPOSITORY}:${ENVIRONMENT} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:latest

# Step 3: Login to ECR
echo -e "\n${GREEN}🔐 Logging into ECR...${NC}"
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Step 4: Push to ECR
echo -e "\n${GREEN}📤 Pushing image to ECR...${NC}"
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${ENVIRONMENT}
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:latest

# Step 5: Update ECS Service
echo -e "\n${GREEN}🔄 Updating ECS service...${NC}"
aws ecs update-service \
    --cluster ${ECS_CLUSTER} \
    --service ${ECS_SERVICE} \
    --force-new-deployment \
    --region ${AWS_REGION}

# Step 6: Wait for deployment to stabilize
echo -e "\n${GREEN}⏳ Waiting for deployment to stabilize...${NC}"
aws ecs wait services-stable \
    --cluster ${ECS_CLUSTER} \
    --services ${ECS_SERVICE} \
    --region ${AWS_REGION}

# Step 7: Get service info
echo -e "\n${GREEN}✅ Deployment complete!${NC}"
echo -e "\n${GREEN}📊 Service Status:${NC}"
aws ecs describe-services \
    --cluster ${ECS_CLUSTER} \
    --services ${ECS_SERVICE} \
    --region ${AWS_REGION} \
    --query 'services[0].{DesiredCount:desiredCount,RunningCount:runningCount,PendingCount:pendingCount,Status:status}' \
    --output table

# Step 8: Get Load Balancer URL
ALB_DNS=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
    --output text \
    --region ${AWS_REGION})

echo -e "\n${GREEN}🌐 Application URLs:${NC}"
echo -e "Internal ALB: ${YELLOW}http://${ALB_DNS}${NC}"
echo -e "Public URL: ${YELLOW}https://www.mackenzie.br/mackintegridade/energia/transporte${NC}"

# Step 9: Health check
echo -e "\n${GREEN}🏥 Running health check...${NC}"
sleep 10
if curl -f -s "http://${ALB_DNS}/health" > /dev/null; then
    echo -e "${GREEN}✅ Health check passed!${NC}"
else
    echo -e "${RED}❌ Health check failed. Please check ECS logs.${NC}"
    exit 1
fi

echo -e "\n${GREEN}🎉 Monitor Legislativo successfully deployed to Mackintegridade!${NC}"
echo -e "${GREEN}📍 Access at: https://www.mackenzie.br/mackintegridade/energia/transporte${NC}"