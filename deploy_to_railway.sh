#!/bin/bash

# Deploy Monitor Legislativo v4 to Railway
# Complete deployment script for R Shiny + Python API services

echo "🚀 Monitor Legislativo v4 - Railway Deployment"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    print_error "Railway CLI not found. Please install it first."
    exit 1
fi

print_status "Railway CLI found: $(railway --version)"

# Check if user is logged in
print_info "Checking Railway authentication..."
if railway status &> /dev/null; then
    print_status "Already logged into Railway"
else
    print_warning "Not logged into Railway"
    echo "Please run: railway login"
    echo "This will open a browser window for authentication"
    echo ""
    read -p "Press Enter after you've completed the login process..."
    
    # Verify login
    if railway status &> /dev/null; then
        print_status "Railway login successful"
    else
        print_error "Railway login failed"
        exit 1
    fi
fi

# Show current project status
print_info "Current Railway project status:"
railway status

echo ""
print_info "Deploying R Shiny service..."

# Navigate to project root
cd "$(dirname "$0")"

# Create railway.toml if it doesn't exist
if [ ! -f "railway.toml" ]; then
    print_warning "Creating railway.toml configuration..."
    cat > railway.toml << 'EOF'
[build]
builder = "dockerfile"
dockerfilePath = "r-shiny-app/Dockerfile"

[deploy]
healthcheckPath = "/health"
healthcheckTimeout = 120
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 3
replicas = 1
EOF
fi

# Deploy R Shiny service
print_info "Deploying R Shiny service to Railway..."
print_warning "This may take 5-10 minutes for the first deployment..."

if railway up; then
    print_status "R Shiny service deployed successfully!"
    
    # Wait a moment for deployment to complete
    sleep 10
    
    # Get the deployment URL
    print_info "Getting deployment URL..."
    DEPLOY_URL=$(railway url 2>/dev/null || echo "URL not available yet")
    
    if [ "$DEPLOY_URL" != "URL not available yet" ]; then
        print_status "Deployment URL: $DEPLOY_URL"
        
        # Test health endpoint
        print_info "Testing health endpoint..."
        if curl -s -f "${DEPLOY_URL}/health" > /dev/null; then
            print_status "Health check passed!"
        else
            print_warning "Health check failed - service may still be starting"
        fi
    else
        print_warning "Deployment URL not available yet. Check Railway dashboard."
    fi
    
    # Set environment variables
    print_info "Setting environment variables..."
    railway env set SHINY_LOG_LEVEL=INFO
    railway env set R_LIBS_USER=/app/renv/library
    railway env set ENVIRONMENT=production
    railway env set PORT=3838
    
    print_status "Environment variables configured"
    
else
    print_error "R Shiny service deployment failed"
    print_info "Check logs with: railway logs"
    exit 1
fi

echo ""
echo "================================================"
echo "🎉 DEPLOYMENT COMPLETE!"
echo "================================================"
echo ""
echo "📊 Service Information:"
echo "───────────────────────────────────────────"
echo "🔗 Railway Dashboard: https://railway.app/dashboard"
echo "📋 View Logs: railway logs"
echo "🔄 Service Status: railway status"
echo ""

if [ "$DEPLOY_URL" != "URL not available yet" ]; then
    echo "🌐 Deployed URLs:"
    echo "───────────────────────────────────────────"
    echo "🔬 R Shiny Service: $DEPLOY_URL"
    echo "📊 Health Check: ${DEPLOY_URL}/health"
    echo "🖥️  React Frontend: https://sofiadonario.github.io/monitor-legislativo-v4/"
    echo ""
fi

echo "🧪 Testing Commands:"
echo "───────────────────────────────────────────"
echo "🔍 View logs: railway logs"
echo "📊 Check health: curl ${DEPLOY_URL}/health"
echo "🔄 Redeploy: railway up"
echo ""

echo "✅ Your R Shiny analytics service is now live!"
echo "🚀 Open your React app to see the integration!"

print_info "Next steps:"
echo "1. Open https://sofiadonario.github.io/monitor-legislativo-v4/"
echo "2. Check the R Shiny status indicator in the dashboard"
echo "3. Click on the R Analytics tab to access advanced features"
echo ""

echo "================================================"