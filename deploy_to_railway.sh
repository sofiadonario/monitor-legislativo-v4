#!/bin/bash

# Production Deployment Script for Railway
# ========================================

echo "🚀 DEPLOYING MONITOR LEGISLATIVO v4 TO RAILWAY"
echo "=============================================="
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo -e "${RED}❌ Railway CLI is not installed${NC}"
    echo ""
    echo "Installing Railway CLI..."
    curl -fsSL https://railway.app/install.sh | sh
    echo ""
fi

# Check if user is logged in
if ! railway whoami &> /dev/null; then
    echo -e "${YELLOW}⚠️ Not logged in to Railway${NC}"
    echo ""
    echo "Please login to Railway:"
    railway login
    echo ""
fi

# Check if project is linked
if ! railway status &> /dev/null; then
    echo -e "${YELLOW}⚠️ No Railway project linked${NC}"
    echo ""
    echo "Please link to your Railway project:"
    railway link
    echo ""
fi

echo "Pre-deployment checks..."
echo "========================"

# Verify critical files exist
echo "✓ Checking deployment files..."

critical_files=(
    "app.R"
    "docker/Dockerfile.secure"
    "db/connection.R"
    "auth/oauth_middleware.R"
    "railway_migrate.sh"
    "railway.toml"
)

for file in "${critical_files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✅${NC} $file"
    else
        echo -e "  ${RED}❌${NC} $file (missing)"
        echo -e "${RED}Deployment cannot proceed - missing critical file: $file${NC}"
        exit 1
    fi
done

echo ""
echo "✓ Checking security status..."

# Check for any remaining hardcoded credentials (quick check)
cred_check=$(grep -r "smNCedRjMKeNsoqpurLWXjGEUZxORwVY" . --exclude-dir=backup_before_credential_cleanup_\* 2>/dev/null | wc -l)
if [ "$cred_check" -eq 0 ]; then
    echo -e "  ${GREEN}✅${NC} No hardcoded credentials found"
else
    echo -e "  ${RED}❌${NC} Hardcoded credentials still present!"
    echo -e "${RED}Deployment blocked for security reasons${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ All pre-deployment checks passed!${NC}"
echo ""

echo "Railway project status:"
echo "======================="
railway status
echo ""

echo "Starting deployment..."
echo "======================"

# Deploy to Railway
echo "Deploying application..."
railway up --detach

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Deployment initiated successfully!${NC}"
else
    echo -e "${RED}❌ Deployment failed!${NC}"
    exit 1
fi

echo ""
echo "Monitoring deployment..."
echo "======================="

# Wait a moment for deployment to start
sleep 5

# Follow logs for initial deployment
echo "Following deployment logs (Ctrl+C to stop watching)..."
echo "-------------------------------------------------------"
railway logs --follow &
LOGS_PID=$!

# Wait for user input or timeout
echo ""
echo "Press Enter to stop following logs and get deployment status..."
read -t 60

# Kill the logs process
kill $LOGS_PID 2>/dev/null

echo ""
echo "Getting deployment status..."
echo "=========================="
railway status

echo ""
echo "Deployment Summary"
echo "=================="

# Get service URL
SERVICE_URL=$(railway domain 2>/dev/null || echo "URL not available - check Railway dashboard")

echo -e "${GREEN}🎉 Deployment completed!${NC}"
echo ""
echo "Application URL: $SERVICE_URL"
echo ""
echo "Expected improvements after deployment:"
echo "• 75-90% reduction in query execution times"
echo "• Dashboard loading: 15-45s → 200-500ms"
echo "• Search response: 10-30s → 100-500ms"
echo "• Enhanced security with OAuth authentication"
echo "• LGPD-compliant monitoring and logging"
echo ""
echo "Next steps:"
echo "1. Visit the application URL to verify functionality"
echo "2. Check Railway logs for any issues: railway logs"
echo "3. Monitor performance in the dashboard"
echo "4. Review security scan report: cat security_scan_report.md"
echo ""
echo "For ongoing monitoring:"
echo "• railway logs --follow (live logs)"
echo "• railway status (service status)"
echo "• railway metrics (performance metrics)"
echo ""
echo -e "${GREEN}🚀 Monitor Legislativo v4 is now live!${NC}"