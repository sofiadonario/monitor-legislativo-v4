#!/bin/bash

# =============================================================================
# SECURITY CONFIGURATION VERIFICATION SCRIPT
# Quick validation of security setup
# =============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔍 Verifying Security Configuration..."

# Check 1: Verify dangerous file exclusion
echo -n "Checking .dockerignore excludes CLOUD_RUN_PRODUCTION_DB_FIX.R... "
if grep -q "CLOUD_RUN_PRODUCTION_DB_FIX.R" .dockerignore; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC} - Add CLOUD_RUN_PRODUCTION_DB_FIX.R to .dockerignore!"
    exit 1
fi

# Check 2: Verify secure Dockerfile exists
echo -n "Checking secure Dockerfile exists... "
if [ -f "docker/Dockerfile.secure" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC} - docker/Dockerfile.secure not found!"
    exit 1
fi

# Check 3: Verify Dockerfile uses non-root user
echo -n "Checking Dockerfile uses non-root user... "
if grep -q "USER shinyapp" docker/Dockerfile.secure; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC} - Dockerfile should specify 'USER shinyapp'"
    exit 1
fi

# Check 4: Verify Cloud Run deployment config exists
echo -n "Checking Cloud Run deployment configuration... "
if [ -f "cloudbuild.yaml" ] || [ -f "Dockerfile" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC} - cloudbuild.yaml or Dockerfile not found!"
    exit 1
fi

# Check 5: Verify security scan script is executable
echo -n "Checking security scan script permissions... "
if [ -x "scripts/security_scan.sh" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${YELLOW}⚠️ WARN${NC} - Making security_scan.sh executable..."
    chmod +x scripts/security_scan.sh
fi

# Check 6: Verify dangerous file doesn't exist in expected locations
echo -n "Checking for dangerous file in application... "
dangerous_file_found=false
if [ -f "CLOUD_RUN_PRODUCTION_DB_FIX.R" ]; then
    echo -e "${YELLOW}⚠️ WARNING${NC} - CLOUD_RUN_PRODUCTION_DB_FIX.R exists in root (will be excluded from Docker build)"
    dangerous_file_found=true
fi

if find modules/ data/ fixes/ scripts/ -name "CLOUD_RUN_PRODUCTION_DB_FIX.R" 2>/dev/null | grep -q .; then
    echo -e "${RED}❌ FAIL${NC} - CLOUD_RUN_PRODUCTION_DB_FIX.R found in application directories!"
    exit 1
fi

if [ "$dangerous_file_found" = false ]; then
    echo -e "${GREEN}✅ PASS${NC}"
fi

echo ""
echo "🎉 Security configuration verification completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Run comprehensive security scan: ./scripts/security_scan.sh"
echo "2. Deploy with: gcloud run deploy mackmonitor --source ."
echo "3. Set secrets via Google Cloud Console (never hardcode!)"
echo "4. Monitor security scan reports in security_reports/ directory"
echo ""
echo "📖 For detailed instructions, see: docker/DOCKER_SECURITY_GUIDE.md"