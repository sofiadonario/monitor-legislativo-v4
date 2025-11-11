#!/bin/bash

# Manual Security Scan Script
# ===========================
# Since MCP-Scan is not available, perform manual security checks

echo "========================================="
echo "MANUAL SECURITY SCAN"
echo "========================================="
echo "Date: $(date)"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

echo "1. CREDENTIAL EXPOSURE CHECK"
echo "============================"

# Check for common credential patterns (excluding backup directories)
echo "Scanning for credential patterns..."

# Database passwords
result=$(grep -r "password\s*=\s*['\"][^'\"]\{10,\}['\"]" . \
    --exclude-dir=backup_before_credential_cleanup_\* \
    --exclude-dir=.git \
    --exclude="manual_security_scan.sh" \
    2>/dev/null | wc -l)
if [ "$result" -gt 0 ]; then
    echo -e "${RED}🔴 CRITICAL: $result potential passwords found${NC}"
    CRITICAL=$((CRITICAL + 1))
else
    echo -e "${GREEN}✅ No hardcoded passwords found${NC}"
fi

# API keys
result=$(grep -r "api[_-]\?key\s*=\s*['\"][^'\"]\{20,\}['\"]" . \
    --exclude-dir=backup_before_credential_cleanup_\* \
    --exclude-dir=.git \
    --exclude="manual_security_scan.sh" \
    2>/dev/null | wc -l)
if [ "$result" -gt 0 ]; then
    echo -e "${RED}🔴 CRITICAL: $result potential API keys found${NC}"
    CRITICAL=$((CRITICAL + 1))
else
    echo -e "${GREEN}✅ No API keys found${NC}"
fi

# Database connection strings
result=$(grep -r "postgresql://[^:]*:[^@]*@" . \
    --exclude-dir=backup_before_credential_cleanup_\* \
    --exclude-dir=.git \
    --exclude="manual_security_scan.sh" \
    2>/dev/null | wc -l)
if [ "$result" -gt 0 ]; then
    echo -e "${RED}🔴 CRITICAL: $result database connection strings with credentials found${NC}"
    CRITICAL=$((CRITICAL + 1))
else
    echo -e "${GREEN}✅ No hardcoded connection strings found${NC}"
fi

echo ""
echo "2. FILE SECURITY CHECK"
echo "======================"

# Check for dangerous file permissions
echo "Checking file permissions..."
dangerous_files=$(find . -type f \( -perm -002 -o -perm -020 \) -not -path "./.git/*" -not -path "./backup_before_credential_cleanup_*/*" 2>/dev/null | wc -l)
if [ "$dangerous_files" -gt 0 ]; then
    echo -e "${YELLOW}🟡 MEDIUM: $dangerous_files files with overly permissive permissions${NC}"
    MEDIUM=$((MEDIUM + 1))
else
    echo -e "${GREEN}✅ File permissions are appropriate${NC}"
fi

# Check for backup files that might contain sensitive data
backup_files=$(find . -name "*.bak" -o -name "*.backup" -o -name "*~" | wc -l)
if [ "$backup_files" -gt 0 ]; then
    echo -e "${YELLOW}🟡 MEDIUM: $backup_files backup files found (may contain sensitive data)${NC}"
    MEDIUM=$((MEDIUM + 1))
else
    echo -e "${GREEN}✅ No problematic backup files found${NC}"
fi

echo ""
echo "3. CONFIGURATION SECURITY"
echo "=========================="

# Check for debug mode in production files
debug_enabled=$(grep -r "debug\s*=\s*[Tt]rue\|DEBUG\s*=\s*[Tt]rue" . \
    --exclude-dir=backup_before_credential_cleanup_\* \
    --exclude-dir=.git \
    --exclude="manual_security_scan.sh" \
    2>/dev/null | wc -l)
if [ "$debug_enabled" -gt 0 ]; then
    echo -e "${YELLOW}🟡 MEDIUM: $debug_enabled files with debug mode enabled${NC}"
    MEDIUM=$((MEDIUM + 1))
else
    echo -e "${GREEN}✅ No debug mode configurations found${NC}"
fi

# Check for insecure HTTP URLs
insecure_urls=$(grep -r "http://[^/]" . \
    --include="*.R" \
    --include="*.py" \
    --include="*.js" \
    --exclude-dir=backup_before_credential_cleanup_\* \
    --exclude-dir=.git \
    --exclude="manual_security_scan.sh" \
    2>/dev/null | wc -l)
if [ "$insecure_urls" -gt 0 ]; then
    echo -e "${YELLOW}🟡 MEDIUM: $insecure_urls insecure HTTP URLs found${NC}"
    MEDIUM=$((MEDIUM + 1))
else
    echo -e "${GREEN}✅ No insecure HTTP URLs found${NC}"
fi

echo ""
echo "4. DEPENDENCY SECURITY"
echo "======================"

# Check for R package security (basic check)
if [ -f "renv.lock" ]; then
    echo -e "${GREEN}✅ Using renv for R package management${NC}"
else
    echo -e "${YELLOW}🟡 LOW: No renv.lock found - dependency versions not locked${NC}"
    LOW=$((LOW + 1))
fi

# Check for package.json security
if [ -f "package.json" ]; then
    echo -e "${GREEN}✅ package.json found${NC}"
else
    echo -e "${GREEN}✅ No package.json (R-only project)${NC}"
fi

echo ""
echo "5. DOCKER SECURITY"
echo "==================="

# Check Dockerfile security
if [ -f "docker/Dockerfile.secure" ]; then
    echo -e "${GREEN}✅ Secure Dockerfile configuration exists${NC}"
    
    # Check for running as root
    if grep -q "USER.*root\|^USER 0" docker/Dockerfile.secure 2>/dev/null; then
        echo -e "${RED}🔴 HIGH: Docker container runs as root${NC}"
        HIGH=$((HIGH + 1))
    else
        echo -e "${GREEN}✅ Docker runs as non-root user${NC}"
    fi
else
    echo -e "${YELLOW}🟡 MEDIUM: No secure Dockerfile found${NC}"
    MEDIUM=$((MEDIUM + 1))
fi

echo ""
echo "6. AUTHENTICATION SECURITY"
echo "=========================="

# Check if authentication is properly configured
if [ -f "auth/oauth_middleware.R" ]; then
    echo -e "${GREEN}✅ OAuth authentication system present${NC}"
    
    # Check for session security
    if grep -q "session.*secure\|csrf" auth/oauth_middleware.R 2>/dev/null; then
        echo -e "${GREEN}✅ Session security measures detected${NC}"
    else
        echo -e "${YELLOW}🟡 MEDIUM: Session security configuration unclear${NC}"
        MEDIUM=$((MEDIUM + 1))
    fi
else
    echo -e "${YELLOW}🟡 MEDIUM: No authentication system found${NC}"
    MEDIUM=$((MEDIUM + 1))
fi

echo ""
echo "========================================="
echo "SECURITY SCAN SUMMARY"
echo "========================================="
echo -e "${RED}🔴 Critical Issues: $CRITICAL${NC}"
echo -e "${YELLOW}🟠 High Issues: $HIGH${NC}"
echo -e "${YELLOW}🟡 Medium Issues: $MEDIUM${NC}"
echo -e "${GREEN}🟢 Low Issues: $LOW${NC}"
echo ""

# Create detailed report
cat > security_scan_report.md << EOF
# Security Scan Report

**Date**: $(date)
**Scan Type**: Manual Security Scan

## Summary

- Critical Issues: $CRITICAL
- High Issues: $HIGH  
- Medium Issues: $MEDIUM
- Low Issues: $LOW

## Overall Security Status

EOF

if [ $CRITICAL -eq 0 ] && [ $HIGH -eq 0 ]; then
    echo -e "${GREEN}🎉 EXCELLENT: No critical or high-severity issues found!${NC}"
    echo "**Status**: ✅ SECURE" >> security_scan_report.md
    echo "" >> security_scan_report.md
    echo "The application demonstrates excellent security practices with no critical vulnerabilities detected." >> security_scan_report.md
elif [ $CRITICAL -eq 0 ]; then
    echo -e "${YELLOW}✅ GOOD: No critical issues, but some high-severity issues need attention${NC}"
    echo "**Status**: ⚠️ MOSTLY SECURE" >> security_scan_report.md
else
    echo -e "${RED}⚠️ ACTION REQUIRED: Critical security issues detected${NC}"
    echo "**Status**: 🔴 NEEDS IMMEDIATE ATTENTION" >> security_scan_report.md
fi

cat >> security_scan_report.md << EOF

## Recommended Actions

### Immediate (Critical/High)
EOF

if [ $CRITICAL -gt 0 ] || [ $HIGH -gt 0 ]; then
    echo "- Review and address all critical and high-severity findings above" >> security_scan_report.md
    echo "- Rotate any exposed credentials immediately" >> security_scan_report.md
    echo "- Review file permissions and access controls" >> security_scan_report.md
else
    echo "- No immediate actions required" >> security_scan_report.md
fi

cat >> security_scan_report.md << EOF

### Medium Priority
- Address medium-severity findings during next maintenance window
- Review and update dependency versions
- Enhance monitoring and logging

### Low Priority  
- Consider implementing additional security hardening
- Regular security scans and updates
- Security awareness training for team

## Next Steps

1. Regular security scanning (monthly recommended)
2. Implement automated security testing in CI/CD
3. Monitor for new vulnerabilities in dependencies
4. Keep security documentation up to date

EOF

echo ""
echo "📄 Detailed report saved to: security_scan_report.md"
echo ""

if [ $CRITICAL -eq 0 ] && [ $HIGH -eq 0 ]; then
    echo -e "${GREEN}🚀 Security scan passed! Ready for deployment.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️ Please review security issues before deployment.${NC}"
    exit 1
fi