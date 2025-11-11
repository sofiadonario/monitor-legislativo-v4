#!/bin/bash

# MCP-Scan Security Scanning Setup Script
# ========================================
# Sets up and runs MCP-Scan for security vulnerability detection

echo "========================================="
echo "MCP-SCAN SECURITY SCANNER SETUP"
echo "========================================="
echo ""

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install Node.js and npm first."
    echo ""
    echo "To install Node.js and npm:"
    echo "  • Visit: https://nodejs.org/"
    echo "  • Or use package manager:"
    echo "    - Ubuntu/Debian: sudo apt install nodejs npm"
    echo "    - MacOS: brew install node"
    echo "    - Windows: Use installer from nodejs.org"
    exit 1
fi

echo "✅ npm is installed"
echo ""

# Function to run security scan
run_security_scan() {
    echo "Running MCP-Scan security analysis..."
    echo "======================================"
    
    # Run MCP-Scan with npx (no installation needed)
    npx -y @invariantlabs/mcp-scan scan \
        --path . \
        --verbose \
        --opt-out \
        --output-format json \
        --output-file security_scan_results.json \
        2>&1 | tee security_scan_output.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo ""
        echo "✅ Security scan completed successfully"
        return 0
    else
        echo ""
        echo "❌ Security scan failed"
        return 1
    fi
}

# Create security scan configuration
echo "Creating scan configuration..."
cat > .mcp-scan.json << 'EOF'
{
  "version": "1.0",
  "scan": {
    "include": [
      "**/*.R",
      "**/*.r",
      "**/*.py",
      "**/*.js",
      "**/*.json",
      "**/*.yml",
      "**/*.yaml",
      "**/*.sh",
      "**/*.toml",
      "**/Dockerfile*"
    ],
    "exclude": [
      "**/node_modules/**",
      "**/venv/**",
      "**/.git/**",
      "**/backup_before_credential_cleanup_*/**",
      "**/renv/**",
      "**/*.RData",
      "**/*.rds",
      "**/*.parquet",
      "**/*.csv"
    ]
  },
  "rules": {
    "credentials": {
      "enabled": true,
      "patterns": [
        "password\\s*=\\s*['\"][^'\"]+['\"]",
        "api[_-]?key\\s*=\\s*['\"][^'\"]+['\"]",
        "secret\\s*=\\s*['\"][^'\"]+['\"]",
        "token\\s*=\\s*['\"][^'\"]+['\"]",
        "DATABASE_URL\\s*=\\s*['\"][^'\"]+['\"]",
        "postgresql://[^\\s]+:[^\\s]+@[^\\s]+",
        "PGPASSWORD\\s*=\\s*[^\\s]+"
      ]
    },
    "security": {
      "enabled": true,
      "checks": [
        "sql-injection",
        "command-injection",
        "path-traversal",
        "insecure-random",
        "hardcoded-credentials",
        "weak-crypto"
      ]
    },
    "dependencies": {
      "enabled": true,
      "check-vulnerabilities": true
    }
  }
}
EOF
echo "✅ Scan configuration created"
echo ""

# Run the security scan
echo "Starting security scan..."
echo "========================="
run_security_scan

echo ""
echo "========================================="
echo "SCAN RESULTS ANALYSIS"
echo "========================================="

# Parse and display results if JSON file exists
if [ -f "security_scan_results.json" ]; then
    echo ""
    echo "Analyzing scan results..."
    
    # Create a Python script to parse results
    cat > parse_scan_results.py << 'EOF'
import json
import sys

def parse_results():
    try:
        with open('security_scan_results.json', 'r') as f:
            results = json.load(f)
        
        print("\n📊 SECURITY SCAN SUMMARY")
        print("=" * 40)
        
        # Count findings by severity
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        if 'findings' in results:
            for finding in results['findings']:
                severity = finding.get('severity', 'info').lower()
                if severity in severities:
                    severities[severity] += 1
        
        # Display summary
        print(f"🔴 Critical: {severities['critical']}")
        print(f"🟠 High: {severities['high']}")
        print(f"🟡 Medium: {severities['medium']}")
        print(f"🟢 Low: {severities['low']}")
        print(f"ℹ️  Info: {severities['info']}")
        print()
        
        # Show critical and high findings
        if 'findings' in results:
            critical_high = [f for f in results['findings'] 
                           if f.get('severity', '').lower() in ['critical', 'high']]
            
            if critical_high:
                print("⚠️  CRITICAL AND HIGH SEVERITY FINDINGS:")
                print("-" * 40)
                for finding in critical_high[:10]:  # Show first 10
                    print(f"• {finding.get('type', 'Unknown')}: {finding.get('file', 'N/A')}")
                    print(f"  Line: {finding.get('line', 'N/A')}")
                    print(f"  Issue: {finding.get('message', 'No description')}")
                    print()
        
        # Save detailed report
        with open('security_scan_report.md', 'w') as f:
            f.write("# Security Scan Report\n\n")
            f.write("## Summary\n\n")
            f.write(f"- Critical Issues: {severities['critical']}\n")
            f.write(f"- High Issues: {severities['high']}\n")
            f.write(f"- Medium Issues: {severities['medium']}\n")
            f.write(f"- Low Issues: {severities['low']}\n")
            f.write(f"- Informational: {severities['info']}\n\n")
            
            if 'findings' in results:
                f.write("## Detailed Findings\n\n")
                for finding in results['findings']:
                    f.write(f"### {finding.get('type', 'Unknown Issue')}\n")
                    f.write(f"- **File**: {finding.get('file', 'N/A')}\n")
                    f.write(f"- **Line**: {finding.get('line', 'N/A')}\n")
                    f.write(f"- **Severity**: {finding.get('severity', 'Unknown')}\n")
                    f.write(f"- **Description**: {finding.get('message', 'No description')}\n\n")
        
        print("📄 Detailed report saved to: security_scan_report.md")
        
    except Exception as e:
        print(f"Error parsing results: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parse_results()
EOF
    
    # Run the parser
    python3 parse_scan_results.py 2>/dev/null || python parse_scan_results.py 2>/dev/null
    
    # Clean up
    rm -f parse_scan_results.py
else
    echo "⚠️ No scan results file found"
fi

echo ""
echo "========================================="
echo "RECOMMENDED ACTIONS"
echo "========================================="
echo ""
echo "1. Review security_scan_report.md for detailed findings"
echo "2. Address all CRITICAL and HIGH severity issues immediately"
echo "3. Plan remediation for MEDIUM severity issues"
echo "4. Consider addressing LOW severity issues"
echo ""
echo "To run scan again:"
echo "  ./scripts/security/mcp_scan_setup.sh"
echo ""
echo "To scan specific directory:"
echo "  npx -y @invariantlabs/mcp-scan scan --path <directory>"
echo ""
echo "========================================="