#!/usr/bin/env python3
"""Generate comprehensive test coverage report for the Legislative Monitoring System."""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

def run_command(cmd, cwd=None):
    """Execute a command and return the result."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, cwd=cwd
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def ensure_test_directories():
    """Create test directory structure if it doesn't exist."""
    test_dirs = [
        "tests/unit/core/api",
        "tests/unit/core/utils",
        "tests/unit/core/models",
        "tests/unit/web",
        "tests/unit/desktop",
        "tests/integration",
        "tests/security",
        "tests/performance",
    ]
    
    for dir_path in test_dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        init_file = Path(dir_path) / "__init__.py"
        if not init_file.exists():
            init_file.write_text("")

def generate_coverage_report():
    """Generate test coverage report."""
    print("🔍 Legislative Monitoring System - Test Coverage Analysis")
    print("=" * 60)
    
    # Ensure test directories exist
    ensure_test_directories()
    
    # Check if virtual environment is activated
    if not os.environ.get("VIRTUAL_ENV"):
        print("⚠️  Warning: Virtual environment not activated")
        print("   Run: python -m venv venv && source venv/bin/activate")
    
    # Install dependencies
    print("\n📦 Installing test dependencies...")
    success, _, _ = run_command("pip install -r requirements-dev.txt")
    if not success:
        print("❌ Failed to install dependencies")
        return
    
    # Run pytest with coverage
    print("\n🧪 Running tests with coverage...")
    success, stdout, stderr = run_command(
        "python -m pytest --cov=core --cov=web --cov=desktop "
        "--cov-report=term-missing --cov-report=html --cov-report=json"
    )
    
    # Parse coverage results
    coverage_file = Path("coverage.json")
    if coverage_file.exists():
        with open(coverage_file) as f:
            coverage_data = json.load(f)
        
        print("\n📊 Coverage Summary:")
        print("-" * 60)
        
        # Overall metrics
        total_lines = coverage_data["totals"]["num_statements"]
        covered_lines = coverage_data["totals"]["covered_lines"]
        coverage_percent = coverage_data["totals"]["percent_covered"]
        
        print(f"Total Lines: {total_lines}")
        print(f"Covered Lines: {covered_lines}")
        print(f"Coverage: {coverage_percent:.2f}%")
        
        # Module breakdown
        print("\n📁 Module Coverage:")
        print("-" * 60)
        
        modules = {}
        for file_path, data in coverage_data["files"].items():
            module = file_path.split("/")[0] if "/" in file_path else "root"
            if module not in modules:
                modules[module] = {"lines": 0, "covered": 0, "files": 0}
            
            modules[module]["lines"] += data["summary"]["num_statements"]
            modules[module]["covered"] += data["summary"]["covered_lines"]
            modules[module]["files"] += 1
        
        for module, stats in sorted(modules.items()):
            if stats["lines"] > 0:
                coverage = (stats["covered"] / stats["lines"]) * 100
                print(f"{module:20} {coverage:6.2f}% ({stats['files']} files)")
    
    # Generate baseline report
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "total_lines": total_lines if 'total_lines' in locals() else 0,
        "covered_lines": covered_lines if 'covered_lines' in locals() else 0,
        "coverage_percent": coverage_percent if 'coverage_percent' in locals() else 0,
        "modules": modules if 'modules' in locals() else {},
        "recommendations": [
            "Create unit tests for all API service classes",
            "Add integration tests for external API calls",
            "Implement security tests for authentication",
            "Add performance benchmarks for critical paths",
            "Mock external dependencies in tests",
        ]
    }
    
    # Save baseline report
    report_path = Path("data/reports/coverage_baseline.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n✅ Baseline report saved to: {report_path}")
    print(f"📈 HTML report available at: htmlcov/index.html")
    
    # Identify untested critical files
    print("\n⚠️  Critical Untested Files:")
    print("-" * 60)
    
    critical_patterns = [
        "api/api_service.py",
        "api/camara_service.py",
        "api/senado_service.py",
        "utils/security.py",
        "utils/cache_manager.py",
    ]
    
    if coverage_file.exists():
        for pattern in critical_patterns:
            found = False
            for file_path in coverage_data["files"]:
                if pattern in file_path:
                    found = True
                    percent = coverage_data["files"][file_path]["summary"]["percent_covered"]
                    if percent < 50:
                        print(f"❌ {file_path}: {percent:.1f}% coverage")
            if not found:
                print(f"❌ {pattern}: No tests found")

if __name__ == "__main__":
    generate_coverage_report()