"""
Mutation Testing Configuration
Monitor Legislativo v4

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas
Financing: MackPesquisa - Instituto de Pesquisa Mackenzie
"""

import sys
import subprocess
import os
from pathlib import Path

def run_mutation_testing():
    """Run comprehensive mutation testing"""
    
    print("🧬 Starting Mutation Testing for Monitor Legislativo v4")
    print("=" * 60)
    
    # Core modules to test
    modules_to_test = [
        "core/api/base_service.py",
        "core/auth/jwt_manager.py", 
        "core/security/zero_trust.py",
        "core/utils/cache_manager.py",
        "core/utils/smart_retry.py",
        "core/models/models.py"
    ]
    
    mutation_results = {}
    
    for module in modules_to_test:
        if os.path.exists(module):
            print(f"\n🔬 Testing mutations in {module}")
            try:
                # Run mutation testing for each module
                result = subprocess.run([
                    sys.executable, "-m", "mutmut", "run",
                    "--paths-to-mutate", module,
                    "--tests-dir", "tests/",
                    "--runner", "python -m pytest"
                ], capture_output=True, text=True)
                
                mutation_results[module] = {
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
                if result.returncode == 0:
                    print(f"✅ Mutation testing completed for {module}")
                else:
                    print(f"⚠️  Mutation testing had issues for {module}")
                    
            except Exception as e:
                print(f"❌ Error running mutation testing for {module}: {e}")
                mutation_results[module] = {'error': str(e)}
        else:
            print(f"⏭️  Skipping {module} (file not found)")
    
    # Generate mutation testing report
    generate_mutation_report(mutation_results)
    
    return mutation_results

def generate_mutation_report(results):
    """Generate comprehensive mutation testing report"""
    
    report_content = """# Mutation Testing Report
Monitor Legislativo v4

**Developed by:** Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães  
**Organization:** MackIntegridade - Integridade e Monitoramento de Políticas Públicas  
**Financing:** MackPesquisa - Instituto de Pesquisa Mackenzie

## Overview
This report contains the results of mutation testing performed on critical modules of the Monitor Legislativo v4 system.

## Results Summary

"""
    
    total_modules = len(results)
    successful_modules = sum(1 for r in results.values() if r.get('returncode') == 0)
    
    report_content += f"- **Total Modules Tested:** {total_modules}\n"
    report_content += f"- **Successful Tests:** {successful_modules}\n"
    report_content += f"- **Success Rate:** {(successful_modules/total_modules*100):.1f}%\n\n"
    
    report_content += "## Detailed Results\n\n"
    
    for module, result in results.items():
        report_content += f"### {module}\n\n"
        
        if 'error' in result:
            report_content += f"**Status:** ❌ Error  \n**Error:** {result['error']}\n\n"
        elif result.get('returncode') == 0:
            report_content += "**Status:** ✅ Completed Successfully\n\n"
            if result.get('stdout'):
                report_content += f"**Output:**\n```\n{result['stdout'][:500]}...\n```\n\n"
        else:
            report_content += f"**Status:** ⚠️ Issues Detected  \n**Return Code:** {result.get('returncode')}\n\n"
            if result.get('stderr'):
                report_content += f"**Errors:**\n```\n{result['stderr'][:500]}...\n```\n\n"
    
    report_content += """## Recommendations

1. **High Mutation Score:** Modules with high mutation scores indicate robust test suites
2. **Low Mutation Score:** Consider adding more comprehensive tests for modules with low scores
3. **Failed Mutations:** Review and improve test coverage for critical code paths
4. **Performance:** Monitor mutation testing execution time and optimize as needed

## Next Steps

1. Review modules with low mutation scores
2. Add additional unit tests for uncovered code paths
3. Implement property-based testing for complex algorithms
4. Set up automated mutation testing in CI/CD pipeline

---
Generated on: """ + str(subprocess.run(['date'], capture_output=True, text=True).stdout.strip()) + "\n"
    
    # Write report to file
    with open('data/reports/mutation_testing_report.md', 'w') as f:
        f.write(report_content)
    
    print(f"\n📊 Mutation testing report saved to: data/reports/mutation_testing_report.md")

def run_coverage_analysis():
    """Run comprehensive test coverage analysis"""
    
    print("\n📈 Running Coverage Analysis")
    print("=" * 40)
    
    try:
        # Run tests with coverage
        result = subprocess.run([
            sys.executable, "-m", "pytest", "tests/",
            "--cov=core", "--cov=web", "--cov=desktop",
            "--cov-report=html:data/reports/coverage_html",
            "--cov-report=term-missing",
            "--cov-report=json:data/reports/coverage.json"
        ], capture_output=True, text=True)
        
        print("Coverage analysis output:")
        print(result.stdout)
        
        if result.stderr:
            print("Coverage analysis errors:")
            print(result.stderr)
        
        # Generate coverage report
        generate_coverage_report()
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ Error running coverage analysis: {e}")
        return False

def generate_coverage_report():
    """Generate coverage summary report"""
    
    import json
    
    try:
        with open('data/reports/coverage.json', 'r') as f:
            coverage_data = json.load(f)
        
        report_content = """# Test Coverage Report
Monitor Legislativo v4

**Developed by:** Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães  
**Organization:** MackIntegridade - Integridade e Monitoramento de Políticas Públicas  
**Financing:** MackPesquisa - Instituto de Pesquisa Mackenzie

## Coverage Summary

"""
        
        totals = coverage_data.get('totals', {})
        coverage_percent = totals.get('percent_covered', 0)
        
        report_content += f"**Overall Coverage:** {coverage_percent:.1f}%\n"
        report_content += f"**Lines Covered:** {totals.get('covered_lines', 0)}\n"
        report_content += f"**Total Lines:** {totals.get('num_statements', 0)}\n"
        report_content += f"**Missing Lines:** {totals.get('missing_lines', 0)}\n\n"
        
        # Coverage by file
        report_content += "## Coverage by Module\n\n"
        
        files = coverage_data.get('files', {})
        for filepath, file_data in files.items():
            if filepath.startswith('core/') or filepath.startswith('web/') or filepath.startswith('desktop/'):
                percent = file_data.get('summary', {}).get('percent_covered', 0)
                status = "🟢" if percent >= 80 else "🟡" if percent >= 60 else "🔴"
                report_content += f"- {status} **{filepath}:** {percent:.1f}%\n"
        
        report_content += f"\n## Quality Gates\n\n"
        report_content += f"- **Target Coverage:** 85%\n"
        report_content += f"- **Current Coverage:** {coverage_percent:.1f}%\n"
        
        if coverage_percent >= 85:
            report_content += f"- **Status:** ✅ Target Achieved\n"
        else:
            needed = 85 - coverage_percent
            report_content += f"- **Status:** ⚠️ Need {needed:.1f}% more coverage\n"
        
        with open('data/reports/coverage_summary.md', 'w') as f:
            f.write(report_content)
        
        print(f"📊 Coverage report saved to: data/reports/coverage_summary.md")
        
    except Exception as e:
        print(f"Error generating coverage report: {e}")

if __name__ == "__main__":
    # Ensure reports directory exists
    os.makedirs('data/reports', exist_ok=True)
    
    print("🧪 Monitor Legislativo v4 - Quality Assurance Suite")
    print("Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães")
    print("Organization: MackIntegridade")
    print("Financing: MackPesquisa")
    print("=" * 70)
    
    # Run coverage analysis
    coverage_success = run_coverage_analysis()
    
    # Run mutation testing
    mutation_results = run_mutation_testing()
    
    print("\n🎯 Quality Assurance Summary")
    print("=" * 40)
    print(f"Coverage Analysis: {'✅ Success' if coverage_success else '❌ Failed'}")
    print(f"Mutation Testing: ✅ Completed")
    print("\nReports generated in data/reports/")