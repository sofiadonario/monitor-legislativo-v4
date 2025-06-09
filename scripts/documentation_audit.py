#!/usr/bin/env python3
"""Documentation gap analysis for Legislative Monitoring System."""

import ast
import json
from datetime import datetime
from pathlib import Path

class DocumentationAuditor:
    def __init__(self):
        self.missing_docs = []
        self.existing_docs = []
        self.recommendations = []
        
    def analyze_python_files(self):
        """Analyze Python files for documentation."""
        print("📝 Analyzing Python documentation...")
        
        for py_file in Path(".").rglob("*.py"):
            if "venv" in str(py_file) or "__pycache__" in str(py_file):
                continue
                
            try:
                content = py_file.read_text()
                tree = ast.parse(content)
                
                # Check module docstring
                has_module_doc = ast.get_docstring(tree) is not None
                
                # Count documented vs undocumented items
                classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
                functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
                
                documented_classes = sum(1 for c in classes if ast.get_docstring(c))
                documented_functions = sum(1 for f in functions if ast.get_docstring(f))
                
                if not has_module_doc or documented_classes < len(classes) or documented_functions < len(functions):
                    self.missing_docs.append({
                        "file": str(py_file),
                        "module_doc": has_module_doc,
                        "classes": {"total": len(classes), "documented": documented_classes},
                        "functions": {"total": len(functions), "documented": documented_functions},
                    })
                    
            except Exception as e:
                print(f"Error analyzing {py_file}: {e}")
    
    def check_api_documentation(self):
        """Check for API documentation files."""
        print("🌐 Checking API documentation...")
        
        required_api_docs = [
            "docs/api/endpoints.md",
            "docs/api/authentication.md",
            "docs/api/errors.md",
            "docs/api/examples.md",
            "openapi.json",
            "openapi.yaml",
        ]
        
        for doc_path in required_api_docs:
            if not Path(doc_path).exists():
                self.missing_docs.append({
                    "type": "api_documentation",
                    "file": doc_path,
                    "priority": "HIGH"
                })
    
    def check_operational_docs(self):
        """Check for operational documentation."""
        print("🔧 Checking operational documentation...")
        
        required_ops_docs = [
            ("docs/deployment/README.md", "Deployment guide"),
            ("docs/deployment/docker.md", "Docker deployment"),
            ("docs/deployment/kubernetes.md", "Kubernetes deployment"),
            ("docs/monitoring/alerts.md", "Alert configuration"),
            ("docs/monitoring/dashboards.md", "Dashboard setup"),
            ("docs/runbooks/incident-response.md", "Incident response"),
            ("docs/runbooks/backup-restore.md", "Backup procedures"),
            ("docs/runbooks/scaling.md", "Scaling procedures"),
            ("docs/security/authentication.md", "Auth documentation"),
            ("docs/security/authorization.md", "Authorization guide"),
        ]
        
        for doc_path, description in required_ops_docs:
            if not Path(doc_path).exists():
                self.missing_docs.append({
                    "type": "operational",
                    "file": doc_path,
                    "description": description,
                    "priority": "HIGH"
                })
    
    def check_readme_files(self):
        """Check for README files in key directories."""
        print("📚 Checking README files...")
        
        key_directories = [
            "core/api",
            "core/utils",
            "core/models",
            "web",
            "desktop",
            "tests",
            "scripts",
            "configs",
        ]
        
        for directory in key_directories:
            readme_path = Path(directory) / "README.md"
            if not readme_path.exists():
                self.missing_docs.append({
                    "type": "readme",
                    "file": str(readme_path),
                    "priority": "MEDIUM"
                })
    
    def analyze_existing_docs(self):
        """Analyze existing documentation quality."""
        print("📖 Analyzing existing documentation...")
        
        for md_file in Path(".").rglob("*.md"):
            if "venv" in str(md_file):
                continue
                
            try:
                content = md_file.read_text()
                word_count = len(content.split())
                has_toc = "## Table of Contents" in content or "## Contents" in content
                has_examples = "## Example" in content or "```" in content
                
                self.existing_docs.append({
                    "file": str(md_file),
                    "word_count": word_count,
                    "has_toc": has_toc,
                    "has_examples": has_examples,
                    "quality_score": self._calculate_quality_score(word_count, has_toc, has_examples)
                })
                
            except Exception:
                pass
    
    def _calculate_quality_score(self, word_count, has_toc, has_examples):
        """Calculate documentation quality score."""
        score = 0
        if word_count > 100:
            score += 30
        if word_count > 500:
            score += 20
        if has_toc:
            score += 25
        if has_examples:
            score += 25
        return score
    
    def generate_recommendations(self):
        """Generate documentation improvement recommendations."""
        self.recommendations = [
            {
                "priority": "CRITICAL",
                "items": [
                    "Create OpenAPI/Swagger specification for all APIs",
                    "Write deployment guide with step-by-step instructions",
                    "Document authentication and authorization flow",
                    "Create incident response runbooks",
                ]
            },
            {
                "priority": "HIGH",
                "items": [
                    "Add docstrings to all Python modules, classes, and functions",
                    "Create architecture diagrams and system overview",
                    "Write configuration management guide",
                    "Document monitoring and alerting setup",
                ]
            },
            {
                "priority": "MEDIUM",
                "items": [
                    "Add README files to all major directories",
                    "Create developer onboarding guide",
                    "Write testing guide with examples",
                    "Document API versioning strategy",
                ]
            }
        ]
    
    def generate_report(self):
        """Generate documentation audit report."""
        total_missing = len(self.missing_docs)
        total_existing = len(self.existing_docs)
        avg_quality = sum(d["quality_score"] for d in self.existing_docs) / len(self.existing_docs) if self.existing_docs else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_missing_docs": total_missing,
                "total_existing_docs": total_existing,
                "average_quality_score": avg_quality,
                "critical_gaps": len([d for d in self.missing_docs if d.get("priority") == "HIGH"]),
            },
            "missing_documentation": self.missing_docs,
            "existing_documentation": self.existing_docs,
            "recommendations": self.recommendations,
            "documentation_coverage": {
                "api_docs": False,
                "deployment_docs": False,
                "runbooks": False,
                "architecture_docs": False,
                "testing_docs": False,
                "security_docs": False,
            }
        }
        
        report_path = Path("data/reports/documentation_audit.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        
        return report, report_path
    
    def run_audit(self):
        """Run complete documentation audit."""
        print("📋 Legislative Monitoring System - Documentation Audit")
        print("=" * 60)
        
        self.analyze_python_files()
        self.check_api_documentation()
        self.check_operational_docs()
        self.check_readme_files()
        self.analyze_existing_docs()
        self.generate_recommendations()
        
        report, report_path = self.generate_report()
        
        print(f"\n📊 Documentation Audit Summary:")
        print(f"Missing Documentation: {report['summary']['total_missing_docs']}")
        print(f"Existing Documentation: {report['summary']['total_existing_docs']}")
        print(f"Average Quality Score: {report['summary']['average_quality_score']:.1f}/100")
        print(f"Critical Gaps: {report['summary']['critical_gaps']}")
        
        print(f"\n🚨 Critical Documentation Needs:")
        for rec in report['recommendations'][0]['items']:
            print(f"  - {rec}")
        
        print(f"\n✅ Report saved to: {report_path}")

if __name__ == "__main__":
    auditor = DocumentationAuditor()
    auditor.run_audit()