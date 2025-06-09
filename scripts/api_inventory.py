#!/usr/bin/env python3
"""API endpoint inventory and analysis for Legislative Monitoring System."""

import ast
import json
import re
from datetime import datetime
from pathlib import Path

class APIInventory:
    def __init__(self):
        self.endpoints = []
        self.external_apis = []
        self.api_patterns = []
        
    def scan_flask_routes(self):
        """Scan for Flask route definitions."""
        print("🌐 Scanning Flask routes...")
        
        route_pattern = r'@\w+\.route\s*\(\s*["\']([^"\']+)["\'].*?\)'
        method_pattern = r'methods\s*=\s*\[([^\]]+)\]'
        
        for py_file in Path(".").rglob("*.py"):
            if "venv" in str(py_file):
                continue
                
            try:
                content = py_file.read_text()
                
                # Find all route decorators
                for match in re.finditer(route_pattern, content):
                    endpoint = match.group(1)
                    line_no = content[:match.start()].count('\n') + 1
                    
                    # Extract methods if specified
                    method_match = re.search(method_pattern, content[match.start():match.end()])
                    methods = ["GET"]  # Default
                    if method_match:
                        methods = [m.strip().strip('"\'') for m in method_match.group(1).split(',')]
                    
                    # Find the function name
                    func_pattern = r'def\s+(\w+)\s*\('
                    func_match = re.search(func_pattern, content[match.end():])
                    func_name = func_match.group(1) if func_match else "unknown"
                    
                    self.endpoints.append({
                        "type": "internal",
                        "file": str(py_file),
                        "line": line_no,
                        "endpoint": endpoint,
                        "methods": methods,
                        "function": func_name,
                        "authenticated": self._check_auth_required(content, match.start()),
                        "documented": self._check_documentation(content, match.end()),
                    })
                    
            except Exception as e:
                print(f"Error scanning {py_file}: {e}")
    
    def scan_external_apis(self):
        """Scan for external API calls."""
        print("🔗 Scanning external API usage...")
        
        # Common API patterns
        api_patterns = [
            (r'requests\.\w+\s*\(\s*["\']([^"\']+)["\']', "requests"),
            (r'httpx\.\w+\s*\(\s*["\']([^"\']+)["\']', "httpx"),
            (r'aiohttp\.\w+\s*\(\s*["\']([^"\']+)["\']', "aiohttp"),
            (r'urllib\.request\.urlopen\s*\(\s*["\']([^"\']+)["\']', "urllib"),
        ]
        
        # Known government APIs
        gov_apis = {
            "dadosabertos.camara.leg.br": "Camara API",
            "legis.senado.leg.br": "Senado API",
            "www.planalto.gov.br": "Planalto API",
            "api.anatel.gov.br": "ANATEL API",
            "api.aneel.gov.br": "ANEEL API",
            "api.anvisa.gov.br": "ANVISA API",
        }
        
        for py_file in Path(".").rglob("*.py"):
            if "venv" in str(py_file):
                continue
                
            try:
                content = py_file.read_text()
                
                for pattern, lib in api_patterns:
                    for match in re.finditer(pattern, content):
                        url = match.group(1)
                        line_no = content[:match.start()].count('\n') + 1
                        
                        # Identify API provider
                        provider = "Unknown"
                        for domain, name in gov_apis.items():
                            if domain in url:
                                provider = name
                                break
                        
                        self.external_apis.append({
                            "file": str(py_file),
                            "line": line_no,
                            "url": url,
                            "library": lib,
                            "provider": provider,
                            "has_retry": self._check_retry_logic(content, match.start()),
                            "has_cache": self._check_cache_usage(content, match.start()),
                        })
                        
            except Exception:
                pass
    
    def analyze_api_patterns(self):
        """Analyze API design patterns."""
        print("🔍 Analyzing API patterns...")
        
        # Check for common patterns
        patterns_found = {
            "versioning": False,
            "pagination": False,
            "filtering": False,
            "sorting": False,
            "rate_limiting": False,
            "authentication": False,
            "error_handling": False,
            "caching": False,
        }
        
        # Check internal endpoints for patterns
        for endpoint in self.endpoints:
            if "/v1/" in endpoint["endpoint"] or "/v2/" in endpoint["endpoint"]:
                patterns_found["versioning"] = True
            if "page" in endpoint["endpoint"] or "limit" in endpoint["endpoint"]:
                patterns_found["pagination"] = True
            if endpoint["authenticated"]:
                patterns_found["authentication"] = True
        
        # Check external API usage for patterns
        for api in self.external_apis:
            if api["has_retry"]:
                patterns_found["error_handling"] = True
            if api["has_cache"]:
                patterns_found["caching"] = True
        
        self.api_patterns = patterns_found
    
    def _check_auth_required(self, content, position):
        """Check if endpoint requires authentication."""
        # Look for auth decorators before the route
        auth_patterns = [
            r'@login_required',
            r'@auth_required',
            r'@require_auth',
            r'@jwt_required',
        ]
        
        # Check 200 characters before the route decorator
        check_content = content[max(0, position-200):position]
        for pattern in auth_patterns:
            if re.search(pattern, check_content):
                return True
        return False
    
    def _check_documentation(self, content, position):
        """Check if function has docstring."""
        # Look for docstring after function definition
        check_content = content[position:position+500]
        return '"""' in check_content or "'''" in check_content
    
    def _check_retry_logic(self, content, position):
        """Check for retry logic around API call."""
        check_content = content[max(0, position-500):position+500]
        retry_patterns = ["retry", "retries", "max_attempts", "backoff"]
        return any(pattern in check_content.lower() for pattern in retry_patterns)
    
    def _check_cache_usage(self, content, position):
        """Check for caching around API call."""
        check_content = content[max(0, position-500):position+500]
        cache_patterns = ["cache", "cached", "redis", "memcache"]
        return any(pattern in check_content.lower() for pattern in cache_patterns)
    
    def generate_openapi_stub(self):
        """Generate OpenAPI specification stub."""
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Legislative Monitoring API",
                "version": "1.0.0",
                "description": "API for monitoring Brazilian legislative activities",
            },
            "servers": [
                {"url": "http://localhost:5000", "description": "Development server"},
                {"url": "https://api.legislativo.gov.br", "description": "Production server"},
            ],
            "paths": {},
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                    }
                }
            }
        }
        
        # Add discovered endpoints
        for endpoint in self.endpoints:
            if endpoint["type"] == "internal":
                path = endpoint["endpoint"]
                if path not in openapi_spec["paths"]:
                    openapi_spec["paths"][path] = {}
                
                for method in endpoint["methods"]:
                    openapi_spec["paths"][path][method.lower()] = {
                        "summary": f"{endpoint['function']} operation",
                        "operationId": endpoint["function"],
                        "responses": {
                            "200": {"description": "Successful response"},
                            "400": {"description": "Bad request"},
                            "401": {"description": "Unauthorized"},
                            "500": {"description": "Internal server error"},
                        }
                    }
                    
                    if endpoint["authenticated"]:
                        openapi_spec["paths"][path][method.lower()]["security"] = [{"bearerAuth": []}]
        
        return openapi_spec
    
    def generate_report(self):
        """Generate API inventory report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_internal_endpoints": len(self.endpoints),
                "total_external_apis": len(set(api["provider"] for api in self.external_apis)),
                "authenticated_endpoints": len([e for e in self.endpoints if e["authenticated"]]),
                "documented_endpoints": len([e for e in self.endpoints if e["documented"]]),
            },
            "internal_endpoints": self.endpoints,
            "external_apis": self.external_apis,
            "api_patterns": self.api_patterns,
            "recommendations": [
                "Implement consistent API versioning (e.g., /api/v1/)",
                "Add OpenAPI/Swagger documentation",
                "Implement rate limiting on all endpoints",
                "Add pagination to list endpoints",
                "Standardize error response format",
                "Implement API key management",
                "Add request/response validation",
                "Create API client SDKs",
            ]
        }
        
        # Save report
        report_path = Path("data/reports/api_inventory.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        
        # Save OpenAPI stub
        openapi_spec = self.generate_openapi_stub()
        openapi_path = Path("docs/api/openapi.json")
        openapi_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(openapi_path, "w") as f:
            json.dump(openapi_spec, f, indent=2)
        
        return report, report_path, openapi_path
    
    def run_inventory(self):
        """Run complete API inventory."""
        print("🔎 Legislative Monitoring System - API Inventory")
        print("=" * 60)
        
        self.scan_flask_routes()
        self.scan_external_apis()
        self.analyze_api_patterns()
        
        report, report_path, openapi_path = self.generate_report()
        
        print(f"\n📊 API Inventory Summary:")
        print(f"Internal Endpoints: {report['summary']['total_internal_endpoints']}")
        print(f"External APIs Used: {report['summary']['total_external_apis']}")
        print(f"Authenticated Endpoints: {report['summary']['authenticated_endpoints']}")
        print(f"Documented Endpoints: {report['summary']['documented_endpoints']}")
        
        print(f"\n🔧 API Patterns Found:")
        for pattern, found in report['api_patterns'].items():
            status = "✅" if found else "❌"
            print(f"  {status} {pattern.replace('_', ' ').title()}")
        
        print(f"\n✅ Reports saved:")
        print(f"  - API Inventory: {report_path}")
        print(f"  - OpenAPI Stub: {openapi_path}")

if __name__ == "__main__":
    inventory = APIInventory()
    inventory.run_inventory()