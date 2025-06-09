"""
API Health Validation Script
Validates all critical API endpoints are working correctly
"""

import asyncio
import aiohttp
import json
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class APIHealthValidator:
    """Validates API health before deployment"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.results = []
    
    async def validate_all_endpoints(self):
        """Validate all critical endpoints"""
        endpoints = [
            {'path': '/health', 'method': 'GET', 'auth': False},
            {'path': '/api/sources', 'method': 'GET', 'auth': False},
            {'path': '/api/status', 'method': 'GET', 'auth': False},
            {'path': '/api/search', 'method': 'GET', 'auth': False, 'params': {'q': 'lei'}},
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                await self.validate_endpoint(session, endpoint)
        
        return self.results
    
    async def validate_endpoint(self, session, endpoint):
        """Validate individual endpoint"""
        url = f"{self.base_url}{endpoint['path']}"
        method = endpoint['method'].lower()
        
        try:
            async with getattr(session, method)(url, params=endpoint.get('params')) as response:
                result = {
                    'endpoint': endpoint['path'],
                    'status': 'PASS' if response.status < 400 else 'FAIL',
                    'status_code': response.status,
                    'response_time': response.headers.get('X-Response-Time', 'N/A')
                }
                
                if response.status >= 400:
                    result['error'] = await response.text()
                
                self.results.append(result)
                logger.info(f"✅ {endpoint['path']}: {result['status']}")
                
        except Exception as e:
            self.results.append({
                'endpoint': endpoint['path'],
                'status': 'ERROR',
                'error': str(e)
            })
            logger.error(f"❌ {endpoint['path']}: ERROR - {e}")

async def main():
    validator = APIHealthValidator('http://localhost:8000')
    results = await validator.validate_all_endpoints()
    
    print("\n🏥 API HEALTH VALIDATION RESULTS:")
    for result in results:
        status_icon = "✅" if result['status'] == 'PASS' else "❌"
        print(f"{status_icon} {result['endpoint']}: {result['status']}")
    
    pass_count = sum(1 for r in results if r['status'] == 'PASS')
    print(f"\n📊 SUMMARY: {pass_count}/{len(results)} endpoints healthy")

if __name__ == "__main__":
    asyncio.run(main())
