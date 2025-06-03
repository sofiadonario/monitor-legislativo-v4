"""
CDN Cache Integration for Monitor Legislativo v4
Integrates with CDN providers for static content caching

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import hashlib
import logging
import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from urllib.parse import urljoin
import json

logger = logging.getLogger(__name__)

class CDNProvider:
    """Base class for CDN providers"""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def connect(self) -> bool:
        """Initialize CDN connection"""
        try:
            self.session = aiohttp.ClientSession(
                headers=self._get_headers()
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to CDN: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Close CDN connection"""
        if self.session:
            await self.session.close()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {
            "User-Agent": "MonitorLegislativo/4.0",
            "Accept": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def purge(self, urls: List[str]) -> bool:
        """Purge URLs from CDN cache"""
        raise NotImplementedError
    
    async def prefetch(self, urls: List[str]) -> bool:
        """Prefetch URLs into CDN cache"""
        raise NotImplementedError
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get CDN usage statistics"""
        raise NotImplementedError

class CloudflareCDN(CDNProvider):
    """Cloudflare CDN integration"""
    
    def __init__(self, zone_id: str, api_key: str, email: str):
        super().__init__("https://api.cloudflare.com/client/v4", api_key)
        self.zone_id = zone_id
        self.email = email
        
    def _get_headers(self) -> Dict[str, str]:
        """Get Cloudflare-specific headers"""
        headers = super()._get_headers()
        headers["X-Auth-Email"] = self.email
        headers["X-Auth-Key"] = self.api_key
        return headers
    
    async def purge(self, urls: List[str]) -> bool:
        """Purge URLs from Cloudflare cache"""
        if not self.session:
            return False
            
        try:
            endpoint = f"{self.base_url}/zones/{self.zone_id}/purge_cache"
            data = {"files": urls}
            
            async with self.session.post(endpoint, json=data) as response:
                result = await response.json()
                return result.get("success", False)
                
        except Exception as e:
            logger.error(f"Cloudflare purge error: {e}")
            return False
    
    async def prefetch(self, urls: List[str]) -> bool:
        """Cloudflare doesn't support prefetch - use preload instead"""
        # Implement custom prefetch logic if needed
        logger.info("Cloudflare prefetch not implemented")
        return True
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get Cloudflare analytics"""
        if not self.session:
            return {}
            
        try:
            endpoint = f"{self.base_url}/zones/{self.zone_id}/analytics/dashboard"
            params = {"since": "-1440", "until": "0"}  # Last 24 hours
            
            async with self.session.get(endpoint, params=params) as response:
                result = await response.json()
                if result.get("success"):
                    data = result.get("result", {}).get("totals", {})
                    return {
                        "requests": data.get("requests", {}).get("all", 0),
                        "bandwidth": data.get("bandwidth", {}).get("all", 0),
                        "cached": data.get("requests", {}).get("cached", 0),
                        "uncached": data.get("requests", {}).get("uncached", 0)
                    }
                return {}
                
        except Exception as e:
            logger.error(f"Cloudflare stats error: {e}")
            return {}

class FastlyCDN(CDNProvider):
    """Fastly CDN integration"""
    
    def __init__(self, service_id: str, api_key: str):
        super().__init__("https://api.fastly.com", api_key)
        self.service_id = service_id
        
    def _get_headers(self) -> Dict[str, str]:
        """Get Fastly-specific headers"""
        headers = super()._get_headers()
        headers["Fastly-Key"] = self.api_key
        return headers
    
    async def purge(self, urls: List[str]) -> bool:
        """Purge URLs from Fastly cache"""
        if not self.session:
            return False
            
        try:
            results = []
            for url in urls:
                endpoint = f"{self.base_url}/purge/{url}"
                async with self.session.post(endpoint) as response:
                    results.append(response.status == 200)
                    
            return all(results)
            
        except Exception as e:
            logger.error(f"Fastly purge error: {e}")
            return False

class CDNCacheManager:
    """Manages CDN caching strategies"""
    
    def __init__(self):
        self.providers: Dict[str, CDNProvider] = {}
        self.cache_rules: List[Dict[str, Any]] = []
        self.purge_queue: List[str] = []
        self._purge_task: Optional[asyncio.Task] = None
        
    async def add_provider(self, name: str, provider: CDNProvider) -> bool:
        """Add a CDN provider"""
        if await provider.connect():
            self.providers[name] = provider
            logger.info(f"Added CDN provider: {name}")
            return True
        return False
    
    def add_cache_rule(self, pattern: str, ttl: int, provider: str):
        """Add a caching rule"""
        self.cache_rules.append({
            "pattern": pattern,
            "ttl": ttl,
            "provider": provider,
            "created_at": datetime.now()
        })
    
    async def cache_content(self, url: str, content: bytes, content_type: str) -> str:
        """Cache content and return CDN URL"""
        # Generate unique filename
        content_hash = hashlib.sha256(content).hexdigest()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{content_hash[:8]}"
        
        # Determine file extension from content type
        extensions = {
            "application/json": ".json",
            "text/csv": ".csv",
            "application/pdf": ".pdf",
            "image/png": ".png",
            "image/jpeg": ".jpg"
        }
        ext = extensions.get(content_type, "")
        
        cdn_path = f"cache/monitor-legislativo/{filename}{ext}"
        
        # In a real implementation, upload to CDN storage
        # For now, return a mock CDN URL
        return f"https://cdn.example.com/{cdn_path}"
    
    async def purge_url(self, url: str) -> bool:
        """Purge a URL from all CDN providers"""
        results = []
        for name, provider in self.providers.items():
            result = await provider.purge([url])
            results.append(result)
            logger.info(f"Purged {url} from {name}: {result}")
            
        return any(results)
    
    async def purge_pattern(self, pattern: str) -> int:
        """Purge URLs matching pattern"""
        # In a real implementation, would query CDN for matching URLs
        # For now, add to purge queue
        self.purge_queue.append(pattern)
        
        if not self._purge_task or self._purge_task.done():
            self._purge_task = asyncio.create_task(self._process_purge_queue())
            
        return len(self.purge_queue)
    
    async def _process_purge_queue(self):
        """Process purge queue in batches"""
        while self.purge_queue:
            batch = []
            for _ in range(min(100, len(self.purge_queue))):
                if self.purge_queue:
                    batch.append(self.purge_queue.pop(0))
                    
            if batch:
                for provider in self.providers.values():
                    await provider.purge(batch)
                    
            await asyncio.sleep(1)  # Rate limiting
    
    async def get_analytics(self) -> Dict[str, Dict[str, Any]]:
        """Get analytics from all CDN providers"""
        analytics = {}
        for name, provider in self.providers.items():
            analytics[name] = await provider.get_stats()
        return analytics
    
    async def optimize_cache(self) -> Dict[str, Any]:
        """Analyze and optimize cache performance"""
        analytics = await self.get_analytics()
        
        recommendations = []
        total_requests = sum(p.get("requests", 0) for p in analytics.values())
        total_cached = sum(p.get("cached", 0) for p in analytics.values())
        
        if total_requests > 0:
            cache_hit_rate = (total_cached / total_requests) * 100
            
            if cache_hit_rate < 80:
                recommendations.append({
                    "type": "low_hit_rate",
                    "message": f"Cache hit rate is {cache_hit_rate:.1f}%. Consider increasing TTL.",
                    "severity": "medium"
                })
        
        return {
            "analytics": analytics,
            "cache_hit_rate": cache_hit_rate if total_requests > 0 else 0,
            "recommendations": recommendations,
            "rules_count": len(self.cache_rules),
            "providers_count": len(self.providers)
        }
    
    async def close_all(self) -> None:
        """Close all CDN connections"""
        for provider in self.providers.values():
            await provider.disconnect()
        self.providers.clear()
        
        if self._purge_task and not self._purge_task.done():
            self._purge_task.cancel()

# Cache key generators
class CacheKeyGenerator:
    """Generate consistent cache keys for different content types"""
    
    @staticmethod
    def search_results_key(query: str, sources: List[str], page: int = 1) -> str:
        """Generate key for search results"""
        sources_str = "_".join(sorted(sources))
        query_hash = hashlib.md5(query.encode()).hexdigest()[:8]
        return f"search_{query_hash}_{sources_str}_p{page}"
    
    @staticmethod
    def proposition_key(source: str, proposition_id: str) -> str:
        """Generate key for proposition details"""
        return f"prop_{source}_{proposition_id}"
    
    @staticmethod
    def analytics_key(metric_type: str, date_range: str) -> str:
        """Generate key for analytics data"""
        return f"analytics_{metric_type}_{date_range}"
    
    @staticmethod
    def export_key(format: str, timestamp: str) -> str:
        """Generate key for exported files"""
        return f"export_{format}_{timestamp}"

# Global CDN manager
cdn_manager = CDNCacheManager()

# Convenience functions
async def cache_static_content(url: str, content: bytes, content_type: str) -> str:
    """Cache static content to CDN"""
    return await cdn_manager.cache_content(url, content, content_type)

async def purge_cdn_cache(url: str) -> bool:
    """Purge URL from CDN cache"""
    return await cdn_manager.purge_url(url)

async def get_cdn_analytics() -> Dict[str, Dict[str, Any]]:
    """Get CDN analytics"""
    return await cdn_manager.get_analytics()