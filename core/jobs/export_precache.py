"""
Export Pre-cache Job for Monitor Legislativo
Background job to pre-generate common exports for faster user experience
"""

import json
import hashlib
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

from core.cache.cache_manager import get_cache_manager
from core.utils.export_service import ExportService
from core.api.api_service import APIService

logger = logging.getLogger(__name__)


class ExportPreCacheJob:
    """
    Background job to pre-generate commonly requested exports
    
    Features:
    - Pre-generates exports for popular queries
    - Multiple format support (CSV, XLSX, PDF, JSON)
    - Smart cache warming based on usage patterns
    - Async processing for better performance
    """
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
        self.export_service = ExportService()
        self.api_service = APIService()
        
        # Common queries to pre-cache
        self.common_queries = [
            {
                'term': 'transporte',
                'sources': ['antt', 'anac', 'antaq'],
                'period': 'last_30_days',
                'priority': 'high'
            },
            {
                'term': 'saúde',
                'sources': ['anvisa', 'ans'],
                'period': 'last_30_days',
                'priority': 'high'
            },
            {
                'term': 'educação',
                'sources': ['camara', 'senado'],
                'period': 'last_30_days',
                'priority': 'medium'
            },
            {
                'term': 'energia',
                'sources': ['aneel', 'anp'],
                'period': 'last_30_days',
                'priority': 'medium'
            },
            {
                'term': 'telecomunicações',
                'sources': ['anatel'],
                'period': 'last_30_days',
                'priority': 'low'
            },
            {
                'term': 'meio ambiente',
                'sources': ['ana', 'anm'],
                'period': 'last_30_days',
                'priority': 'low'
            }
        ]
        
        # Export formats to pre-generate
        self.export_formats = ['csv', 'xlsx', 'json']  # PDF is heavy, generate on-demand
        
        # Cache TTLs by priority
        self.cache_ttls = {
            'high': 21600,    # 6 hours
            'medium': 43200,  # 12 hours
            'low': 86400      # 24 hours
        }
    
    async def run_daily(self):
        """Daily job to pre-cache common exports"""
        logger.info("Starting daily export pre-cache job")
        
        try:
            await self._warm_common_exports()
            await self._cleanup_stale_exports()
            await self._update_usage_patterns()
            
            logger.info("Daily export pre-cache job completed successfully")
            
        except Exception as e:
            logger.error(f"Daily pre-cache job failed: {e}")
            raise
    
    async def run_hourly(self):
        """Hourly job to refresh high-priority exports"""
        logger.info("Starting hourly export pre-cache job")
        
        try:
            high_priority_queries = [q for q in self.common_queries if q['priority'] == 'high']
            await self._warm_exports(high_priority_queries)
            
            logger.info("Hourly export pre-cache job completed successfully")
            
        except Exception as e:
            logger.error(f"Hourly pre-cache job failed: {e}")
    
    async def _warm_common_exports(self):
        """Pre-generate exports for common queries"""
        tasks = []
        
        for query in self.common_queries:
            for format_type in self.export_formats:
                task = self._generate_and_cache_export(query, format_type)
                tasks.append(task)
        
        # Process in batches to avoid overwhelming the system
        batch_size = 5
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            
            # Small delay between batches
            await asyncio.sleep(1)
    
    async def _warm_exports(self, queries: List[Dict]):
        """Warm exports for specific queries"""
        tasks = []
        
        for query in queries:
            for format_type in self.export_formats:
                cache_key = self._generate_cache_key(query, format_type)
                
                # Check if already cached
                if not self.cache_manager.get(cache_key):
                    task = self._generate_and_cache_export(query, format_type)
                    tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _generate_and_cache_export(self, query: Dict, format_type: str):
        """Generate and cache a single export"""
        try:
            # Generate cache key
            cache_key = self._generate_cache_key(query, format_type)
            
            logger.info(f"Generating export: {cache_key}")
            
            # Fetch data
            data = await self._fetch_data(query)
            
            if not data:
                logger.warning(f"No data found for query: {query}")
                return
            
            # Generate export
            export_content = await self._generate_export(data, format_type, query)
            
            # Cache the export
            ttl = self.cache_ttls.get(query['priority'], 86400)
            
            export_metadata = {
                'content': export_content,
                'format': format_type,
                'query': query,
                'generated_at': datetime.utcnow().isoformat(),
                'size_bytes': len(export_content) if isinstance(export_content, (str, bytes)) else 0,
                'record_count': len(data) if isinstance(data, list) else 0
            }
            
            self.cache_manager.set(cache_key, export_metadata, ttl)
            
            logger.info(f"Cached export: {cache_key} ({export_metadata['size_bytes']} bytes)")
            
        except Exception as e:
            logger.error(f"Failed to generate export for {query} ({format_type}): {e}")
    
    def _generate_cache_key(self, query: Dict, format_type: str) -> str:
        """Generate cache key for export"""
        # Create deterministic hash from query
        query_str = json.dumps(query, sort_keys=True)
        query_hash = hashlib.md5(query_str.encode()).hexdigest()[:12]
        
        return f"export:{query_hash}:{format_type}"
    
    async def _fetch_data(self, query: Dict) -> List[Dict]:
        """Fetch data for query"""
        try:
            # Build search parameters
            search_params = {
                'term': query['term'],
                'sources': query['sources'],
                'limit': 1000  # Reasonable limit for exports
            }
            
            # Add date range if specified
            if query.get('period'):
                search_params.update(self._parse_period(query['period']))
            
            # Fetch from API service
            results = await self.api_service.search_proposals(search_params)
            
            return results.get('data', [])
            
        except Exception as e:
            logger.error(f"Failed to fetch data for query {query}: {e}")
            return []
    
    async def _generate_export(self, data: List[Dict], format_type: str, query: Dict) -> str:
        """Generate export in specified format"""
        try:
            export_config = {
                'title': f"Monitor Legislativo - {query['term']}",
                'description': f"Dados de {query.get('period', 'período especificado')}",
                'generated_at': datetime.utcnow().isoformat(),
                'sources': query.get('sources', []),
                'query': query
            }
            
            if format_type == 'csv':
                return await self.export_service.generate_csv(data, export_config)
            elif format_type == 'xlsx':
                return await self.export_service.generate_xlsx(data, export_config)
            elif format_type == 'json':
                return await self.export_service.generate_json(data, export_config)
            elif format_type == 'pdf':
                return await self.export_service.generate_pdf(data, export_config)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
        except Exception as e:
            logger.error(f"Failed to generate {format_type} export: {e}")
            raise
    
    def _parse_period(self, period: str) -> Dict[str, str]:
        """Parse period string into date range"""
        now = datetime.utcnow()
        
        if period == 'last_7_days':
            start_date = now - timedelta(days=7)
        elif period == 'last_30_days':
            start_date = now - timedelta(days=30)
        elif period == 'last_90_days':
            start_date = now - timedelta(days=90)
        else:
            start_date = now - timedelta(days=30)  # Default
        
        return {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': now.strftime('%Y-%m-%d')
        }
    
    async def _cleanup_stale_exports(self):
        """Clean up old cached exports"""
        try:
            # This would scan for old export cache keys and remove them
            pattern = "export:*"
            
            # Get all export cache keys
            # In production, you'd implement a more efficient cleanup
            logger.info("Cleaning up stale exports")
            
            # For now, just log - actual cleanup would depend on Redis SCAN
            # self.cache_manager.invalidate_pattern(pattern)
            
        except Exception as e:
            logger.error(f"Failed to cleanup stale exports: {e}")
    
    async def _update_usage_patterns(self):
        """Update common queries based on usage patterns"""
        try:
            # This would analyze actual usage to update common_queries
            # For now, just log
            logger.info("Updating usage patterns")
            
            # In production, you'd:
            # 1. Analyze export request logs
            # 2. Identify most requested queries
            # 3. Update self.common_queries accordingly
            
        except Exception as e:
            logger.error(f"Failed to update usage patterns: {e}")
    
    def get_cache_status(self) -> Dict[str, Any]:
        """Get status of cached exports"""
        status = {
            'total_cached': 0,
            'by_format': {},
            'by_priority': {},
            'cache_size_mb': 0
        }
        
        try:
            # Count cached exports
            for query in self.common_queries:
                for format_type in self.export_formats:
                    cache_key = self._generate_cache_key(query, format_type)
                    cached = self.cache_manager.get(cache_key)
                    
                    if cached:
                        status['total_cached'] += 1
                        
                        # Count by format
                        if format_type not in status['by_format']:
                            status['by_format'][format_type] = 0
                        status['by_format'][format_type] += 1
                        
                        # Count by priority
                        priority = query['priority']
                        if priority not in status['by_priority']:
                            status['by_priority'][priority] = 0
                        status['by_priority'][priority] += 1
                        
                        # Add to size
                        if isinstance(cached, dict) and 'size_bytes' in cached:
                            status['cache_size_mb'] += cached['size_bytes'] / 1048576
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get cache status: {e}")
            return status


# Singleton instance
_precache_job: Optional[ExportPreCacheJob] = None


def get_precache_job() -> ExportPreCacheJob:
    """Get or create precache job singleton"""
    global _precache_job
    if _precache_job is None:
        _precache_job = ExportPreCacheJob()
    return _precache_job