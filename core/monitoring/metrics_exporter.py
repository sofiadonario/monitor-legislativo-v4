"""
Metrics Exporter for External Systems
"""
import asyncio
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import aiohttp
from dataclasses import dataclass, asdict
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, HistogramMetricFamily

from .performance_monitor import get_performance_monitor

logger = logging.getLogger(__name__)


@dataclass
class MetricExportConfig:
    """Configuration for metric export"""
    enabled: bool = True
    interval_seconds: int = 60
    destinations: Dict[str, Dict[str, Any]] = None
    include_patterns: List[str] = None
    exclude_patterns: List[str] = None
    batch_size: int = 1000


class MetricsExporter:
    """Export metrics to external monitoring systems"""
    
    def __init__(self, config: MetricExportConfig):
        self.config = config
        self.performance_monitor = get_performance_monitor()
        self._running = False
        self._export_task = None
        
        # Registry for custom metrics
        self.registry = CollectorRegistry()
        
        # Export destinations
        self.destinations = {
            'prometheus': self._export_to_prometheus,
            'datadog': self._export_to_datadog,
            'cloudwatch': self._export_to_cloudwatch,
            'newrelic': self._export_to_newrelic,
            'elastic': self._export_to_elasticsearch,
        }
    
    async def start_export(self):
        """Start metric export process"""
        if self._running:
            return
        
        self._running = True
        self._export_task = asyncio.create_task(self._export_loop())
        logger.info("Metrics export started")
    
    async def stop_export(self):
        """Stop metric export process"""
        self._running = False
        if self._export_task:
            self._export_task.cancel()
            try:
                await self._export_task
            except asyncio.CancelledError:
                pass
        logger.info("Metrics export stopped")
    
    async def _export_loop(self):
        """Main export loop"""
        while self._running:
            try:
                await self._export_metrics()
                await asyncio.sleep(self.config.interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics export loop: {e}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _export_metrics(self):
        """Export metrics to configured destinations"""
        # Get current metrics
        stats = self.performance_monitor.get_stats(time_range=300)  # Last 5 minutes
        
        # Process each destination
        for dest_name, dest_config in (self.config.destinations or {}).items():
            if not dest_config.get('enabled', False):
                continue
            
            try:
                if dest_name in self.destinations:
                    await self.destinations[dest_name](stats, dest_config)
                else:
                    logger.warning(f"Unknown destination: {dest_name}")
            except Exception as e:
                logger.error(f"Failed to export to {dest_name}: {e}")
    
    async def _export_to_prometheus(self, stats: Dict[str, Any], config: Dict[str, Any]):
        """Export metrics to Prometheus"""
        # This is handled by the prometheus_client library automatically
        # Just log the export
        logger.debug("Metrics available for Prometheus scraping")
    
    async def _export_to_datadog(self, stats: Dict[str, Any], config: Dict[str, Any]):
        """Export metrics to Datadog"""
        api_key = config.get('api_key')
        app_key = config.get('app_key')
        
        if not api_key:
            logger.error("Datadog API key not configured")
            return
        
        # Convert stats to Datadog format
        metrics = []
        timestamp = int(time.time())
        
        # System metrics
        if 'system' in stats:
            sys_stats = stats['system']
            metrics.extend([
                {
                    'metric': 'monitor_legislativo.system.cpu_percent',
                    'points': [[timestamp, sys_stats.get('cpu', {}).get('current', 0)]],
                    'tags': ['service:monitor-legislativo']
                },
                {
                    'metric': 'monitor_legislativo.system.memory_percent',
                    'points': [[timestamp, sys_stats.get('memory', {}).get('current_percent', 0)]],
                    'tags': ['service:monitor-legislativo']
                }
            ])
        
        # Request metrics
        if 'requests' in stats:
            req_stats = stats['requests']
            metrics.extend([
                {
                    'metric': 'monitor_legislativo.requests.total',
                    'points': [[timestamp, req_stats.get('total', 0)]],
                    'tags': ['service:monitor-legislativo']
                },
                {
                    'metric': 'monitor_legislativo.requests.error_rate',
                    'points': [[timestamp, req_stats.get('error_rate', 0)]],
                    'tags': ['service:monitor-legislativo']
                }
            ])
        
        # Send to Datadog
        url = 'https://api.datadoghq.com/api/v1/series'
        headers = {
            'Content-Type': 'application/json',
            'DD-API-KEY': api_key
        }
        
        if app_key:
            headers['DD-APPLICATION-KEY'] = app_key
        
        payload = {'series': metrics}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 202:
                    logger.debug("Metrics exported to Datadog successfully")
                else:
                    logger.error(f"Failed to export to Datadog: {response.status}")
    
    async def _export_to_cloudwatch(self, stats: Dict[str, Any], config: Dict[str, Any]):
        """Export metrics to AWS CloudWatch"""
        import boto3
        
        cloudwatch = boto3.client(
            'cloudwatch',
            region_name=config.get('region', 'us-east-1'),
            aws_access_key_id=config.get('access_key_id'),
            aws_secret_access_key=config.get('secret_access_key')
        )
        
        namespace = config.get('namespace', 'MonitorLegislativo')
        metric_data = []
        
        # System metrics
        if 'system' in stats:
            sys_stats = stats['system']
            metric_data.extend([
                {
                    'MetricName': 'CPUPercent',
                    'Value': sys_stats.get('cpu', {}).get('current', 0),
                    'Unit': 'Percent',
                    'Dimensions': [{'Name': 'Service', 'Value': 'MonitorLegislativo'}]
                },
                {
                    'MetricName': 'MemoryPercent',
                    'Value': sys_stats.get('memory', {}).get('current_percent', 0),
                    'Unit': 'Percent',
                    'Dimensions': [{'Name': 'Service', 'Value': 'MonitorLegislativo'}]
                }
            ])
        
        # Request metrics
        if 'requests' in stats:
            req_stats = stats['requests']
            metric_data.extend([
                {
                    'MetricName': 'RequestCount',
                    'Value': req_stats.get('total', 0),
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Service', 'Value': 'MonitorLegislativo'}]
                },
                {
                    'MetricName': 'ErrorRate',
                    'Value': req_stats.get('error_rate', 0),
                    'Unit': 'Percent',
                    'Dimensions': [{'Name': 'Service', 'Value': 'MonitorLegislativo'}]
                }
            ])
        
        # Send metrics in batches (CloudWatch limit is 20 per request)
        for i in range(0, len(metric_data), 20):
            batch = metric_data[i:i + 20]
            try:
                cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=batch
                )
            except Exception as e:
                logger.error(f"Failed to send CloudWatch batch: {e}")
        
        logger.debug("Metrics exported to CloudWatch successfully")
    
    async def _export_to_newrelic(self, stats: Dict[str, Any], config: Dict[str, Any]):
        """Export metrics to New Relic"""
        license_key = config.get('license_key')
        
        if not license_key:
            logger.error("New Relic license key not configured")
            return
        
        # Convert stats to New Relic format
        metrics = []
        timestamp = int(time.time() * 1000)  # New Relic uses milliseconds
        
        # System metrics
        if 'system' in stats:
            sys_stats = stats['system']
            metrics.extend([
                {
                    'name': 'Custom/System/CPUPercent',
                    'value': sys_stats.get('cpu', {}).get('current', 0),
                    'timestamp': timestamp,
                    'attributes': {'service': 'monitor-legislativo'}
                },
                {
                    'name': 'Custom/System/MemoryPercent',
                    'value': sys_stats.get('memory', {}).get('current_percent', 0),
                    'timestamp': timestamp,
                    'attributes': {'service': 'monitor-legislativo'}
                }
            ])
        
        # Request metrics
        if 'requests' in stats:
            req_stats = stats['requests']
            metrics.extend([
                {
                    'name': 'Custom/Requests/Total',
                    'value': req_stats.get('total', 0),
                    'timestamp': timestamp,
                    'attributes': {'service': 'monitor-legislativo'}
                },
                {
                    'name': 'Custom/Requests/ErrorRate',
                    'value': req_stats.get('error_rate', 0),
                    'timestamp': timestamp,
                    'attributes': {'service': 'monitor-legislativo'}
                }
            ])
        
        # Send to New Relic
        url = 'https://metric-api.newrelic.com/metric/v1'
        headers = {
            'Content-Type': 'application/json',
            'Api-Key': license_key
        }
        
        payload = [{
            'metrics': metrics,
            'common': {
                'timestamp': timestamp,
                'attributes': {
                    'service.name': 'monitor-legislativo',
                    'service.version': '4.0.0'
                }
            }
        }]
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 202:
                    logger.debug("Metrics exported to New Relic successfully")
                else:
                    logger.error(f"Failed to export to New Relic: {response.status}")
    
    async def _export_to_elasticsearch(self, stats: Dict[str, Any], config: Dict[str, Any]):
        """Export metrics to Elasticsearch"""
        host = config.get('host', 'localhost:9200')
        index_prefix = config.get('index_prefix', 'monitor-legislativo-metrics')
        
        # Create index name with date
        index_name = f"{index_prefix}-{datetime.utcnow().strftime('%Y.%m.%d')}"
        
        # Prepare document
        doc = {
            '@timestamp': datetime.utcnow().isoformat(),
            'service': 'monitor-legislativo',
            'stats': stats
        }
        
        # Send to Elasticsearch
        url = f"http://{host}/{index_name}/_doc"
        headers = {'Content-Type': 'application/json'}
        
        # Add authentication if configured
        auth = None
        if config.get('username') and config.get('password'):
            auth = aiohttp.BasicAuth(config['username'], config['password'])
        
        async with aiohttp.ClientSession(auth=auth) as session:
            async with session.post(url, headers=headers, json=doc) as response:
                if response.status in [200, 201]:
                    logger.debug("Metrics exported to Elasticsearch successfully")
                else:
                    logger.error(f"Failed to export to Elasticsearch: {response.status}")
    
    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format"""
        return generate_latest(self.registry)


# Custom Prometheus collector
class CustomMetricsCollector:
    """Custom collector for Prometheus metrics"""
    
    def __init__(self):
        self.performance_monitor = get_performance_monitor()
    
    def collect(self):
        """Collect metrics for Prometheus"""
        stats = self.performance_monitor.get_stats(time_range=60)
        
        # Request metrics
        if 'requests' in stats:
            req_stats = stats['requests']
            
            # Request counter
            yield CounterMetricFamily(
                'http_requests_total',
                'Total HTTP requests',
                value=req_stats.get('total', 0)
            )
            
            # Response time histogram
            buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, float('inf')]
            
            yield HistogramMetricFamily(
                'http_request_duration_seconds',
                'HTTP request duration',
                buckets=buckets,
                sum_value=req_stats.get('response_times', {}).get('mean', 0) / 1000,
                count_value=req_stats.get('total', 0)
            )
        
        # System metrics
        if 'system' in stats:
            sys_stats = stats['system']
            
            yield GaugeMetricFamily(
                'system_cpu_percent',
                'CPU usage percentage',
                value=sys_stats.get('cpu', {}).get('current', 0)
            )
            
            yield GaugeMetricFamily(
                'system_memory_percent',
                'Memory usage percentage',
                value=sys_stats.get('memory', {}).get('current_percent', 0)
            )


# Global exporter instance
_exporter: Optional[MetricsExporter] = None


async def initialize_metrics_exporter(config: MetricExportConfig):
    """Initialize the global metrics exporter"""
    global _exporter
    _exporter = MetricsExporter(config)
    await _exporter.start_export()
    return _exporter


def get_metrics_exporter() -> Optional[MetricsExporter]:
    """Get the global metrics exporter instance"""
    return _exporter