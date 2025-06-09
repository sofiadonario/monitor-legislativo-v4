"""
Production Health Checks and Monitoring Endpoints
Monitor Legislativo v4 - Production Ready Health Monitoring

This module provides comprehensive health checking for production deployment,
including liveness probes, readiness probes, and detailed metrics.
"""

import time
import psutil
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from flask import Blueprint, jsonify, request
from sqlalchemy import text
from redis import Redis
import requests

from core.config.config import Config
from core.database.models import get_db_session
from core.utils.monitoring import metrics_collector
from core.monitoring.structured_logging import get_logger

logger = get_logger(__name__)

# Create blueprint for health checks
health_bp = Blueprint('health', __name__, url_prefix='/health')

@dataclass
class HealthCheckResult:
    """Health check result structure"""
    name: str
    healthy: bool
    response_time: float
    message: str
    details: Optional[Dict[str, Any]] = None

class HealthChecker:
    """Comprehensive health checking for production deployment"""
    
    def __init__(self):
        self.config = Config()
        self.start_time = datetime.utcnow()
        self.redis_client = None
        self.api_endpoints = {
            'antt': 'https://www.antt.gov.br',
            'dou': 'https://www.in.gov.br',
            'camara': 'https://dadosabertos.camara.leg.br/api/v2',
            'senado': 'https://legis.senado.leg.br/dadosabertos',
            'dnit': 'https://www.dnit.gov.br'
        }
    
    async def check_database(self) -> HealthCheckResult:
        """Check database connectivity and performance"""
        start_time = time.time()
        
        try:
            with get_db_session() as session:
                # Test basic connectivity
                result = session.execute(text("SELECT 1")).fetchone()
                
                # Test application-specific query
                result = session.execute(text("""
                    SELECT COUNT(*) as count, 
                           MAX(created_at) as last_update
                    FROM documents 
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                """)).fetchone()
                
                response_time = time.time() - start_time
                
                # Check if we have recent data
                if result.count == 0:
                    logger.warning("No documents created in the last 24 hours")
                
                return HealthCheckResult(
                    name="database",
                    healthy=True,
                    response_time=response_time,
                    message="Database connection healthy",
                    details={
                        "documents_24h": result.count,
                        "last_update": result.last_update.isoformat() if result.last_update else None,
                        "query_time_ms": round(response_time * 1000, 2)
                    }
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Database health check failed: {e}")
            
            return HealthCheckResult(
                name="database",
                healthy=False,
                response_time=response_time,
                message=f"Database connection failed: {str(e)}"
            )
    
    async def check_redis(self) -> HealthCheckResult:
        """Check Redis connectivity and performance"""
        start_time = time.time()
        
        try:
            if not self.redis_client:
                self.redis_client = Redis.from_url(self.config.redis_url)
            
            # Test basic connectivity
            self.redis_client.ping()
            
            # Test read/write operations
            test_key = f"health_check:{int(time.time())}"
            self.redis_client.set(test_key, "test", ex=60)
            retrieved_value = self.redis_client.get(test_key)
            self.redis_client.delete(test_key)
            
            response_time = time.time() - start_time
            
            # Get Redis info
            redis_info = self.redis_client.info()
            
            return HealthCheckResult(
                name="redis",
                healthy=True,
                response_time=response_time,
                message="Redis connection healthy",
                details={
                    "connected_clients": redis_info.get('connected_clients', 0),
                    "used_memory_human": redis_info.get('used_memory_human', 'unknown'),
                    "hit_rate": redis_info.get('keyspace_hits', 0) / max(1, redis_info.get('keyspace_hits', 0) + redis_info.get('keyspace_misses', 0)),
                    "response_time_ms": round(response_time * 1000, 2)
                }
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Redis health check failed: {e}")
            
            return HealthCheckResult(
                name="redis",
                healthy=False,
                response_time=response_time,
                message=f"Redis connection failed: {str(e)}"
            )
    
    async def check_government_apis(self) -> List[HealthCheckResult]:
        """Check government API endpoints connectivity"""
        results = []
        
        for api_name, base_url in self.api_endpoints.items():
            start_time = time.time()
            
            try:
                # Test with timeout and proper headers
                headers = {
                    'User-Agent': 'Monitor-Legislativo/4.0 (https://github.com/mackintegridade)',
                    'Accept': 'text/html,application/json'
                }
                
                response = requests.get(
                    base_url, 
                    headers=headers,
                    timeout=10,
                    allow_redirects=True
                )
                
                response_time = time.time() - start_time
                
                # Check if response is reasonable
                healthy = 200 <= response.status_code < 400
                
                results.append(HealthCheckResult(
                    name=f"api_{api_name}",
                    healthy=healthy,
                    response_time=response_time,
                    message=f"API {api_name} {'healthy' if healthy else 'unhealthy'}",
                    details={
                        "status_code": response.status_code,
                        "response_time_ms": round(response_time * 1000, 2),
                        "content_length": len(response.content) if response.content else 0
                    }
                ))
                
            except Exception as e:
                response_time = time.time() - start_time
                logger.warning(f"API {api_name} health check failed: {e}")
                
                results.append(HealthCheckResult(
                    name=f"api_{api_name}",
                    healthy=False,
                    response_time=response_time,
                    message=f"API {api_name} failed: {str(e)}"
                ))
        
        return results
    
    async def check_system_resources(self) -> HealthCheckResult:
        """Check system resource usage"""
        start_time = time.time()
        
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Check thresholds
            cpu_healthy = cpu_percent < 80
            memory_healthy = memory.percent < 85
            disk_healthy = disk.percent < 90
            
            overall_healthy = cpu_healthy and memory_healthy and disk_healthy
            
            response_time = time.time() - start_time
            
            return HealthCheckResult(
                name="system_resources",
                healthy=overall_healthy,
                response_time=response_time,
                message="System resources " + ("healthy" if overall_healthy else "under stress"),
                details={
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory.percent, 2),
                    "disk_percent": round(disk.percent, 2),
                    "memory_available_gb": round(memory.available / (1024**3), 2),
                    "disk_free_gb": round(disk.free / (1024**3), 2)
                }
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"System resources check failed: {e}")
            
            return HealthCheckResult(
                name="system_resources",
                healthy=False,
                response_time=response_time,
                message=f"System check failed: {str(e)}"
            )

# Global health checker instance
health_checker = HealthChecker()

@health_bp.route('/live')
def liveness_probe():
    """
    Kubernetes liveness probe - checks if application is running
    This should only fail if the application is completely broken
    """
    uptime = datetime.utcnow() - health_checker.start_time
    
    return jsonify({
        'status': 'alive',
        'timestamp': datetime.utcnow().isoformat(),
        'uptime_seconds': int(uptime.total_seconds()),
        'version': '4.0.0',
        'environment': 'production'
    }), 200

@health_bp.route('/ready')
async def readiness_probe():
    """
    Kubernetes readiness probe - checks if application is ready to serve traffic
    This should fail if any critical dependency is unavailable
    """
    start_time = time.time()
    
    try:
        # Run critical health checks in parallel
        checks = await asyncio.gather(
            health_checker.check_database(),
            health_checker.check_redis(),
            return_exceptions=True
        )
        
        # Add system resource check
        system_check = await health_checker.check_system_resources()
        checks.append(system_check)
        
        # Determine overall health
        healthy_checks = [c for c in checks if isinstance(c, HealthCheckResult) and c.healthy]
        failed_checks = [c for c in checks if isinstance(c, HealthCheckResult) and not c.healthy]
        error_checks = [c for c in checks if isinstance(c, Exception)]
        
        # Critical services that must be healthy
        critical_services = ['database', 'redis']
        critical_failed = [c for c in failed_checks if c.name in critical_services]
        
        overall_healthy = len(critical_failed) == 0 and len(error_checks) == 0
        
        total_time = time.time() - start_time
        
        response_data = {
            'status': 'ready' if overall_healthy else 'not_ready',
            'timestamp': datetime.utcnow().isoformat(),
            'check_duration_ms': round(total_time * 1000, 2),
            'checks': {
                'total': len(checks),
                'healthy': len(healthy_checks),
                'failed': len(failed_checks),
                'errors': len(error_checks)
            },
            'details': [
                {
                    'name': c.name,
                    'healthy': c.healthy,
                    'response_time_ms': round(c.response_time * 1000, 2),
                    'message': c.message,
                    'details': c.details
                } for c in checks if isinstance(c, HealthCheckResult)
            ]
        }
        
        # Add errors
        if error_checks:
            response_data['errors'] = [str(e) for e in error_checks]
        
        status_code = 200 if overall_healthy else 503
        
        # Log health check results
        if not overall_healthy:
            logger.warning(f"Readiness check failed: {len(failed_checks)} failed, {len(error_checks)} errors")
        
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Readiness probe failed with exception: {e}")
        
        return jsonify({
            'status': 'error',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 503

@health_bp.route('/metrics')
async def detailed_metrics():
    """
    Detailed application metrics for monitoring and debugging
    """
    start_time = time.time()
    
    try:
        # Run all health checks including government APIs
        api_checks = await health_checker.check_government_apis()
        
        core_checks = await asyncio.gather(
            health_checker.check_database(),
            health_checker.check_redis(),
            health_checker.check_system_resources(),
            return_exceptions=True
        )
        
        all_checks = core_checks + api_checks
        
        # Application metrics
        uptime = datetime.utcnow() - health_checker.start_time
        
        # Performance metrics from metrics collector
        perf_metrics = metrics_collector.get_metrics_summary()
        
        # Build comprehensive response
        metrics_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'application': {
                'name': 'monitor_legislativo_v4',
                'version': '4.0.0',
                'environment': 'production',
                'uptime_seconds': int(uptime.total_seconds()),
                'uptime_human': str(uptime)
            },
            'health_checks': {
                check.name: {
                    'healthy': check.healthy,
                    'response_time_ms': round(check.response_time * 1000, 2),
                    'message': check.message,
                    'details': check.details
                } for check in all_checks if isinstance(check, HealthCheckResult)
            },
            'performance': perf_metrics,
            'government_apis': {
                'total_endpoints': len(health_checker.api_endpoints),
                'healthy_endpoints': len([c for c in api_checks if c.healthy]),
                'average_response_time_ms': round(
                    sum(c.response_time for c in api_checks) / len(api_checks) * 1000, 2
                ) if api_checks else 0
            },
            'check_duration_ms': round((time.time() - start_time) * 1000, 2)
        }
        
        return jsonify(metrics_data), 200
        
    except Exception as e:
        logger.error(f"Metrics endpoint failed: {e}")
        
        return jsonify({
            'error': 'Failed to collect metrics',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@health_bp.route('/deep')
async def deep_health_check():
    """
    Comprehensive deep health check for detailed diagnostics
    Only use this for troubleshooting, not for automated monitoring
    """
    if request.args.get('confirm') != 'true':
        return jsonify({
            'error': 'Deep health check requires confirmation',
            'message': 'Add ?confirm=true to run deep health check',
            'warning': 'This check may impact performance'
        }), 400
    
    start_time = time.time()
    
    try:
        # Run comprehensive checks
        logger.info("Starting deep health check")
        
        # All standard checks
        api_checks = await health_checker.check_government_apis()
        core_checks = await asyncio.gather(
            health_checker.check_database(),
            health_checker.check_redis(),
            health_checker.check_system_resources()
        )
        
        # Additional deep checks
        additional_checks = []
        
        # Database performance test
        try:
            with get_db_session() as session:
                test_start = time.time()
                result = session.execute(text("""
                    SELECT 
                        COUNT(*) as total_documents,
                        COUNT(CASE WHEN created_at > NOW() - INTERVAL '1 hour' THEN 1 END) as recent_documents,
                        AVG(CASE WHEN LENGTH(content) > 0 THEN LENGTH(content) END) as avg_content_length
                    FROM documents
                """)).fetchone()
                test_time = time.time() - test_start
                
                additional_checks.append({
                    'name': 'database_performance',
                    'healthy': test_time < 5.0,
                    'response_time_ms': round(test_time * 1000, 2),
                    'details': {
                        'total_documents': result.total_documents,
                        'recent_documents': result.recent_documents,
                        'avg_content_length': round(result.avg_content_length or 0, 2)
                    }
                })
        except Exception as e:
            additional_checks.append({
                'name': 'database_performance',
                'healthy': False,
                'error': str(e)
            })
        
        total_time = time.time() - start_time
        
        response_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'deep_check_duration_ms': round(total_time * 1000, 2),
            'core_systems': [
                {
                    'name': c.name,
                    'healthy': c.healthy,
                    'response_time_ms': round(c.response_time * 1000, 2),
                    'message': c.message,
                    'details': c.details
                } for c in core_checks
            ],
            'government_apis': [
                {
                    'name': c.name,
                    'healthy': c.healthy,
                    'response_time_ms': round(c.response_time * 1000, 2),
                    'message': c.message,
                    'details': c.details
                } for c in api_checks
            ],
            'additional_checks': additional_checks,
            'summary': {
                'total_checks': len(core_checks) + len(api_checks) + len(additional_checks),
                'healthy_checks': len([c for c in core_checks + api_checks if c.healthy]) + len([c for c in additional_checks if c.get('healthy', False)]),
                'overall_healthy': all(c.healthy for c in core_checks + api_checks) and all(c.get('healthy', False) for c in additional_checks)
            }
        }
        
        logger.info(f"Deep health check completed in {total_time:.2f}s")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Deep health check failed: {e}")
        
        return jsonify({
            'error': 'Deep health check failed',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat(),
            'duration_ms': round((time.time() - start_time) * 1000, 2)
        }), 500