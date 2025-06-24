"""
Monitoring and alerting utilities for collection service
Tracks performance metrics and sends alerts
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
import json
import os

logger = logging.getLogger(__name__)


class CollectionMetrics:
    """Collection metrics tracker"""
    
    def __init__(self):
        self.metrics = {
            'collections_started': 0,
            'collections_completed': 0,
            'collections_failed': 0,
            'documents_collected': 0,
            'documents_stored': 0,
            'documents_skipped': 0,
            'total_execution_time_ms': 0,
            'average_execution_time_ms': 0.0,
            'last_collection': None,
            'sources': {},
            'errors': []
        }
    
    def start_collection(self, source: str, search_term: str):
        """Record collection start"""
        self.metrics['collections_started'] += 1
        self.metrics['last_collection'] = datetime.now().isoformat()
        
        if source not in self.metrics['sources']:
            self.metrics['sources'][source] = {
                'started': 0,
                'completed': 0,
                'failed': 0,
                'documents': 0
            }
        
        self.metrics['sources'][source]['started'] += 1
        
        logger.info(f"📊 Collection started: {source} - {search_term}")
    
    def complete_collection(self, source: str, documents_count: int, execution_time_ms: int):
        """Record successful collection completion"""
        self.metrics['collections_completed'] += 1
        self.metrics['documents_collected'] += documents_count
        self.metrics['total_execution_time_ms'] += execution_time_ms
        
        # Update average execution time
        if self.metrics['collections_completed'] > 0:
            self.metrics['average_execution_time_ms'] = (
                self.metrics['total_execution_time_ms'] / self.metrics['collections_completed']
            )
        
        if source in self.metrics['sources']:
            self.metrics['sources'][source]['completed'] += 1
            self.metrics['sources'][source]['documents'] += documents_count
        
        logger.info(
            f"✅ Collection completed: {source} - "
            f"{documents_count} docs in {execution_time_ms}ms"
        )
    
    def fail_collection(self, source: str, error: str):
        """Record collection failure"""
        self.metrics['collections_failed'] += 1
        
        if source in self.metrics['sources']:
            self.metrics['sources'][source]['failed'] += 1
        
        # Store recent errors (keep last 10)
        error_entry = {
            'source': source,
            'error': error,
            'timestamp': datetime.now().isoformat()
        }
        
        self.metrics['errors'].append(error_entry)
        if len(self.metrics['errors']) > 10:
            self.metrics['errors'] = self.metrics['errors'][-10:]
        
        logger.error(f"❌ Collection failed: {source} - {error}")
    
    def record_storage(self, new_docs: int, updated_docs: int, skipped_docs: int):
        """Record document storage results"""
        self.metrics['documents_stored'] += (new_docs + updated_docs)
        self.metrics['documents_skipped'] += skipped_docs
        
        logger.info(f"💾 Storage: {new_docs} new, {updated_docs} updated, {skipped_docs} skipped")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return self.metrics.copy()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        total_collections = self.metrics['collections_started']
        success_rate = 0.0
        
        if total_collections > 0:
            success_rate = (self.metrics['collections_completed'] / total_collections) * 100
        
        return {
            'success_rate': round(success_rate, 2),
            'total_collections': total_collections,
            'completed': self.metrics['collections_completed'],
            'failed': self.metrics['collections_failed'],
            'documents_collected': self.metrics['documents_collected'],
            'documents_stored': self.metrics['documents_stored'],
            'average_time_ms': round(self.metrics['average_execution_time_ms'], 2),
            'active_sources': len(self.metrics['sources']),
            'last_collection': self.metrics['last_collection']
        }


class AlertManager:
    """Alert manager for collection service"""
    
    def __init__(self):
        self.alert_config = {
            'max_failures': 5,
            'min_success_rate': 80.0,
            'max_execution_time_ms': 30000,  # 30 seconds
            'email_enabled': False,
            'slack_enabled': False,
            'webhook_url': os.getenv('ALERT_WEBHOOK_URL')
        }
        
        self.recent_alerts = []
    
    async def check_and_send_alerts(self, metrics: Dict[str, Any]):
        """Check metrics and send alerts if needed"""
        alerts = []
        
        # Check failure rate
        total_collections = metrics.get('collections_started', 0)
        failed_collections = metrics.get('collections_failed', 0)
        
        if total_collections > 0:
            failure_rate = (failed_collections / total_collections) * 100
            success_rate = 100 - failure_rate
            
            if success_rate < self.alert_config['min_success_rate']:
                alerts.append({
                    'level': 'warning',
                    'type': 'low_success_rate',
                    'message': f"Low success rate: {success_rate:.1f}%",
                    'details': {
                        'success_rate': success_rate,
                        'total_collections': total_collections,
                        'failed_collections': failed_collections
                    }
                })
        
        # Check consecutive failures
        if failed_collections >= self.alert_config['max_failures']:
            alerts.append({
                'level': 'critical',
                'type': 'high_failure_count',
                'message': f"High failure count: {failed_collections}",
                'details': {
                    'failed_collections': failed_collections,
                    'recent_errors': metrics.get('errors', [])[-3:]
                }
            })
        
        # Check execution time
        avg_time = metrics.get('average_execution_time_ms', 0)
        if avg_time > self.alert_config['max_execution_time_ms']:
            alerts.append({
                'level': 'warning',
                'type': 'slow_execution',
                'message': f"Slow execution time: {avg_time:.0f}ms",
                'details': {
                    'average_time_ms': avg_time,
                    'threshold_ms': self.alert_config['max_execution_time_ms']
                }
            })
        
        # Send alerts
        for alert in alerts:
            await self.send_alert(alert)
    
    async def send_alert(self, alert: Dict[str, Any]):
        """Send alert via configured channels"""
        alert['timestamp'] = datetime.now().isoformat()
        
        # Add to recent alerts
        self.recent_alerts.append(alert)
        if len(self.recent_alerts) > 50:
            self.recent_alerts = self.recent_alerts[-50:]
        
        logger.warning(f"🚨 ALERT [{alert['level']}]: {alert['message']}")
        
        # Send to webhook if configured
        if self.alert_config.get('webhook_url'):
            await self._send_webhook_alert(alert)
        
        # Log detailed alert info
        logger.warning(f"Alert details: {json.dumps(alert['details'], indent=2)}")
    
    async def _send_webhook_alert(self, alert: Dict[str, Any]):
        """Send alert to webhook URL"""
        try:
            import httpx
            
            payload = {
                'text': f"Monitor Legislativo Alert: {alert['message']}",
                'level': alert['level'],
                'type': alert['type'],
                'timestamp': alert['timestamp'],
                'details': alert['details']
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.alert_config['webhook_url'],
                    json=payload,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    logger.info("Alert sent to webhook successfully")
                else:
                    logger.warning(f"Webhook alert failed: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.recent_alerts[-limit:]


class PerformanceTracker:
    """Performance tracking for collection operations"""
    
    def __init__(self):
        self.operations = {}
        self.thresholds = {
            'lexml_search': 10000,  # 10 seconds
            'document_storage': 5000,  # 5 seconds
            'api_request': 30000,  # 30 seconds
            'batch_insert': 15000  # 15 seconds
        }
    
    def start_operation(self, operation_id: str, operation_type: str):
        """Start tracking an operation"""
        self.operations[operation_id] = {
            'type': operation_type,
            'start_time': datetime.now(),
            'end_time': None,
            'duration_ms': None,
            'status': 'running'
        }
    
    def end_operation(self, operation_id: str, status: str = 'completed'):
        """End tracking an operation"""
        if operation_id in self.operations:
            op = self.operations[operation_id]
            op['end_time'] = datetime.now()
            op['duration_ms'] = int((op['end_time'] - op['start_time']).total_seconds() * 1000)
            op['status'] = status
            
            # Check if operation exceeded threshold
            threshold = self.thresholds.get(op['type'], 60000)
            if op['duration_ms'] > threshold:
                logger.warning(
                    f"⚠️ Slow operation: {op['type']} took {op['duration_ms']}ms "
                    f"(threshold: {threshold}ms)"
                )
    
    def get_operation_stats(self, operation_type: Optional[str] = None) -> Dict[str, Any]:
        """Get operation statistics"""
        operations = self.operations.values()
        
        if operation_type:
            operations = [op for op in operations if op['type'] == operation_type]
        
        completed_ops = [op for op in operations if op['status'] == 'completed']
        
        if not completed_ops:
            return {'count': 0}
        
        durations = [op['duration_ms'] for op in completed_ops]
        
        return {
            'count': len(completed_ops),
            'average_duration_ms': sum(durations) / len(durations),
            'min_duration_ms': min(durations),
            'max_duration_ms': max(durations),
            'total_duration_ms': sum(durations)
        }


# Global instances
collection_metrics = CollectionMetrics()
alert_manager = AlertManager()
performance_tracker = PerformanceTracker()


async def track_collection_metrics(source: str, search_term: str, 
                                 documents_collected: int, documents_validated: int,
                                 execution_time_ms: int):
    """Track collection metrics"""
    collection_metrics.start_collection(source, search_term)
    
    if documents_validated > 0:
        collection_metrics.complete_collection(source, documents_validated, execution_time_ms)
    else:
        collection_metrics.fail_collection(source, "No documents validated")


async def send_alert(level: str, message: str, details: Dict[str, Any]):
    """Send alert via alert manager"""
    alert = {
        'level': level,
        'type': 'manual',
        'message': message,
        'details': details
    }
    await alert_manager.send_alert(alert)


def start_performance_tracking(operation_id: str, operation_type: str):
    """Start performance tracking for an operation"""
    performance_tracker.start_operation(operation_id, operation_type)


def end_performance_tracking(operation_id: str, status: str = 'completed'):
    """End performance tracking for an operation"""
    performance_tracker.end_operation(operation_id, status)


async def generate_health_report() -> Dict[str, Any]:
    """Generate comprehensive health report"""
    metrics = collection_metrics.get_metrics()
    summary = collection_metrics.get_summary()
    recent_alerts = alert_manager.get_recent_alerts()
    
    # Get performance stats
    perf_stats = {}
    for op_type in performance_tracker.thresholds.keys():
        perf_stats[op_type] = performance_tracker.get_operation_stats(op_type)
    
    return {
        'timestamp': datetime.now().isoformat(),
        'service_status': 'healthy' if summary['success_rate'] > 80 else 'degraded',
        'metrics_summary': summary,
        'detailed_metrics': metrics,
        'performance_stats': perf_stats,
        'recent_alerts': recent_alerts,
        'alert_count_24h': len([a for a in recent_alerts if 
                               (datetime.now() - datetime.fromisoformat(a['timestamp'])).days < 1])
    }


async def start_monitoring_loop():
    """Start background monitoring loop"""
    logger.info("🔍 Starting monitoring loop")
    
    while True:
        try:
            # Check metrics and send alerts if needed
            metrics = collection_metrics.get_metrics()
            await alert_manager.check_and_send_alerts(metrics)
            
            # Log summary every 5 minutes
            summary = collection_metrics.get_summary()
            logger.info(f"📊 Collection Summary: {json.dumps(summary, indent=2)}")
            
            # Wait 5 minutes
            await asyncio.sleep(300)
            
        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")
            await asyncio.sleep(60)  # Wait 1 minute on error