"""
Advanced alerting service for collection monitoring and system health
Handles email notifications, webhook alerts, and escalation policies
"""

import asyncio
import json
import logging
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp

from .database_service import CollectionDatabaseService
from ..utils.monitoring import performance_tracker

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of alerts"""
    COLLECTION_FAILURE = "collection_failure"
    API_UNAVAILABLE = "api_unavailable"
    DATABASE_ERROR = "database_error"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    QUOTA_EXCEEDED = "quota_exceeded"
    DISK_SPACE_LOW = "disk_space_low"
    EXPORT_FAILURE = "export_failure"
    SYSTEM_HEALTH = "system_health"


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    source: str
    timestamp: datetime
    metadata: Dict[str, Any]
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    escalated: bool = False
    notification_count: int = 0


class AlertingService:
    """Service for monitoring alerts and notifications"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.db_service: Optional[CollectionDatabaseService] = None
        
        # Email configuration
        self.smtp_host = self.config.get('smtp_host', 'localhost')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.smtp_user = self.config.get('smtp_user', '')
        self.smtp_password = self.config.get('smtp_password', '')
        self.from_email = self.config.get('from_email', 'monitor@example.com')
        self.alert_emails = self.config.get('alert_emails', [])
        
        # Webhook configuration
        self.webhook_urls = self.config.get('webhook_urls', [])
        
        # Alert thresholds
        self.thresholds = {
            'collection_failure_rate': 0.3,  # 30% failure rate
            'api_response_time_ms': 5000,    # 5 seconds
            'database_query_time_ms': 2000,  # 2 seconds
            'disk_usage_percentage': 85,     # 85% disk usage
            'memory_usage_percentage': 90,   # 90% memory usage
            'export_age_hours': 25          # 25 hours without export
        }
        
        # Alert suppression (prevent spam)
        self.suppression_windows = {
            AlertType.COLLECTION_FAILURE: timedelta(minutes=30),
            AlertType.API_UNAVAILABLE: timedelta(minutes=15),
            AlertType.DATABASE_ERROR: timedelta(minutes=10),
            AlertType.PERFORMANCE_DEGRADATION: timedelta(hours=1),
            AlertType.SYSTEM_HEALTH: timedelta(hours=2)
        }
        
        self.active_alerts = {}  # Cache for active alerts
        
    async def initialize(self):
        """Initialize the alerting service"""
        self.db_service = CollectionDatabaseService()
        await self.db_service.initialize()
        logger.info("Alerting service initialized")
    
    async def check_system_health(self) -> Dict[str, Any]:
        """Comprehensive system health check with alerting"""
        health_start = datetime.now()
        
        health_status = {
            'timestamp': health_start.isoformat(),
            'overall_status': 'healthy',
            'checks': {},
            'alerts_triggered': []
        }
        
        try:
            # Check collection performance
            collection_health = await self._check_collection_health()
            health_status['checks']['collection'] = collection_health
            
            # Check API availability
            api_health = await self._check_api_health()
            health_status['checks']['apis'] = api_health
            
            # Check database performance
            db_health = await self._check_database_health()
            health_status['checks']['database'] = db_health
            
            # Check export status
            export_health = await self._check_export_health()
            health_status['checks']['exports'] = export_health
            
            # Check system resources
            resource_health = await self._check_system_resources()
            health_status['checks']['resources'] = resource_health
            
            # Determine overall status
            all_checks = [collection_health, api_health, db_health, export_health, resource_health]
            
            if any(check.get('status') == 'critical' for check in all_checks):
                health_status['overall_status'] = 'critical'
            elif any(check.get('status') == 'degraded' for check in all_checks):
                health_status['overall_status'] = 'degraded'
            
            # Process any alerts found during health checks
            for check_name, check_result in health_status['checks'].items():
                if check_result.get('alerts'):
                    for alert_data in check_result['alerts']:
                        alert = await self._create_alert(alert_data)
                        if alert:
                            health_status['alerts_triggered'].append(alert.alert_id)
            
            logger.info(f"System health check completed: {health_status['overall_status']}")
            return health_status
            
        except Exception as e:
            logger.error(f"Error in system health check: {e}")
            
            # Create critical alert for health check failure
            await self._create_alert({
                'alert_type': AlertType.SYSTEM_HEALTH,
                'severity': AlertSeverity.CRITICAL,
                'title': 'System Health Check Failed',
                'message': f'Unable to complete system health check: {str(e)}',
                'source': 'health_monitor',
                'metadata': {'error': str(e)}
            })
            
            health_status['overall_status'] = 'unknown'
            health_status['error'] = str(e)
            return health_status
    
    async def _check_collection_health(self) -> Dict[str, Any]:
        """Check collection system health"""
        try:
            # Get recent collection statistics
            async with self.db_service.pool.acquire() as conn:
                stats = await conn.fetchrow("""
                    SELECT 
                        COUNT(*) as total_collections,
                        COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_collections,
                        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_collections,
                        AVG(execution_time_ms) as avg_execution_time,
                        MAX(completed_at) as last_collection
                    FROM collection_logs
                    WHERE completed_at >= NOW() - INTERVAL '24 hours'
                """)
            
            total = stats['total_collections'] or 0
            failed = stats['failed_collections'] or 0
            success_rate = (total - failed) / total if total > 0 else 1.0
            avg_time = stats['avg_execution_time'] or 0
            
            health = {
                'status': 'healthy',
                'success_rate': success_rate,
                'avg_execution_time_ms': avg_time,
                'total_collections_24h': total,
                'failed_collections_24h': failed,
                'last_collection': stats['last_collection'].isoformat() if stats['last_collection'] else None,
                'alerts': []
            }
            
            # Check for collection failures
            if success_rate < (1 - self.thresholds['collection_failure_rate']):
                health['status'] = 'critical'
                health['alerts'].append({
                    'alert_type': AlertType.COLLECTION_FAILURE,
                    'severity': AlertSeverity.HIGH,
                    'title': f'High Collection Failure Rate: {failed}/{total}',
                    'message': f'Collection success rate ({success_rate:.1%}) is below threshold',
                    'source': 'collection_monitor',
                    'metadata': {'success_rate': success_rate, 'failed_count': failed, 'total_count': total}
                })
            
            # Check for performance degradation
            if avg_time > self.thresholds['api_response_time_ms']:
                health['status'] = 'degraded' if health['status'] == 'healthy' else health['status']
                health['alerts'].append({
                    'alert_type': AlertType.PERFORMANCE_DEGRADATION,
                    'severity': AlertSeverity.MEDIUM,
                    'title': f'Slow Collection Performance: {avg_time:.0f}ms',
                    'message': f'Average collection time ({avg_time:.0f}ms) exceeds threshold',
                    'source': 'collection_monitor',
                    'metadata': {'avg_execution_time_ms': avg_time}
                })
            
            return health
            
        except Exception as e:
            logger.error(f"Error checking collection health: {e}")
            return {
                'status': 'unknown',
                'error': str(e),
                'alerts': [{
                    'alert_type': AlertType.SYSTEM_HEALTH,
                    'severity': AlertSeverity.MEDIUM,
                    'title': 'Collection Health Check Failed',
                    'message': f'Unable to check collection health: {str(e)}',
                    'source': 'collection_monitor',
                    'metadata': {'error': str(e)}
                }]
            }
    
    async def _check_api_health(self) -> Dict[str, Any]:
        """Check external API health"""
        api_sources = [
            'lexml', 'camara', 'senado', 'antt', 'anac', 'aneel', 
            'anatel', 'anvisa', 'ans', 'ana', 'ancine', 'anm', 
            'anp', 'antaq', 'cade'
        ]
        
        health = {
            'status': 'healthy',
            'apis_checked': len(api_sources),
            'apis_available': 0,
            'apis_unavailable': 0,
            'response_times': {},
            'alerts': []
        }
        
        # Quick health check for each API
        for api_source in api_sources:
            try:
                # Simulate API health check (in real implementation, make actual test calls)
                # For now, we'll check recent collection logs for this API
                async with self.db_service.pool.acquire() as conn:
                    recent_success = await conn.fetchval("""
                        SELECT COUNT(*) > 0
                        FROM collection_logs 
                        WHERE source_api = $1 
                          AND status = 'completed' 
                          AND completed_at >= NOW() - INTERVAL '1 hour'
                    """, api_source)
                
                if recent_success:
                    health['apis_available'] += 1
                else:
                    health['apis_unavailable'] += 1
                    
                    # Check if this API has been failing consistently
                    failure_count = await conn.fetchval("""
                        SELECT COUNT(*)
                        FROM collection_logs
                        WHERE source_api = $1
                          AND status = 'failed'
                          AND completed_at >= NOW() - INTERVAL '6 hours'
                    """, api_source)
                    
                    if failure_count >= 3:  # Multiple failures in 6 hours
                        health['alerts'].append({
                            'alert_type': AlertType.API_UNAVAILABLE,
                            'severity': AlertSeverity.HIGH,
                            'title': f'API Unavailable: {api_source.upper()}',
                            'message': f'API {api_source} has {failure_count} failures in the last 6 hours',
                            'source': 'api_monitor',
                            'metadata': {'api_source': api_source, 'failure_count': failure_count}
                        })
                        
            except Exception as e:
                logger.error(f"Error checking {api_source} API health: {e}")
                health['apis_unavailable'] += 1
        
        # Determine overall API health status
        unavailable_percentage = health['apis_unavailable'] / health['apis_checked']
        if unavailable_percentage > 0.5:  # More than 50% APIs unavailable
            health['status'] = 'critical'
        elif unavailable_percentage > 0.2:  # More than 20% APIs unavailable
            health['status'] = 'degraded'
        
        return health
    
    async def _check_database_health(self) -> Dict[str, Any]:
        """Check database performance and connectivity"""
        try:
            start_time = datetime.now()
            
            # Test database connectivity and performance
            async with self.db_service.pool.acquire() as conn:
                # Simple query to test connectivity
                await conn.fetchval("SELECT 1")
                
                # Check database size and performance
                db_stats = await conn.fetchrow("""
                    SELECT 
                        pg_database_size(current_database()) as db_size_bytes,
                        (SELECT count(*) FROM legislative_documents) as total_documents,
                        (SELECT count(*) FROM search_terms WHERE active = true) as active_terms
                """)
            
            query_time_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            health = {
                'status': 'healthy',
                'connectivity': 'ok',
                'query_time_ms': query_time_ms,
                'database_size_mb': db_stats['db_size_bytes'] / (1024 * 1024),
                'total_documents': db_stats['total_documents'],
                'active_search_terms': db_stats['active_terms'],
                'alerts': []
            }
            
            # Check query performance
            if query_time_ms > self.thresholds['database_query_time_ms']:
                health['status'] = 'degraded'
                health['alerts'].append({
                    'alert_type': AlertType.PERFORMANCE_DEGRADATION,
                    'severity': AlertSeverity.MEDIUM,
                    'title': f'Slow Database Performance: {query_time_ms:.0f}ms',
                    'message': f'Database query time ({query_time_ms:.0f}ms) exceeds threshold',
                    'source': 'database_monitor',
                    'metadata': {'query_time_ms': query_time_ms}
                })
            
            return health
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'status': 'critical',
                'connectivity': 'failed',
                'error': str(e),
                'alerts': [{
                    'alert_type': AlertType.DATABASE_ERROR,
                    'severity': AlertSeverity.CRITICAL,
                    'title': 'Database Connectivity Failed',
                    'message': f'Unable to connect to database: {str(e)}',
                    'source': 'database_monitor',
                    'metadata': {'error': str(e)}
                }]
            }
    
    async def _check_export_health(self) -> Dict[str, Any]:
        """Check export system health"""
        try:
            async with self.db_service.pool.acquire() as conn:
                export_stats = await conn.fetchrow("""
                    SELECT 
                        COUNT(*) as total_exports_24h,
                        COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_exports,
                        MAX(created_at) as last_export,
                        COUNT(DISTINCT search_term_id) as terms_exported
                    FROM export_logs
                    WHERE created_at >= NOW() - INTERVAL '24 hours'
                """)
                
                # Check for terms that need exports
                overdue_exports = await conn.fetchval("""
                    SELECT COUNT(*)
                    FROM search_terms st
                    WHERE st.active = true 
                      AND st.export_enabled = true
                      AND (st.last_export IS NULL OR st.last_export < NOW() - INTERVAL '25 hours')
                """)
            
            health = {
                'status': 'healthy',
                'exports_24h': export_stats['total_exports_24h'] or 0,
                'successful_exports': export_stats['successful_exports'] or 0,
                'last_export': export_stats['last_export'].isoformat() if export_stats['last_export'] else None,
                'terms_exported': export_stats['terms_exported'] or 0,
                'overdue_exports': overdue_exports or 0,
                'alerts': []
            }
            
            # Check for overdue exports
            if overdue_exports > 0:
                severity = AlertSeverity.MEDIUM if overdue_exports < 10 else AlertSeverity.HIGH
                health['status'] = 'degraded'
                health['alerts'].append({
                    'alert_type': AlertType.EXPORT_FAILURE,
                    'severity': severity,
                    'title': f'Overdue Exports: {overdue_exports} terms',
                    'message': f'{overdue_exports} search terms have not been exported in the last 25 hours',
                    'source': 'export_monitor',
                    'metadata': {'overdue_count': overdue_exports}
                })
            
            return health
            
        except Exception as e:
            logger.error(f"Export health check failed: {e}")
            return {
                'status': 'unknown',
                'error': str(e),
                'alerts': [{
                    'alert_type': AlertType.EXPORT_FAILURE,
                    'severity': AlertSeverity.MEDIUM,
                    'title': 'Export Health Check Failed',
                    'message': f'Unable to check export health: {str(e)}',
                    'source': 'export_monitor',
                    'metadata': {'error': str(e)}
                }]
            }
    
    async def _check_system_resources(self) -> Dict[str, Any]:
        """Check system resource usage"""
        try:
            import psutil
            
            # Get system resource usage
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            health = {
                'status': 'healthy',
                'cpu_usage_percent': cpu_percent,
                'memory_usage_percent': memory.percent,
                'disk_usage_percent': disk.percent,
                'disk_free_gb': disk.free / (1024**3),
                'alerts': []
            }
            
            # Check disk usage
            if disk.percent > self.thresholds['disk_usage_percentage']:
                health['status'] = 'critical'
                health['alerts'].append({
                    'alert_type': AlertType.DISK_SPACE_LOW,
                    'severity': AlertSeverity.HIGH,
                    'title': f'Low Disk Space: {disk.percent:.1f}% used',
                    'message': f'Disk usage ({disk.percent:.1f}%) exceeds threshold, {disk.free / (1024**3):.1f}GB free',
                    'source': 'resource_monitor',
                    'metadata': {'disk_usage_percent': disk.percent, 'disk_free_gb': disk.free / (1024**3)}
                })
            
            # Check memory usage
            if memory.percent > self.thresholds['memory_usage_percentage']:
                severity = AlertSeverity.CRITICAL if health['status'] == 'critical' else AlertSeverity.HIGH
                health['status'] = 'critical' if health['status'] != 'critical' else health['status']
                health['alerts'].append({
                    'alert_type': AlertType.SYSTEM_HEALTH,
                    'severity': severity,
                    'title': f'High Memory Usage: {memory.percent:.1f}%',
                    'message': f'Memory usage ({memory.percent:.1f}%) exceeds threshold',
                    'source': 'resource_monitor',
                    'metadata': {'memory_usage_percent': memory.percent}
                })
            
            return health
            
        except ImportError:
            # psutil not available, skip resource checks
            return {
                'status': 'unknown',
                'message': 'Resource monitoring unavailable (psutil not installed)'
            }
        except Exception as e:
            logger.error(f"Resource health check failed: {e}")
            return {
                'status': 'unknown',
                'error': str(e)
            }
    
    async def _create_alert(self, alert_data: Dict[str, Any]) -> Optional[Alert]:
        """Create and process an alert"""
        try:
            alert_id = f"{alert_data['alert_type'].value}_{alert_data['source']}_{int(datetime.now().timestamp())}"
            
            alert = Alert(
                alert_id=alert_id,
                alert_type=alert_data['alert_type'],
                severity=alert_data['severity'],
                title=alert_data['title'],
                message=alert_data['message'],
                source=alert_data['source'],
                timestamp=datetime.now(),
                metadata=alert_data.get('metadata', {})
            )
            
            # Check if this alert should be suppressed
            if await self._should_suppress_alert(alert):
                logger.info(f"Alert suppressed: {alert.title}")
                return None
            
            # Store alert in database
            await self._store_alert(alert)
            
            # Send notifications
            await self._send_alert_notifications(alert)
            
            # Cache active alert
            self.active_alerts[alert.alert_id] = alert
            
            logger.info(f"Alert created: {alert.title} ({alert.severity.value})")
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    async def _should_suppress_alert(self, alert: Alert) -> bool:
        """Check if alert should be suppressed to prevent spam"""
        try:
            suppression_window = self.suppression_windows.get(alert.alert_type)
            if not suppression_window:
                return False
            
            cutoff_time = alert.timestamp - suppression_window
            
            # Check for similar recent alerts
            async with self.db_service.pool.acquire() as conn:
                recent_count = await conn.fetchval("""
                    SELECT COUNT(*)
                    FROM alerts
                    WHERE alert_type = $1
                      AND source = $2
                      AND created_at >= $3
                      AND resolved = false
                """, alert.alert_type.value, alert.source, cutoff_time)
            
            return recent_count > 0
            
        except Exception as e:
            logger.error(f"Error checking alert suppression: {e}")
            return False
    
    async def _store_alert(self, alert: Alert):
        """Store alert in database"""
        try:
            async with self.db_service.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO alerts 
                    (alert_id, alert_type, severity, title, message, source, 
                     metadata, created_at, resolved, escalated, notification_count)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                """, 
                alert.alert_id, alert.alert_type.value, alert.severity.value,
                alert.title, alert.message, alert.source,
                json.dumps(alert.metadata), alert.timestamp,
                alert.resolved, alert.escalated, alert.notification_count)
                
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
    
    async def _send_alert_notifications(self, alert: Alert):
        """Send alert notifications via email and webhooks"""
        try:
            # Send email notifications
            if self.alert_emails:
                await self._send_email_notification(alert)
            
            # Send webhook notifications
            if self.webhook_urls:
                await self._send_webhook_notifications(alert)
            
            # Update notification count
            alert.notification_count += 1
            await self._update_alert_notification_count(alert)
            
        except Exception as e:
            logger.error(f"Error sending alert notifications: {e}")
    
    async def _send_email_notification(self, alert: Alert):
        """Send email notification for alert"""
        try:
            if not self.smtp_user or not self.alert_emails:
                return
            
            subject = f"[{alert.severity.value.upper()}] {alert.title}"
            
            body = f"""
Alert Details:
- Type: {alert.alert_type.value}
- Severity: {alert.severity.value}
- Source: {alert.source}
- Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

Message:
{alert.message}

Metadata:
{json.dumps(alert.metadata, indent=2)}

Alert ID: {alert.alert_id}
"""
            
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.alert_emails)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent for alert: {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
    
    async def _send_webhook_notifications(self, alert: Alert):
        """Send webhook notifications for alert"""
        try:
            payload = {
                'alert_id': alert.alert_id,
                'alert_type': alert.alert_type.value,
                'severity': alert.severity.value,
                'title': alert.title,
                'message': alert.message,
                'source': alert.source,
                'timestamp': alert.timestamp.isoformat(),
                'metadata': alert.metadata
            }
            
            async with aiohttp.ClientSession() as session:
                for webhook_url in self.webhook_urls:
                    try:
                        async with session.post(webhook_url, json=payload, timeout=10) as response:
                            if response.status == 200:
                                logger.info(f"Webhook notification sent to {webhook_url}")
                            else:
                                logger.warning(f"Webhook notification failed: {response.status}")
                    except Exception as e:
                        logger.error(f"Error sending webhook to {webhook_url}: {e}")
                        
        except Exception as e:
            logger.error(f"Error sending webhook notifications: {e}")
    
    async def _update_alert_notification_count(self, alert: Alert):
        """Update alert notification count in database"""
        try:
            async with self.db_service.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE alerts 
                    SET notification_count = $1, updated_at = NOW()
                    WHERE alert_id = $2
                """, alert.notification_count, alert.alert_id)
                
        except Exception as e:
            logger.error(f"Error updating alert notification count: {e}")
    
    async def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved"""
        try:
            async with self.db_service.pool.acquire() as conn:
                updated = await conn.fetchval("""
                    UPDATE alerts 
                    SET resolved = true, resolved_at = NOW(), updated_at = NOW()
                    WHERE alert_id = $1 AND resolved = false
                    RETURNING 1
                """, alert_id)
            
            if updated:
                # Remove from active alerts cache
                self.active_alerts.pop(alert_id, None)
                logger.info(f"Alert resolved: {alert_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error resolving alert: {e}")
            return False
    
    async def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active (unresolved) alerts"""
        try:
            async with self.db_service.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT alert_id, alert_type, severity, title, message, 
                           source, created_at, metadata, notification_count
                    FROM alerts
                    WHERE resolved = false
                    ORDER BY severity DESC, created_at DESC
                """)
            
            return [dict(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting active alerts: {e}")
            return []


# Global instance
alerting_service = None

async def get_alerting_service(config: Optional[Dict[str, Any]] = None):
    """Get or create global alerting service instance"""
    global alerting_service
    if alerting_service is None:
        alerting_service = AlertingService(config)
        await alerting_service.initialize()
    return alerting_service