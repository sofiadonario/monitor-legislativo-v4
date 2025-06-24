"""
Prefect flows for system monitoring, health checks, and alerting
Provides automated monitoring and alerting for the collection system
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner

from ..services.alerting_service import get_alerting_service
from ..services.database_service import CollectionDatabaseService
from ..utils.monitoring import performance_tracker, collection_metrics

logger = logging.getLogger(__name__)


@task(name="initialize_monitoring_services", retries=2)
async def initialize_monitoring_services(alerting_config: Optional[Dict[str, Any]] = None):
    """Initialize monitoring and alerting services"""
    try:
        alerting_service = await get_alerting_service(alerting_config)
        db_service = CollectionDatabaseService()
        await db_service.initialize()
        
        logger.info("Monitoring services initialized successfully")
        return {'alerting_service': alerting_service, 'db_service': db_service}
    except Exception as e:
        logger.error(f"Failed to initialize monitoring services: {e}")
        raise


@task(name="system_health_check", retries=1)
async def system_health_check_task(services: Dict[str, Any]) -> Dict[str, Any]:
    """Perform comprehensive system health check"""
    try:
        alerting_service = services['alerting_service']
        logger.info("Starting system health check")
        
        health_status = await alerting_service.check_system_health()
        
        logger.info(f"System health check completed: {health_status['overall_status']}")
        logger.info(f"Alerts triggered: {len(health_status.get('alerts_triggered', []))}")
        
        return health_status
    except Exception as e:
        logger.error(f"Error in system health check task: {e}")
        raise


@task(name="collection_metrics_analysis", retries=1)
async def collection_metrics_analysis_task(db_service) -> Dict[str, Any]:
    """Analyze collection metrics and trends"""
    try:
        logger.info("Analyzing collection metrics")
        
        # Get collection metrics for the last 24 hours
        async with db_service.pool.acquire() as conn:
            metrics = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_collections,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_collections,
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_collections,
                    AVG(execution_time_ms) as avg_execution_time,
                    AVG(documents_collected) as avg_documents_per_collection,
                    SUM(documents_collected) as total_documents_collected,
                    COUNT(DISTINCT search_term_id) as active_search_terms,
                    COUNT(DISTINCT source_api) as active_sources
                FROM collection_logs
                WHERE completed_at >= NOW() - INTERVAL '24 hours'
            """)
            
            # Get hourly breakdown
            hourly_stats = await conn.fetch("""
                SELECT 
                    date_trunc('hour', completed_at) as hour,
                    COUNT(*) as collections,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful,
                    AVG(execution_time_ms) as avg_time
                FROM collection_logs
                WHERE completed_at >= NOW() - INTERVAL '24 hours'
                GROUP BY date_trunc('hour', completed_at)
                ORDER BY hour
            """)
            
            # Get source performance
            source_stats = await conn.fetch("""
                SELECT 
                    source_api,
                    COUNT(*) as total_collections,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful,
                    AVG(execution_time_ms) as avg_execution_time,
                    SUM(documents_collected) as total_documents
                FROM collection_logs
                WHERE completed_at >= NOW() - INTERVAL '24 hours'
                GROUP BY source_api
                ORDER BY total_collections DESC
            """)
        
        analysis = {
            'period': '24_hours',
            'timestamp': datetime.now().isoformat(),
            'overall_metrics': dict(metrics) if metrics else {},
            'hourly_breakdown': [dict(row) for row in hourly_stats],
            'source_performance': [dict(row) for row in source_stats],
            'success_rate': 0.0,
            'performance_trend': 'stable',
            'issues_detected': []
        }
        
        # Calculate success rate
        total = metrics['total_collections'] or 0
        successful = metrics['successful_collections'] or 0
        analysis['success_rate'] = successful / total if total > 0 else 1.0
        
        # Analyze performance trends
        if len(hourly_stats) >= 12:  # At least 12 hours of data
            recent_avg = sum(row['avg_time'] or 0 for row in hourly_stats[-6:]) / 6
            older_avg = sum(row['avg_time'] or 0 for row in hourly_stats[-12:-6]) / 6
            
            if recent_avg > older_avg * 1.2:
                analysis['performance_trend'] = 'degrading'
                analysis['issues_detected'].append('Performance degradation detected')
            elif recent_avg < older_avg * 0.8:
                analysis['performance_trend'] = 'improving'
        
        # Check for API issues
        for source in source_stats:
            source_success_rate = source['successful'] / source['total_collections'] if source['total_collections'] > 0 else 0
            if source_success_rate < 0.8 and source['total_collections'] >= 5:
                analysis['issues_detected'].append(f"Low success rate for {source['source_api']}: {source_success_rate:.1%}")
        
        logger.info(f"Collection metrics analysis completed: {analysis['success_rate']:.1%} success rate")
        return analysis
        
    except Exception as e:
        logger.error(f"Error in collection metrics analysis: {e}")
        return {'error': str(e), 'timestamp': datetime.now().isoformat()}


@task(name="performance_monitoring", retries=1)
async def performance_monitoring_task(db_service) -> Dict[str, Any]:
    """Monitor system performance metrics"""
    try:
        logger.info("Monitoring system performance")
        
        # Get performance data from monitoring utils
        performance_data = {
            'timestamp': datetime.now().isoformat(),
            'active_operations': len(performance_tracker.active_operations),
            'completed_operations_24h': 0,
            'avg_operation_time_ms': 0,
            'slowest_operations': [],
            'collection_metrics': {}
        }
        
        # Get database performance metrics
        async with db_service.pool.acquire() as conn:
            # Query performance
            query_stats = await conn.fetchrow("""
                SELECT 
                    count(*) as total_queries,
                    avg(extract(milliseconds from now() - query_start)) as avg_query_time_ms
                FROM pg_stat_activity 
                WHERE state = 'active' AND query != '<IDLE>'
            """)
            
            if query_stats:
                performance_data['database'] = {
                    'active_queries': query_stats['total_queries'] or 0,
                    'avg_query_time_ms': query_stats['avg_query_time_ms'] or 0
                }
            
            # Connection pool stats
            pool_stats = {
                'pool_size': db_service.pool.get_size(),
                'checked_out_connections': db_service.pool.get_size() - db_service.pool.get_idle_size(),
                'idle_connections': db_service.pool.get_idle_size()
            }
            performance_data['connection_pool'] = pool_stats
            
            # Table sizes and growth
            table_stats = await conn.fetch("""
                SELECT 
                    schemaname,
                    tablename,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                LIMIT 10
            """)
            performance_data['table_sizes'] = [dict(row) for row in table_stats]
        
        # Get collection metrics from monitoring utils
        performance_data['collection_metrics'] = {
            'total_collections': collection_metrics.total_collections,
            'successful_collections': collection_metrics.successful_collections,
            'failed_collections': collection_metrics.failed_collections,
            'avg_collection_time_ms': collection_metrics.avg_execution_time_ms
        }
        
        logger.info("Performance monitoring completed")
        return performance_data
        
    except Exception as e:
        logger.error(f"Error in performance monitoring: {e}")
        return {'error': str(e), 'timestamp': datetime.now().isoformat()}


@task(name="alert_management", retries=1)
async def alert_management_task(alerting_service) -> Dict[str, Any]:
    """Manage and process alerts"""
    try:
        logger.info("Managing alerts")
        
        # Get active alerts
        active_alerts = await alerting_service.get_active_alerts()
        
        alert_summary = {
            'timestamp': datetime.now().isoformat(),
            'total_active_alerts': len(active_alerts),
            'alerts_by_severity': {},
            'alerts_by_type': {},
            'oldest_unresolved': None,
            'recent_alerts_1h': 0
        }
        
        # Analyze alerts
        one_hour_ago = datetime.now() - timedelta(hours=1)
        
        for alert in active_alerts:
            # Count by severity
            severity = alert['severity']
            alert_summary['alerts_by_severity'][severity] = alert_summary['alerts_by_severity'].get(severity, 0) + 1
            
            # Count by type
            alert_type = alert['alert_type']
            alert_summary['alerts_by_type'][alert_type] = alert_summary['alerts_by_type'].get(alert_type, 0) + 1
            
            # Find oldest unresolved
            alert_time = alert['created_at']
            if alert_summary['oldest_unresolved'] is None or alert_time < alert_summary['oldest_unresolved']:
                alert_summary['oldest_unresolved'] = alert_time.isoformat()
            
            # Count recent alerts
            if alert_time >= one_hour_ago:
                alert_summary['recent_alerts_1h'] += 1
        
        # Auto-resolve certain alerts based on conditions
        resolved_count = 0
        for alert in active_alerts:
            if alert['alert_type'] == 'api_unavailable':
                # Check if API is now available
                # This would require additional logic to test API availability
                pass
            elif alert['alert_type'] == 'collection_failure':
                # Check if recent collections are now successful
                # This would require checking recent collection logs
                pass
        
        alert_summary['auto_resolved_count'] = resolved_count
        
        logger.info(f"Alert management completed: {len(active_alerts)} active alerts")
        return alert_summary
        
    except Exception as e:
        logger.error(f"Error in alert management: {e}")
        return {'error': str(e), 'timestamp': datetime.now().isoformat()}


@flow(
    name="system_monitoring_flow",
    description="Comprehensive system monitoring with health checks and alerting",
    task_runner=ConcurrentTaskRunner()
)
async def system_monitoring_flow(
    alerting_config: Optional[Dict[str, Any]] = None,
    include_performance_analysis: bool = True,
    include_metrics_analysis: bool = True
) -> Dict[str, Any]:
    """
    Main flow for system monitoring and health checks
    
    Args:
        alerting_config: Configuration for alerting service
        include_performance_analysis: Whether to run performance analysis
        include_metrics_analysis: Whether to run metrics analysis
    
    Returns:
        Dict with monitoring results
    """
    flow_logger = get_run_logger()
    flow_start = datetime.now()
    
    monitoring_results = {
        'flow_name': 'system_monitoring_flow',
        'execution_start': flow_start.isoformat(),
        'status': 'started'
    }
    
    try:
        flow_logger.info("Starting system monitoring flow")
        
        # Initialize services
        services = await initialize_monitoring_services(alerting_config)
        
        # Run system health check
        health_status = await system_health_check_task(services)
        monitoring_results['health_check'] = health_status
        
        # Run performance monitoring
        if include_performance_analysis:
            performance_data = await performance_monitoring_task(services['db_service'])
            monitoring_results['performance'] = performance_data
        
        # Run collection metrics analysis
        if include_metrics_analysis:
            metrics_analysis = await collection_metrics_analysis_task(services['db_service'])
            monitoring_results['metrics_analysis'] = metrics_analysis
        
        # Manage alerts
        alert_summary = await alert_management_task(services['alerting_service'])
        monitoring_results['alert_management'] = alert_summary
        
        # Determine overall monitoring status
        overall_health = health_status.get('overall_status', 'unknown')
        active_alerts = alert_summary.get('total_active_alerts', 0)
        critical_alerts = alert_summary.get('alerts_by_severity', {}).get('critical', 0)
        
        if overall_health == 'critical' or critical_alerts > 0:
            monitoring_results['overall_status'] = 'critical'
        elif overall_health == 'degraded' or active_alerts > 5:
            monitoring_results['overall_status'] = 'degraded'
        elif overall_health == 'healthy':
            monitoring_results['overall_status'] = 'healthy'
        else:
            monitoring_results['overall_status'] = 'unknown'
        
        monitoring_results['status'] = 'completed'
        monitoring_results['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.info(f"System monitoring flow completed: {monitoring_results['overall_status']}")
        return monitoring_results
        
    except Exception as e:
        monitoring_results['status'] = 'failed'
        monitoring_results['error'] = str(e)
        monitoring_results['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.error(f"System monitoring flow failed: {e}")
        raise


@flow(
    name="alert_escalation_flow",
    description="Handle alert escalation for critical issues"
)
async def alert_escalation_flow(
    escalation_threshold_hours: int = 4,
    critical_alert_threshold: int = 3
) -> Dict[str, Any]:
    """
    Flow for handling alert escalation
    
    Args:
        escalation_threshold_hours: Hours before escalating unresolved alerts
        critical_alert_threshold: Number of critical alerts to trigger escalation
    
    Returns:
        Dict with escalation results
    """
    flow_logger = get_run_logger()
    
    try:
        flow_logger.info("Starting alert escalation flow")
        
        alerting_service = await get_alerting_service()
        
        escalation_results = {
            'timestamp': datetime.now().isoformat(),
            'escalated_alerts': [],
            'critical_alerts_count': 0,
            'escalation_triggered': False
        }
        
        # Get active alerts
        active_alerts = await alerting_service.get_active_alerts()
        
        escalation_cutoff = datetime.now() - timedelta(hours=escalation_threshold_hours)
        critical_alerts = [a for a in active_alerts if a['severity'] == 'critical']
        
        escalation_results['critical_alerts_count'] = len(critical_alerts)
        
        # Check for escalation conditions
        should_escalate = False
        
        # Condition 1: Too many critical alerts
        if len(critical_alerts) >= critical_alert_threshold:
            should_escalate = True
            escalation_results['escalation_reason'] = f'{len(critical_alerts)} critical alerts active'
        
        # Condition 2: Long-running unresolved alerts
        old_alerts = [a for a in active_alerts if a['created_at'] <= escalation_cutoff]
        if len(old_alerts) > 0:
            should_escalate = True
            escalation_results['escalation_reason'] = f'{len(old_alerts)} alerts unresolved for {escalation_threshold_hours}+ hours'
            escalation_results['escalated_alerts'] = [a['alert_id'] for a in old_alerts]
        
        if should_escalate:
            escalation_results['escalation_triggered'] = True
            
            # Here you would implement actual escalation logic:
            # - Send escalation emails to management
            # - Create escalation tickets
            # - Trigger emergency procedures
            
            flow_logger.warning(f"Alert escalation triggered: {escalation_results['escalation_reason']}")
        else:
            flow_logger.info("No escalation needed")
        
        return escalation_results
        
    except Exception as e:
        flow_logger.error(f"Alert escalation flow failed: {e}")
        return {'error': str(e), 'timestamp': datetime.now().isoformat()}


@flow(
    name="monitoring_validation_flow",
    description="Validate monitoring system functionality"
)
async def monitoring_validation_flow() -> Dict[str, Any]:
    """
    Flow for validating monitoring system functionality
    
    Returns:
        Dict with validation results
    """
    flow_logger = get_run_logger()
    
    try:
        flow_logger.info("Starting monitoring validation flow")
        
        validation_results = {
            'timestamp': datetime.now().isoformat(),
            'alerting_service_functional': False,
            'database_connectivity': False,
            'health_checks_working': False,
            'alert_storage_working': False,
            'overall_status': 'failed'
        }
        
        # Test alerting service initialization
        try:
            alerting_service = await get_alerting_service()
            validation_results['alerting_service_functional'] = True
        except Exception as e:
            flow_logger.error(f"Alerting service validation failed: {e}")
        
        # Test database connectivity
        try:
            db_service = CollectionDatabaseService()
            await db_service.initialize()
            validation_results['database_connectivity'] = True
        except Exception as e:
            flow_logger.error(f"Database connectivity validation failed: {e}")
        
        # Test health checks
        if validation_results['alerting_service_functional']:
            try:
                health_result = await alerting_service.check_system_health()
                validation_results['health_checks_working'] = 'overall_status' in health_result
            except Exception as e:
                flow_logger.error(f"Health check validation failed: {e}")
        
        # Test alert storage
        if validation_results['alerting_service_functional']:
            try:
                test_alert = await alerting_service._create_alert({
                    'alert_type': 'system_health',
                    'severity': 'low',
                    'title': 'Monitoring Validation Test',
                    'message': 'This is a test alert for validation purposes',
                    'source': 'validation_test',
                    'metadata': {'test': True}
                })
                
                if test_alert:
                    validation_results['alert_storage_working'] = True
                    # Clean up test alert
                    await alerting_service.resolve_alert(test_alert.alert_id)
                    
            except Exception as e:
                flow_logger.error(f"Alert storage validation failed: {e}")
        
        # Overall validation status
        validation_results['overall_status'] = 'passed' if all([
            validation_results['alerting_service_functional'],
            validation_results['database_connectivity'],
            validation_results['health_checks_working']
        ]) else 'failed'
        
        flow_logger.info(f"Monitoring validation completed: {validation_results['overall_status']}")
        return validation_results
        
    except Exception as e:
        flow_logger.error(f"Monitoring validation flow failed: {e}")
        return {'error': str(e), 'overall_status': 'failed'}


# Scheduled flows can be added here for automation
if __name__ == "__main__":
    # Example of running the flow directly
    import asyncio
    asyncio.run(system_monitoring_flow())