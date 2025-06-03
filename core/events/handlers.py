"""
Event Handlers for Monitor Legislativo v4
Implements specific handlers for system events

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
import asyncio

from .event_bus import Event, EventType, event_bus
from ..cache.cache_strategy import invalidate_cache
from ..monitoring.metrics_collector import metrics_collector
from web.realtime.websocket_handler import notify_new_proposition, notify_proposition_update

logger = logging.getLogger(__name__)

class CacheInvalidationHandler:
    """Handles cache invalidation based on events"""
    
    @staticmethod
    async def handle_proposition_change(event: Event) -> None:
        """Invalidate cache when proposition changes"""
        try:
            proposition_id = event.data.get("proposition_id")
            if not proposition_id:
                return
                
            # Invalidate specific proposition cache
            await invalidate_cache(f"prop_*_{proposition_id}")
            
            # Invalidate search results that might include this proposition
            await invalidate_cache("search_*")
            
            logger.info(f"Cache invalidated for proposition {proposition_id}")
            
        except Exception as e:
            logger.error(f"Cache invalidation error: {e}")
            
    @staticmethod
    async def handle_system_maintenance(event: Event) -> None:
        """Clear all caches during maintenance"""
        try:
            count = await invalidate_cache("*")
            logger.info(f"Cleared {count} cache entries for maintenance")
        except Exception as e:
            logger.error(f"Cache clear error: {e}")

class WebSocketNotificationHandler:
    """Handles WebSocket notifications for real-time updates"""
    
    @staticmethod
    async def handle_new_proposition(event: Event) -> None:
        """Notify WebSocket clients of new proposition"""
        try:
            proposition_data = event.data
            
            # Create proposition object for notification
            from core.models.models import Proposition
            proposition = Proposition(
                id=proposition_data.get("id"),
                source=proposition_data.get("source"),
                type=proposition_data.get("type"),
                number=proposition_data.get("number"),
                year=proposition_data.get("year"),
                title=proposition_data.get("title"),
                summary=proposition_data.get("summary"),
                status=proposition_data.get("status"),
                author=proposition_data.get("author"),
                created_at=datetime.fromisoformat(proposition_data.get("created_at")),
                keywords=proposition_data.get("keywords", [])
            )
            
            await notify_new_proposition(proposition)
            logger.info(f"WebSocket notification sent for new proposition {proposition.id}")
            
        except Exception as e:
            logger.error(f"WebSocket notification error: {e}")
            
    @staticmethod
    async def handle_proposition_update(event: Event) -> None:
        """Notify WebSocket clients of proposition update"""
        try:
            proposition_id = event.data.get("proposition_id")
            changes = event.data.get("changes", {})
            
            # Create minimal proposition object for notification
            from core.models.models import Proposition
            proposition = Proposition(
                id=proposition_id,
                source=changes.get("source", "unknown"),
                title=changes.get("title", ""),
                status=changes.get("status", "unknown"),
                updated_at=datetime.now()
            )
            
            await notify_proposition_update(proposition)
            logger.info(f"WebSocket notification sent for proposition update {proposition_id}")
            
        except Exception as e:
            logger.error(f"WebSocket notification error: {e}")

class MetricsCollectionHandler:
    """Handles metrics collection based on events"""
    
    @staticmethod
    async def handle_search_performed(event: Event) -> None:
        """Collect search metrics"""
        try:
            query = event.data.get("query")
            results_count = event.data.get("results_count", 0)
            sources = event.data.get("sources", [])
            
            # Record search metrics
            metrics_collector.record_search(
                query=query,
                results_count=results_count,
                sources=sources
            )
            
            # Track popular queries
            metrics_collector.increment_counter(
                "search_query_count",
                tags={"query": query[:50]}  # Truncate long queries
            )
            
        except Exception as e:
            logger.error(f"Metrics collection error: {e}")
            
    @staticmethod
    async def handle_system_error(event: Event) -> None:
        """Collect error metrics"""
        try:
            error_type = event.data.get("error_type")
            component = event.source
            
            metrics_collector.increment_counter(
                "system_errors",
                tags={
                    "error_type": error_type,
                    "component": component
                }
            )
            
        except Exception as e:
            logger.error(f"Error metrics collection failed: {e}")

class AlertingHandler:
    """Handles alerting based on critical events"""
    
    @staticmethod
    async def handle_critical_error(event: Event) -> None:
        """Send alerts for critical errors"""
        try:
            error_message = event.data.get("error_message")
            component = event.source
            
            # Check if this is a critical error
            severity = event.metadata.get("severity", "error")
            if severity != "critical":
                return
                
            # Send alert (integrate with alerting service)
            alert_data = {
                "type": "critical_error",
                "component": component,
                "message": error_message,
                "timestamp": event.timestamp.isoformat()
            }
            
            # In production, would send to PagerDuty, OpsGenie, etc.
            logger.critical(f"ALERT: Critical error in {component}: {error_message}")
            
        except Exception as e:
            logger.error(f"Alerting error: {e}")
            
    @staticmethod
    async def handle_high_load(event: Event) -> None:
        """Alert on high system load"""
        try:
            load_metrics = event.data
            
            # Check thresholds
            if load_metrics.get("cpu_usage", 0) > 90:
                logger.warning("ALERT: High CPU usage detected")
                
            if load_metrics.get("memory_usage", 0) > 85:
                logger.warning("ALERT: High memory usage detected")
                
        except Exception as e:
            logger.error(f"Load alerting error: {e}")

class PluginEventHandler:
    """Handles plugin-related events"""
    
    @staticmethod
    async def handle_plugin_loaded(event: Event) -> None:
        """Handle plugin loaded event"""
        try:
            plugin_name = event.data.get("plugin_name")
            plugin_type = event.data.get("plugin_type")
            
            logger.info(f"Plugin {plugin_name} ({plugin_type}) loaded successfully")
            
            # Update system capabilities based on plugin
            if plugin_type == "exporter":
                # Register new export format
                pass
            elif plugin_type == "analyzer":
                # Register new analysis capability
                pass
                
        except Exception as e:
            logger.error(f"Plugin load handler error: {e}")
            
    @staticmethod
    async def handle_plugin_error(event: Event) -> None:
        """Handle plugin error event"""
        try:
            plugin_name = event.data.get("plugin_name")
            error_message = event.data.get("error_message")
            
            logger.error(f"Plugin {plugin_name} error: {error_message}")
            
            # Potentially disable plugin if too many errors
            error_count = event.metadata.get("error_count", 1)
            if error_count > 5:
                logger.warning(f"Plugin {plugin_name} has too many errors, consider disabling")
                
        except Exception as e:
            logger.error(f"Plugin error handler failed: {e}")

class AuditLogHandler:
    """Handles audit logging for compliance"""
    
    @staticmethod
    async def handle_user_action(event: Event) -> None:
        """Log user actions for audit trail"""
        try:
            user_id = event.metadata.get("user_id", "anonymous")
            action = event.type.value
            
            audit_entry = {
                "timestamp": event.timestamp.isoformat(),
                "user_id": user_id,
                "action": action,
                "source": event.source,
                "data": event.data
            }
            
            # In production, would write to audit log storage
            logger.info(f"AUDIT: User {user_id} performed {action}")
            
        except Exception as e:
            logger.error(f"Audit logging error: {e}")

def register_event_handlers():
    """Register all event handlers with the event bus"""
    
    # Cache invalidation handlers
    event_bus.subscribe(
        [EventType.PROPOSITION_CREATED, EventType.PROPOSITION_UPDATED],
        CacheInvalidationHandler.handle_proposition_change,
        priority=10
    )
    
    event_bus.subscribe(
        [EventType.SYSTEM_MAINTENANCE],
        CacheInvalidationHandler.handle_system_maintenance,
        priority=10
    )
    
    # WebSocket notification handlers
    event_bus.subscribe(
        [EventType.PROPOSITION_CREATED],
        WebSocketNotificationHandler.handle_new_proposition,
        priority=5
    )
    
    event_bus.subscribe(
        [EventType.PROPOSITION_UPDATED, EventType.PROPOSITION_STATUS_CHANGED],
        WebSocketNotificationHandler.handle_proposition_update,
        priority=5
    )
    
    # Metrics collection handlers
    event_bus.subscribe(
        [EventType.SEARCH_PERFORMED],
        MetricsCollectionHandler.handle_search_performed,
        priority=3
    )
    
    event_bus.subscribe(
        [EventType.SYSTEM_ERROR],
        MetricsCollectionHandler.handle_system_error,
        priority=3
    )
    
    # Alerting handlers
    event_bus.subscribe(
        [EventType.SYSTEM_ERROR],
        AlertingHandler.handle_critical_error,
        priority=8
    )
    
    # Plugin event handlers
    event_bus.subscribe(
        [EventType.PLUGIN_LOADED],
        PluginEventHandler.handle_plugin_loaded,
        priority=5
    )
    
    event_bus.subscribe(
        [EventType.PLUGIN_ERROR],
        PluginEventHandler.handle_plugin_error,
        priority=8
    )
    
    # Audit log handlers
    event_bus.subscribe(
        [EventType.USER_LOGIN, EventType.USER_LOGOUT],
        AuditLogHandler.handle_user_action,
        priority=2
    )
    
    logger.info("All event handlers registered")

# Auto-register handlers on import
register_event_handlers()