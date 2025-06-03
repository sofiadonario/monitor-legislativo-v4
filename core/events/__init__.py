"""
Event-Driven Architecture for Monitor Legislativo v4
Central event system for real-time processing

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .event_bus import (
    Event,
    EventType,
    EventBus,
    EventBuilder,
    event_bus,
    publish_event,
    subscribe_to_events,
    start_event_processing,
    stop_event_processing
)

from .handlers import (
    CacheInvalidationHandler,
    WebSocketNotificationHandler,
    MetricsCollectionHandler,
    AlertingHandler,
    PluginEventHandler,
    AuditLogHandler,
    register_event_handlers
)

from .event_stream import (
    EventStream,
    InMemoryEventStream,
    KafkaEventStream,
    EventStreamManager,
    EventReplay,
    EventAggregator,
    stream_manager,
    create_event_stream,
    start_event_streaming,
    stop_event_streaming
)

__all__ = [
    # Core event system
    "Event",
    "EventType",
    "EventBus",
    "EventBuilder",
    "event_bus",
    "publish_event",
    "subscribe_to_events",
    "start_event_processing",
    "stop_event_processing",
    
    # Event handlers
    "CacheInvalidationHandler",
    "WebSocketNotificationHandler",
    "MetricsCollectionHandler",
    "AlertingHandler",
    "PluginEventHandler",
    "AuditLogHandler",
    "register_event_handlers",
    
    # Event streaming
    "EventStream",
    "InMemoryEventStream",
    "KafkaEventStream",
    "EventStreamManager",
    "EventReplay",
    "EventAggregator",
    "stream_manager",
    "create_event_stream",
    "start_event_streaming",
    "stop_event_streaming"
]