"""
Event Bus for Monitor Legislativo v4
Implements event-driven architecture for real-time features

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, List, Callable, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import uuid

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Types of events in the system"""
    # Proposition events
    PROPOSITION_CREATED = "proposition.created"
    PROPOSITION_UPDATED = "proposition.updated"
    PROPOSITION_STATUS_CHANGED = "proposition.status_changed"
    PROPOSITION_ARCHIVED = "proposition.archived"
    
    # Search events
    SEARCH_PERFORMED = "search.performed"
    SEARCH_ALERT_TRIGGERED = "search.alert_triggered"
    
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_MAINTENANCE = "system.maintenance"
    
    # Cache events
    CACHE_INVALIDATED = "cache.invalidated"
    CACHE_WARMED = "cache.warmed"
    
    # User events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_SUBSCRIBED = "user.subscribed"
    USER_UNSUBSCRIBED = "user.unsubscribed"
    
    # Plugin events
    PLUGIN_LOADED = "plugin.loaded"
    PLUGIN_UNLOADED = "plugin.unloaded"
    PLUGIN_ERROR = "plugin.error"
    
    # Analytics events
    ANALYTICS_GENERATED = "analytics.generated"
    REPORT_CREATED = "report.created"

@dataclass
class Event:
    """Base event class"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EventType = None
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "system"
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "id": self.id,
            "type": self.type.value if self.type else None,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "data": self.data,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """Convert event to JSON"""
        return json.dumps(self.to_dict(), default=str)

class EventHandler:
    """Wrapper for event handlers with metadata"""
    
    def __init__(self, 
                 handler: Callable,
                 event_types: List[EventType],
                 priority: int = 0,
                 filter_func: Optional[Callable] = None):
        self.handler = handler
        self.event_types = set(event_types)
        self.priority = priority
        self.filter_func = filter_func
        self.execution_count = 0
        self.error_count = 0
        
    async def handle(self, event: Event) -> Any:
        """Execute handler if event matches criteria"""
        # Check event type
        if event.type not in self.event_types:
            return None
            
        # Apply filter if exists
        if self.filter_func and not self.filter_func(event):
            return None
            
        # Execute handler
        try:
            self.execution_count += 1
            if asyncio.iscoroutinefunction(self.handler):
                return await self.handler(event)
            else:
                return self.handler(event)
        except Exception as e:
            self.error_count += 1
            logger.error(f"Event handler error: {e}", exc_info=True)
            raise

class EventBus:
    """Central event bus for publishing and subscribing to events"""
    
    def __init__(self):
        self.handlers: Dict[str, List[EventHandler]] = {}
        self.event_history: List[Event] = []
        self.max_history_size = 1000
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self._processing = False
        self._processor_task: Optional[asyncio.Task] = None
        
    def subscribe(self,
                  event_types: List[EventType],
                  handler: Callable,
                  priority: int = 0,
                  filter_func: Optional[Callable] = None) -> str:
        """Subscribe to events"""
        handler_id = str(uuid.uuid4())
        event_handler = EventHandler(handler, event_types, priority, filter_func)
        
        for event_type in event_types:
            if event_type.value not in self.handlers:
                self.handlers[event_type.value] = []
            
            self.handlers[event_type.value].append(event_handler)
            # Sort by priority (higher priority first)
            self.handlers[event_type.value].sort(key=lambda h: h.priority, reverse=True)
            
        logger.info(f"Handler {handler_id} subscribed to {[t.value for t in event_types]}")
        return handler_id
        
    def unsubscribe(self, handler: Callable) -> int:
        """Unsubscribe handler from all events"""
        removed = 0
        for event_type, handlers in self.handlers.items():
            handlers_to_remove = [h for h in handlers if h.handler == handler]
            for h in handlers_to_remove:
                handlers.remove(h)
                removed += 1
                
        logger.info(f"Removed {removed} handler subscriptions")
        return removed
        
    async def publish(self, event: Event) -> None:
        """Publish an event to the bus"""
        # Add to history
        self.event_history.append(event)
        if len(self.event_history) > self.max_history_size:
            self.event_history.pop(0)
            
        # Add to processing queue
        await self.event_queue.put(event)
        
        logger.debug(f"Published event: {event.type.value} from {event.source}")
        
    async def publish_now(self, event: Event) -> List[Any]:
        """Publish event and process immediately (blocking)"""
        results = []
        
        if event.type.value in self.handlers:
            for handler in self.handlers[event.type.value]:
                try:
                    result = await handler.handle(event)
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error in immediate event handler: {e}")
                    
        return results
        
    async def start_processing(self) -> None:
        """Start processing events from the queue"""
        if self._processing:
            return
            
        self._processing = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Event bus processing started")
        
    async def stop_processing(self) -> None:
        """Stop processing events"""
        self._processing = False
        
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
                
        logger.info("Event bus processing stopped")
        
    async def _process_events(self) -> None:
        """Process events from the queue"""
        while self._processing:
            try:
                # Wait for event with timeout
                event = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )
                
                # Process event
                await self._handle_event(event)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                
    async def _handle_event(self, event: Event) -> None:
        """Handle a single event"""
        if event.type.value not in self.handlers:
            return
            
        # Execute handlers concurrently
        tasks = []
        for handler in self.handlers[event.type.value]:
            task = asyncio.create_task(handler.handle(event))
            tasks.append(task)
            
        # Wait for all handlers to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Log any errors
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Handler error for {event.type.value}: {result}")
                
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics"""
        stats = {
            "handlers": {},
            "event_history_size": len(self.event_history),
            "queue_size": self.event_queue.qsize(),
            "processing": self._processing
        }
        
        # Handler statistics
        for event_type, handlers in self.handlers.items():
            stats["handlers"][event_type] = {
                "count": len(handlers),
                "total_executions": sum(h.execution_count for h in handlers),
                "total_errors": sum(h.error_count for h in handlers)
            }
            
        return stats
        
    def get_event_history(self, 
                         event_type: Optional[EventType] = None,
                         limit: int = 100) -> List[Event]:
        """Get event history with optional filtering"""
        history = self.event_history
        
        if event_type:
            history = [e for e in history if e.type == event_type]
            
        return history[-limit:]

# Event builders for common events
class EventBuilder:
    """Helper class to build common events"""
    
    @staticmethod
    def proposition_created(proposition_data: Dict[str, Any], source: str = "api") -> Event:
        """Build proposition created event"""
        return Event(
            type=EventType.PROPOSITION_CREATED,
            source=source,
            data=proposition_data,
            metadata={"proposition_id": proposition_data.get("id")}
        )
    
    @staticmethod
    def proposition_updated(proposition_id: str, 
                          changes: Dict[str, Any],
                          source: str = "api") -> Event:
        """Build proposition updated event"""
        return Event(
            type=EventType.PROPOSITION_UPDATED,
            source=source,
            data={"proposition_id": proposition_id, "changes": changes},
            metadata={"proposition_id": proposition_id}
        )
    
    @staticmethod
    def search_performed(query: str,
                        results_count: int,
                        sources: List[str],
                        user_id: Optional[str] = None) -> Event:
        """Build search performed event"""
        return Event(
            type=EventType.SEARCH_PERFORMED,
            source="search",
            data={
                "query": query,
                "results_count": results_count,
                "sources": sources
            },
            metadata={"user_id": user_id} if user_id else {}
        )
    
    @staticmethod
    def system_error(error_type: str,
                    error_message: str,
                    component: str) -> Event:
        """Build system error event"""
        return Event(
            type=EventType.SYSTEM_ERROR,
            source=component,
            data={
                "error_type": error_type,
                "error_message": error_message
            },
            metadata={"severity": "error"}
        )

# Global event bus instance
event_bus = EventBus()

# Convenience functions
async def publish_event(event: Event) -> None:
    """Publish an event to the global event bus"""
    await event_bus.publish(event)

def subscribe_to_events(event_types: List[EventType],
                       handler: Callable,
                       priority: int = 0) -> str:
    """Subscribe to events on the global event bus"""
    return event_bus.subscribe(event_types, handler, priority)

async def start_event_processing() -> None:
    """Start the global event bus processing"""
    await event_bus.start_processing()

async def stop_event_processing() -> None:
    """Stop the global event bus processing"""
    await event_bus.stop_processing()