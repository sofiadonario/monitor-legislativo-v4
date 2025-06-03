"""
Event Streaming for Monitor Legislativo v4
Provides event streaming capabilities for external systems

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, AsyncIterator
from datetime import datetime, timedelta
import json
from collections import deque

try:
    import aiokafka
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    aiokafka = None

from .event_bus import Event, EventType, event_bus

logger = logging.getLogger(__name__)

class EventStream:
    """Base class for event streaming"""
    
    def __init__(self, stream_id: str):
        self.stream_id = stream_id
        self.subscribers = 0
        self.events_sent = 0
        self.created_at = datetime.now()
        
    async def send_event(self, event: Event) -> None:
        """Send event to stream"""
        raise NotImplementedError
        
    async def close(self) -> None:
        """Close the stream"""
        raise NotImplementedError

class InMemoryEventStream(EventStream):
    """In-memory event stream for development/testing"""
    
    def __init__(self, stream_id: str, buffer_size: int = 1000):
        super().__init__(stream_id)
        self.buffer = deque(maxlen=buffer_size)
        self.subscribers_queues: List[asyncio.Queue] = []
        
    async def send_event(self, event: Event) -> None:
        """Send event to all subscribers"""
        self.buffer.append(event)
        self.events_sent += 1
        
        # Send to all subscriber queues
        for queue in self.subscribers_queues:
            try:
                await queue.put(event)
            except asyncio.QueueFull:
                logger.warning(f"Subscriber queue full for stream {self.stream_id}")
                
    async def subscribe(self) -> AsyncIterator[Event]:
        """Subscribe to event stream"""
        queue = asyncio.Queue(maxsize=100)
        self.subscribers_queues.append(queue)
        self.subscribers += 1
        
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self.subscribers_queues.remove(queue)
            self.subscribers -= 1
            
    async def close(self) -> None:
        """Close the stream"""
        self.subscribers_queues.clear()

class KafkaEventStream(EventStream):
    """Kafka-based event stream for production"""
    
    def __init__(self, stream_id: str, 
                 bootstrap_servers: str = "localhost:9092",
                 topic_prefix: str = "monitor-legislativo"):
        super().__init__(stream_id)
        self.bootstrap_servers = bootstrap_servers
        self.topic = f"{topic_prefix}.{stream_id}"
        self.producer = None
        
    async def connect(self) -> bool:
        """Connect to Kafka"""
        if not KAFKA_AVAILABLE:
            logger.error("Kafka not available")
            return False
            
        try:
            self.producer = aiokafka.AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode()
            )
            await self.producer.start()
            logger.info(f"Connected to Kafka for stream {self.stream_id}")
            return True
        except Exception as e:
            logger.error(f"Kafka connection error: {e}")
            return False
            
    async def send_event(self, event: Event) -> None:
        """Send event to Kafka topic"""
        if not self.producer:
            logger.error("Kafka producer not connected")
            return
            
        try:
            await self.producer.send(
                self.topic,
                value=event.to_dict(),
                key=event.type.value.encode()
            )
            self.events_sent += 1
        except Exception as e:
            logger.error(f"Kafka send error: {e}")
            
    async def close(self) -> None:
        """Close Kafka connection"""
        if self.producer:
            await self.producer.stop()

class EventStreamManager:
    """Manages multiple event streams"""
    
    def __init__(self):
        self.streams: Dict[str, EventStream] = {}
        self.stream_filters: Dict[str, List[EventType]] = {}
        self._routing_task: Optional[asyncio.Task] = None
        
    def create_stream(self, 
                     stream_id: str,
                     event_types: List[EventType],
                     stream_type: str = "memory") -> EventStream:
        """Create a new event stream"""
        if stream_id in self.streams:
            raise ValueError(f"Stream {stream_id} already exists")
            
        # Create stream based on type
        if stream_type == "kafka" and KAFKA_AVAILABLE:
            stream = KafkaEventStream(stream_id)
            asyncio.create_task(stream.connect())
        else:
            stream = InMemoryEventStream(stream_id)
            
        self.streams[stream_id] = stream
        self.stream_filters[stream_id] = event_types
        
        logger.info(f"Created event stream {stream_id} with types: {[t.value for t in event_types]}")
        return stream
        
    def get_stream(self, stream_id: str) -> Optional[EventStream]:
        """Get an existing stream"""
        return self.streams.get(stream_id)
        
    async def route_event(self, event: Event) -> None:
        """Route event to appropriate streams"""
        for stream_id, event_types in self.stream_filters.items():
            if event.type in event_types:
                stream = self.streams.get(stream_id)
                if stream:
                    await stream.send_event(event)
                    
    async def start_routing(self) -> None:
        """Start routing events from event bus to streams"""
        async def event_router(event: Event):
            await self.route_event(event)
            
        # Subscribe to all events
        event_bus.subscribe(
            list(EventType),
            event_router,
            priority=1  # Low priority to run after other handlers
        )
        
        logger.info("Event stream routing started")
        
    async def close_all(self) -> None:
        """Close all streams"""
        for stream in self.streams.values():
            await stream.close()
        self.streams.clear()
        self.stream_filters.clear()

class EventReplay:
    """Replay historical events"""
    
    def __init__(self, event_store: List[Event]):
        self.event_store = event_store
        
    async def replay(self,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    event_types: Optional[List[EventType]] = None,
                    speed: float = 1.0) -> AsyncIterator[Event]:
        """Replay events with optional filtering and speed control"""
        
        # Filter events
        events = self.event_store
        
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
            
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
            
        if event_types:
            events = [e for e in events if e.type in event_types]
            
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Replay events
        last_timestamp = None
        
        for event in events:
            # Calculate delay based on timestamp difference
            if last_timestamp and speed > 0:
                time_diff = (event.timestamp - last_timestamp).total_seconds()
                delay = time_diff / speed
                if delay > 0:
                    await asyncio.sleep(delay)
                    
            yield event
            last_timestamp = event.timestamp

class EventAggregator:
    """Aggregate events over time windows"""
    
    def __init__(self, window_size: timedelta = timedelta(minutes=1)):
        self.window_size = window_size
        self.windows: Dict[datetime, Dict[str, Any]] = {}
        
    def add_event(self, event: Event) -> None:
        """Add event to aggregation"""
        window_start = self._get_window_start(event.timestamp)
        
        if window_start not in self.windows:
            self.windows[window_start] = {
                "event_count": 0,
                "event_types": {},
                "sources": {}
            }
            
        window = self.windows[window_start]
        window["event_count"] += 1
        
        # Count by type
        event_type = event.type.value
        if event_type not in window["event_types"]:
            window["event_types"][event_type] = 0
        window["event_types"][event_type] += 1
        
        # Count by source
        if event.source not in window["sources"]:
            window["sources"][event.source] = 0
        window["sources"][event.source] += 1
        
    def _get_window_start(self, timestamp: datetime) -> datetime:
        """Get the start of the window for a timestamp"""
        seconds = int(timestamp.timestamp())
        window_seconds = int(self.window_size.total_seconds())
        window_start_seconds = (seconds // window_seconds) * window_seconds
        return datetime.fromtimestamp(window_start_seconds)
        
    def get_aggregates(self, 
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get aggregated data for time range"""
        results = []
        
        for window_start, data in sorted(self.windows.items()):
            if start_time and window_start < start_time:
                continue
            if end_time and window_start > end_time:
                continue
                
            results.append({
                "window_start": window_start.isoformat(),
                "window_end": (window_start + self.window_size).isoformat(),
                **data
            })
            
        return results

# Global stream manager
stream_manager = EventStreamManager()

# Convenience functions
def create_event_stream(stream_id: str,
                       event_types: List[EventType],
                       stream_type: str = "memory") -> EventStream:
    """Create a new event stream"""
    return stream_manager.create_stream(stream_id, event_types, stream_type)

async def start_event_streaming() -> None:
    """Start event streaming"""
    await stream_manager.start_routing()

async def stop_event_streaming() -> None:
    """Stop event streaming"""
    await stream_manager.close_all()