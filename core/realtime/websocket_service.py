"""
WebSocket Real-time Notifications Service
Provides real-time updates for propositions, searches, and system events
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Set, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import websockets
from websockets.server import WebSocketServerProtocol
import threading
from collections import defaultdict

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Types of real-time events"""
    PROPOSITION_NEW = "proposition.new"
    PROPOSITION_UPDATE = "proposition.update"
    PROPOSITION_STATUS_CHANGE = "proposition.status_change"
    SEARCH_ALERT = "search.alert"
    SYSTEM_NOTIFICATION = "system.notification"
    USER_NOTIFICATION = "user.notification"
    ANALYTICS_UPDATE = "analytics.update"
    HEALTH_CHECK = "health.check"

@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    id: str
    type: EventType
    timestamp: datetime
    data: Dict[str, Any]
    metadata: Dict[str, Any] = None
    
    def to_json(self) -> str:
        """Convert message to JSON"""
        return json.dumps({
            'id': self.id,
            'type': self.type.value,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'metadata': self.metadata or {}
        })

@dataclass
class Subscription:
    """Client subscription to specific events"""
    client_id: str
    event_types: Set[EventType]
    filters: Dict[str, Any] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

class WebSocketConnection:
    """Represents a WebSocket client connection"""
    
    def __init__(self, websocket: WebSocketServerProtocol, client_id: str = None):
        self.websocket = websocket
        self.client_id = client_id or str(uuid.uuid4())
        self.subscriptions: Set[Subscription] = set()
        self.connected_at = datetime.utcnow()
        self.last_ping = time.time()
        self.metadata: Dict[str, Any] = {}
    
    async def send_message(self, message: WebSocketMessage):
        """Send message to client"""
        try:
            await self.websocket.send(message.to_json())
        except Exception as e:
            logger.error(f"Failed to send message to client {self.client_id}: {e}")
            raise
    
    def add_subscription(self, subscription: Subscription):
        """Add subscription for this connection"""
        subscription.client_id = self.client_id
        self.subscriptions.add(subscription)
    
    def remove_subscription(self, event_type: EventType):
        """Remove subscription for event type"""
        self.subscriptions = {
            sub for sub in self.subscriptions 
            if event_type not in sub.event_types
        }
    
    def is_subscribed_to(self, event_type: EventType) -> bool:
        """Check if client is subscribed to event type"""
        return any(event_type in sub.event_types for sub in self.subscriptions)
    
    def matches_filters(self, event_type: EventType, data: Dict[str, Any]) -> bool:
        """Check if event data matches subscription filters"""
        for sub in self.subscriptions:
            if event_type in sub.event_types:
                if not sub.filters:
                    return True
                
                # Check filters
                for key, value in sub.filters.items():
                    if key not in data or data[key] != value:
                        continue
                else:
                    return True
        
        return False

class WebSocketServer:
    """Main WebSocket server for real-time notifications"""
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.connections: Dict[str, WebSocketConnection] = {}
        self.event_handlers: Dict[EventType, List[Callable]] = defaultdict(list)
        self.server = None
        self._running = False
        self._event_queue: asyncio.Queue = None
        self._stats = {
            'total_connections': 0,
            'messages_sent': 0,
            'events_processed': 0,
            'errors': 0
        }
    
    async def start(self):
        """Start WebSocket server"""
        self._running = True
        self._event_queue = asyncio.Queue()
        
        # Start event processor
        asyncio.create_task(self._process_events())
        
        # Start ping task
        asyncio.create_task(self._ping_clients())
        
        # Start WebSocket server
        self.server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10
        )
        
        logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
    
    async def stop(self):
        """Stop WebSocket server"""
        self._running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all connections
        for connection in list(self.connections.values()):
            await connection.websocket.close()
        
        logger.info("WebSocket server stopped")
    
    async def _handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection"""
        connection = WebSocketConnection(websocket)
        self.connections[connection.client_id] = connection
        self._stats['total_connections'] += 1
        
        logger.info(f"New WebSocket connection: {connection.client_id}")
        
        # Send welcome message
        welcome_msg = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=EventType.SYSTEM_NOTIFICATION,
            timestamp=datetime.utcnow(),
            data={
                'message': 'Connected to Legislative Monitor WebSocket',
                'client_id': connection.client_id,
                'version': '1.0'
            }
        )
        
        await connection.send_message(welcome_msg)
        
        try:
            # Handle incoming messages
            async for message in websocket:
                await self._handle_message(connection, message)
                
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"WebSocket connection closed: {connection.client_id}")
        except Exception as e:
            logger.error(f"WebSocket error for {connection.client_id}: {e}")
            self._stats['errors'] += 1
        finally:
            # Remove connection
            del self.connections[connection.client_id]
    
    async def _handle_message(self, connection: WebSocketConnection, message: str):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'subscribe':
                await self._handle_subscribe(connection, data)
            elif msg_type == 'unsubscribe':
                await self._handle_unsubscribe(connection, data)
            elif msg_type == 'ping':
                await self._handle_ping(connection)
            elif msg_type == 'search':
                await self._handle_search_request(connection, data)
            else:
                await self._send_error(connection, f"Unknown message type: {msg_type}")
                
        except json.JSONDecodeError:
            await self._send_error(connection, "Invalid JSON message")
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            await self._send_error(connection, str(e))
    
    async def _handle_subscribe(self, connection: WebSocketConnection, data: Dict[str, Any]):
        """Handle subscription request"""
        event_types_str = data.get('event_types', [])
        filters = data.get('filters', {})
        
        # Convert string event types to EventType enum
        event_types = set()
        for event_type_str in event_types_str:
            try:
                event_type = EventType(event_type_str)
                event_types.add(event_type)
            except ValueError:
                await self._send_error(connection, f"Invalid event type: {event_type_str}")
                return
        
        # Create subscription
        subscription = Subscription(
            client_id=connection.client_id,
            event_types=event_types,
            filters=filters
        )
        
        connection.add_subscription(subscription)
        
        # Send confirmation
        confirmation = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=EventType.SYSTEM_NOTIFICATION,
            timestamp=datetime.utcnow(),
            data={
                'message': 'Subscription successful',
                'event_types': list(event_type.value for event_type in event_types),
                'filters': filters
            }
        )
        
        await connection.send_message(confirmation)
        logger.info(f"Client {connection.client_id} subscribed to {event_types}")
    
    async def _handle_unsubscribe(self, connection: WebSocketConnection, data: Dict[str, Any]):
        """Handle unsubscription request"""
        event_type_str = data.get('event_type')
        
        try:
            event_type = EventType(event_type_str)
            connection.remove_subscription(event_type)
            
            # Send confirmation
            confirmation = WebSocketMessage(
                id=str(uuid.uuid4()),
                type=EventType.SYSTEM_NOTIFICATION,
                timestamp=datetime.utcnow(),
                data={
                    'message': 'Unsubscription successful',
                    'event_type': event_type_str
                }
            )
            
            await connection.send_message(confirmation)
            
        except ValueError:
            await self._send_error(connection, f"Invalid event type: {event_type_str}")
    
    async def _handle_ping(self, connection: WebSocketConnection):
        """Handle ping message"""
        connection.last_ping = time.time()
        
        pong = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=EventType.SYSTEM_NOTIFICATION,
            timestamp=datetime.utcnow(),
            data={'message': 'pong', 'timestamp': time.time()}
        )
        
        await connection.send_message(pong)
    
    async def _handle_search_request(self, connection: WebSocketConnection, data: Dict[str, Any]):
        """Handle real-time search request"""
        # This would integrate with the search service
        # For now, send acknowledgment
        ack = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=EventType.SEARCH_ALERT,
            timestamp=datetime.utcnow(),
            data={
                'message': 'Search request received',
                'query': data.get('query', ''),
                'status': 'processing'
            }
        )
        
        await connection.send_message(ack)
    
    async def _send_error(self, connection: WebSocketConnection, error_message: str):
        """Send error message to client"""
        error = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=EventType.SYSTEM_NOTIFICATION,
            timestamp=datetime.utcnow(),
            data={
                'error': True,
                'message': error_message
            }
        )
        
        await connection.send_message(error)
    
    async def _process_events(self):
        """Process events from queue and broadcast to clients"""
        while self._running:
            try:
                # Get event from queue
                event = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=1.0
                )
                
                self._stats['events_processed'] += 1
                
                # Broadcast to subscribed clients
                await self._broadcast_event(event)
                
                # Call registered handlers
                await self._call_handlers(event)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                self._stats['errors'] += 1
    
    async def _broadcast_event(self, event: WebSocketMessage):
        """Broadcast event to all subscribed clients"""
        # Get list of connections to avoid modification during iteration
        connections = list(self.connections.values())
        
        for connection in connections:
            try:
                # Check if client is subscribed and matches filters
                if (connection.is_subscribed_to(event.type) and 
                    connection.matches_filters(event.type, event.data)):
                    
                    await connection.send_message(event)
                    self._stats['messages_sent'] += 1
                    
            except websockets.exceptions.ConnectionClosed:
                # Connection closed, will be cleaned up
                pass
            except Exception as e:
                logger.error(f"Error broadcasting to {connection.client_id}: {e}")
    
    async def _ping_clients(self):
        """Periodically ping clients to check connection health"""
        while self._running:
            try:
                await asyncio.sleep(30)  # Ping every 30 seconds
                
                current_time = time.time()
                timeout_threshold = 60  # 60 seconds timeout
                
                for connection in list(self.connections.values()):
                    if current_time - connection.last_ping > timeout_threshold:
                        logger.warning(f"Client {connection.client_id} timed out")
                        await connection.websocket.close()
                        
            except Exception as e:
                logger.error(f"Error in ping task: {e}")
    
    async def _call_handlers(self, event: WebSocketMessage):
        """Call registered event handlers"""
        handlers = self.event_handlers.get(event.type, [])
        
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Error in event handler: {e}")
    
    def register_handler(self, event_type: EventType, handler: Callable):
        """Register event handler"""
        self.event_handlers[event_type].append(handler)
    
    def unregister_handler(self, event_type: EventType, handler: Callable):
        """Unregister event handler"""
        if handler in self.event_handlers[event_type]:
            self.event_handlers[event_type].remove(handler)
    
    async def publish_event(self, event_type: EventType, data: Dict[str, Any], 
                          metadata: Dict[str, Any] = None):
        """Publish event to all subscribed clients"""
        event = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=event_type,
            timestamp=datetime.utcnow(),
            data=data,
            metadata=metadata
        )
        
        await self._event_queue.put(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        return {
            **self._stats,
            'active_connections': len(self.connections),
            'total_subscriptions': sum(
                len(conn.subscriptions) for conn in self.connections.values()
            ),
            'clients': [
                {
                    'client_id': conn.client_id,
                    'connected_at': conn.connected_at.isoformat(),
                    'subscriptions': len(conn.subscriptions),
                    'last_ping': datetime.fromtimestamp(conn.last_ping).isoformat()
                }
                for conn in self.connections.values()
            ]
        }

class WebSocketClient:
    """WebSocket client for testing and integration"""
    
    def __init__(self, url: str = "ws://localhost:8765"):
        self.url = url
        self.websocket = None
        self._running = False
        self._handlers: Dict[EventType, List[Callable]] = defaultdict(list)
    
    async def connect(self):
        """Connect to WebSocket server"""
        self.websocket = await websockets.connect(self.url)
        self._running = True
        
        # Start message receiver
        asyncio.create_task(self._receive_messages())
        
        logger.info(f"Connected to WebSocket server: {self.url}")
    
    async def disconnect(self):
        """Disconnect from server"""
        self._running = False
        
        if self.websocket:
            await self.websocket.close()
    
    async def subscribe(self, event_types: List[EventType], filters: Dict[str, Any] = None):
        """Subscribe to event types"""
        message = {
            'type': 'subscribe',
            'event_types': [et.value for et in event_types],
            'filters': filters or {}
        }
        
        await self.websocket.send(json.dumps(message))
    
    async def unsubscribe(self, event_type: EventType):
        """Unsubscribe from event type"""
        message = {
            'type': 'unsubscribe',
            'event_type': event_type.value
        }
        
        await self.websocket.send(json.dumps(message))
    
    async def search(self, query: str, filters: Dict[str, Any] = None):
        """Send search request"""
        message = {
            'type': 'search',
            'query': query,
            'filters': filters or {}
        }
        
        await self.websocket.send(json.dumps(message))
    
    def on_event(self, event_type: EventType, handler: Callable):
        """Register event handler"""
        self._handlers[event_type].append(handler)
    
    async def _receive_messages(self):
        """Receive and process messages"""
        while self._running:
            try:
                message = await self.websocket.recv()
                data = json.loads(message)
                
                # Convert to WebSocketMessage
                event_type = EventType(data['type'])
                msg = WebSocketMessage(
                    id=data['id'],
                    type=event_type,
                    timestamp=datetime.fromisoformat(data['timestamp']),
                    data=data['data'],
                    metadata=data.get('metadata', {})
                )
                
                # Call handlers
                for handler in self._handlers.get(event_type, []):
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(msg)
                        else:
                            handler(msg)
                    except Exception as e:
                        logger.error(f"Error in client handler: {e}")
                        
            except websockets.exceptions.ConnectionClosed:
                logger.info("WebSocket connection closed")
                break
            except Exception as e:
                logger.error(f"Error receiving message: {e}")

# Integration helpers

class NotificationService:
    """Service for sending notifications through WebSocket"""
    
    def __init__(self, websocket_server: WebSocketServer):
        self.server = websocket_server
    
    async def notify_new_proposition(self, proposition: Dict[str, Any]):
        """Notify about new proposition"""
        await self.server.publish_event(
            EventType.PROPOSITION_NEW,
            {
                'id': proposition['id'],
                'type': proposition['type'],
                'title': proposition['title'],
                'summary': proposition.get('summary', ''),
                'url': proposition.get('url', ''),
                'authors': proposition.get('authors', [])
            },
            metadata={
                'source': proposition.get('source', ''),
                'importance': 'high' if 'urgente' in proposition.get('title', '').lower() else 'normal'
            }
        )
    
    async def notify_proposition_update(self, proposition_id: str, changes: Dict[str, Any]):
        """Notify about proposition update"""
        await self.server.publish_event(
            EventType.PROPOSITION_UPDATE,
            {
                'proposition_id': proposition_id,
                'changes': changes,
                'updated_at': datetime.utcnow().isoformat()
            }
        )
    
    async def notify_status_change(self, proposition_id: str, old_status: str, new_status: str):
        """Notify about status change"""
        await self.server.publish_event(
            EventType.PROPOSITION_STATUS_CHANGE,
            {
                'proposition_id': proposition_id,
                'old_status': old_status,
                'new_status': new_status,
                'changed_at': datetime.utcnow().isoformat()
            },
            metadata={
                'importance': 'high' if new_status in ['APPROVED', 'REJECTED'] else 'normal'
            }
        )
    
    async def send_search_alert(self, user_id: str, search_query: str, 
                               new_results: List[Dict[str, Any]]):
        """Send search alert to user"""
        await self.server.publish_event(
            EventType.SEARCH_ALERT,
            {
                'user_id': user_id,
                'search_query': search_query,
                'new_results_count': len(new_results),
                'results': new_results[:5],  # First 5 results
                'timestamp': datetime.utcnow().isoformat()
            }
        )
    
    async def send_user_notification(self, user_id: str, title: str, 
                                   message: str, notification_type: str = 'info'):
        """Send notification to specific user"""
        await self.server.publish_event(
            EventType.USER_NOTIFICATION,
            {
                'user_id': user_id,
                'title': title,
                'message': message,
                'type': notification_type,  # info, warning, error, success
                'timestamp': datetime.utcnow().isoformat()
            }
        )

# Example usage
async def example_usage():
    """Example of how to use the WebSocket server"""
    
    # Create and start server
    server = WebSocketServer(host="localhost", port=8765)
    await server.start()
    
    # Create notification service
    notifications = NotificationService(server)
    
    # Example: Notify about new proposition
    await notifications.notify_new_proposition({
        'id': 'PL-1234-2024',
        'type': 'PL',
        'title': 'Projeto de Lei sobre Educação Digital',
        'summary': 'Estabelece diretrizes para educação digital nas escolas',
        'url': 'https://example.com/pl-1234-2024',
        'authors': [{'name': 'Dep. João Silva', 'party': 'ABC', 'state': 'SP'}],
        'source': 'CAMARA'
    })
    
    # Keep server running
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        await server.stop()

if __name__ == "__main__":
    # Run example
    asyncio.run(example_usage())