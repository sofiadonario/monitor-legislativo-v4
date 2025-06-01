"""
Flask-SocketIO Integration
Real-time WebSocket server integrated with Flask web application
"""

import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass
import json
import time
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_cors import CORS
import threading

logger = logging.getLogger(__name__)

@dataclass
class SocketIOConfig:
    """SocketIO server configuration"""
    cors_allowed_origins: str = "*"
    async_mode: str = "threading"
    ping_timeout: int = 60
    ping_interval: int = 25
    max_http_buffer_size: int = 1000000
    logger: bool = True
    engineio_logger: bool = False

class SocketIOServer:
    """Flask-SocketIO server for real-time notifications"""
    
    def __init__(self, app: Flask = None, config: SocketIOConfig = None):
        self.config = config or SocketIOConfig()
        self.app = app
        self.socketio = None
        self.connected_clients: Dict[str, Dict[str, Any]] = {}
        self.room_subscriptions: Dict[str, Set[str]] = {}
        self._init_socketio()
        
        # Statistics
        self._stats = {
            'total_connections': 0,
            'messages_sent': 0,
            'events_emitted': 0,
            'errors': 0
        }
    
    def _init_socketio(self):
        """Initialize SocketIO with Flask app"""
        if self.app:
            CORS(self.app, resources={r"/socket.io/*": {"origins": self.config.cors_allowed_origins}})
            
            self.socketio = SocketIO(
                self.app,
                cors_allowed_origins=self.config.cors_allowed_origins,
                async_mode=self.config.async_mode,
                ping_timeout=self.config.ping_timeout,
                ping_interval=self.config.ping_interval,
                max_http_buffer_size=self.config.max_http_buffer_size,
                logger=self.config.logger,
                engineio_logger=self.config.engineio_logger
            )
            
            self._register_handlers()
    
    def init_app(self, app: Flask):
        """Initialize with Flask app"""
        self.app = app
        self._init_socketio()
    
    def _register_handlers(self):
        """Register SocketIO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            client_id = request.sid
            self._stats['total_connections'] += 1
            
            # Store client info
            self.connected_clients[client_id] = {
                'id': client_id,
                'connected_at': datetime.utcnow().isoformat(),
                'rooms': set(),
                'metadata': {
                    'user_agent': request.headers.get('User-Agent', ''),
                    'remote_addr': request.remote_addr
                }
            }
            
            logger.info(f"Client connected: {client_id}")
            
            # Send welcome message
            emit('connected', {
                'client_id': client_id,
                'server_time': datetime.utcnow().isoformat(),
                'version': '1.0'
            })
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            client_id = request.sid
            
            # Clean up client data
            if client_id in self.connected_clients:
                # Leave all rooms
                for room in self.connected_clients[client_id]['rooms']:
                    if room in self.room_subscriptions:
                        self.room_subscriptions[room].discard(client_id)
                
                del self.connected_clients[client_id]
            
            logger.info(f"Client disconnected: {client_id}")
        
        @self.socketio.on('subscribe')
        def handle_subscribe(data):
            """Handle subscription to topics/rooms"""
            client_id = request.sid
            topics = data.get('topics', [])
            
            for topic in topics:
                join_room(topic)
                
                # Track subscription
                if topic not in self.room_subscriptions:
                    self.room_subscriptions[topic] = set()
                self.room_subscriptions[topic].add(client_id)
                
                if client_id in self.connected_clients:
                    self.connected_clients[client_id]['rooms'].add(topic)
            
            emit('subscribed', {
                'topics': topics,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            logger.info(f"Client {client_id} subscribed to: {topics}")
        
        @self.socketio.on('unsubscribe')
        def handle_unsubscribe(data):
            """Handle unsubscription from topics/rooms"""
            client_id = request.sid
            topics = data.get('topics', [])
            
            for topic in topics:
                leave_room(topic)
                
                # Remove from tracking
                if topic in self.room_subscriptions:
                    self.room_subscriptions[topic].discard(client_id)
                
                if client_id in self.connected_clients:
                    self.connected_clients[client_id]['rooms'].discard(topic)
            
            emit('unsubscribed', {
                'topics': topics,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            logger.info(f"Client {client_id} unsubscribed from: {topics}")
        
        @self.socketio.on('search_subscribe')
        def handle_search_subscribe(data):
            """Subscribe to search alerts"""
            client_id = request.sid
            search_query = data.get('query', '')
            filters = data.get('filters', {})
            
            # Create unique room for this search
            search_room = f"search:{hash(json.dumps({'query': search_query, 'filters': filters}))}"
            join_room(search_room)
            
            # Store search subscription
            if client_id in self.connected_clients:
                if 'searches' not in self.connected_clients[client_id]:
                    self.connected_clients[client_id]['searches'] = []
                
                self.connected_clients[client_id]['searches'].append({
                    'query': search_query,
                    'filters': filters,
                    'room': search_room,
                    'created_at': datetime.utcnow().isoformat()
                })
            
            emit('search_subscribed', {
                'query': search_query,
                'filters': filters,
                'room': search_room,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        @self.socketio.on('ping')
        def handle_ping():
            """Handle ping for connection health check"""
            emit('pong', {
                'timestamp': time.time(),
                'server_time': datetime.utcnow().isoformat()
            })
        
        @self.socketio.on('get_stats')
        def handle_get_stats():
            """Get client statistics"""
            client_id = request.sid
            client_info = self.connected_clients.get(client_id, {})
            
            emit('stats', {
                'client_id': client_id,
                'connected_at': client_info.get('connected_at'),
                'rooms': list(client_info.get('rooms', [])),
                'server_stats': self.get_stats()
            })
    
    def emit_to_room(self, room: str, event: str, data: Any):
        """Emit event to all clients in a room"""
        if self.socketio:
            self.socketio.emit(event, data, room=room)
            self._stats['events_emitted'] += 1
            self._stats['messages_sent'] += len(self.room_subscriptions.get(room, []))
    
    def emit_to_client(self, client_id: str, event: str, data: Any):
        """Emit event to specific client"""
        if self.socketio:
            self.socketio.emit(event, data, room=client_id)
            self._stats['events_emitted'] += 1
            self._stats['messages_sent'] += 1
    
    def broadcast(self, event: str, data: Any):
        """Broadcast event to all connected clients"""
        if self.socketio:
            self.socketio.emit(event, data)
            self._stats['events_emitted'] += 1
            self._stats['messages_sent'] += len(self.connected_clients)
    
    # Real-time notification methods
    
    def notify_new_proposition(self, proposition: Dict[str, Any]):
        """Notify about new proposition"""
        data = {
            'id': proposition['id'],
            'type': proposition['type'],
            'title': proposition['title'],
            'summary': proposition.get('summary', ''),
            'url': proposition.get('url', ''),
            'authors': proposition.get('authors', []),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Emit to topic rooms
        self.emit_to_room('propositions:new', 'proposition_new', data)
        self.emit_to_room(f'propositions:type:{proposition["type"]}', 'proposition_new', data)
        
        # Check search subscriptions
        self._check_search_matches(proposition)
    
    def notify_proposition_update(self, proposition_id: str, changes: Dict[str, Any]):
        """Notify about proposition update"""
        data = {
            'proposition_id': proposition_id,
            'changes': changes,
            'updated_at': datetime.utcnow().isoformat()
        }
        
        self.emit_to_room('propositions:updates', 'proposition_update', data)
        self.emit_to_room(f'proposition:{proposition_id}', 'proposition_update', data)
    
    def notify_status_change(self, proposition_id: str, old_status: str, new_status: str):
        """Notify about proposition status change"""
        data = {
            'proposition_id': proposition_id,
            'old_status': old_status,
            'new_status': new_status,
            'changed_at': datetime.utcnow().isoformat()
        }
        
        self.emit_to_room('propositions:status_changes', 'proposition_status_change', data)
        self.emit_to_room(f'proposition:{proposition_id}', 'proposition_status_change', data)
        
        # Special notifications for important status changes
        if new_status in ['APPROVED', 'REJECTED']:
            self.emit_to_room('propositions:important', 'important_status_change', data)
    
    def send_search_results(self, client_id: str, search_id: str, results: List[Dict[str, Any]], 
                          total_count: int, took_ms: int):
        """Send search results to client"""
        data = {
            'search_id': search_id,
            'results': results,
            'total_count': total_count,
            'took_ms': took_ms,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.emit_to_client(client_id, 'search_results', data)
    
    def send_analytics_update(self, analytics_type: str, data: Dict[str, Any]):
        """Send analytics update"""
        update_data = {
            'type': analytics_type,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.emit_to_room('analytics', 'analytics_update', update_data)
        self.emit_to_room(f'analytics:{analytics_type}', 'analytics_update', update_data)
    
    def send_system_notification(self, level: str, message: str, details: Dict[str, Any] = None):
        """Send system-wide notification"""
        data = {
            'level': level,  # info, warning, error, critical
            'message': message,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.broadcast('system_notification', data)
    
    def _check_search_matches(self, proposition: Dict[str, Any]):
        """Check if proposition matches any search subscriptions"""
        # This would integrate with search service to check matches
        # For now, simplified implementation
        
        for client_id, client_data in self.connected_clients.items():
            if 'searches' in client_data:
                for search in client_data['searches']:
                    query = search['query'].lower()
                    
                    # Simple text matching
                    if (query in proposition.get('title', '').lower() or 
                        query in proposition.get('summary', '').lower()):
                        
                        # Send alert to search room
                        self.emit_to_room(search['room'], 'search_alert', {
                            'query': search['query'],
                            'matching_proposition': proposition,
                            'timestamp': datetime.utcnow().isoformat()
                        })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        return {
            **self._stats,
            'active_connections': len(self.connected_clients),
            'active_rooms': len(self.room_subscriptions),
            'total_subscriptions': sum(len(subs) for subs in self.room_subscriptions.values()),
            'clients_per_room': {
                room: len(clients) 
                for room, clients in self.room_subscriptions.items()
            }
        }
    
    def get_client_info(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get information about specific client"""
        if client_id in self.connected_clients:
            client_data = self.connected_clients[client_id].copy()
            client_data['rooms'] = list(client_data['rooms'])
            return client_data
        return None
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """Run the SocketIO server"""
        if self.socketio and self.app:
            self.socketio.run(self.app, host=host, port=port, debug=debug)
        else:
            raise RuntimeError("SocketIO server not initialized with Flask app")

# Integration with Flask app

def create_socketio_app(flask_app: Flask = None) -> SocketIOServer:
    """Create SocketIO server with Flask app"""
    
    if not flask_app:
        flask_app = Flask(__name__)
        flask_app.config['SECRET_KEY'] = 'your-secret-key'
    
    # Create SocketIO server
    socketio_server = SocketIOServer(flask_app)
    
    # Add health check endpoint
    @flask_app.route('/socket.io/health')
    def socketio_health():
        stats = socketio_server.get_stats()
        return {
            'status': 'healthy',
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    return socketio_server

# Background task for periodic updates

class PeriodicNotifier:
    """Send periodic notifications and updates"""
    
    def __init__(self, socketio_server: SocketIOServer, interval: int = 60):
        self.server = socketio_server
        self.interval = interval
        self._running = False
        self._thread = None
    
    def start(self):
        """Start periodic notifications"""
        self._running = True
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()
    
    def stop(self):
        """Stop periodic notifications"""
        self._running = False
        if self._thread:
            self._thread.join()
    
    def _run(self):
        """Run periodic tasks"""
        while self._running:
            try:
                # Send analytics update
                self.server.send_analytics_update('server_stats', self.server.get_stats())
                
                # Send health check
                self.server.emit_to_room('monitoring', 'health_check', {
                    'status': 'healthy',
                    'active_connections': len(self.server.connected_clients),
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                time.sleep(self.interval)
                
            except Exception as e:
                logger.error(f"Error in periodic notifier: {e}")

# Example usage with existing Flask app

def integrate_socketio(app: Flask) -> SocketIOServer:
    """Integrate SocketIO with existing Flask app"""
    
    # Create SocketIO server
    socketio_server = create_socketio_app(app)
    
    # Start periodic notifier
    notifier = PeriodicNotifier(socketio_server)
    notifier.start()
    
    # Add custom routes if needed
    @app.route('/notify/test')
    def test_notification():
        socketio_server.send_system_notification(
            'info',
            'Test notification from API',
            {'source': 'api', 'test': True}
        )
        return {'status': 'sent'}
    
    return socketio_server