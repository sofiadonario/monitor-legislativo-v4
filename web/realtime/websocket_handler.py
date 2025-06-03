"""
WebSocket Handler for Real-time Features
Provides real-time updates for legislative monitoring

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import json
import asyncio
import logging
from typing import Dict, Set, Optional, Any
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from core.auth.jwt_manager import decode_token
from core.models.models import Proposition

logger = logging.getLogger(__name__)

# Global connection manager
class ConnectionManager:
    """Manages WebSocket connections and broadcasting"""
    
    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Store subscriptions by topic
        self.subscriptions: Dict[str, Set[str]] = {}
        # Store connection metadata
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        
    async def connect(self, websocket: WebSocket, user_id: str, metadata: Dict[str, Any] = None):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        
        # Add to active connections
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        
        # Store metadata
        self.connection_metadata[websocket] = {
            "user_id": user_id,
            "connected_at": datetime.now(),
            "metadata": metadata or {}
        }
        
        logger.info(f"WebSocket connected: user_id={user_id}")
        
        # Send welcome message
        await self.send_personal_message(
            websocket,
            {
                "type": "connection",
                "status": "connected",
                "message": "Welcome to Monitor Legislativo Real-time Updates",
                "timestamp": datetime.now().isoformat()
            }
        )
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        metadata = self.connection_metadata.get(websocket)
        if metadata:
            user_id = metadata["user_id"]
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            
            # Remove from all subscriptions
            for topic, subscribers in self.subscriptions.items():
                subscribers.discard(user_id)
            
            # Clean up metadata
            del self.connection_metadata[websocket]
            
            logger.info(f"WebSocket disconnected: user_id={user_id}")
    
    async def send_personal_message(self, websocket: WebSocket, message: dict):
        """Send a message to a specific connection"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
    
    async def broadcast_to_user(self, user_id: str, message: dict):
        """Send a message to all connections of a specific user"""
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await self.send_personal_message(connection, message)
    
    async def broadcast_to_topic(self, topic: str, message: dict):
        """Broadcast a message to all subscribers of a topic"""
        if topic in self.subscriptions:
            for user_id in self.subscriptions[topic]:
                await self.broadcast_to_user(user_id, message)
    
    async def subscribe(self, user_id: str, topic: str):
        """Subscribe a user to a topic"""
        if topic not in self.subscriptions:
            self.subscriptions[topic] = set()
        self.subscriptions[topic].add(user_id)
        
        logger.info(f"User {user_id} subscribed to topic: {topic}")
        
        # Send confirmation
        await self.broadcast_to_user(
            user_id,
            {
                "type": "subscription",
                "topic": topic,
                "status": "subscribed",
                "timestamp": datetime.now().isoformat()
            }
        )
    
    async def unsubscribe(self, user_id: str, topic: str):
        """Unsubscribe a user from a topic"""
        if topic in self.subscriptions:
            self.subscriptions[topic].discard(user_id)
            
            logger.info(f"User {user_id} unsubscribed from topic: {topic}")
            
            # Send confirmation
            await self.broadcast_to_user(
                user_id,
                {
                    "type": "subscription",
                    "topic": topic,
                    "status": "unsubscribed",
                    "timestamp": datetime.now().isoformat()
                }
            )

# Global instance
manager = ConnectionManager()

# Message handlers
class MessageHandler:
    """Handles different types of WebSocket messages"""
    
    @staticmethod
    async def handle_subscribe(user_id: str, data: dict):
        """Handle subscription requests"""
        topic = data.get("topic")
        if topic:
            await manager.subscribe(user_id, topic)
        else:
            await manager.broadcast_to_user(
                user_id,
                {
                    "type": "error",
                    "message": "Topic is required for subscription",
                    "timestamp": datetime.now().isoformat()
                }
            )
    
    @staticmethod
    async def handle_unsubscribe(user_id: str, data: dict):
        """Handle unsubscription requests"""
        topic = data.get("topic")
        if topic:
            await manager.unsubscribe(user_id, topic)
    
    @staticmethod
    async def handle_ping(user_id: str, data: dict):
        """Handle ping messages for connection keep-alive"""
        await manager.broadcast_to_user(
            user_id,
            {
                "type": "pong",
                "timestamp": datetime.now().isoformat()
            }
        )
    
    @staticmethod
    async def handle_search_alert(user_id: str, data: dict):
        """Handle search alert configuration"""
        query = data.get("query")
        sources = data.get("sources", [])
        
        # TODO: Store alert configuration
        logger.info(f"User {user_id} configured alert: query='{query}', sources={sources}")
        
        await manager.broadcast_to_user(
            user_id,
            {
                "type": "alert_configured",
                "query": query,
                "sources": sources,
                "status": "active",
                "timestamp": datetime.now().isoformat()
            }
        )

# WebSocket endpoint handler
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = None
):
    """Main WebSocket endpoint handler"""
    
    # Authenticate user (optional for public updates)
    user_id = "anonymous"
    if token:
        try:
            payload = decode_token(token)
            user_id = payload.get("sub", "anonymous")
        except Exception as e:
            logger.warning(f"Invalid token: {e}")
            await websocket.close(code=1008, reason="Invalid authentication")
            return
    
    # Connect
    await manager.connect(websocket, user_id)
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_json()
            
            message_type = data.get("type")
            logger.info(f"Received message: type={message_type} from user={user_id}")
            
            # Route message to appropriate handler
            if message_type == "subscribe":
                await MessageHandler.handle_subscribe(user_id, data)
            elif message_type == "unsubscribe":
                await MessageHandler.handle_unsubscribe(user_id, data)
            elif message_type == "ping":
                await MessageHandler.handle_ping(user_id, data)
            elif message_type == "configure_alert":
                await MessageHandler.handle_search_alert(user_id, data)
            else:
                await manager.broadcast_to_user(
                    user_id,
                    {
                        "type": "error",
                        "message": f"Unknown message type: {message_type}",
                        "timestamp": datetime.now().isoformat()
                    }
                )
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
        await websocket.close()

# Notification functions for external use
async def notify_proposition_update(proposition: Proposition):
    """Notify subscribers about proposition updates"""
    message = {
        "type": "proposition_update",
        "data": {
            "id": proposition.id,
            "source": proposition.source,
            "title": proposition.title,
            "status": proposition.status,
            "updated_at": proposition.updated_at.isoformat() if proposition.updated_at else None
        },
        "timestamp": datetime.now().isoformat()
    }
    
    # Notify topic subscribers
    await manager.broadcast_to_topic(f"proposition:{proposition.id}", message)
    await manager.broadcast_to_topic(f"source:{proposition.source}", message)
    await manager.broadcast_to_topic("all_propositions", message)

async def notify_new_proposition(proposition: Proposition):
    """Notify subscribers about new propositions"""
    message = {
        "type": "new_proposition",
        "data": {
            "id": proposition.id,
            "source": proposition.source,
            "type": proposition.type,
            "number": proposition.number,
            "year": proposition.year,
            "title": proposition.title,
            "summary": proposition.summary,
            "author": proposition.author,
            "created_at": proposition.created_at.isoformat()
        },
        "timestamp": datetime.now().isoformat()
    }
    
    # Notify relevant topics
    await manager.broadcast_to_topic(f"source:{proposition.source}", message)
    await manager.broadcast_to_topic("new_propositions", message)
    
    # Check for keyword alerts
    if proposition.keywords:
        for keyword in proposition.keywords:
            await manager.broadcast_to_topic(f"keyword:{keyword.lower()}", message)

async def notify_system_status(status: str, details: dict = None):
    """Notify all users about system status changes"""
    message = {
        "type": "system_status",
        "status": status,
        "details": details or {},
        "timestamp": datetime.now().isoformat()
    }
    
    # Broadcast to all connected users
    for user_id in manager.active_connections:
        await manager.broadcast_to_user(user_id, message)