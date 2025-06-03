"""
WebSocket Routes for Monitor Legislativo v4
Real-time communication endpoints

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from fastapi import APIRouter, WebSocket, Query
from typing import Optional

from web.realtime.websocket_handler import websocket_endpoint

router = APIRouter()

@router.websocket("/ws")
async def websocket_route(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT authentication token")
):
    """
    Main WebSocket endpoint for real-time updates
    
    Authentication is optional - anonymous users can receive public updates.
    Authenticated users can receive personalized notifications.
    
    Message format:
    {
        "type": "message_type",
        "data": {...}
    }
    
    Supported message types:
    - subscribe: Subscribe to a topic
    - unsubscribe: Unsubscribe from a topic
    - ping: Keep connection alive
    - configure_alert: Set up search alerts
    
    Example topics:
    - all_propositions: All proposition updates
    - new_propositions: Only new propositions
    - source:camara: Updates from Câmara
    - proposition:PL-1234-2025: Specific proposition
    - keyword:saude: Propositions with keyword
    """
    await websocket_endpoint(websocket, token)