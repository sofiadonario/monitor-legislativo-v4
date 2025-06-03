# WebSocket Real-time API Guide - Monitor Legislativo v4

**Developed by:** Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães  
**Organization:** MackIntegridade  
**Financing:** MackPesquisa

## Overview

The WebSocket API provides real-time updates for legislative monitoring, including:
- New proposition notifications
- Status updates for tracked propositions
- Search alert notifications
- System status updates

## Connection

### Endpoint
```
ws://localhost:8000/api/v1/ws
wss://yourdomain.com/api/v1/ws (production with SSL)
```

### Authentication (Optional)
```
ws://localhost:8000/api/v1/ws?token=<JWT_TOKEN>
```

### JavaScript Example
```javascript
// Connect without authentication (public updates only)
const ws = new WebSocket('ws://localhost:8000/api/v1/ws');

// Connect with authentication
const token = localStorage.getItem('jwt_token');
const ws = new WebSocket(`ws://localhost:8000/api/v1/ws?token=${token}`);

ws.onopen = (event) => {
    console.log('Connected to Legislative Monitor');
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = (event) => {
    console.log('Disconnected:', event.code, event.reason);
};
```

## Message Types

### Client to Server

#### 1. Subscribe to Topic
```json
{
    "type": "subscribe",
    "topic": "source:camara"
}
```

Available topics:
- `all_propositions` - All proposition updates
- `new_propositions` - Only new propositions
- `source:camara` - Updates from Câmara dos Deputados
- `source:senado` - Updates from Senado Federal
- `source:planalto` - Updates from Planalto
- `source:agencies` - Updates from regulatory agencies
- `proposition:ID` - Specific proposition updates
- `keyword:WORD` - Propositions containing keyword

#### 2. Unsubscribe from Topic
```json
{
    "type": "unsubscribe",
    "topic": "source:camara"
}
```

#### 3. Configure Search Alert
```json
{
    "type": "configure_alert",
    "query": "reforma tributária",
    "sources": ["camara", "senado"]
}
```

#### 4. Keep-alive Ping
```json
{
    "type": "ping"
}
```

### Server to Client

#### 1. Connection Confirmation
```json
{
    "type": "connection",
    "status": "connected",
    "message": "Welcome to Monitor Legislativo Real-time Updates",
    "timestamp": "2025-01-06T10:00:00Z"
}
```

#### 2. Subscription Confirmation
```json
{
    "type": "subscription",
    "topic": "source:camara",
    "status": "subscribed",
    "timestamp": "2025-01-06T10:00:01Z"
}
```

#### 3. New Proposition Notification
```json
{
    "type": "new_proposition",
    "data": {
        "id": "PL-1234-2025",
        "source": "camara",
        "type": "PL",
        "number": "1234",
        "year": 2025,
        "title": "Projeto de Lei sobre Educação Digital",
        "summary": "Estabelece diretrizes para educação digital...",
        "author": {
            "name": "João Silva",
            "party": "PT"
        },
        "created_at": "2025-01-06T09:30:00Z"
    },
    "timestamp": "2025-01-06T10:00:02Z"
}
```

#### 4. Proposition Update Notification
```json
{
    "type": "proposition_update",
    "data": {
        "id": "PL-1234-2025",
        "source": "camara",
        "title": "Projeto de Lei sobre Educação Digital",
        "status": "approved",
        "updated_at": "2025-01-06T14:00:00Z"
    },
    "timestamp": "2025-01-06T14:00:01Z"
}
```

#### 5. System Status
```json
{
    "type": "system_status",
    "status": "maintenance",
    "details": {
        "message": "System will be unavailable from 02:00 to 02:30",
        "affected_sources": ["senado"]
    },
    "timestamp": "2025-01-06T01:00:00Z"
}
```

#### 6. Pong Response
```json
{
    "type": "pong",
    "timestamp": "2025-01-06T10:00:03Z"
}
```

#### 7. Error Message
```json
{
    "type": "error",
    "message": "Invalid topic format",
    "timestamp": "2025-01-06T10:00:04Z"
}
```

## Usage Examples

### React Hook Example
```javascript
import { useEffect, useState, useCallback } from 'react';

function useWebSocket(token) {
    const [socket, setSocket] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [messages, setMessages] = useState([]);

    useEffect(() => {
        const wsUrl = token 
            ? `ws://localhost:8000/api/v1/ws?token=${token}`
            : 'ws://localhost:8000/api/v1/ws';
            
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            setIsConnected(true);
            console.log('WebSocket connected');
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setMessages(prev => [...prev, data]);
            
            // Handle specific message types
            if (data.type === 'new_proposition') {
                notifyUser(`New proposition: ${data.data.title}`);
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        ws.onclose = () => {
            setIsConnected(false);
            console.log('WebSocket disconnected');
        };

        setSocket(ws);

        return () => {
            ws.close();
        };
    }, [token]);

    const subscribe = useCallback((topic) => {
        if (socket && isConnected) {
            socket.send(JSON.stringify({
                type: 'subscribe',
                topic: topic
            }));
        }
    }, [socket, isConnected]);

    const unsubscribe = useCallback((topic) => {
        if (socket && isConnected) {
            socket.send(JSON.stringify({
                type: 'unsubscribe',
                topic: topic
            }));
        }
    }, [socket, isConnected]);

    return {
        isConnected,
        messages,
        subscribe,
        unsubscribe
    };
}
```

### Python Client Example
```python
import asyncio
import websockets
import json

async def monitor_propositions():
    uri = "ws://localhost:8000/api/v1/ws"
    
    async with websockets.connect(uri) as websocket:
        # Subscribe to new propositions
        await websocket.send(json.dumps({
            "type": "subscribe",
            "topic": "new_propositions"
        }))
        
        # Listen for messages
        async for message in websocket:
            data = json.loads(message)
            print(f"Received: {data['type']}")
            
            if data['type'] == 'new_proposition':
                prop = data['data']
                print(f"New: {prop['title']} - {prop['source']}")

# Run the client
asyncio.run(monitor_propositions())
```

## Best Practices

1. **Connection Management**
   - Implement automatic reconnection on disconnect
   - Use exponential backoff for reconnection attempts
   - Send periodic pings to keep connection alive

2. **Message Handling**
   - Always validate message format
   - Handle unknown message types gracefully
   - Log all errors for debugging

3. **Performance**
   - Batch subscriptions when possible
   - Limit the number of topics per client
   - Implement client-side message throttling

4. **Security**
   - Use WSS (WebSocket Secure) in production
   - Validate JWT tokens on connection
   - Implement rate limiting per client

## Testing

Use the provided WebSocket client example:
```bash
cd examples
python websocket_client.py
```

Or use a WebSocket testing tool like:
- [wscat](https://github.com/websockets/wscat)
- [WebSocket King](https://websocketking.com/)
- Browser DevTools Console

## Error Codes

| Code | Description |
|------|-------------|
| 1000 | Normal closure |
| 1001 | Going away |
| 1008 | Policy violation (invalid auth) |
| 1011 | Internal server error |

## Rate Limiting

- Anonymous clients: 100 messages per minute
- Authenticated clients: 1000 messages per minute
- Burst limit: 10 messages per second