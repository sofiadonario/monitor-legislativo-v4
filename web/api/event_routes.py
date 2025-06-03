"""
Event Management Routes for Monitor Legislativo v4
API endpoints for event system monitoring and control

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel
import json
import asyncio

from core.events import (
    Event, EventType, EventBuilder,
    event_bus, stream_manager,
    EventAggregator
)
from core.auth.decorators import require_auth, require_admin

router = APIRouter(tags=["events"])

class EventData(BaseModel):
    """Event data model"""
    type: str
    source: str
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None

class StreamConfig(BaseModel):
    """Stream configuration model"""
    stream_id: str
    event_types: List[str]
    stream_type: str = "memory"

@router.get("/events/types")
async def list_event_types():
    """
    List all available event types
    """
    return [
        {
            "type": event_type.value,
            "description": get_event_description(event_type)
        }
        for event_type in EventType
    ]

def get_event_description(event_type: EventType) -> str:
    """Get description for event type"""
    descriptions = {
        EventType.PROPOSITION_CREATED: "New proposition created",
        EventType.PROPOSITION_UPDATED: "Proposition updated",
        EventType.PROPOSITION_STATUS_CHANGED: "Proposition status changed",
        EventType.SEARCH_PERFORMED: "Search query executed",
        EventType.SYSTEM_ERROR: "System error occurred",
        EventType.USER_LOGIN: "User logged in",
        # Add more descriptions as needed
    }
    return descriptions.get(event_type, "No description available")

@router.get("/events/stats")
async def get_event_statistics(_admin = Depends(require_admin)):
    """
    Get event bus statistics (requires admin)
    """
    return event_bus.get_stats()

@router.get("/events/history")
async def get_event_history(
    event_type: Optional[str] = None,
    limit: int = Query(100, le=1000),
    _admin = Depends(require_admin)
):
    """
    Get event history with optional filtering (requires admin)
    """
    try:
        # Parse event type if provided
        type_filter = None
        if event_type:
            type_filter = EventType(event_type)
            
        # Get history
        history = event_bus.get_event_history(
            event_type=type_filter,
            limit=limit
        )
        
        # Convert to JSON-serializable format
        return [event.to_dict() for event in history]
        
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid event type: {event_type}")

@router.post("/events/publish")
async def publish_custom_event(
    event_data: EventData,
    _admin = Depends(require_admin)
):
    """
    Publish a custom event (requires admin)
    """
    try:
        # Create event
        event_type = EventType(event_data.type)
        event = Event(
            type=event_type,
            source=event_data.source,
            data=event_data.data,
            metadata=event_data.metadata or {}
        )
        
        # Publish event
        await event_bus.publish(event)
        
        return {
            "message": "Event published successfully",
            "event_id": event.id
        }
        
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid event type: {event_data.type}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/events/streams")
async def create_event_stream(
    config: StreamConfig,
    _admin = Depends(require_admin)
):
    """
    Create a new event stream (requires admin)
    """
    try:
        # Parse event types
        event_types = []
        for type_str in config.event_types:
            event_types.append(EventType(type_str))
            
        # Create stream
        stream = stream_manager.create_stream(
            stream_id=config.stream_id,
            event_types=event_types,
            stream_type=config.stream_type
        )
        
        return {
            "message": "Stream created successfully",
            "stream_id": stream.stream_id,
            "stream_type": config.stream_type
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/events/streams")
async def list_event_streams(_admin = Depends(require_admin)):
    """
    List all active event streams (requires admin)
    """
    streams = []
    
    for stream_id, stream in stream_manager.streams.items():
        event_types = stream_manager.stream_filters.get(stream_id, [])
        
        streams.append({
            "stream_id": stream_id,
            "event_types": [t.value for t in event_types],
            "subscribers": stream.subscribers,
            "events_sent": stream.events_sent,
            "created_at": stream.created_at.isoformat()
        })
        
    return streams

@router.get("/events/stream/{stream_id}")
async def subscribe_to_stream(
    stream_id: str,
    _auth = Depends(require_auth)
):
    """
    Subscribe to an event stream (requires authentication)
    Returns Server-Sent Events stream
    """
    stream = stream_manager.get_stream(stream_id)
    if not stream:
        raise HTTPException(status_code=404, detail=f"Stream {stream_id} not found")
        
    # Only InMemoryEventStream supports subscription for now
    if not hasattr(stream, 'subscribe'):
        raise HTTPException(status_code=501, detail="Stream type does not support subscription")
        
    async def event_generator():
        """Generate Server-Sent Events"""
        try:
            async for event in stream.subscribe():
                # Format as SSE
                data = json.dumps(event.to_dict())
                yield f"data: {data}\n\n"
                
        except asyncio.CancelledError:
            # Client disconnected
            pass
            
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )

@router.get("/events/aggregate")
async def get_event_aggregates(
    window_minutes: int = Query(1, ge=1, le=60),
    hours_back: int = Query(1, ge=1, le=24),
    _admin = Depends(require_admin)
):
    """
    Get aggregated event statistics (requires admin)
    """
    from datetime import timedelta
    
    # Create aggregator
    aggregator = EventAggregator(
        window_size=timedelta(minutes=window_minutes)
    )
    
    # Add events from history
    now = datetime.now()
    start_time = now - timedelta(hours=hours_back)
    
    history = event_bus.get_event_history(limit=10000)
    for event in history:
        if event.timestamp >= start_time:
            aggregator.add_event(event)
            
    # Get aggregates
    aggregates = aggregator.get_aggregates(
        start_time=start_time,
        end_time=now
    )
    
    return {
        "window_size_minutes": window_minutes,
        "time_range": {
            "start": start_time.isoformat(),
            "end": now.isoformat()
        },
        "aggregates": aggregates
    }

@router.post("/events/replay")
async def replay_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_types: Optional[List[str]] = None,
    speed: float = Query(1.0, ge=0.1, le=10.0),
    _admin = Depends(require_admin)
):
    """
    Replay historical events (requires admin)
    """
    try:
        # Parse event types
        type_filter = None
        if event_types:
            type_filter = [EventType(t) for t in event_types]
            
        # Get events to replay
        from core.events import EventReplay
        
        history = event_bus.get_event_history(limit=10000)
        replay = EventReplay(history)
        
        # Count events to replay
        count = 0
        async for event in replay.replay(
            start_time=start_time,
            end_time=end_time,
            event_types=type_filter,
            speed=0  # Just count, don't delay
        ):
            count += 1
            
        # Start actual replay in background
        async def do_replay():
            async for event in replay.replay(
                start_time=start_time,
                end_time=end_time,
                event_types=type_filter,
                speed=speed
            ):
                await event_bus.publish(event)
                
        asyncio.create_task(do_replay())
        
        return {
            "message": f"Started replaying {count} events at {speed}x speed",
            "event_count": count
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/events/health")
async def event_system_health():
    """
    Check event system health
    """
    stats = event_bus.get_stats()
    
    health = {
        "status": "healthy",
        "processing": stats["processing"],
        "queue_size": stats["queue_size"],
        "handlers_count": len(stats["handlers"]),
        "streams_count": len(stream_manager.streams)
    }
    
    # Check for issues
    if stats["queue_size"] > 1000:
        health["status"] = "degraded"
        health["issue"] = "High queue size"
    elif not stats["processing"]:
        health["status"] = "degraded"
        health["issue"] = "Event processing not running"
        
    return health