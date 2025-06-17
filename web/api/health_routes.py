"""
Health Monitoring API Routes
============================

FastAPI routes for the health monitoring dashboard providing real-time
system status, metrics, and alerting endpoints.

Endpoints:
- GET /health/status - Current system status
- GET /health/components - Detailed component status
- GET /health/metrics/{component} - Component metrics
- GET /health/alerts - Active alerts
- WebSocket /health/ws - Real-time updates

Author: Academic Legislative Monitor Development Team
Created: June 2025
Version: 1.0.0
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ...core.utils.health_dashboard import HealthMonitoringDashboard, HealthMetrics, SystemOverview
from ...core.utils.health_monitor import HealthStatus


logger = logging.getLogger(__name__)

# Global dashboard instance
health_dashboard = HealthMonitoringDashboard()

# Router for health monitoring endpoints
router = APIRouter(prefix="/health", tags=["health"])


# Pydantic models for API responses
class ComponentStatusResponse(BaseModel):
    """Response model for component status."""
    component: str
    name: str
    status: str
    response_time_ms: float
    message: str
    last_check: datetime
    uptime_24h: float
    is_critical: bool


class SystemStatusResponse(BaseModel):
    """Response model for system status."""
    overall_status: str
    total_components: int
    healthy_components: int
    degraded_components: int
    unhealthy_components: int
    system_uptime: float
    total_alerts: int
    critical_alerts: int
    last_updated: datetime


class AlertResponse(BaseModel):
    """Response model for alerts."""
    id: str
    component: str
    severity: str
    message: str
    triggered_at: datetime
    details: Optional[Dict[str, Any]] = None


class MetricsResponse(BaseModel):
    """Response model for component metrics."""
    component: str
    current_status: str
    uptime_24h: float
    uptime_7d: float
    avg_response_time_24h: float
    max_response_time_24h: float
    total_requests_24h: int
    failed_requests_24h: int
    last_success: Optional[datetime]
    last_failure: Optional[datetime]
    alert_count_24h: int


# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Add to dashboard's client list
        health_dashboard.websocket_clients.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in health_dashboard.websocket_clients:
            health_dashboard.websocket_clients.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message, default=str))
            except Exception:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


manager = ConnectionManager()


@router.get("/status", response_model=SystemStatusResponse)
async def get_system_status():
    """
    Get overall system health status.
    
    Returns comprehensive system status including component counts,
    overall health, and alert summary.
    """
    try:
        overview = await health_dashboard.get_system_overview()
        
        return SystemStatusResponse(
            overall_status=overview.overall_status.value,
            total_components=overview.total_components,
            healthy_components=overview.healthy_components,
            degraded_components=overview.degraded_components,
            unhealthy_components=overview.unhealthy_components,
            system_uptime=overview.system_uptime,
            total_alerts=overview.total_alerts,
            critical_alerts=overview.critical_alerts,
            last_updated=overview.last_updated
        )
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system status")


@router.get("/components", response_model=List[ComponentStatusResponse])
async def get_components_status():
    """
    Get status of all monitored components.
    
    Returns detailed status for each component including health status,
    response times, and uptime metrics.
    """
    try:
        # Get current health checks
        health_results = await health_dashboard.check_all_components()
        
        components = []
        for component_id, result in health_results.items():
            config = health_dashboard.components.get(component_id, {})
            
            # Get 24h uptime
            metrics = await health_dashboard.get_component_metrics(component_id)
            
            components.append(ComponentStatusResponse(
                component=component_id,
                name=config.get('name', component_id),
                status=result.status.value,
                response_time_ms=result.response_time_ms,
                message=result.message,
                last_check=result.timestamp,
                uptime_24h=metrics.uptime_24h,
                is_critical=config.get('critical', False)
            ))
        
        return components
    except Exception as e:
        logger.error(f"Error getting components status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get components status")


@router.get("/components/{component_id}", response_model=ComponentStatusResponse)
async def get_component_status(component_id: str):
    """
    Get status of a specific component.
    
    Args:
        component_id: ID of the component to check
        
    Returns:
        Detailed status for the specified component
    """
    if component_id not in health_dashboard.components:
        raise HTTPException(status_code=404, detail="Component not found")
    
    try:
        result = await health_dashboard.check_component_health(component_id)
        config = health_dashboard.components[component_id]
        metrics = await health_dashboard.get_component_metrics(component_id)
        
        return ComponentStatusResponse(
            component=component_id,
            name=config['name'],
            status=result.status.value,
            response_time_ms=result.response_time_ms,
            message=result.message,
            last_check=result.timestamp,
            uptime_24h=metrics.uptime_24h,
            is_critical=config.get('critical', False)
        )
    except Exception as e:
        logger.error(f"Error getting component status for {component_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get component status")


@router.get("/metrics/{component_id}", response_model=MetricsResponse)
async def get_component_metrics(component_id: str):
    """
    Get detailed metrics for a specific component.
    
    Args:
        component_id: ID of the component
        
    Returns:
        Comprehensive metrics including uptime, response times, and error rates
    """
    if component_id not in health_dashboard.components:
        raise HTTPException(status_code=404, detail="Component not found")
    
    try:
        metrics = await health_dashboard.get_component_metrics(component_id)
        
        return MetricsResponse(
            component=metrics.component,
            current_status=metrics.current_status.value,
            uptime_24h=metrics.uptime_24h,
            uptime_7d=metrics.uptime_7d,
            avg_response_time_24h=metrics.avg_response_time_24h,
            max_response_time_24h=metrics.max_response_time_24h,
            total_requests_24h=metrics.total_requests_24h,
            failed_requests_24h=metrics.failed_requests_24h,
            last_success=metrics.last_success,
            last_failure=metrics.last_failure,
            alert_count_24h=metrics.alert_count_24h
        )
    except Exception as e:
        logger.error(f"Error getting metrics for {component_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get component metrics")


@router.get("/alerts", response_model=List[AlertResponse])
async def get_active_alerts(severity: Optional[str] = Query(None, description="Filter by severity")):
    """
    Get active alerts.
    
    Args:
        severity: Optional severity filter (warning, critical)
        
    Returns:
        List of active alerts
    """
    try:
        alerts = []
        for component, component_alerts in health_dashboard.active_alerts.items():
            for alert in component_alerts:
                if severity and alert.get('severity') != severity:
                    continue
                
                alerts.append(AlertResponse(
                    id=alert['id'],
                    component=alert['component'],
                    severity=alert['severity'],
                    message=alert['message'],
                    triggered_at=alert['triggered_at'],
                    details=alert.get('details')
                ))
        
        return alerts
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")


@router.get("/dashboard")
async def get_dashboard_data():
    """
    Get comprehensive dashboard data.
    
    Returns all data needed for the monitoring dashboard including
    system overview, component details, and active alerts.
    """
    try:
        dashboard_data = health_dashboard.get_dashboard_data()
        return JSONResponse(content=dashboard_data)
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard data")


@router.post("/check/{component_id}")
async def trigger_health_check(component_id: str):
    """
    Manually trigger a health check for a component.
    
    Args:
        component_id: ID of the component to check
        
    Returns:
        Health check result
    """
    if component_id not in health_dashboard.components:
        raise HTTPException(status_code=404, detail="Component not found")
    
    try:
        result = await health_dashboard.check_component_health(component_id)
        
        return {
            "component": result.component,
            "status": result.status.value,
            "response_time_ms": result.response_time_ms,
            "message": result.message,
            "timestamp": result.timestamp,
            "details": result.details
        }
    except Exception as e:
        logger.error(f"Error triggering health check for {component_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger health check")


@router.post("/check/all")
async def trigger_all_health_checks():
    """
    Manually trigger health checks for all components.
    
    Returns:
        Health check results for all components
    """
    try:
        results = await health_dashboard.check_all_components()
        
        return {
            component_id: {
                "status": result.status.value,
                "response_time_ms": result.response_time_ms,
                "message": result.message,
                "timestamp": result.timestamp
            }
            for component_id, result in results.items()
        }
    except Exception as e:
        logger.error(f"Error triggering all health checks: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger health checks")


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time health monitoring updates.
    
    Provides real-time updates for:
    - Component status changes
    - New alerts
    - System overview updates
    """
    await manager.connect(websocket)
    
    try:
        # Send initial dashboard data
        dashboard_data = health_dashboard.get_dashboard_data()
        await websocket.send_text(json.dumps({
            'type': 'initial_data',
            'data': dashboard_data
        }, default=str))
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages from client (ping/pong, etc.)
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get('type') == 'ping':
                    await websocket.send_text(json.dumps({
                        'type': 'pong',
                        'timestamp': datetime.now().isoformat()
                    }))
                elif message.get('type') == 'request_update':
                    # Send current dashboard data
                    dashboard_data = health_dashboard.get_dashboard_data()
                    await websocket.send_text(json.dumps({
                        'type': 'dashboard_update',
                        'data': dashboard_data
                    }, default=str))
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
    
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)


# Background task to send periodic updates
async def send_periodic_updates():
    """Send periodic updates to all connected WebSocket clients."""
    while True:
        try:
            if manager.active_connections:
                dashboard_data = health_dashboard.get_dashboard_data()
                await manager.broadcast({
                    'type': 'dashboard_update',
                    'data': dashboard_data
                })
            
            await asyncio.sleep(30)  # Update every 30 seconds
        except Exception as e:
            logger.error(f"Error sending periodic updates: {e}")
            await asyncio.sleep(60)  # Wait longer on error


# Start background monitoring when module is imported
async def start_background_monitoring():
    """Start background monitoring tasks."""
    # Start the health monitoring loop
    monitoring_task = asyncio.create_task(health_dashboard.start_monitoring(interval_seconds=60))
    
    # Start periodic WebSocket updates
    updates_task = asyncio.create_task(send_periodic_updates())
    
    logger.info("Health monitoring background tasks started")
    
    return monitoring_task, updates_task


# Function to be called when starting the application
def setup_health_monitoring():
    """Setup function to initialize health monitoring."""
    logger.info("Setting up health monitoring dashboard")
    return health_dashboard