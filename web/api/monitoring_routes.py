"""
Monitoring and Circuit Breaker API routes
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

from core.utils.circuit_breaker import circuit_manager
from core.utils.monitoring import metrics_collector

router = APIRouter()


class CircuitBreakerAction(BaseModel):
    """Model for circuit breaker actions"""
    action: str  # "reset", "open", "close"
    breaker_name: Optional[str] = None


@router.get("/health/dashboard")
async def get_health_dashboard():
    """
    Get comprehensive health dashboard data
    """
    try:
        dashboard_data = metrics_collector.get_dashboard_data()
        circuit_stats = circuit_manager.get_all_stats()
        
        return {
            "dashboard": dashboard_data,
            "circuit_breakers": circuit_stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")


@router.get("/health/sources")
async def get_sources_health():
    """
    Get health status for all data sources
    """
    try:
        all_health = metrics_collector.get_all_health()
        
        # Convert SourceHealth objects to dict
        sources_data = {}
        for source, health in all_health.items():
            sources_data[source] = {
                "source": health.source,
                "total_calls": health.total_calls,
                "successful_calls": health.successful_calls,
                "failed_calls": health.failed_calls,
                "avg_response_time": health.avg_response_time,
                "last_success": health.last_success.isoformat() if health.last_success else None,
                "last_failure": health.last_failure.isoformat() if health.last_failure else None,
                "success_rate": health.success_rate,
                "current_status": health.current_status
            }
        
        return {
            "sources": sources_data,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get sources health: {str(e)}")


@router.get("/health/source/{source_name}")
async def get_source_health(source_name: str):
    """
    Get detailed health information for a specific source
    """
    try:
        health = metrics_collector.get_source_health(source_name)
        
        if not health:
            raise HTTPException(status_code=404, detail=f"Source '{source_name}' not found")
        
        return {
            "source": health.source,
            "total_calls": health.total_calls,
            "successful_calls": health.successful_calls,
            "failed_calls": health.failed_calls,
            "avg_response_time": health.avg_response_time,
            "last_success": health.last_success.isoformat() if health.last_success else None,
            "last_failure": health.last_failure.isoformat() if health.last_failure else None,
            "success_rate": health.success_rate,
            "current_status": health.current_status,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get source health: {str(e)}")


@router.get("/circuit-breakers")
async def get_circuit_breakers():
    """
    Get status of all circuit breakers
    """
    try:
        stats = circuit_manager.get_all_stats()
        return {
            "circuit_breakers": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get circuit breaker stats: {str(e)}")


@router.get("/circuit-breakers/{breaker_name}")
async def get_circuit_breaker(breaker_name: str):
    """
    Get status of a specific circuit breaker
    """
    try:
        if breaker_name not in circuit_manager.breakers:
            raise HTTPException(status_code=404, detail=f"Circuit breaker '{breaker_name}' not found")
        
        breaker = circuit_manager.breakers[breaker_name]
        stats = breaker.get_stats()
        
        return {
            "circuit_breaker": stats,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get circuit breaker: {str(e)}")


@router.post("/circuit-breakers/action")
async def circuit_breaker_action(action: CircuitBreakerAction):
    """
    Perform action on circuit breakers (reset, reset all)
    """
    try:
        if action.action == "reset_all":
            circuit_manager.reset_all()
            return {
                "message": "All circuit breakers reset successfully",
                "timestamp": datetime.now().isoformat()
            }
        
        elif action.action == "reset" and action.breaker_name:
            circuit_manager.reset_breaker(action.breaker_name)
            return {
                "message": f"Circuit breaker '{action.breaker_name}' reset successfully",
                "timestamp": datetime.now().isoformat()
            }
        
        else:
            raise HTTPException(status_code=400, detail="Invalid action or missing breaker_name")
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to perform action: {str(e)}")


@router.get("/metrics/export")
async def export_metrics(
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    source: Optional[str] = Query(None, description="Filter by source")
):
    """
    Export metrics data for analysis
    """
    try:
        start_time = None
        end_time = None
        
        if start_date:
            start_time = datetime.fromisoformat(start_date)
        
        if end_date:
            end_time = datetime.fromisoformat(end_date)
        
        metrics = metrics_collector.export_metrics(start_time, end_time)
        
        # Filter by source if specified
        if source:
            metrics = [m for m in metrics if m.get('source') == source]
        
        return {
            "metrics": metrics,
            "count": len(metrics),
            "filters": {
                "start_date": start_date,
                "end_date": end_date,
                "source": source
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export metrics: {str(e)}")


@router.delete("/metrics/cleanup")
async def cleanup_old_metrics(days: int = Query(7, description="Days to keep")):
    """
    Clean up old metrics data
    """
    try:
        metrics_collector.cleanup_old_metrics(days)
        return {
            "message": f"Cleaned up metrics older than {days} days",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup metrics: {str(e)}")


@router.get("/alerts")
async def get_alerts():
    """
    Get current system alerts based on health status
    """
    try:
        alerts = []
        dashboard_data = metrics_collector.get_dashboard_data()
        
        # Check for down sources
        for source, health in dashboard_data["sources"].items():
            if health["current_status"] == "down":
                alerts.append({
                    "level": "critical",
                    "source": source,
                    "message": f"Source {source} is down",
                    "details": f"Success rate: {health['success_rate']}%"
                })
            elif health["current_status"] == "degraded":
                alerts.append({
                    "level": "warning",
                    "source": source,
                    "message": f"Source {source} is degraded",
                    "details": f"Success rate: {health['success_rate']}%"
                })
        
        # Check for open circuit breakers
        circuit_stats = circuit_manager.get_all_stats()
        for name, stats in circuit_stats.items():
            if stats["state"] == "open":
                alerts.append({
                    "level": "warning",
                    "source": name,
                    "message": f"Circuit breaker {name} is open",
                    "details": f"Failed calls: {stats['failure_count']}"
                })
        
        # Check overall system health
        summary = dashboard_data["summary"]
        if summary["down_sources"] > 0:
            alerts.append({
                "level": "critical" if summary["down_sources"] > 2 else "warning",
                "source": "system",
                "message": f"{summary['down_sources']} sources are down",
                "details": f"Total sources: {summary['total_sources']}"
            })
        
        return {
            "alerts": alerts,
            "alert_count": len(alerts),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")