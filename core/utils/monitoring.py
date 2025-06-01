"""
Monitoring and Metrics Collection
Tracks API performance and health
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class APIMetrics:
    """Metrics for a single API call"""
    source: str
    endpoint: str
    method: str
    status_code: Optional[int]
    response_time: float
    success: bool
    error_message: Optional[str]
    timestamp: datetime
    result_count: int = 0


@dataclass
class SourceHealth:
    """Health metrics for a data source"""
    source: str
    total_calls: int
    successful_calls: int
    failed_calls: int
    avg_response_time: float
    last_success: Optional[datetime]
    last_failure: Optional[datetime]
    success_rate: float
    current_status: str  # "healthy", "degraded", "down"


class MetricsCollector:
    """Collects and stores API metrics"""
    
    def __init__(self, storage_path: Optional[Path] = None):
        self.logger = logging.getLogger("MetricsCollector")
        self.storage_path = storage_path or Path("metrics.jsonl")
        self.metrics: List[APIMetrics] = []
        self.source_stats: Dict[str, Dict[str, Any]] = {}
        
    def record_api_call(self, source: str, endpoint: str, method: str = "GET",
                       status_code: Optional[int] = None, response_time: float = 0.0,
                       success: bool = True, error_message: Optional[str] = None,
                       result_count: int = 0):
        """Record an API call metric"""
        
        metric = APIMetrics(
            source=source,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time=response_time,
            success=success,
            error_message=error_message,
            timestamp=datetime.now(),
            result_count=result_count
        )
        
        self.metrics.append(metric)
        self._update_source_stats(metric)
        self._persist_metric(metric)
        
        # Log significant events
        if not success:
            self.logger.warning(f"API call failed: {source} - {error_message}")
        elif response_time > 10:
            self.logger.warning(f"Slow API response: {source} took {response_time:.2f}s")
    
    def _update_source_stats(self, metric: APIMetrics):
        """Update aggregated statistics for a source"""
        source = metric.source
        
        if source not in self.source_stats:
            self.source_stats[source] = {
                "total_calls": 0,
                "successful_calls": 0,
                "failed_calls": 0,
                "total_response_time": 0.0,
                "last_success": None,
                "last_failure": None,
                "recent_errors": []
            }
        
        stats = self.source_stats[source]
        stats["total_calls"] += 1
        stats["total_response_time"] += metric.response_time
        
        if metric.success:
            stats["successful_calls"] += 1
            stats["last_success"] = metric.timestamp
        else:
            stats["failed_calls"] += 1
            stats["last_failure"] = metric.timestamp
            
            # Keep track of recent errors
            if len(stats["recent_errors"]) >= 10:
                stats["recent_errors"].pop(0)
            stats["recent_errors"].append({
                "timestamp": metric.timestamp.isoformat(),
                "error": metric.error_message,
                "endpoint": metric.endpoint
            })
    
    def _persist_metric(self, metric: APIMetrics):
        """Persist metric to storage"""
        try:
            with open(self.storage_path, "a", encoding="utf-8") as f:
                # Convert to dict and handle datetime serialization
                metric_dict = asdict(metric)
                metric_dict["timestamp"] = metric.timestamp.isoformat()
                f.write(json.dumps(metric_dict) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to persist metric: {e}")
    
    def get_source_health(self, source: str) -> Optional[SourceHealth]:
        """Get health metrics for a specific source"""
        if source not in self.source_stats:
            return None
        
        stats = self.source_stats[source]
        
        # Calculate averages
        avg_response_time = 0.0
        if stats["total_calls"] > 0:
            avg_response_time = stats["total_response_time"] / stats["total_calls"]
        
        success_rate = 0.0
        if stats["total_calls"] > 0:
            success_rate = (stats["successful_calls"] / stats["total_calls"]) * 100
        
        # Determine current status
        current_status = "down"
        if success_rate >= 90:
            current_status = "healthy"
        elif success_rate >= 50:
            current_status = "degraded"
        
        # Check if there have been recent failures
        now = datetime.now()
        recent_failures = sum(1 for m in self.metrics[-20:] 
                            if m.source == source and not m.success 
                            and (now - m.timestamp).total_seconds() < 300)  # Last 5 minutes
        
        if recent_failures >= 3 and current_status != "down":
            current_status = "degraded"
        
        return SourceHealth(
            source=source,
            total_calls=stats["total_calls"],
            successful_calls=stats["successful_calls"],
            failed_calls=stats["failed_calls"],
            avg_response_time=round(avg_response_time, 2),
            last_success=stats["last_success"],
            last_failure=stats["last_failure"],
            success_rate=round(success_rate, 2),
            current_status=current_status
        )
    
    def get_all_health(self) -> Dict[str, SourceHealth]:
        """Get health metrics for all sources"""
        return {source: self.get_source_health(source) 
                for source in self.source_stats.keys()}
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get formatted data for monitoring dashboard"""
        all_health = self.get_all_health()
        
        # Summary statistics
        total_sources = len(all_health)
        healthy_sources = sum(1 for h in all_health.values() if h.current_status == "healthy")
        degraded_sources = sum(1 for h in all_health.values() if h.current_status == "degraded")
        down_sources = sum(1 for h in all_health.values() if h.current_status == "down")
        
        # Recent activity (last hour)
        now = datetime.now()
        recent_metrics = [m for m in self.metrics 
                         if (now - m.timestamp).total_seconds() < 3600]
        
        recent_calls = len(recent_metrics)
        recent_failures = sum(1 for m in recent_metrics if not m.success)
        
        return {
            "summary": {
                "total_sources": total_sources,
                "healthy_sources": healthy_sources,
                "degraded_sources": degraded_sources,
                "down_sources": down_sources,
                "overall_health": "healthy" if healthy_sources > total_sources * 0.7 else "degraded"
            },
            "recent_activity": {
                "total_calls_last_hour": recent_calls,
                "failed_calls_last_hour": recent_failures,
                "success_rate_last_hour": round(
                    ((recent_calls - recent_failures) / recent_calls * 100) if recent_calls > 0 else 0, 2
                )
            },
            "sources": {source: asdict(health) for source, health in all_health.items()},
            "timestamp": now.isoformat()
        }
    
    def export_metrics(self, start_time: Optional[datetime] = None, 
                      end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Export metrics for analysis"""
        filtered_metrics = self.metrics
        
        if start_time:
            filtered_metrics = [m for m in filtered_metrics if m.timestamp >= start_time]
        
        if end_time:
            filtered_metrics = [m for m in filtered_metrics if m.timestamp <= end_time]
        
        return [asdict(m) for m in filtered_metrics]
    
    def cleanup_old_metrics(self, days: int = 7):
        """Remove metrics older than specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        original_count = len(self.metrics)
        
        self.metrics = [m for m in self.metrics if m.timestamp >= cutoff]
        
        removed_count = original_count - len(self.metrics)
        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} old metrics")


# Global metrics collector instance
metrics_collector = MetricsCollector()