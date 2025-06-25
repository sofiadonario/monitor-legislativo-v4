# Materialized View Management System for Monitor Legislativo v4
# Phase 4 Week 14: Intelligent refresh strategies and performance optimization
# Handles automatic refresh scheduling, dependency tracking, and performance monitoring

import asyncio
import asyncpg
import logging
import time
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import os
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class RefreshStrategy(Enum):
    """Materialized view refresh strategies"""
    IMMEDIATE = "immediate"        # Refresh immediately after data changes
    SCHEDULED = "scheduled"        # Refresh on a fixed schedule
    THRESHOLD = "threshold"        # Refresh when data change threshold is met
    SMART = "smart"               # Intelligent refresh based on usage patterns
    MANUAL = "manual"             # Manual refresh only

class ViewStatus(Enum):
    """Materialized view status"""
    FRESH = "fresh"               # Recently refreshed, data is current
    STALE = "stale"              # Data may be outdated
    REFRESHING = "refreshing"     # Currently being refreshed
    ERROR = "error"              # Last refresh failed
    UNKNOWN = "unknown"          # Status cannot be determined

@dataclass
class ViewMetrics:
    """Performance metrics for materialized views"""
    name: str
    last_refresh: Optional[datetime] = None
    refresh_duration: float = 0.0
    row_count: int = 0
    size_bytes: int = 0
    query_count: int = 0
    status: ViewStatus = ViewStatus.UNKNOWN
    error_message: Optional[str] = None
    staleness_score: float = 0.0  # 0-1, where 1 is very stale
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        if self.last_refresh:
            result['last_refresh'] = self.last_refresh.isoformat()
        return result

@dataclass
class ViewDefinition:
    """Materialized view configuration and metadata"""
    name: str
    dependencies: List[str] = field(default_factory=list)  # Tables this view depends on
    refresh_strategy: RefreshStrategy = RefreshStrategy.SCHEDULED
    refresh_interval: timedelta = field(default_factory=lambda: timedelta(hours=1))
    threshold_changes: int = 100  # Number of changes to trigger refresh
    priority: int = 1  # Higher priority views refresh first
    query_pattern: Optional[str] = None  # SQL pattern for creating the view
    indexes: List[str] = field(default_factory=list)  # Indexes to create on the view
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['refresh_strategy'] = self.refresh_strategy.value
        result['refresh_interval'] = str(self.refresh_interval)
        return result

class MaterializedViewManager:
    """
    Intelligent materialized view management system for Monitor Legislativo v4
    
    Features:
    - Automatic refresh scheduling based on data changes
    - Dependency tracking between views and tables
    - Performance monitoring and optimization
    - Concurrent refresh with proper locking
    - Error handling and retry mechanisms
    """
    
    def __init__(self, connection_pool):
        self.pool = connection_pool
        self.views: Dict[str, ViewDefinition] = {}
        self.metrics: Dict[str, ViewMetrics] = {}
        self.change_counters: Dict[str, int] = {}  # Track changes per table
        self.refresh_locks: Dict[str, asyncio.Lock] = {}
        self.is_monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Initialize predefined views for Monitor Legislativo v4
        self._initialize_default_views()
    
    def _initialize_default_views(self) -> None:
        """Initialize materialized views specific to Monitor Legislativo v4"""
        
        # Document statistics view - high priority, frequent updates
        self.register_view(ViewDefinition(
            name="mv_document_statistics",
            dependencies=["legislative_documents"],
            refresh_strategy=RefreshStrategy.THRESHOLD,
            refresh_interval=timedelta(minutes=30),
            threshold_changes=50,
            priority=1,
            indexes=["idx_mv_doc_stats_type_month", "idx_mv_doc_stats_state"]
        ))
        
        # Transport summary view - medium priority, less frequent updates
        self.register_view(ViewDefinition(
            name="mv_transport_summary", 
            dependencies=["legislative_documents"],
            refresh_strategy=RefreshStrategy.SCHEDULED,
            refresh_interval=timedelta(hours=2),
            threshold_changes=25,
            priority=2,
            indexes=["idx_mv_transport_modal", "idx_mv_transport_state"]
        ))
        
        # Collection performance view - depends on logs, smart refresh
        self.register_view(ViewDefinition(
            name="mv_collection_performance",
            dependencies=["search_terms", "collection_logs"],
            refresh_strategy=RefreshStrategy.SMART,
            refresh_interval=timedelta(hours=1),
            threshold_changes=10,
            priority=3
        ))
    
    def register_view(self, view_def: ViewDefinition) -> None:
        """Register a materialized view for management"""
        self.views[view_def.name] = view_def
        self.metrics[view_def.name] = ViewMetrics(name=view_def.name)
        self.refresh_locks[view_def.name] = asyncio.Lock()
        
        # Initialize change counters for dependencies
        for dep in view_def.dependencies:
            if dep not in self.change_counters:
                self.change_counters[dep] = 0
        
        logger.info(f"Registered materialized view: {view_def.name}")
    
    async def start_monitoring(self) -> None:
        """Start background monitoring and refresh scheduling"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self._monitor_task = asyncio.create_task(self._monitoring_loop())
            logger.info("Materialized view monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop background monitoring"""
        self.is_monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Materialized view monitoring stopped")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop for automatic refresh scheduling"""
        while self.is_monitoring:
            try:
                # Update metrics for all views
                await self._update_all_metrics()
                
                # Check which views need refreshing
                refresh_candidates = await self._identify_refresh_candidates()
                
                # Refresh views that need it (in priority order)
                for view_name in sorted(refresh_candidates, 
                                      key=lambda x: self.views[x].priority):
                    try:
                        await self.refresh_view(view_name, background=True)
                    except Exception as e:
                        logger.error(f"Background refresh failed for {view_name}: {e}")
                
                # Sleep before next check
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(10)  # Brief pause before retry
    
    async def _update_all_metrics(self) -> None:
        """Update metrics for all registered materialized views"""
        async with self.pool.acquire_connection() as conn:
            for view_name in self.views.keys():
                try:
                    await self._update_view_metrics(conn, view_name)
                except Exception as e:
                    logger.error(f"Failed to update metrics for {view_name}: {e}")
                    self.metrics[view_name].status = ViewStatus.ERROR
                    self.metrics[view_name].error_message = str(e)
    
    async def _update_view_metrics(self, conn: asyncpg.Connection, view_name: str) -> None:
        """Update metrics for a specific materialized view"""
        metrics = self.metrics[view_name]
        
        # Check if view exists
        view_exists = await conn.fetchval("""
            SELECT COUNT(*) FROM pg_matviews 
            WHERE matviewname = $1 AND schemaname = 'public'
        """, view_name)
        
        if not view_exists:
            metrics.status = ViewStatus.ERROR
            metrics.error_message = "Materialized view does not exist"
            return
        
        # Get view statistics
        stats = await conn.fetchrow("""
            SELECT 
                pg_total_relation_size($1) as size_bytes,
                (SELECT reltuples::bigint FROM pg_class WHERE relname = $1) as row_count
        """, view_name)
        
        if stats:
            metrics.size_bytes = stats['size_bytes'] or 0
            metrics.row_count = stats['row_count'] or 0
        
        # Get last refresh time from pg_stat_user_tables
        last_refresh_info = await conn.fetchrow("""
            SELECT n_tup_ins + n_tup_upd as modifications, last_vacuum, last_analyze
            FROM pg_stat_user_tables 
            WHERE relname = $1 AND schemaname = 'public'
        """, view_name)
        
        # Calculate staleness score based on dependency changes
        metrics.staleness_score = await self._calculate_staleness(view_name)
        
        # Determine status
        if metrics.staleness_score > 0.8:
            metrics.status = ViewStatus.STALE
        elif metrics.staleness_score > 0.3:
            metrics.status = ViewStatus.FRESH
        else:
            metrics.status = ViewStatus.FRESH
    
    async def _calculate_staleness(self, view_name: str) -> float:
        """Calculate staleness score for a materialized view (0-1)"""
        view_def = self.views[view_name]
        metrics = self.metrics[view_name]
        
        # Time-based staleness
        time_staleness = 0.0
        if metrics.last_refresh:
            time_since_refresh = datetime.now() - metrics.last_refresh
            expected_interval = view_def.refresh_interval
            time_staleness = min(1.0, time_since_refresh.total_seconds() / expected_interval.total_seconds())
        else:
            time_staleness = 1.0  # Never refreshed
        
        # Change-based staleness
        change_staleness = 0.0
        total_changes = sum(self.change_counters.get(dep, 0) for dep in view_def.dependencies)
        if total_changes > 0:
            change_staleness = min(1.0, total_changes / view_def.threshold_changes)
        
        # Combine factors (weighted average)
        return (time_staleness * 0.6) + (change_staleness * 0.4)
    
    async def _identify_refresh_candidates(self) -> List[str]:
        """Identify materialized views that need refreshing"""
        candidates = []
        
        for view_name, view_def in self.views.items():
            metrics = self.metrics[view_name]
            
            # Skip if currently refreshing
            if metrics.status == ViewStatus.REFRESHING:
                continue
            
            should_refresh = False
            
            if view_def.refresh_strategy == RefreshStrategy.IMMEDIATE:
                # Refresh if any dependencies have changes
                total_changes = sum(self.change_counters.get(dep, 0) for dep in view_def.dependencies)
                should_refresh = total_changes > 0
                
            elif view_def.refresh_strategy == RefreshStrategy.SCHEDULED:
                # Refresh based on time interval
                if metrics.last_refresh:
                    time_since_refresh = datetime.now() - metrics.last_refresh
                    should_refresh = time_since_refresh >= view_def.refresh_interval
                else:
                    should_refresh = True  # Never refreshed
                    
            elif view_def.refresh_strategy == RefreshStrategy.THRESHOLD:
                # Refresh when change threshold is met
                total_changes = sum(self.change_counters.get(dep, 0) for dep in view_def.dependencies)
                should_refresh = total_changes >= view_def.threshold_changes
                
            elif view_def.refresh_strategy == RefreshStrategy.SMART:
                # Intelligent refresh based on staleness score
                should_refresh = metrics.staleness_score > 0.5
            
            if should_refresh:
                candidates.append(view_name)
        
        return candidates
    
    async def refresh_view(self, view_name: str, background: bool = False) -> Dict[str, Any]:
        """
        Refresh a specific materialized view with performance tracking
        
        Args:
            view_name: Name of the materialized view to refresh
            background: Whether this is a background refresh (affects logging)
        
        Returns:
            Dictionary with refresh results and metrics
        """
        if view_name not in self.views:
            raise ValueError(f"Unknown materialized view: {view_name}")
        
        view_def = self.views[view_name]
        metrics = self.metrics[view_name]
        
        # Acquire lock to prevent concurrent refreshes
        async with self.refresh_locks[view_name]:
            if not background:
                logger.info(f"Starting refresh of materialized view: {view_name}")
            
            metrics.status = ViewStatus.REFRESHING
            start_time = time.time()
            
            try:
                async with self.pool.acquire_connection() as conn:
                    # Check if view exists
                    view_exists = await conn.fetchval("""
                        SELECT COUNT(*) FROM pg_matviews 
                        WHERE matviewname = $1 AND schemaname = 'public'
                    """, view_name)
                    
                    if not view_exists:
                        raise Exception(f"Materialized view {view_name} does not exist")
                    
                    # Get row count before refresh
                    old_row_count = await conn.fetchval(f"SELECT COUNT(*) FROM {view_name}")
                    
                    # Perform the refresh
                    await conn.execute(f"REFRESH MATERIALIZED VIEW CONCURRENTLY {view_name}")
                    
                    # Get row count after refresh
                    new_row_count = await conn.fetchval(f"SELECT COUNT(*) FROM {view_name}")
                    
                    # Update metrics
                    refresh_duration = time.time() - start_time
                    metrics.last_refresh = datetime.now()
                    metrics.refresh_duration = refresh_duration
                    metrics.row_count = new_row_count
                    metrics.status = ViewStatus.FRESH
                    metrics.error_message = None
                    metrics.staleness_score = 0.0
                    
                    # Reset change counters for dependencies
                    for dep in view_def.dependencies:
                        self.change_counters[dep] = 0
                    
                    result = {
                        "success": True,
                        "view_name": view_name,
                        "refresh_duration": refresh_duration,
                        "old_row_count": old_row_count,
                        "new_row_count": new_row_count,
                        "row_change": new_row_count - old_row_count,
                        "timestamp": metrics.last_refresh.isoformat()
                    }
                    
                    if not background:
                        logger.info(f"Successfully refreshed {view_name} in {refresh_duration:.2f}s "
                                  f"({old_row_count} -> {new_row_count} rows)")
                    
                    return result
                    
            except Exception as e:
                metrics.status = ViewStatus.ERROR
                metrics.error_message = str(e)
                
                result = {
                    "success": False,
                    "view_name": view_name,
                    "error": str(e),
                    "refresh_duration": time.time() - start_time,
                    "timestamp": datetime.now().isoformat()
                }
                
                if not background:
                    logger.error(f"Failed to refresh {view_name}: {e}")
                
                return result
    
    async def refresh_all_views(self, force: bool = False) -> Dict[str, Any]:
        """Refresh all materialized views"""
        results = {}
        total_start_time = time.time()
        
        logger.info("Starting refresh of all materialized views")
        
        # Sort by priority (higher priority first)
        view_order = sorted(self.views.keys(), 
                           key=lambda x: self.views[x].priority, 
                           reverse=True)
        
        for view_name in view_order:
            # Skip if not forced and view doesn't need refresh
            if not force and self.metrics[view_name].staleness_score < 0.3:
                results[view_name] = {
                    "skipped": True,
                    "reason": "Not stale enough"
                }
                continue
            
            try:
                result = await self.refresh_view(view_name)
                results[view_name] = result
            except Exception as e:
                results[view_name] = {
                    "success": False,
                    "error": str(e)
                }
        
        total_duration = time.time() - total_start_time
        
        summary = {
            "total_duration": total_duration,
            "views_processed": len(results),
            "successful_refreshes": len([r for r in results.values() if r.get("success", False)]),
            "failed_refreshes": len([r for r in results.values() if not r.get("success", True)]),
            "skipped_refreshes": len([r for r in results.values() if r.get("skipped", False)]),
            "results": results
        }
        
        logger.info(f"Completed refresh of all views in {total_duration:.2f}s")
        return summary
    
    async def get_view_status(self, view_name: Optional[str] = None) -> Dict[str, Any]:
        """Get status and metrics for materialized views"""
        if view_name:
            if view_name not in self.views:
                return {"error": f"Unknown view: {view_name}"}
            
            view_def = self.views[view_name]
            metrics = self.metrics[view_name]
            
            return {
                "view_definition": view_def.to_dict(),
                "metrics": metrics.to_dict(),
                "dependency_changes": {
                    dep: self.change_counters.get(dep, 0) 
                    for dep in view_def.dependencies
                }
            }
        else:
            # Return status for all views
            return {
                view_name: {
                    "definition": view_def.to_dict(),
                    "metrics": self.metrics[view_name].to_dict(),
                    "dependency_changes": {
                        dep: self.change_counters.get(dep, 0)
                        for dep in view_def.dependencies
                    }
                }
                for view_name, view_def in self.views.items()
            }
    
    async def record_table_change(self, table_name: str, change_count: int = 1) -> None:
        """Record changes to a table that may affect materialized views"""
        if table_name in self.change_counters:
            self.change_counters[table_name] += change_count
            
            # Trigger immediate refresh for views with IMMEDIATE strategy
            for view_name, view_def in self.views.items():
                if (view_def.refresh_strategy == RefreshStrategy.IMMEDIATE and
                    table_name in view_def.dependencies):
                    asyncio.create_task(self.refresh_view(view_name, background=True))
    
    async def optimize_refresh_schedule(self) -> Dict[str, Any]:
        """Analyze and optimize refresh schedules based on usage patterns"""
        optimization_report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "views_analyzed": len(self.views),
            "recommendations": []
        }
        
        for view_name, view_def in self.views.items():
            metrics = self.metrics[view_name]
            
            # Analyze query patterns and refresh frequency
            recommendation = {
                "view_name": view_name,
                "current_strategy": view_def.refresh_strategy.value,
                "current_interval": str(view_def.refresh_interval),
                "suggestions": []
            }
            
            # Performance-based recommendations
            if metrics.refresh_duration > 60:  # Slow refresh
                recommendation["suggestions"].append({
                    "type": "performance",
                    "message": f"Slow refresh ({metrics.refresh_duration:.1f}s) - consider partitioning or incremental refresh",
                    "priority": "high"
                })
            
            # Staleness-based recommendations
            if metrics.staleness_score > 0.7:
                recommendation["suggestions"].append({
                    "type": "staleness",
                    "message": "View is frequently stale - consider more frequent refresh",
                    "suggested_interval": str(view_def.refresh_interval * 0.5),
                    "priority": "medium"
                })
            
            # Change pattern analysis
            total_changes = sum(self.change_counters.get(dep, 0) for dep in view_def.dependencies)
            if total_changes < view_def.threshold_changes * 0.1:
                recommendation["suggestions"].append({
                    "type": "efficiency", 
                    "message": "Low change rate - consider less frequent refresh",
                    "suggested_interval": str(view_def.refresh_interval * 1.5),
                    "priority": "low"
                })
            
            if recommendation["suggestions"]:
                optimization_report["recommendations"].append(recommendation)
        
        return optimization_report
    
    async def create_view_indexes(self, view_name: str) -> Dict[str, Any]:
        """Create indexes for a materialized view if defined"""
        if view_name not in self.views:
            return {"error": f"Unknown view: {view_name}"}
        
        view_def = self.views[view_name]
        results = []
        
        if not view_def.indexes:
            return {"message": "No indexes defined for this view"}
        
        async with self.pool.acquire_connection() as conn:
            for index_name in view_def.indexes:
                try:
                    # Check if index exists
                    index_exists = await conn.fetchval("""
                        SELECT COUNT(*) FROM pg_indexes 
                        WHERE indexname = $1 AND schemaname = 'public'
                    """, index_name)
                    
                    if index_exists:
                        results.append({
                            "index": index_name,
                            "status": "exists",
                            "action": "skipped"
                        })
                    else:
                        # Index creation would need specific DDL - placeholder
                        results.append({
                            "index": index_name,
                            "status": "missing",
                            "action": "manual_creation_required",
                            "note": "Index DDL not stored - manual creation required"
                        })
                        
                except Exception as e:
                    results.append({
                        "index": index_name,
                        "status": "error",
                        "error": str(e)
                    })
        
        return {"view_name": view_name, "index_results": results}

# Factory function for easy manager creation
async def create_view_manager(connection_pool) -> MaterializedViewManager:
    """Create and initialize a materialized view manager"""
    manager = MaterializedViewManager(connection_pool)
    await manager.start_monitoring()
    return manager

# Export main classes
__all__ = [
    'MaterializedViewManager',
    'ViewDefinition', 
    'ViewMetrics',
    'RefreshStrategy',
    'ViewStatus',
    'create_view_manager'
]