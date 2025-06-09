"""
Data Synchronization Monitoring Module
Real-time monitoring of legislative data synchronization across all APIs

CRITICAL: Monitors data freshness, sync status, and consistency to ensure
the system always has up-to-date legislative information.
"""

import asyncio
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import hashlib
import json
import logging

from core.database.models import get_session, Proposition, DataSource
from core.monitoring.structured_logging import get_logger
from core.monitoring.performance_dashboard import get_performance_collector
from core.monitoring.security_monitor import SecurityEventType, ThreatLevel, get_security_monitor
from core.utils.alerting import send_critical_alert
from core.utils.metrics_collector import metrics

logger = get_logger(__name__)


class SyncStatus(Enum):
    """Data synchronization status."""
    SYNCED = "synced"           # Data is up-to-date
    SYNCING = "syncing"         # Sync in progress
    STALE = "stale"            # Data is outdated
    FAILED = "failed"          # Sync failed
    NEVER_SYNCED = "never"     # Never synced


class DataFreshness(Enum):
    """Data freshness categories."""
    FRESH = "fresh"             # < 1 hour old
    RECENT = "recent"           # 1-6 hours old
    STALE = "stale"            # 6-24 hours old
    OUTDATED = "outdated"       # > 24 hours old
    CRITICAL = "critical"       # > 48 hours old


@dataclass
class SyncMetrics:
    """Metrics for a single sync operation."""
    source: DataSource
    start_time: datetime
    end_time: Optional[datetime]
    status: SyncStatus
    records_processed: int
    records_added: int
    records_updated: int
    records_failed: int
    error_message: Optional[str]
    duration_seconds: Optional[float]


@dataclass
class DataSourceStatus:
    """Current status of a data source."""
    source: DataSource
    last_sync_time: Optional[datetime]
    last_successful_sync: Optional[datetime]
    sync_status: SyncStatus
    data_freshness: DataFreshness
    oldest_record: Optional[datetime]
    newest_record: Optional[datetime]
    total_records: int
    sync_frequency_hours: float
    next_sync_due: Optional[datetime]
    consecutive_failures: int
    error_rate_24h: float


@dataclass
class DataConsistencyIssue:
    """Data consistency issue detected."""
    issue_type: str
    severity: ThreatLevel
    source: DataSource
    description: str
    affected_records: int
    detected_at: datetime
    resolution: Optional[str]


class DataSyncMonitor:
    """
    Monitors data synchronization across all legislative data sources.
    
    Tracks:
    - Sync status and history
    - Data freshness metrics
    - Consistency checks
    - Sync failures and recovery
    - Real-time sync operations
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize data sync monitor."""
        self.config = config or {}
        
        # Sync configuration
        self.sync_intervals = {
            DataSource.CAMARA: timedelta(hours=1),
            DataSource.SENADO: timedelta(hours=2),
            DataSource.PLANALTO: timedelta(hours=6),
            DataSource.LEXML: timedelta(hours=12)
        }
        
        # Freshness thresholds
        self.freshness_thresholds = {
            DataFreshness.FRESH: timedelta(hours=1),
            DataFreshness.RECENT: timedelta(hours=6),
            DataFreshness.STALE: timedelta(hours=24),
            DataFreshness.OUTDATED: timedelta(hours=48)
        }
        
        # Tracking data structures
        self._sync_history = defaultdict(lambda: deque(maxlen=1000))
        self._source_status = {}
        self._active_syncs = {}
        self._consistency_issues = deque(maxlen=100)
        self._lock = threading.RLock()
        
        # Performance metrics
        self._performance_collector = get_performance_collector()
        
        # Initialize source status
        self._initialize_source_status()
        
        # Start monitoring thread
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Data sync monitor initialized", extra={
            "sources": len(self.sync_intervals),
            "monitoring_enabled": True
        })
    
    def _initialize_source_status(self):
        """Initialize status for all data sources."""
        session = get_session()
        try:
            for source in DataSource:
                # Get latest sync info from database
                latest_prop = session.query(Proposition).filter(
                    Proposition.source == source
                ).order_by(Proposition.created_at.desc()).first()
                
                oldest_prop = session.query(Proposition).filter(
                    Proposition.source == source
                ).order_by(Proposition.created_at.asc()).first()
                
                total_count = session.query(Proposition).filter(
                    Proposition.source == source
                ).count()
                
                last_sync = latest_prop.created_at if latest_prop else None
                oldest_record = oldest_prop.publication_date if oldest_prop else None
                
                self._source_status[source] = DataSourceStatus(
                    source=source,
                    last_sync_time=last_sync,
                    last_successful_sync=last_sync,
                    sync_status=SyncStatus.NEVER_SYNCED if not last_sync else SyncStatus.SYNCED,
                    data_freshness=self._calculate_freshness(last_sync),
                    oldest_record=oldest_record,
                    newest_record=latest_prop.publication_date if latest_prop else None,
                    total_records=total_count,
                    sync_frequency_hours=self.sync_intervals[source].total_seconds() / 3600,
                    next_sync_due=self._calculate_next_sync(source, last_sync),
                    consecutive_failures=0,
                    error_rate_24h=0.0
                )
                
        finally:
            session.close()
    
    def _calculate_freshness(self, last_sync: Optional[datetime]) -> DataFreshness:
        """Calculate data freshness based on last sync time."""
        if not last_sync:
            return DataFreshness.CRITICAL
        
        # Ensure timezone-aware comparison
        if last_sync.tzinfo is None:
            last_sync = last_sync.replace(tzinfo=timezone.utc)
        
        age = datetime.now(timezone.utc) - last_sync
        
        for freshness, threshold in self.freshness_thresholds.items():
            if age <= threshold:
                return freshness
        
        return DataFreshness.CRITICAL
    
    def _calculate_next_sync(self, source: DataSource, last_sync: Optional[datetime]) -> Optional[datetime]:
        """Calculate when next sync is due."""
        if not last_sync:
            return datetime.now(timezone.utc)
        
        if last_sync.tzinfo is None:
            last_sync = last_sync.replace(tzinfo=timezone.utc)
        
        return last_sync + self.sync_intervals[source]
    
    def start_sync(self, source: DataSource) -> str:
        """Record start of sync operation."""
        sync_id = f"{source.value}_{datetime.now().timestamp()}"
        
        with self._lock:
            self._active_syncs[sync_id] = SyncMetrics(
                source=source,
                start_time=datetime.now(timezone.utc),
                end_time=None,
                status=SyncStatus.SYNCING,
                records_processed=0,
                records_added=0,
                records_updated=0,
                records_failed=0,
                error_message=None,
                duration_seconds=None
            )
            
            # Update source status
            if source in self._source_status:
                self._source_status[source].sync_status = SyncStatus.SYNCING
        
        # Record performance metric
        self._performance_collector.record_metric(
            f"data_sync_started",
            1,
            labels={"source": source.value}
        )
        
        logger.info(f"Data sync started", extra={
            "sync_id": sync_id,
            "source": source.value
        })
        
        return sync_id
    
    def update_sync_progress(self, sync_id: str, processed: int = 0, 
                           added: int = 0, updated: int = 0, failed: int = 0):
        """Update sync progress metrics."""
        with self._lock:
            if sync_id in self._active_syncs:
                sync = self._active_syncs[sync_id]
                sync.records_processed += processed
                sync.records_added += added
                sync.records_updated += updated
                sync.records_failed += failed
    
    def complete_sync(self, sync_id: str, success: bool = True, 
                     error_message: Optional[str] = None):
        """Record completion of sync operation."""
        with self._lock:
            if sync_id not in self._active_syncs:
                logger.warning(f"Unknown sync_id: {sync_id}")
                return
            
            sync = self._active_syncs[sync_id]
            sync.end_time = datetime.now(timezone.utc)
            sync.status = SyncStatus.SYNCED if success else SyncStatus.FAILED
            sync.error_message = error_message
            sync.duration_seconds = (sync.end_time - sync.start_time).total_seconds()
            
            # Move to history
            self._sync_history[sync.source].append(sync)
            del self._active_syncs[sync_id]
            
            # Update source status
            if sync.source in self._source_status:
                status = self._source_status[sync.source]
                status.last_sync_time = sync.end_time
                
                if success:
                    status.last_successful_sync = sync.end_time
                    status.sync_status = SyncStatus.SYNCED
                    status.consecutive_failures = 0
                    status.data_freshness = DataFreshness.FRESH
                else:
                    status.sync_status = SyncStatus.FAILED
                    status.consecutive_failures += 1
                
                status.next_sync_due = self._calculate_next_sync(sync.source, sync.end_time)
                
                # Calculate error rate
                self._update_error_rate(sync.source)
        
        # Record performance metrics
        self._performance_collector.record_metric(
            f"data_sync_duration",
            sync.duration_seconds,
            labels={
                "source": sync.source.value,
                "status": "success" if success else "failed"
            }
        )
        
        self._performance_collector.record_metric(
            f"data_sync_records",
            sync.records_processed,
            labels={
                "source": sync.source.value,
                "type": "processed"
            }
        )
        
        # Log completion
        logger.info(f"Data sync completed", extra={
            "sync_id": sync_id,
            "source": sync.source.value,
            "success": success,
            "duration": sync.duration_seconds,
            "records_processed": sync.records_processed,
            "records_added": sync.records_added,
            "records_updated": sync.records_updated,
            "records_failed": sync.records_failed,
            "error": error_message
        })
        
        # Alert on failures
        if not success and status.consecutive_failures >= 3:
            self._alert_sync_failure(sync.source, status)
    
    def _update_error_rate(self, source: DataSource):
        """Update 24-hour error rate for source."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_syncs = [
            s for s in self._sync_history[source]
            if s.end_time and s.end_time > cutoff
        ]
        
        if recent_syncs:
            failed_syncs = sum(1 for s in recent_syncs if s.status == SyncStatus.FAILED)
            error_rate = (failed_syncs / len(recent_syncs)) * 100
            self._source_status[source].error_rate_24h = error_rate
    
    def _alert_sync_failure(self, source: DataSource, status: DataSourceStatus):
        """Send alert for sync failures."""
        alert_message = (
            f"Data sync failure for {source.value}\n"
            f"Consecutive failures: {status.consecutive_failures}\n"
            f"Last successful sync: {status.last_successful_sync}\n"
            f"Error rate (24h): {status.error_rate_24h:.1f}%"
        )
        
        # Log security event
        security_monitor = get_security_monitor()
        security_monitor.log_security_event(
            SecurityEventType.UNUSUAL_ACTIVITY,
            ThreatLevel.HIGH if status.consecutive_failures >= 5 else ThreatLevel.MEDIUM,
            details={
                "event": "data_sync_failure",
                "source": source.value,
                "consecutive_failures": status.consecutive_failures,
                "error_rate_24h": status.error_rate_24h
            }
        )
        
        # Send critical alert
        asyncio.create_task(send_critical_alert(
            "Data Sync Failure",
            alert_message,
            {
                "source": source.value,
                "failures": status.consecutive_failures
            }
        ))
    
    def check_data_consistency(self, source: DataSource) -> List[DataConsistencyIssue]:
        """Check data consistency for a source."""
        issues = []
        session = get_session()
        
        try:
            # Check for duplicate records
            duplicates = session.execute("""
                SELECT COUNT(*) as count, number, year, type
                FROM propositions
                WHERE source = :source
                GROUP BY number, year, type
                HAVING COUNT(*) > 1
            """, {"source": source.value}).fetchall()
            
            if duplicates:
                total_duplicates = sum(row.count - 1 for row in duplicates)
                issues.append(DataConsistencyIssue(
                    issue_type="duplicate_records",
                    severity=ThreatLevel.MEDIUM,
                    source=source,
                    description=f"Found {len(duplicates)} sets of duplicate propositions",
                    affected_records=total_duplicates,
                    detected_at=datetime.now(timezone.utc),
                    resolution="Deduplication required"
                ))
            
            # Check for missing required fields
            missing_fields = session.execute("""
                SELECT COUNT(*) as count
                FROM propositions
                WHERE source = :source
                AND (number IS NULL OR year IS NULL OR type IS NULL OR summary IS NULL)
            """, {"source": source.value}).scalar()
            
            if missing_fields > 0:
                issues.append(DataConsistencyIssue(
                    issue_type="missing_required_fields",
                    severity=ThreatLevel.HIGH,
                    source=source,
                    description=f"Found {missing_fields} records with missing required fields",
                    affected_records=missing_fields,
                    detected_at=datetime.now(timezone.utc),
                    resolution="Data validation and cleanup required"
                ))
            
            # Check for future dates
            future_dates = session.execute("""
                SELECT COUNT(*) as count
                FROM propositions
                WHERE source = :source
                AND publication_date > :future_date
            """, {
                "source": source.value,
                "future_date": datetime.now() + timedelta(days=1)
            }).scalar()
            
            if future_dates > 0:
                issues.append(DataConsistencyIssue(
                    issue_type="future_dates",
                    severity=ThreatLevel.LOW,
                    source=source,
                    description=f"Found {future_dates} records with future publication dates",
                    affected_records=future_dates,
                    detected_at=datetime.now(timezone.utc),
                    resolution="Date validation required"
                ))
            
            # Store issues
            with self._lock:
                self._consistency_issues.extend(issues)
            
        finally:
            session.close()
        
        return issues
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status for all sources."""
        with self._lock:
            status = {
                "sources": {},
                "active_syncs": len(self._active_syncs),
                "consistency_issues": len(self._consistency_issues),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            for source, source_status in self._source_status.items():
                status["sources"][source.value] = {
                    "last_sync": source_status.last_sync_time.isoformat() if source_status.last_sync_time else None,
                    "sync_status": source_status.sync_status.value,
                    "data_freshness": source_status.data_freshness.value,
                    "total_records": source_status.total_records,
                    "next_sync_due": source_status.next_sync_due.isoformat() if source_status.next_sync_due else None,
                    "consecutive_failures": source_status.consecutive_failures,
                    "error_rate_24h": source_status.error_rate_24h,
                    "is_overdue": self._is_sync_overdue(source)
                }
            
            return status
    
    def _is_sync_overdue(self, source: DataSource) -> bool:
        """Check if sync is overdue for a source."""
        status = self._source_status.get(source)
        if not status or not status.next_sync_due:
            return True
        
        return datetime.now(timezone.utc) > status.next_sync_due
    
    def get_sync_history(self, source: Optional[DataSource] = None, 
                        hours: int = 24) -> List[Dict[str, Any]]:
        """Get sync history for specified period."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        history = []
        
        with self._lock:
            sources = [source] if source else self._sync_history.keys()
            
            for src in sources:
                for sync in self._sync_history[src]:
                    if sync.end_time and sync.end_time > cutoff:
                        history.append({
                            "source": src.value,
                            "start_time": sync.start_time.isoformat(),
                            "end_time": sync.end_time.isoformat() if sync.end_time else None,
                            "status": sync.status.value,
                            "duration_seconds": sync.duration_seconds,
                            "records_processed": sync.records_processed,
                            "records_added": sync.records_added,
                            "records_updated": sync.records_updated,
                            "records_failed": sync.records_failed,
                            "error_message": sync.error_message
                        })
        
        return sorted(history, key=lambda x: x["start_time"], reverse=True)
    
    def get_data_freshness_report(self) -> Dict[str, Any]:
        """Get data freshness report for all sources."""
        report = {
            "summary": {
                "fresh_sources": 0,
                "stale_sources": 0,
                "critical_sources": 0
            },
            "sources": {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        with self._lock:
            for source, status in self._source_status.items():
                freshness = status.data_freshness
                
                if freshness == DataFreshness.FRESH:
                    report["summary"]["fresh_sources"] += 1
                elif freshness in [DataFreshness.STALE, DataFreshness.OUTDATED]:
                    report["summary"]["stale_sources"] += 1
                elif freshness == DataFreshness.CRITICAL:
                    report["summary"]["critical_sources"] += 1
                
                age = None
                if status.last_sync_time:
                    if status.last_sync_time.tzinfo is None:
                        last_sync = status.last_sync_time.replace(tzinfo=timezone.utc)
                    else:
                        last_sync = status.last_sync_time
                    age = (datetime.now(timezone.utc) - last_sync).total_seconds()
                
                report["sources"][source.value] = {
                    "freshness": freshness.value,
                    "last_sync": status.last_sync_time.isoformat() if status.last_sync_time else None,
                    "age_seconds": age,
                    "age_human": self._format_age(age) if age else "Never synced",
                    "oldest_record": status.oldest_record.isoformat() if status.oldest_record else None,
                    "newest_record": status.newest_record.isoformat() if status.newest_record else None
                }
        
        return report
    
    def _format_age(self, seconds: float) -> str:
        """Format age in human-readable format."""
        if seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        else:
            return f"{int(seconds / 86400)} days"
    
    def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._monitoring_active:
            try:
                # Check for overdue syncs
                self._check_overdue_syncs()
                
                # Update data freshness
                self._update_freshness_status()
                
                # Run consistency checks periodically
                if datetime.now().minute == 0:  # Once per hour
                    for source in DataSource:
                        self.check_data_consistency(source)
                
                # Sleep for monitoring interval
                threading.Event().wait(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                threading.Event().wait(30)
    
    def _check_overdue_syncs(self):
        """Check for overdue syncs and send alerts."""
        with self._lock:
            for source, status in self._source_status.items():
                if self._is_sync_overdue(source):
                    # Calculate how overdue
                    if status.next_sync_due:
                        overdue = datetime.now(timezone.utc) - status.next_sync_due
                        overdue_hours = overdue.total_seconds() / 3600
                        
                        # Alert if significantly overdue
                        if overdue_hours > 2:  # 2 hours overdue
                            logger.warning(f"Sync overdue for {source.value}", extra={
                                "source": source.value,
                                "overdue_hours": overdue_hours,
                                "last_sync": status.last_sync_time
                            })
                            
                            # Record metric
                            self._performance_collector.record_metric(
                                "data_sync_overdue",
                                overdue_hours,
                                labels={"source": source.value}
                            )
    
    def _update_freshness_status(self):
        """Update data freshness status for all sources."""
        with self._lock:
            for source, status in self._source_status.items():
                old_freshness = status.data_freshness
                new_freshness = self._calculate_freshness(status.last_sync_time)
                
                if old_freshness != new_freshness:
                    status.data_freshness = new_freshness
                    
                    # Log freshness change
                    logger.info(f"Data freshness changed for {source.value}", extra={
                        "source": source.value,
                        "old_freshness": old_freshness.value,
                        "new_freshness": new_freshness.value
                    })
                    
                    # Alert on critical freshness
                    if new_freshness == DataFreshness.CRITICAL:
                        self._alert_critical_freshness(source, status)
    
    def _alert_critical_freshness(self, source: DataSource, status: DataSourceStatus):
        """Alert when data becomes critically stale."""
        alert_message = (
            f"Data critically stale for {source.value}\n"
            f"Last sync: {status.last_sync_time}\n"
            f"Data age: {self._format_age((datetime.now(timezone.utc) - status.last_sync_time).total_seconds())}"
        )
        
        # Log security event
        security_monitor = get_security_monitor()
        security_monitor.log_security_event(
            SecurityEventType.UNUSUAL_ACTIVITY,
            ThreatLevel.HIGH,
            details={
                "event": "data_critically_stale",
                "source": source.value,
                "last_sync": status.last_sync_time.isoformat() if status.last_sync_time else None
            }
        )
    
    def shutdown(self):
        """Shutdown the monitor."""
        logger.info("Shutting down data sync monitor")
        self._monitoring_active = False


# Global instance
_data_sync_monitor: Optional[DataSyncMonitor] = None
_monitor_lock = threading.Lock()


def get_data_sync_monitor() -> DataSyncMonitor:
    """Get or create data sync monitor instance."""
    global _data_sync_monitor
    
    if _data_sync_monitor is None:
        with _monitor_lock:
            if _data_sync_monitor is None:
                _data_sync_monitor = DataSyncMonitor()
    
    return _data_sync_monitor