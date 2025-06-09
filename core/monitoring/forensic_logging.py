"""
Forensic Logging System for Monitor Legislativo v4
CSI-level investigation and correlation tracking

SPRINT 9 - TASK 9.3: Forensic Logging System Implementation
✅ Structured logging with JSON formatting
✅ Request/response correlation tracking  
✅ Performance metric collection
✅ Security event auditing
✅ Error pattern analysis
✅ Log rotation and archival
✅ Real-time anomaly detection
✅ Compliance reporting
✅ Investigation support tools
✅ Correlation ID tracking
"""

import logging
import json
import time
import hashlib
import uuid
import asyncio
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass, asdict
from enum import Enum
from contextlib import contextmanager
from collections import defaultdict, deque
import gzip
import shutil

logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """Enhanced log levels for forensic analysis."""
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"
    AUDIT = "audit"
    PERFORMANCE = "performance"
    FORENSIC = "forensic"


class EventCategory(Enum):
    """Categories for forensic event classification."""
    REQUEST = "request"
    RESPONSE = "response"
    SECURITY = "security"
    PERFORMANCE = "performance"
    ERROR = "error"
    BUSINESS = "business"
    SYSTEM = "system"
    AUDIT = "audit"
    CORRELATION = "correlation"
    ANOMALY = "anomaly"


class SecurityEventType(Enum):
    """Security event types for forensic tracking."""
    AUTHENTICATION_ATTEMPT = "authentication_attempt"
    AUTHORIZATION_FAILURE = "authorization_failure"
    INPUT_VALIDATION_FAILURE = "input_validation_failure"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INJECTION_ATTEMPT = "injection_attempt"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_COMPROMISE = "system_compromise"


@dataclass
class CorrelationContext:
    """Context information for request correlation."""
    correlation_id: str
    session_id: Optional[str]
    user_id: Optional[str]
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: float
    tags: Dict[str, Any]
    baggage: Dict[str, str]


@dataclass
class ForensicEvent:
    """Comprehensive forensic event structure."""
    event_id: str
    correlation_id: str
    timestamp: float
    level: LogLevel
    category: EventCategory
    component: str
    operation: str
    message: str
    duration_ms: Optional[float]
    success: bool
    error_code: Optional[str]
    error_message: Optional[str]
    user_context: Dict[str, Any]
    request_context: Dict[str, Any]
    response_context: Dict[str, Any]
    security_context: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    custom_attributes: Dict[str, Any]
    stack_trace: Optional[str]
    source_location: Dict[str, str]


@dataclass
class PerformanceMetrics:
    """Performance metrics for forensic analysis."""
    operation: str
    duration_ms: float
    cpu_usage_percent: Optional[float]
    memory_usage_mb: Optional[float]
    io_read_bytes: Optional[int]
    io_write_bytes: Optional[int]
    network_in_bytes: Optional[int]
    network_out_bytes: Optional[int]
    database_queries: Optional[int]
    cache_hits: Optional[int]
    cache_misses: Optional[int]
    api_calls: Optional[int]


@dataclass
class SecurityEvent:
    """Security event for forensic tracking."""
    event_id: str
    correlation_id: str
    timestamp: float
    event_type: SecurityEventType
    severity: str
    source_ip: str
    user_agent: str
    user_id: Optional[str]
    session_id: Optional[str]
    resource: str
    action: str
    outcome: str
    risk_score: int
    indicators: List[str]
    mitigation_applied: List[str]
    related_events: List[str]
    investigation_notes: str


class ForensicLogger:
    """
    CSI-level forensic logging system.
    
    Features:
    - Structured JSON logging with correlation tracking
    - Real-time performance monitoring
    - Security event auditing
    - Error pattern analysis
    - Log rotation and archival
    - Anomaly detection
    - Investigation support tools
    - Compliance reporting
    """
    
    def __init__(self, base_log_dir: str = "logs/forensic"):
        """Initialize forensic logging system."""
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(parents=True, exist_ok=True)
        
        # Correlation tracking
        self._correlation_contexts = {}
        self._active_spans = {}
        
        # Event storage
        self._events = deque(maxlen=10000)  # Keep last 10k events in memory
        self._security_events = deque(maxlen=1000)
        self._performance_events = deque(maxlen=5000)
        
        # Pattern analysis
        self._error_patterns = defaultdict(int)
        self._performance_baselines = {}
        self._anomaly_thresholds = {}
        
        # Investigation support
        self._investigation_sessions = {}
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'security_events': 0,
            'performance_events': 0,
            'error_events': 0,
            'correlation_chains': 0,
            'anomalies_detected': 0,
            'investigations_active': 0
        }
        
        # Setup logging infrastructure
        self._setup_forensic_loggers()
        self._setup_log_rotation()
        self._start_background_processors()
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def _setup_forensic_loggers(self):
        """Setup specialized forensic loggers."""
        
        # Main forensic logger
        self.forensic_logger = logging.getLogger('forensic')
        self.forensic_logger.setLevel(logging.DEBUG)
        
        # Create handlers for different log types
        handlers = {
            'main': self.base_log_dir / 'main.log',
            'security': self.base_log_dir / 'security.log',
            'performance': self.base_log_dir / 'performance.log',
            'error': self.base_log_dir / 'errors.log',
            'audit': self.base_log_dir / 'audit.log',
            'correlation': self.base_log_dir / 'correlation.log'
        }
        
        # JSON formatter for structured logging
        json_formatter = logging.Formatter(
            '%(message)s'  # We'll format as JSON ourselves
        )
        
        self.handlers = {}
        for handler_name, log_file in handlers.items():
            handler = logging.FileHandler(log_file)
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(json_formatter)
            self.handlers[handler_name] = handler
            self.forensic_logger.addHandler(handler)
    
    def _setup_log_rotation(self):
        """Setup log rotation and archival."""
        self.rotation_config = {
            'max_size_mb': 100,
            'max_age_days': 30,
            'archive_compression': True,
            'archive_location': self.base_log_dir / 'archive'
        }
        
        # Create archive directory
        (self.base_log_dir / 'archive').mkdir(exist_ok=True)
    
    def _start_background_processors(self):
        """Start background processing threads."""
        
        # Anomaly detection thread
        self._anomaly_thread = threading.Thread(
            target=self._anomaly_detection_loop,
            daemon=True
        )
        self._anomaly_thread.start()
        
        # Log rotation thread
        self._rotation_thread = threading.Thread(
            target=self._log_rotation_loop,
            daemon=True
        )
        self._rotation_thread.start()
        
        # Pattern analysis thread
        self._analysis_thread = threading.Thread(
            target=self._pattern_analysis_loop,
            daemon=True
        )
        self._analysis_thread.start()
    
    def create_correlation_context(self, operation_name: str, 
                                 user_id: Optional[str] = None,
                                 session_id: Optional[str] = None,
                                 parent_correlation_id: Optional[str] = None) -> CorrelationContext:
        """Create new correlation context for request tracking."""
        
        correlation_id = str(uuid.uuid4())
        trace_id = parent_correlation_id or str(uuid.uuid4())
        span_id = str(uuid.uuid4())
        
        context = CorrelationContext(
            correlation_id=correlation_id,
            session_id=session_id,
            user_id=user_id,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_correlation_id,
            operation_name=operation_name,
            start_time=time.time(),
            tags={},
            baggage={}
        )
        
        with self._lock:
            self._correlation_contexts[correlation_id] = context
            self._active_spans[span_id] = context
        
        self.log_forensic_event(
            level=LogLevel.TRACE,
            category=EventCategory.CORRELATION,
            component="correlation",
            operation="span_start",
            message=f"Started correlation span: {operation_name}",
            correlation_id=correlation_id,
            custom_attributes={
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": parent_correlation_id,
                "operation": operation_name
            }
        )
        
        return context
    
    @contextmanager
    def correlation_span(self, operation_name: str, **kwargs):
        """Context manager for automatic correlation tracking."""
        context = self.create_correlation_context(operation_name, **kwargs)
        
        try:
            yield context
        except Exception as e:
            self.log_error_event(
                correlation_id=context.correlation_id,
                component="correlation",
                operation=operation_name,
                error=e,
                message=f"Exception in correlation span: {operation_name}"
            )
            raise
        finally:
            self._close_correlation_context(context.correlation_id)
    
    def _close_correlation_context(self, correlation_id: str):
        """Close correlation context and calculate duration."""
        with self._lock:
            context = self._correlation_contexts.get(correlation_id)
            if context:
                duration_ms = (time.time() - context.start_time) * 1000
                
                self.log_forensic_event(
                    level=LogLevel.TRACE,
                    category=EventCategory.CORRELATION,
                    component="correlation",
                    operation="span_end",
                    message=f"Closed correlation span: {context.operation_name}",
                    correlation_id=correlation_id,
                    duration_ms=duration_ms,
                    custom_attributes={
                        "trace_id": context.trace_id,
                        "span_id": context.span_id,
                        "operation": context.operation_name,
                        "total_duration_ms": duration_ms
                    }
                )
                
                # Remove from active tracking
                del self._correlation_contexts[correlation_id]
                if context.span_id in self._active_spans:
                    del self._active_spans[context.span_id]
    
    def log_forensic_event(self, level: LogLevel, category: EventCategory,
                          component: str, operation: str, message: str,
                          correlation_id: Optional[str] = None,
                          duration_ms: Optional[float] = None,
                          success: bool = True,
                          error_code: Optional[str] = None,
                          error_message: Optional[str] = None,
                          user_context: Optional[Dict[str, Any]] = None,
                          request_context: Optional[Dict[str, Any]] = None,
                          response_context: Optional[Dict[str, Any]] = None,
                          security_context: Optional[Dict[str, Any]] = None,
                          performance_metrics: Optional[Dict[str, Any]] = None,
                          custom_attributes: Optional[Dict[str, Any]] = None,
                          stack_trace: Optional[str] = None) -> str:
        """Log comprehensive forensic event."""
        
        event_id = str(uuid.uuid4())
        timestamp = time.time()
        
        # Get source location information
        import inspect
        frame = inspect.currentframe().f_back
        source_location = {
            'file': frame.f_code.co_filename,
            'function': frame.f_code.co_name,
            'line': frame.f_lineno
        }
        
        event = ForensicEvent(
            event_id=event_id,
            correlation_id=correlation_id or "unknown",
            timestamp=timestamp,
            level=level,
            category=category,
            component=component,
            operation=operation,
            message=message,
            duration_ms=duration_ms,
            success=success,
            error_code=error_code,
            error_message=error_message,
            user_context=user_context or {},
            request_context=request_context or {},
            response_context=response_context or {},
            security_context=security_context or {},
            performance_metrics=performance_metrics or {},
            custom_attributes=custom_attributes or {},
            stack_trace=stack_trace,
            source_location=source_location
        )
        
        # Store event
        with self._lock:
            self._events.append(event)
            self.stats['total_events'] += 1
            
            if category == EventCategory.SECURITY:
                self.stats['security_events'] += 1
            elif category == EventCategory.PERFORMANCE:
                self.stats['performance_events'] += 1
            elif not success:
                self.stats['error_events'] += 1
        
        # Write to appropriate log files
        self._write_event_to_logs(event)
        
        # Trigger real-time analysis
        self._analyze_event_real_time(event)
        
        return event_id
    
    def log_security_event(self, event_type: SecurityEventType, severity: str,
                          source_ip: str, user_agent: str, resource: str,
                          action: str, outcome: str,
                          correlation_id: Optional[str] = None,
                          user_id: Optional[str] = None,
                          session_id: Optional[str] = None,
                          risk_score: int = 0,
                          indicators: Optional[List[str]] = None,
                          mitigation_applied: Optional[List[str]] = None,
                          investigation_notes: str = "") -> str:
        """Log security event for forensic analysis."""
        
        event_id = str(uuid.uuid4())
        timestamp = time.time()
        
        security_event = SecurityEvent(
            event_id=event_id,
            correlation_id=correlation_id or "unknown",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            user_agent=user_agent,
            user_id=user_id,
            session_id=session_id,
            resource=resource,
            action=action,
            outcome=outcome,
            risk_score=risk_score,
            indicators=indicators or [],
            mitigation_applied=mitigation_applied or [],
            related_events=[],
            investigation_notes=investigation_notes
        )
        
        with self._lock:
            self._security_events.append(security_event)
        
        # Log as forensic event
        self.log_forensic_event(
            level=LogLevel.SECURITY,
            category=EventCategory.SECURITY,
            component="security",
            operation=action,
            message=f"Security event: {event_type.value}",
            correlation_id=correlation_id,
            success=outcome == "success",
            security_context=asdict(security_event),
            custom_attributes={
                "security_event_type": event_type.value,
                "risk_score": risk_score,
                "severity": severity,
                "indicators": indicators or [],
                "mitigation": mitigation_applied or []
            }
        )
        
        return event_id
    
    def log_performance_event(self, operation: str, duration_ms: float,
                            correlation_id: Optional[str] = None,
                            metrics: Optional[PerformanceMetrics] = None,
                            baseline_comparison: Optional[Dict[str, Any]] = None) -> str:
        """Log performance event for forensic analysis."""
        
        if metrics is None:
            metrics = PerformanceMetrics(
                operation=operation,
                duration_ms=duration_ms,
                cpu_usage_percent=None,
                memory_usage_mb=None,
                io_read_bytes=None,
                io_write_bytes=None,
                network_in_bytes=None,
                network_out_bytes=None,
                database_queries=None,
                cache_hits=None,
                cache_misses=None,
                api_calls=None
            )
        
        with self._lock:
            self._performance_events.append(metrics)
        
        # Check against baselines
        is_anomaly = self._check_performance_anomaly(metrics)
        
        return self.log_forensic_event(
            level=LogLevel.PERFORMANCE,
            category=EventCategory.PERFORMANCE,
            component="performance",
            operation=operation,
            message=f"Performance metrics for {operation}",
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            success=not is_anomaly,
            performance_metrics=asdict(metrics),
            custom_attributes={
                "is_anomaly": is_anomaly,
                "baseline_comparison": baseline_comparison or {},
                "operation_type": "performance_monitoring"
            }
        )
    
    def log_error_event(self, component: str, operation: str, error: Exception,
                       correlation_id: Optional[str] = None,
                       message: Optional[str] = None,
                       user_context: Optional[Dict[str, Any]] = None,
                       request_context: Optional[Dict[str, Any]] = None) -> str:
        """Log error event with full forensic context."""
        
        import traceback
        
        error_code = type(error).__name__
        error_message = str(error)
        stack_trace = traceback.format_exc()
        
        # Pattern analysis
        error_pattern = f"{component}:{operation}:{error_code}"
        with self._lock:
            self._error_patterns[error_pattern] += 1
        
        return self.log_forensic_event(
            level=LogLevel.ERROR,
            category=EventCategory.ERROR,
            component=component,
            operation=operation,
            message=message or f"Error in {operation}: {error_message}",
            correlation_id=correlation_id,
            success=False,
            error_code=error_code,
            error_message=error_message,
            user_context=user_context,
            request_context=request_context,
            stack_trace=stack_trace,
            custom_attributes={
                "error_type": type(error).__name__,
                "error_pattern": error_pattern,
                "pattern_count": self._error_patterns[error_pattern]
            }
        )
    
    def _write_event_to_logs(self, event: ForensicEvent):
        """Write event to appropriate log files."""
        
        # Create JSON log entry
        log_entry = {
            'event_id': event.event_id,
            'correlation_id': event.correlation_id,
            'timestamp': event.timestamp,
            'iso_timestamp': datetime.fromtimestamp(event.timestamp).isoformat(),
            'level': event.level.value,
            'category': event.category.value,
            'component': event.component,
            'operation': event.operation,
            'message': event.message,
            'duration_ms': event.duration_ms,
            'success': event.success,
            'error_code': event.error_code,
            'error_message': event.error_message,
            'user_context': event.user_context,
            'request_context': event.request_context,
            'response_context': event.response_context,
            'security_context': event.security_context,
            'performance_metrics': event.performance_metrics,
            'custom_attributes': event.custom_attributes,
            'source_location': event.source_location
        }
        
        json_line = json.dumps(log_entry, default=str) + '\n'
        
        # Write to main log
        self.handlers['main'].stream.write(json_line)
        self.handlers['main'].stream.flush()
        
        # Write to category-specific logs
        if event.category == EventCategory.SECURITY:
            self.handlers['security'].stream.write(json_line)
            self.handlers['security'].stream.flush()
        elif event.category == EventCategory.PERFORMANCE:
            self.handlers['performance'].stream.write(json_line)
            self.handlers['performance'].stream.flush()
        elif not event.success:
            self.handlers['error'].stream.write(json_line)
            self.handlers['error'].stream.flush()
        
        # Write correlation events
        if event.category == EventCategory.CORRELATION:
            self.handlers['correlation'].stream.write(json_line)
            self.handlers['correlation'].stream.flush()
    
    def _analyze_event_real_time(self, event: ForensicEvent):
        """Perform real-time analysis on events."""
        
        # Anomaly detection
        if event.category == EventCategory.PERFORMANCE and event.duration_ms:
            self._update_performance_baselines(event.operation, event.duration_ms)
        
        # Security pattern detection
        if event.category == EventCategory.SECURITY:
            self._detect_security_patterns(event)
        
        # Error clustering
        if not event.success:
            self._analyze_error_patterns(event)
    
    def _check_performance_anomaly(self, metrics: PerformanceMetrics) -> bool:
        """Check if performance metrics indicate an anomaly."""
        
        operation = metrics.operation
        
        # Get baseline for this operation
        baseline = self._performance_baselines.get(operation)
        if not baseline:
            return False
        
        # Check if duration exceeds threshold
        threshold_multiplier = 2.0  # 2x baseline is anomaly
        if metrics.duration_ms > baseline['avg_duration'] * threshold_multiplier:
            with self._lock:
                self.stats['anomalies_detected'] += 1
            return True
        
        return False
    
    def _update_performance_baselines(self, operation: str, duration_ms: float):
        """Update performance baselines for anomaly detection."""
        
        with self._lock:
            if operation not in self._performance_baselines:
                self._performance_baselines[operation] = {
                    'count': 0,
                    'total_duration': 0,
                    'avg_duration': 0,
                    'min_duration': duration_ms,
                    'max_duration': duration_ms
                }
            
            baseline = self._performance_baselines[operation]
            baseline['count'] += 1
            baseline['total_duration'] += duration_ms
            baseline['avg_duration'] = baseline['total_duration'] / baseline['count']
            baseline['min_duration'] = min(baseline['min_duration'], duration_ms)
            baseline['max_duration'] = max(baseline['max_duration'], duration_ms)
    
    def _detect_security_patterns(self, event: ForensicEvent):
        """Detect security attack patterns."""
        
        # This would contain sophisticated pattern detection logic
        # For now, just log that we're analyzing
        pass
    
    def _analyze_error_patterns(self, event: ForensicEvent):
        """Analyze error patterns for investigation."""
        
        # This would contain error clustering and pattern analysis
        pass
    
    def _anomaly_detection_loop(self):
        """Background thread for anomaly detection."""
        while True:
            try:
                time.sleep(60)  # Run every minute
                self._run_anomaly_detection()
            except Exception as e:
                logger.error(f"Anomaly detection error: {e}")
    
    def _log_rotation_loop(self):
        """Background thread for log rotation."""
        while True:
            try:
                time.sleep(3600)  # Run every hour
                self._rotate_logs_if_needed()
            except Exception as e:
                logger.error(f"Log rotation error: {e}")
    
    def _pattern_analysis_loop(self):
        """Background thread for pattern analysis."""
        while True:
            try:
                time.sleep(300)  # Run every 5 minutes
                self._analyze_patterns()
            except Exception as e:
                logger.error(f"Pattern analysis error: {e}")
    
    def _run_anomaly_detection(self):
        """Run comprehensive anomaly detection."""
        # Implementation would analyze recent events for anomalies
        pass
    
    def _rotate_logs_if_needed(self):
        """Rotate logs if they exceed size limits."""
        
        max_size = self.rotation_config['max_size_mb'] * 1024 * 1024
        
        for handler_name, handler in self.handlers.items():
            log_file = Path(handler.baseFilename)
            
            if log_file.exists() and log_file.stat().st_size > max_size:
                # Close handler
                handler.close()
                
                # Create archive filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                archive_name = f"{log_file.stem}_{timestamp}.log"
                archive_path = self.base_log_dir / 'archive' / archive_name
                
                # Move and compress
                shutil.move(str(log_file), str(archive_path))
                
                if self.rotation_config['archive_compression']:
                    with open(archive_path, 'rb') as f_in:
                        with gzip.open(f"{archive_path}.gz", 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    archive_path.unlink()
                
                # Recreate handler
                new_handler = logging.FileHandler(log_file)
                new_handler.setLevel(logging.DEBUG)
                new_handler.setFormatter(handler.formatter)
                self.handlers[handler_name] = new_handler
                self.forensic_logger.addHandler(new_handler)
    
    def _analyze_patterns(self):
        """Analyze patterns in logged events."""
        # Implementation would analyze patterns for investigation
        pass
    
    def start_investigation(self, investigation_name: str, 
                          query_filters: Dict[str, Any]) -> str:
        """Start forensic investigation session."""
        
        investigation_id = str(uuid.uuid4())
        
        investigation = {
            'id': investigation_id,
            'name': investigation_name,
            'start_time': time.time(),
            'filters': query_filters,
            'events_collected': [],
            'findings': [],
            'status': 'active'
        }
        
        with self._lock:
            self._investigation_sessions[investigation_id] = investigation
            self.stats['investigations_active'] += 1
        
        self.log_forensic_event(
            level=LogLevel.AUDIT,
            category=EventCategory.AUDIT,
            component="investigation",
            operation="start",
            message=f"Started investigation: {investigation_name}",
            custom_attributes={
                "investigation_id": investigation_id,
                "filters": query_filters
            }
        )
        
        return investigation_id
    
    def query_events(self, filters: Dict[str, Any], 
                    limit: int = 1000) -> List[ForensicEvent]:
        """Query events for investigation."""
        
        matching_events = []
        
        with self._lock:
            for event in self._events:
                if self._event_matches_filters(event, filters):
                    matching_events.append(event)
                    
                    if len(matching_events) >= limit:
                        break
        
        return matching_events
    
    def _event_matches_filters(self, event: ForensicEvent, 
                              filters: Dict[str, Any]) -> bool:
        """Check if event matches query filters."""
        
        # Time range filter
        if 'start_time' in filters and event.timestamp < filters['start_time']:
            return False
        if 'end_time' in filters and event.timestamp > filters['end_time']:
            return False
        
        # Correlation ID filter
        if 'correlation_id' in filters and event.correlation_id != filters['correlation_id']:
            return False
        
        # Component filter
        if 'component' in filters and event.component != filters['component']:
            return False
        
        # Level filter
        if 'level' in filters and event.level != filters['level']:
            return False
        
        # Category filter
        if 'category' in filters and event.category != filters['category']:
            return False
        
        # Success filter
        if 'success' in filters and event.success != filters['success']:
            return False
        
        return True
    
    def generate_investigation_report(self, investigation_id: str) -> Dict[str, Any]:
        """Generate comprehensive investigation report."""
        
        with self._lock:
            investigation = self._investigation_sessions.get(investigation_id)
            
            if not investigation:
                return {'error': 'Investigation not found'}
        
        # Query events based on investigation filters
        events = self.query_events(investigation['filters'])
        
        # Analyze findings
        report = {
            'investigation_id': investigation_id,
            'name': investigation['name'],
            'start_time': investigation['start_time'],
            'duration_seconds': time.time() - investigation['start_time'],
            'total_events': len(events),
            'event_breakdown': self._analyze_event_breakdown(events),
            'timeline': self._create_timeline(events),
            'correlation_chains': self._find_correlation_chains(events),
            'security_incidents': self._analyze_security_incidents(events),
            'performance_issues': self._analyze_performance_issues(events),
            'error_patterns': self._analyze_error_patterns_for_investigation(events),
            'recommendations': self._generate_investigation_recommendations(events)
        }
        
        return report
    
    def _analyze_event_breakdown(self, events: List[ForensicEvent]) -> Dict[str, Any]:
        """Analyze breakdown of events by various dimensions."""
        
        breakdown = {
            'by_level': defaultdict(int),
            'by_category': defaultdict(int),
            'by_component': defaultdict(int),
            'by_success': {'success': 0, 'failure': 0},
            'by_hour': defaultdict(int)
        }
        
        for event in events:
            breakdown['by_level'][event.level.value] += 1
            breakdown['by_category'][event.category.value] += 1
            breakdown['by_component'][event.component] += 1
            breakdown['by_success']['success' if event.success else 'failure'] += 1
            
            # Hour breakdown
            hour = datetime.fromtimestamp(event.timestamp).hour
            breakdown['by_hour'][hour] += 1
        
        return {k: dict(v) for k, v in breakdown.items()}
    
    def _create_timeline(self, events: List[ForensicEvent]) -> List[Dict[str, Any]]:
        """Create timeline of significant events."""
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        timeline = []
        for event in sorted_events[:100]:  # Limit to first 100 events
            timeline.append({
                'timestamp': event.timestamp,
                'iso_timestamp': datetime.fromtimestamp(event.timestamp).isoformat(),
                'event_id': event.event_id,
                'correlation_id': event.correlation_id,
                'level': event.level.value,
                'category': event.category.value,
                'component': event.component,
                'operation': event.operation,
                'message': event.message,
                'success': event.success,
                'duration_ms': event.duration_ms
            })
        
        return timeline
    
    def _find_correlation_chains(self, events: List[ForensicEvent]) -> Dict[str, List[str]]:
        """Find correlation chains in events."""
        
        chains = defaultdict(list)
        
        for event in events:
            if event.correlation_id != "unknown":
                chains[event.correlation_id].append(event.event_id)
        
        return {k: v for k, v in chains.items() if len(v) > 1}
    
    def _analyze_security_incidents(self, events: List[ForensicEvent]) -> List[Dict[str, Any]]:
        """Analyze security incidents from events."""
        
        security_events = [e for e in events if e.category == EventCategory.SECURITY]
        
        incidents = []
        for event in security_events:
            incidents.append({
                'event_id': event.event_id,
                'timestamp': event.timestamp,
                'security_context': event.security_context,
                'severity': event.security_context.get('severity', 'unknown'),
                'indicators': event.custom_attributes.get('indicators', [])
            })
        
        return incidents
    
    def _analyze_performance_issues(self, events: List[ForensicEvent]) -> List[Dict[str, Any]]:
        """Analyze performance issues from events."""
        
        performance_events = [e for e in events if e.category == EventCategory.PERFORMANCE]
        
        issues = []
        for event in performance_events:
            if event.custom_attributes.get('is_anomaly'):
                issues.append({
                    'event_id': event.event_id,
                    'timestamp': event.timestamp,
                    'operation': event.operation,
                    'duration_ms': event.duration_ms,
                    'performance_metrics': event.performance_metrics
                })
        
        return issues
    
    def _analyze_error_patterns_for_investigation(self, events: List[ForensicEvent]) -> Dict[str, Any]:
        """Analyze error patterns for investigation."""
        
        error_events = [e for e in events if not e.success]
        
        patterns = defaultdict(int)
        for event in error_events:
            pattern = f"{event.component}:{event.operation}:{event.error_code}"
            patterns[pattern] += 1
        
        return dict(patterns)
    
    def _generate_investigation_recommendations(self, events: List[ForensicEvent]) -> List[str]:
        """Generate recommendations based on investigation findings."""
        
        recommendations = []
        
        # Security recommendations
        security_events = [e for e in events if e.category == EventCategory.SECURITY]
        if security_events:
            recommendations.append("Review security events for potential threats")
            recommendations.append("Implement additional monitoring for suspicious activities")
        
        # Performance recommendations
        perf_issues = [e for e in events if e.custom_attributes.get('is_anomaly')]
        if perf_issues:
            recommendations.append("Investigate performance anomalies")
            recommendations.append("Consider scaling resources or optimization")
        
        # Error recommendations
        error_events = [e for e in events if not e.success]
        if len(error_events) > len(events) * 0.1:  # More than 10% errors
            recommendations.append("High error rate detected - investigate root causes")
            recommendations.append("Implement additional error handling and recovery")
        
        return recommendations
    
    def get_forensic_stats(self) -> Dict[str, Any]:
        """Get comprehensive forensic statistics."""
        
        with self._lock:
            return {
                'total_events': self.stats['total_events'],
                'security_events': self.stats['security_events'],
                'performance_events': self.stats['performance_events'],
                'error_events': self.stats['error_events'],
                'correlation_chains': len(self._correlation_contexts),
                'anomalies_detected': self.stats['anomalies_detected'],
                'investigations_active': self.stats['investigations_active'],
                'error_patterns': len(self._error_patterns),
                'performance_baselines': len(self._performance_baselines),
                'recent_events_in_memory': len(self._events),
                'security_events_in_memory': len(self._security_events),
                'log_files': [
                    {
                        'name': handler_name,
                        'size_bytes': Path(handler.baseFilename).stat().st_size if Path(handler.baseFilename).exists() else 0
                    }
                    for handler_name, handler in self.handlers.items()
                ]
            }


# Global forensic logger instance
_forensic_logger: Optional[ForensicLogger] = None


def get_forensic_logger() -> ForensicLogger:
    """Get or create forensic logger instance."""
    global _forensic_logger
    if _forensic_logger is None:
        _forensic_logger = ForensicLogger()
    return _forensic_logger


# Convenience functions for common forensic operations
def log_request(operation: str, correlation_id: str, 
               request_data: Dict[str, Any]) -> None:
    """Log request for forensic tracking."""
    logger = get_forensic_logger()
    logger.log_forensic_event(
        level=LogLevel.INFO,
        category=EventCategory.REQUEST,
        component="api",
        operation=operation,
        message=f"API request: {operation}",
        correlation_id=correlation_id,
        request_context=request_data
    )


def log_response(operation: str, correlation_id: str,
                response_data: Dict[str, Any], duration_ms: float,
                success: bool = True) -> None:
    """Log response for forensic tracking."""
    logger = get_forensic_logger()
    logger.log_forensic_event(
        level=LogLevel.INFO,
        category=EventCategory.RESPONSE,
        component="api",
        operation=operation,
        message=f"API response: {operation}",
        correlation_id=correlation_id,
        duration_ms=duration_ms,
        success=success,
        response_context=response_data
    )


def log_business_event(operation: str, message: str,
                      correlation_id: Optional[str] = None,
                      custom_attributes: Optional[Dict[str, Any]] = None) -> None:
    """Log business event for forensic tracking."""
    logger = get_forensic_logger()
    logger.log_forensic_event(
        level=LogLevel.INFO,
        category=EventCategory.BUSINESS,
        component="business",
        operation=operation,
        message=message,
        correlation_id=correlation_id,
        custom_attributes=custom_attributes or {}
    )


if __name__ == "__main__":
    # Test forensic logging system
    print("🔍 TESTANDO SISTEMA DE LOGGING FORENSE")
    print("=" * 60)
    
    # Initialize forensic logger
    forensic = ForensicLogger()
    
    # Test correlation tracking
    with forensic.correlation_span("test_operation", user_id="test_user") as ctx:
        # Log some events
        forensic.log_forensic_event(
            level=LogLevel.INFO,
            category=EventCategory.BUSINESS,
            component="test",
            operation="test_op",
            message="Test message",
            correlation_id=ctx.correlation_id
        )
        
        # Log performance event
        forensic.log_performance_event(
            operation="test_operation",
            duration_ms=150.5,
            correlation_id=ctx.correlation_id
        )
        
        # Log security event
        forensic.log_security_event(
            event_type=SecurityEventType.AUTHENTICATION_ATTEMPT,
            severity="low",
            source_ip="127.0.0.1",
            user_agent="test-agent",
            resource="/api/test",
            action="login",
            outcome="success",
            correlation_id=ctx.correlation_id
        )
    
    # Start investigation
    investigation_id = forensic.start_investigation(
        "test_investigation",
        {"correlation_id": ctx.correlation_id}
    )
    
    # Generate report
    report = forensic.generate_investigation_report(investigation_id)
    
    # Print results
    print(f"\n📊 Forensic Statistics:")
    stats = forensic.get_forensic_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print(f"\n📋 Investigation Report:")
    print(f"   Events: {report['total_events']}")
    print(f"   Duration: {report['duration_seconds']:.2f}s")
    print(f"   Security incidents: {len(report['security_incidents'])}")
    print(f"   Performance issues: {len(report['performance_issues'])}")
    
    print(f"\n✅ Forensic logging system test completed!")