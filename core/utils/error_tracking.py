"""
Error tracking and monitoring system
Provides comprehensive error tracking, alerting, and diagnostic capabilities
"""

import os
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from threading import Lock
import traceback
import sys

from .production_logger import get_logger

@dataclass
class ErrorContext:
    """Error context information"""
    timestamp: str
    error_type: str
    error_message: str
    function_name: str
    file_name: str
    line_number: int
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    stack_trace: Optional[List[str]] = None
    additional_data: Optional[Dict[str, Any]] = None

@dataclass
class ErrorPattern:
    """Error pattern for detection and alerting"""
    error_hash: str
    first_occurrence: datetime
    last_occurrence: datetime
    occurrence_count: int
    error_type: str
    error_message: str
    function_name: str
    file_name: str
    resolved: bool = False
    alert_sent: bool = False

class ErrorTracker:
    """Comprehensive error tracking and monitoring system"""
    
    def __init__(self, max_history_size: int = 10000, alert_threshold: int = 5):
        self.logger = get_logger()
        self.max_history_size = max_history_size
        self.alert_threshold = alert_threshold
        
        # Error storage
        self.error_history: deque = deque(maxlen=max_history_size)
        self.error_patterns: Dict[str, ErrorPattern] = {}
        self.error_counts: Dict[str, int] = defaultdict(int)
        
        # Threading protection
        self._lock = Lock()
        
        # Alert callbacks
        self.alert_callbacks: List[Callable] = []
        
        # Suppression rules
        self.suppression_rules: List[Dict[str, Any]] = []
        
        # Configuration
        self.config = {
            'enable_tracking': True,
            'enable_alerts': True,
            'enable_auto_resolution': True,
            'resolution_threshold_hours': 24,
            'max_alert_frequency_minutes': 60
        }
    
    def track_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> str:
        """Track an error occurrence and return error hash"""
        if not self.config['enable_tracking']:
            return ""
        
        # Extract error information
        error_context = self._extract_error_context(error, context)
        error_hash = self._generate_error_hash(error_context)
        
        with self._lock:
            # Add to history
            self.error_history.append(error_context)
            
            # Update error patterns
            if error_hash in self.error_patterns:
                pattern = self.error_patterns[error_hash]
                pattern.occurrence_count += 1
                pattern.last_occurrence = datetime.utcnow()
                pattern.resolved = False
            else:
                pattern = ErrorPattern(
                    error_hash=error_hash,
                    first_occurrence=datetime.utcnow(),
                    last_occurrence=datetime.utcnow(),
                    occurrence_count=1,
                    error_type=error_context.error_type,
                    error_message=error_context.error_message,
                    function_name=error_context.function_name,
                    file_name=error_context.file_name
                )
                self.error_patterns[error_hash] = pattern
            
            # Update counts
            self.error_counts[error_hash] += 1
            
            # Check for alerts
            if self.config['enable_alerts']:
                self._check_alert_conditions(pattern)
        
        # Log the error
        self.logger.log_error(error, {
            'error_hash': error_hash,
            'occurrence_count': pattern.occurrence_count,
            'pattern_first_seen': pattern.first_occurrence.isoformat()
        })
        
        return error_hash
    
    def _extract_error_context(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> ErrorContext:
        """Extract comprehensive error context"""
        tb = traceback.extract_tb(error.__traceback__)
        
        # Get the last frame (where error occurred)
        if tb:
            last_frame = tb[-1]
            function_name = last_frame.name
            file_name = os.path.basename(last_frame.filename)
            line_number = last_frame.lineno
        else:
            function_name = "unknown"
            file_name = "unknown"
            line_number = 0
        
        return ErrorContext(
            timestamp=datetime.utcnow().isoformat(),
            error_type=type(error).__name__,
            error_message=str(error),
            function_name=function_name,
            file_name=file_name,
            line_number=line_number,
            stack_trace=traceback.format_exception(type(error), error, error.__traceback__),
            additional_data=context or {}
        )
    
    def _generate_error_hash(self, error_context: ErrorContext) -> str:
        """Generate unique hash for error pattern"""
        hash_input = f"{error_context.error_type}:{error_context.function_name}:{error_context.file_name}:{error_context.line_number}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]
    
    def _check_alert_conditions(self, pattern: ErrorPattern):
        """Check if alert conditions are met"""
        now = datetime.utcnow()
        
        # Check if should suppress
        if self._should_suppress_alert(pattern):
            return
        
        # Check frequency threshold
        if pattern.occurrence_count >= self.alert_threshold:
            # Check if enough time has passed since last alert
            if not pattern.alert_sent or self._should_send_alert(pattern):
                self._send_alert(pattern)
                pattern.alert_sent = True
    
    def _should_suppress_alert(self, pattern: ErrorPattern) -> bool:
        """Check if alert should be suppressed based on rules"""
        for rule in self.suppression_rules:
            if self._matches_suppression_rule(pattern, rule):
                return True
        return False
    
    def _matches_suppression_rule(self, pattern: ErrorPattern, rule: Dict[str, Any]) -> bool:
        """Check if pattern matches suppression rule"""
        for key, value in rule.items():
            if key == 'error_type' and pattern.error_type != value:
                return False
            elif key == 'function_name' and pattern.function_name != value:
                return False
            elif key == 'file_name' and pattern.file_name != value:
                return False
        return True
    
    def _should_send_alert(self, pattern: ErrorPattern) -> bool:
        """Check if enough time has passed to send another alert"""
        if not pattern.alert_sent:
            return True
        
        time_since_first = datetime.utcnow() - pattern.first_occurrence
        min_frequency = timedelta(minutes=self.config['max_alert_frequency_minutes'])
        
        return time_since_first >= min_frequency
    
    def _send_alert(self, pattern: ErrorPattern):
        """Send alert for error pattern"""
        alert_data = {
            'alert_type': 'error_pattern',
            'error_hash': pattern.error_hash,
            'error_type': pattern.error_type,
            'error_message': pattern.error_message,
            'occurrence_count': pattern.occurrence_count,
            'first_occurrence': pattern.first_occurrence.isoformat(),
            'last_occurrence': pattern.last_occurrence.isoformat(),
            'function_name': pattern.function_name,
            'file_name': pattern.file_name
        }
        
        # Send to registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                self.logger.logger.error(f"Failed to send alert via callback: {e}")
        
        # Log alert
        self.logger.logger.warning("Error pattern alert triggered", extra={
            'extra_fields': alert_data
        })
    
    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add alert callback function"""
        self.alert_callbacks.append(callback)
    
    def add_suppression_rule(self, rule: Dict[str, Any]):
        """Add error suppression rule"""
        self.suppression_rules.append(rule)
    
    def resolve_error_pattern(self, error_hash: str):
        """Mark error pattern as resolved"""
        with self._lock:
            if error_hash in self.error_patterns:
                self.error_patterns[error_hash].resolved = True
                self.logger.logger.info(f"Error pattern resolved: {error_hash}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics and patterns"""
        with self._lock:
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            one_day_ago = now - timedelta(days=1)
            
            # Count recent errors
            recent_errors_1h = sum(1 for error in self.error_history 
                                 if datetime.fromisoformat(error.timestamp.replace('Z', '')) >= one_hour_ago)
            recent_errors_24h = sum(1 for error in self.error_history 
                                  if datetime.fromisoformat(error.timestamp.replace('Z', '')) >= one_day_ago)
            
            # Get top error patterns
            top_patterns = sorted(
                self.error_patterns.values(),
                key=lambda p: p.occurrence_count,
                reverse=True
            )[:10]
            
            # Get unresolved patterns
            unresolved_patterns = [p for p in self.error_patterns.values() if not p.resolved]
            
            return {
                'total_errors_tracked': len(self.error_history),
                'unique_error_patterns': len(self.error_patterns),
                'recent_errors_1h': recent_errors_1h,
                'recent_errors_24h': recent_errors_24h,
                'unresolved_patterns': len(unresolved_patterns),
                'top_error_patterns': [
                    {
                        'error_hash': p.error_hash,
                        'error_type': p.error_type,
                        'occurrence_count': p.occurrence_count,
                        'last_occurrence': p.last_occurrence.isoformat(),
                        'resolved': p.resolved
                    }
                    for p in top_patterns
                ],
                'error_rate_1h': recent_errors_1h / 3600 if recent_errors_1h > 0 else 0,
                'error_rate_24h': recent_errors_24h / 86400 if recent_errors_24h > 0 else 0
            }
    
    def get_error_pattern_details(self, error_hash: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about specific error pattern"""
        with self._lock:
            pattern = self.error_patterns.get(error_hash)
            if not pattern:
                return None
            
            # Get related error occurrences
            related_errors = [
                error for error in self.error_history
                if self._generate_error_hash(error) == error_hash
            ]
            
            return {
                'pattern': asdict(pattern),
                'recent_occurrences': [asdict(error) for error in related_errors[-10:]],
                'occurrence_timeline': self._get_occurrence_timeline(related_errors)
            }
    
    def _get_occurrence_timeline(self, errors: List[ErrorContext]) -> List[Dict[str, Any]]:
        """Generate timeline of error occurrences"""
        timeline = defaultdict(int)
        
        for error in errors:
            timestamp = datetime.fromisoformat(error.timestamp.replace('Z', ''))
            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            timeline[hour_key] += 1
        
        return [
            {'timestamp': timestamp.isoformat(), 'count': count}
            for timestamp, count in sorted(timeline.items())
        ]
    
    def auto_resolve_old_patterns(self):
        """Automatically resolve old error patterns"""
        if not self.config['enable_auto_resolution']:
            return
        
        threshold = datetime.utcnow() - timedelta(hours=self.config['resolution_threshold_hours'])
        
        with self._lock:
            for pattern in self.error_patterns.values():
                if not pattern.resolved and pattern.last_occurrence < threshold:
                    pattern.resolved = True
                    self.logger.logger.info(f"Auto-resolved old error pattern: {pattern.error_hash}")
    
    def export_error_data(self, file_path: str):
        """Export error data to JSON file"""
        with self._lock:
            data = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'error_patterns': [asdict(pattern) for pattern in self.error_patterns.values()],
                'error_history': [asdict(error) for error in list(self.error_history)],
                'statistics': self.get_error_statistics()
            }
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        self.logger.logger.info(f"Error data exported to: {file_path}")

# Global error tracker instance
_global_error_tracker = None

def get_error_tracker() -> ErrorTracker:
    """Get the global error tracker instance"""
    global _global_error_tracker
    if _global_error_tracker is None:
        _global_error_tracker = ErrorTracker()
    return _global_error_tracker

def track_error(error: Exception, context: Optional[Dict[str, Any]] = None) -> str:
    """Track an error using the global tracker"""
    return get_error_tracker().track_error(error, context)

def error_tracking_decorator(context_func: Optional[Callable] = None):
    """Decorator for automatic error tracking"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                context = {}
                if context_func:
                    try:
                        context = context_func(*args, **kwargs)
                    except:
                        pass
                
                context.update({
                    'function_args': str(args)[:200],
                    'function_kwargs': str(kwargs)[:200]
                })
                
                track_error(e, context)
                raise
        
        return wrapper
    return decorator

# Error tracking middleware for Flask
def setup_flask_error_tracking(app):
    """Setup error tracking for Flask application"""
    error_tracker = get_error_tracker()
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        # Track the error
        context = {
            'request_method': request.method if 'request' in globals() else 'unknown',
            'request_url': request.url if 'request' in globals() else 'unknown',
            'user_agent': request.headers.get('User-Agent', 'unknown') if 'request' in globals() else 'unknown'
        }
        
        error_tracker.track_error(e, context)
        
        # Re-raise the exception
        raise e
    
    return error_tracker