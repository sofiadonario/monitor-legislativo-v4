"""Structured logging system for production observability."""

import logging
import json
import sys
import traceback
from typing import Dict, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue
import os
from pathlib import Path


class LogLevel(Enum):
    """Log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogEvent:
    """Structured log event."""
    timestamp: str
    level: str
    message: str
    logger_name: str
    module: str
    function: str
    line_number: int
    thread_id: str
    process_id: int
    user_id: Optional[int] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    component: Optional[str] = None
    operation: Optional[str] = None
    duration_ms: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}


class StructuredLogFormatter(logging.Formatter):
    """JSON formatter for structured logs."""
    
    def __init__(self, include_timestamp: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Extract structured data from record
        log_event = LogEvent(
            timestamp=datetime.fromtimestamp(record.created).isoformat() if self.include_timestamp else "",
            level=record.levelname,
            message=record.getMessage(),
            logger_name=record.name,
            module=record.module,
            function=record.funcName,
            line_number=record.lineno,
            thread_id=str(threading.current_thread().ident),
            process_id=os.getpid(),
            user_id=getattr(record, 'user_id', None),
            request_id=getattr(record, 'request_id', None),
            session_id=getattr(record, 'session_id', None),
            correlation_id=getattr(record, 'correlation_id', None),
            component=getattr(record, 'component', None),
            operation=getattr(record, 'operation', None),
            duration_ms=getattr(record, 'duration_ms', None),
            error_type=getattr(record, 'error_type', None),
            error_message=getattr(record, 'error_message', None),
            metadata=getattr(record, 'metadata', None)
        )
        
        # Add exception info if present
        if record.exc_info:
            log_event.stack_trace = self.formatException(record.exc_info)
            if record.exc_info[1]:
                log_event.error_type = type(record.exc_info[1]).__name__
                log_event.error_message = str(record.exc_info[1])
        
        return json.dumps(log_event.to_dict(), ensure_ascii=False, separators=(',', ':'))


class ContextualLogAdapter(logging.LoggerAdapter):
    """Log adapter that includes contextual information."""
    
    def __init__(self, logger: logging.Logger, context: Dict[str, Any] = None):
        super().__init__(logger, context or {})
        self._context = context or {}
    
    def process(self, msg, kwargs):
        """Add context to log record."""
        # Merge context with any extra data
        extra = kwargs.get('extra', {})
        extra.update(self._context)
        kwargs['extra'] = extra
        return msg, kwargs
    
    def set_context(self, **context):
        """Update context."""
        self._context.update(context)
    
    def clear_context(self):
        """Clear context."""
        self._context.clear()
    
    def with_context(self, **context) -> 'ContextualLogAdapter':
        """Create new adapter with additional context."""
        new_context = self._context.copy()
        new_context.update(context)
        return ContextualLogAdapter(self.logger, new_context)


class AsyncLogHandler(logging.Handler):
    """Asynchronous log handler for high-performance logging."""
    
    def __init__(self, target_handler: logging.Handler, queue_size: int = 10000):
        super().__init__()
        self.target_handler = target_handler
        self.log_queue = queue.Queue(maxsize=queue_size)
        self.worker_thread = None
        self.running = False
    
    def start(self):
        """Start the async handler."""
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
    
    def stop(self):
        """Stop the async handler."""
        if not self.running:
            return
        
        self.running = False
        self.log_queue.put(None)  # Sentinel to stop worker
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
    
    def emit(self, record: logging.LogRecord):
        """Emit log record asynchronously."""
        if not self.running:
            self.target_handler.emit(record)
            return
        
        try:
            self.log_queue.put_nowait(record)
        except queue.Full:
            # Drop log if queue is full (prevents blocking)
            pass
    
    def _worker(self):
        """Worker thread for processing log records."""
        while self.running:
            try:
                record = self.log_queue.get(timeout=1)
                if record is None:  # Sentinel to stop
                    break
                
                self.target_handler.emit(record)
                self.log_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                # Log error to stderr to avoid infinite recursion
                print(f"Error in async log handler: {e}", file=sys.stderr)


class StructuredLogger:
    """Enhanced structured logger with contextual information."""
    
    def __init__(self, name: str, level: Union[str, int] = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Set up structured logging if not already configured
        if not self.logger.handlers:
            self._setup_handlers()
        
        self.adapter = ContextualLogAdapter(self.logger)
    
    def _setup_handlers(self):
        """Set up log handlers."""
        # Console handler with structured format
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(StructuredLogFormatter())
        
        # File handler for persistent logs
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(
            log_dir / f"{self.logger.name}.log",
            encoding='utf-8'
        )
        file_handler.setFormatter(StructuredLogFormatter())
        
        # Error file handler
        error_handler = logging.FileHandler(
            log_dir / f"{self.logger.name}_errors.log",
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(StructuredLogFormatter())
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)
    
    def with_context(self, **context) -> ContextualLogAdapter:
        """Create logger with context."""
        return self.adapter.with_context(**context)
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self.adapter.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self.adapter.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.adapter.warning(message, extra=kwargs)
    
    def error(self, message: str, error: Exception = None, **kwargs):
        """Log error message."""
        if error:
            kwargs.update({
                'error_type': type(error).__name__,
                'error_message': str(error)
            })
        self.adapter.error(message, exc_info=error is not None, extra=kwargs)
    
    def critical(self, message: str, error: Exception = None, **kwargs):
        """Log critical message."""
        if error:
            kwargs.update({
                'error_type': type(error).__name__,
                'error_message': str(error)
            })
        self.adapter.critical(message, exc_info=error is not None, extra=kwargs)
    
    def log_operation(self, operation: str, component: str = None):
        """Context manager for logging operations."""
        return OperationLogger(self, operation, component)
    
    def log_request(self, request_id: str, method: str, endpoint: str, user_id: int = None):
        """Context manager for logging HTTP requests."""
        return RequestLogger(self, request_id, method, endpoint, user_id)


class OperationLogger:
    """Context manager for logging operations with timing."""
    
    def __init__(self, logger: StructuredLogger, operation: str, component: str = None):
        self.logger = logger
        self.operation = operation
        self.component = component
        self.start_time = None
        self.context_logger = None
    
    def __enter__(self) -> ContextualLogAdapter:
        """Start operation logging."""
        self.start_time = datetime.now()
        
        context = {
            'operation': self.operation,
            'component': self.component
        }
        
        self.context_logger = self.logger.with_context(**{k: v for k, v in context.items() if v})
        
        self.context_logger.info(f"Starting operation: {self.operation}")
        return self.context_logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End operation logging."""
        if self.start_time:
            duration_ms = (datetime.now() - self.start_time).total_seconds() * 1000
            
            if exc_type:
                self.context_logger.error(
                    f"Operation failed: {self.operation}",
                    error=exc_val,
                    duration_ms=duration_ms
                )
            else:
                self.context_logger.info(
                    f"Operation completed: {self.operation}",
                    duration_ms=duration_ms
                )


class RequestLogger:
    """Context manager for logging HTTP requests."""
    
    def __init__(self, logger: StructuredLogger, request_id: str, method: str, 
                 endpoint: str, user_id: int = None):
        self.logger = logger
        self.request_id = request_id
        self.method = method
        self.endpoint = endpoint
        self.user_id = user_id
        self.start_time = None
        self.context_logger = None
    
    def __enter__(self) -> ContextualLogAdapter:
        """Start request logging."""
        self.start_time = datetime.now()
        
        context = {
            'request_id': self.request_id,
            'user_id': self.user_id,
            'component': 'web'
        }
        
        self.context_logger = self.logger.with_context(**{k: v for k, v in context.items() if v})
        
        self.context_logger.info(
            f"Request started: {self.method} {self.endpoint}",
            operation='http_request'
        )
        return self.context_logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End request logging."""
        if self.start_time:
            duration_ms = (datetime.now() - self.start_time).total_seconds() * 1000
            
            if exc_type:
                self.context_logger.error(
                    f"Request failed: {self.method} {self.endpoint}",
                    error=exc_val,
                    duration_ms=duration_ms,
                    operation='http_request'
                )
            else:
                self.context_logger.info(
                    f"Request completed: {self.method} {self.endpoint}",
                    duration_ms=duration_ms,
                    operation='http_request'
                )


class LogAggregator:
    """Log aggregation and analysis."""
    
    def __init__(self, log_file_path: str):
        self.log_file_path = Path(log_file_path)
    
    def analyze_logs(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze logs for the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        stats = {
            'total_logs': 0,
            'by_level': {},
            'by_component': {},
            'by_operation': {},
            'errors': [],
            'slowest_operations': [],
            'request_stats': {
                'total': 0,
                'avg_duration': 0,
                'error_rate': 0
            }
        }
        
        if not self.log_file_path.exists():
            return stats
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        log_time = datetime.fromisoformat(log_entry.get('timestamp', ''))
                        
                        if log_time < cutoff_time:
                            continue
                        
                        stats['total_logs'] += 1
                        
                        # Level stats
                        level = log_entry.get('level', 'UNKNOWN')
                        stats['by_level'][level] = stats['by_level'].get(level, 0) + 1
                        
                        # Component stats
                        component = log_entry.get('component', 'unknown')
                        stats['by_component'][component] = stats['by_component'].get(component, 0) + 1
                        
                        # Operation stats
                        operation = log_entry.get('operation')
                        if operation:
                            stats['by_operation'][operation] = stats['by_operation'].get(operation, 0) + 1
                        
                        # Error collection
                        if level in ['ERROR', 'CRITICAL']:
                            stats['errors'].append({
                                'timestamp': log_entry.get('timestamp'),
                                'message': log_entry.get('message'),
                                'error_type': log_entry.get('error_type'),
                                'component': component
                            })
                        
                        # Slow operations
                        duration = log_entry.get('duration_ms')
                        if duration and duration > 1000:  # > 1 second
                            stats['slowest_operations'].append({
                                'operation': operation,
                                'duration_ms': duration,
                                'timestamp': log_entry.get('timestamp')
                            })
                        
                        # Request stats
                        if operation == 'http_request':
                            stats['request_stats']['total'] += 1
                            if duration:
                                current_avg = stats['request_stats']['avg_duration']
                                count = stats['request_stats']['total']
                                stats['request_stats']['avg_duration'] = (
                                    (current_avg * (count - 1) + duration) / count
                                )
                            
                            if level in ['ERROR', 'CRITICAL']:
                                error_count = stats['request_stats'].get('errors', 0) + 1
                                stats['request_stats']['errors'] = error_count
                                stats['request_stats']['error_rate'] = (
                                    error_count / stats['request_stats']['total']
                                )
                    
                    except (json.JSONDecodeError, ValueError, KeyError):
                        continue
        
        except Exception as e:
            print(f"Error analyzing logs: {e}")
        
        # Sort slowest operations
        stats['slowest_operations'].sort(key=lambda x: x['duration_ms'], reverse=True)
        stats['slowest_operations'] = stats['slowest_operations'][:10]
        
        # Sort errors by timestamp
        stats['errors'].sort(key=lambda x: x['timestamp'], reverse=True)
        stats['errors'] = stats['errors'][:50]
        
        return stats


# Global logger instances
def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)


# Pre-configured loggers for common components
api_logger = get_logger('api')
auth_logger = get_logger('auth')
monitoring_logger = get_logger('monitoring')
search_logger = get_logger('search')
db_logger = get_logger('database')
cache_logger = get_logger('cache')


def setup_logging(level: Union[str, int] = logging.INFO, 
                 enable_async: bool = True,
                 log_dir: str = "data/logs"):
    """Setup global logging configuration."""
    # Create log directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Setup structured handlers
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(StructuredLogFormatter())
    
    file_handler = logging.FileHandler(
        Path(log_dir) / "application.log",
        encoding='utf-8'
    )
    file_handler.setFormatter(StructuredLogFormatter())
    
    if enable_async:
        # Wrap handlers in async handlers
        async_console = AsyncLogHandler(console_handler)
        async_file = AsyncLogHandler(file_handler)
        
        async_console.start()
        async_file.start()
        
        root_logger.addHandler(async_console)
        root_logger.addHandler(async_file)
    else:
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
    
    # Setup specific loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logging.info("Structured logging initialized")


# Context decorators
def log_function_call(logger: StructuredLogger = None, component: str = None):
    """Decorator to log function calls."""
    def decorator(func):
        nonlocal logger
        if logger is None:
            logger = get_logger(func.__module__)
        
        def wrapper(*args, **kwargs):
            operation = f"{func.__name__}"
            with logger.log_operation(operation, component) as op_logger:
                try:
                    result = func(*args, **kwargs)
                    op_logger.debug(f"Function {func.__name__} completed successfully")
                    return result
                except Exception as e:
                    op_logger.error(f"Function {func.__name__} failed", error=e)
                    raise
        
        return wrapper
    return decorator