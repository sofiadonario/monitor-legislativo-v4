"""
Production-grade logging and error tracking system
Provides structured logging, error tracking, and observability features
"""

import os
import sys
import json
import logging
import logging.handlers
from datetime import datetime
from typing import Dict, Any, Optional, Union
import traceback
from functools import wraps
import threading
from contextlib import contextmanager

try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    from sentry_sdk.integrations.redis import RedisIntegration
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def __init__(self, include_extra_fields=True):
        super().__init__()
        self.include_extra_fields = include_extra_fields
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': threading.current_thread().name,
            'process': os.getpid()
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields if available
        if self.include_extra_fields and hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        # Add correlation ID if available
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
        
        # Add user context if available
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        
        return json.dumps(log_entry, ensure_ascii=False)

class ContextFilter(logging.Filter):
    """Filter to add contextual information to log records"""
    
    def __init__(self, app_name='monitor-legislativo', version='1.0.0'):
        super().__init__()
        self.app_name = app_name
        self.version = version
    
    def filter(self, record):
        record.app_name = self.app_name
        record.app_version = self.version
        record.hostname = os.getenv('HOSTNAME', 'unknown')
        record.environment = os.getenv('FLASK_ENV', 'production')
        
        # Add correlation ID from thread local storage
        correlation_id = getattr(_context, 'correlation_id', None)
        if correlation_id:
            record.correlation_id = correlation_id
        
        # Add user context from thread local storage
        user_id = getattr(_context, 'user_id', None)
        if user_id:
            record.user_id = user_id
        
        # Add request context from thread local storage
        request_id = getattr(_context, 'request_id', None)
        if request_id:
            record.request_id = request_id
        
        return True

# Thread local storage for context
_context = threading.local()

class ProductionLogger:
    """Production-grade logging system with error tracking"""
    
    def __init__(self, app_name='monitor-legislativo'):
        self.app_name = app_name
        self.logger = logging.getLogger(app_name)
        self.is_configured = False
        
        # Sentry configuration
        self.sentry_dsn = os.getenv('SENTRY_DSN')
        self.sentry_environment = os.getenv('SENTRY_ENVIRONMENT', 'production')
        
    def configure(self, 
                 log_level: str = 'INFO',
                 enable_file_logging: bool = True,
                 enable_console_logging: bool = True,
                 enable_sentry: bool = True,
                 log_dir: str = 'data/logs',
                 max_file_size: int = 100 * 1024 * 1024,  # 100MB
                 backup_count: int = 10):
        """Configure the logging system"""
        
        if self.is_configured:
            return
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set log level
        log_level_enum = getattr(logging, log_level.upper(), logging.INFO)
        self.logger.setLevel(log_level_enum)
        
        # Add context filter
        context_filter = ContextFilter(self.app_name)
        
        # Configure console logging
        if enable_console_logging:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(JSONFormatter())
            console_handler.addFilter(context_filter)
            self.logger.addHandler(console_handler)
        
        # Configure file logging
        if enable_file_logging:
            os.makedirs(log_dir, exist_ok=True)
            
            # Main application log
            app_log_file = os.path.join(log_dir, f'{self.app_name}.log')
            app_handler = logging.handlers.RotatingFileHandler(
                app_log_file,
                maxBytes=max_file_size,
                backupCount=backup_count
            )
            app_handler.setFormatter(JSONFormatter())
            app_handler.addFilter(context_filter)
            self.logger.addHandler(app_handler)
            
            # Error-only log
            error_log_file = os.path.join(log_dir, f'{self.app_name}-errors.log')
            error_handler = logging.handlers.RotatingFileHandler(
                error_log_file,
                maxBytes=max_file_size,
                backupCount=backup_count
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(JSONFormatter())
            error_handler.addFilter(context_filter)
            self.logger.addHandler(error_handler)
        
        # Configure Sentry
        if enable_sentry and SENTRY_AVAILABLE and self.sentry_dsn:
            self._configure_sentry()
        
        # Configure root logger to prevent duplicate logs
        logging.getLogger().setLevel(logging.WARNING)
        
        self.is_configured = True
        self.logger.info("Production logging system configured", extra={
            'extra_fields': {
                'log_level': log_level,
                'file_logging': enable_file_logging,
                'console_logging': enable_console_logging,
                'sentry_enabled': enable_sentry and SENTRY_AVAILABLE and bool(self.sentry_dsn)
            }
        })
    
    def _configure_sentry(self):
        """Configure Sentry error tracking"""
        try:
            sentry_sdk.init(
                dsn=self.sentry_dsn,
                environment=self.sentry_environment,
                integrations=[
                    FlaskIntegration(transaction_style='endpoint'),
                    SqlalchemyIntegration(),
                    RedisIntegration(),
                ],
                traces_sample_rate=0.1,  # 10% sampling for performance monitoring
                profiles_sample_rate=0.1,  # 10% sampling for profiling
                attach_stacktrace=True,
                send_default_pii=False,  # Don't send PII for privacy
                before_send=self._sentry_before_send,
                before_send_transaction=self._sentry_before_send_transaction,
            )
            self.logger.info("Sentry error tracking configured")
        except Exception as e:
            self.logger.error(f"Failed to configure Sentry: {e}")
    
    def _sentry_before_send(self, event, hint):
        """Filter Sentry events before sending"""
        # Don't send health check errors
        if 'health' in str(event.get('request', {}).get('url', '')):
            return None
        
        # Don't send certain known errors
        exc_info = hint.get('exc_info')
        if exc_info:
            exc_type, exc_value, exc_traceback = exc_info
            if exc_type.__name__ in ['ConnectionError', 'TimeoutError']:
                # Only send if error rate is high
                return event if self._should_send_connection_error() else None
        
        return event
    
    def _sentry_before_send_transaction(self, event, hint):
        """Filter Sentry transactions before sending"""
        # Don't send health check transactions
        if event.get('transaction') == '/health':
            return None
        return event
    
    def _should_send_connection_error(self) -> bool:
        """Determine if connection errors should be sent to Sentry"""
        # Simple rate limiting logic - can be enhanced
        return True
    
    @contextmanager
    def correlation_context(self, correlation_id: str):
        """Context manager for setting correlation ID"""
        old_correlation_id = getattr(_context, 'correlation_id', None)
        _context.correlation_id = correlation_id
        try:
            yield
        finally:
            if old_correlation_id:
                _context.correlation_id = old_correlation_id
            else:
                delattr(_context, 'correlation_id')
    
    @contextmanager
    def user_context(self, user_id: Union[str, int]):
        """Context manager for setting user context"""
        old_user_id = getattr(_context, 'user_id', None)
        _context.user_id = user_id
        try:
            yield
        finally:
            if old_user_id:
                _context.user_id = old_user_id
            else:
                delattr(_context, 'user_id')
    
    @contextmanager
    def request_context(self, request_id: str):
        """Context manager for setting request context"""
        old_request_id = getattr(_context, 'request_id', None)
        _context.request_id = request_id
        try:
            yield
        finally:
            if old_request_id:
                _context.request_id = old_request_id
            else:
                delattr(_context, 'request_id')
    
    def log_api_call(self, method: str, url: str, status_code: int, 
                    duration: float, user_id: Optional[str] = None):
        """Log API call with structured data"""
        self.logger.info("API call", extra={
            'extra_fields': {
                'event_type': 'api_call',
                'method': method,
                'url': url,
                'status_code': status_code,
                'duration_ms': round(duration * 1000, 2),
                'user_id': user_id
            }
        })
    
    def log_database_query(self, query: str, duration: float, 
                          row_count: Optional[int] = None):
        """Log database query with performance metrics"""
        self.logger.debug("Database query", extra={
            'extra_fields': {
                'event_type': 'database_query',
                'query': query[:500],  # Truncate long queries
                'duration_ms': round(duration * 1000, 2),
                'row_count': row_count
            }
        })
    
    def log_external_api_call(self, service: str, endpoint: str, 
                             status_code: int, duration: float,
                             success: bool = True):
        """Log external API call"""
        log_level = logging.INFO if success else logging.WARNING
        self.logger.log(log_level, f"External API call to {service}", extra={
            'extra_fields': {
                'event_type': 'external_api_call',
                'service': service,
                'endpoint': endpoint,
                'status_code': status_code,
                'duration_ms': round(duration * 1000, 2),
                'success': success
            }
        })
    
    def log_business_event(self, event_type: str, event_data: Dict[str, Any]):
        """Log business events for analytics"""
        self.logger.info(f"Business event: {event_type}", extra={
            'extra_fields': {
                'event_type': 'business_event',
                'business_event_type': event_type,
                **event_data
            }
        })
    
    def log_security_event(self, event_type: str, user_id: Optional[str] = None,
                          ip_address: Optional[str] = None, 
                          additional_data: Optional[Dict[str, Any]] = None):
        """Log security-related events"""
        self.logger.warning(f"Security event: {event_type}", extra={
            'extra_fields': {
                'event_type': 'security_event',
                'security_event_type': event_type,
                'user_id': user_id,
                'ip_address': ip_address,
                **(additional_data or {})
            }
        })
    
    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Log error with full context"""
        self.logger.error(f"Error occurred: {str(error)}", 
                         exc_info=error, extra={
            'extra_fields': {
                'event_type': 'error',
                'error_type': type(error).__name__,
                **(context or {})
            }
        })

def log_execution_time(logger_instance: ProductionLogger = None):
    """Decorator to log function execution time"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logger_instance or get_logger()
            start_time = datetime.utcnow()
            
            try:
                result = func(*args, **kwargs)
                duration = (datetime.utcnow() - start_time).total_seconds()
                
                logger.logger.debug(f"Function executed: {func.__name__}", extra={
                    'extra_fields': {
                        'event_type': 'function_execution',
                        'function_name': func.__name__,
                        'duration_ms': round(duration * 1000, 2),
                        'success': True
                    }
                })
                
                return result
                
            except Exception as e:
                duration = (datetime.utcnow() - start_time).total_seconds()
                
                logger.logger.error(f"Function failed: {func.__name__}: {str(e)}", 
                                   exc_info=e, extra={
                    'extra_fields': {
                        'event_type': 'function_execution',
                        'function_name': func.__name__,
                        'duration_ms': round(duration * 1000, 2),
                        'success': False,
                        'error_type': type(e).__name__
                    }
                })
                raise
        
        return wrapper
    return decorator

# Global logger instance
_global_logger = None

def get_logger() -> ProductionLogger:
    """Get the global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = ProductionLogger()
        _global_logger.configure()
    return _global_logger

def configure_logging(app_name: str = 'monitor-legislativo', **kwargs):
    """Configure the global logging system"""
    global _global_logger
    _global_logger = ProductionLogger(app_name)
    _global_logger.configure(**kwargs)
    return _global_logger

# Convenience functions
def log_info(message: str, **kwargs):
    """Log info message"""
    get_logger().logger.info(message, **kwargs)

def log_warning(message: str, **kwargs):
    """Log warning message"""
    get_logger().logger.warning(message, **kwargs)

def log_error(message: str, error: Exception = None, **kwargs):
    """Log error message"""
    if error:
        get_logger().logger.error(message, exc_info=error, **kwargs)
    else:
        get_logger().logger.error(message, **kwargs)

def log_debug(message: str, **kwargs):
    """Log debug message"""
    get_logger().logger.debug(message, **kwargs)