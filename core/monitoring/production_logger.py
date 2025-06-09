"""
Production Logging Configuration for Monitor Legislativo v4
Structured logging with audit trails, security logging, and compliance features

This module provides enterprise-grade logging suitable for Brazilian government 
systems, including LGPD compliance and forensic audit capabilities.
"""

import os
import json
import logging
import logging.handlers
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from functools import wraps
from flask import request, g, has_request_context
from pythonjsonlogger import jsonlogger
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration

class SecurityFormatter(jsonlogger.JsonFormatter):
    """
    Custom JSON formatter with security and audit features
    """
    
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        
        # Add standard fields
        log_record['timestamp'] = datetime.now(timezone.utc).isoformat()
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        log_record['service'] = 'monitor_legislativo_v4'
        log_record['environment'] = os.getenv('APP_ENV', 'development')
        
        # Add request context if available
        if has_request_context():
            log_record['request_id'] = getattr(g, 'request_id', None)
            log_record['user_id'] = getattr(g, 'user_id', None)
            log_record['ip_address'] = self._get_client_ip()
            log_record['user_agent'] = request.headers.get('User-Agent', '')
            log_record['endpoint'] = request.endpoint
            log_record['method'] = request.method
            log_record['url'] = request.url
        
        # Add security context
        if hasattr(record, 'security_event'):
            log_record['security_event'] = record.security_event
            log_record['threat_level'] = getattr(record, 'threat_level', 'low')
        
        # Add audit context
        if hasattr(record, 'audit_action'):
            log_record['audit_action'] = record.audit_action
            log_record['audit_resource'] = getattr(record, 'audit_resource', None)
            log_record['audit_outcome'] = getattr(record, 'audit_outcome', 'success')
    
    def _get_client_ip(self) -> str:
        """Get client IP address considering proxies"""
        if not has_request_context():
            return 'unknown'
        
        # Check for forwarded headers (load balancer/proxy)
        forwarded_ips = request.headers.get('X-Forwarded-For')
        if forwarded_ips:
            return forwarded_ips.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or 'unknown'

class AuditLogger:
    """
    Specialized logger for audit events with LGPD compliance
    """
    
    def __init__(self, logger_name: str = 'monitor_legislativo.audit'):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        
        # Create audit-specific handler if not exists
        if not self.logger.handlers:
            self._setup_audit_handler()
    
    def _setup_audit_handler(self):
        """Setup audit-specific file handler"""
        audit_log_path = os.getenv('AUDIT_LOG_PATH', '/var/log/monitor-legislativo/audit.log')
        os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)
        
        # Rotating file handler for audit logs
        handler = logging.handlers.TimedRotatingFileHandler(
            audit_log_path,
            when='D',  # Daily rotation
            interval=1,
            backupCount=90,  # Keep 90 days
            encoding='utf-8'
        )
        
        formatter = SecurityFormatter(
            '%(timestamp)s %(level)s %(logger)s %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Prevent propagation to avoid duplicate logs
        self.logger.propagate = False
    
    def log_access(self, action: str, resource: str, outcome: str = 'success', **kwargs):
        """Log access events for audit trail"""
        extra = {
            'audit_action': action,
            'audit_resource': resource,
            'audit_outcome': outcome,
            'audit_type': 'access',
            **kwargs
        }
        
        self.logger.info(f"ACCESS: {action} on {resource} - {outcome}", extra=extra)
    
    def log_data_operation(self, operation: str, data_type: str, record_count: int = 1, **kwargs):
        """Log data operations for LGPD compliance"""
        extra = {
            'audit_action': operation,
            'audit_resource': data_type,
            'audit_outcome': 'success',
            'audit_type': 'data_operation',
            'record_count': record_count,
            **kwargs
        }
        
        self.logger.info(f"DATA_OP: {operation} on {data_type} ({record_count} records)", extra=extra)
    
    def log_security_event(self, event_type: str, threat_level: str, description: str, **kwargs):
        """Log security events"""
        extra = {
            'security_event': event_type,
            'threat_level': threat_level,
            'audit_type': 'security',
            **kwargs
        }
        
        self.logger.warning(f"SECURITY: {event_type} - {description}", extra=extra)
    
    def log_government_api_access(self, api_name: str, endpoint: str, response_code: int, **kwargs):
        """Log government API access for compliance"""
        extra = {
            'audit_action': 'api_request',
            'audit_resource': f"gov_api_{api_name}",
            'audit_outcome': 'success' if 200 <= response_code < 300 else 'failure',
            'audit_type': 'government_api',
            'api_name': api_name,
            'endpoint': endpoint,
            'response_code': response_code,
            **kwargs
        }
        
        self.logger.info(f"GOV_API: {api_name} {endpoint} - {response_code}", extra=extra)

class PerformanceLogger:
    """
    Logger for performance monitoring and optimization
    """
    
    def __init__(self, logger_name: str = 'monitor_legislativo.performance'):
        self.logger = logging.getLogger(logger_name)
    
    def log_slow_query(self, query: str, duration: float, **kwargs):
        """Log slow database queries"""
        extra = {
            'performance_type': 'slow_query',
            'duration_ms': round(duration * 1000, 2),
            'query': query[:500],  # Truncate long queries
            **kwargs
        }
        
        self.logger.warning(f"SLOW_QUERY: {duration:.2f}s - {query[:100]}...", extra=extra)
    
    def log_api_performance(self, api_name: str, endpoint: str, duration: float, **kwargs):
        """Log API performance metrics"""
        extra = {
            'performance_type': 'api_call',
            'api_name': api_name,
            'endpoint': endpoint,
            'duration_ms': round(duration * 1000, 2),
            **kwargs
        }
        
        level = logging.WARNING if duration > 2.0 else logging.INFO
        self.logger.log(level, f"API_PERF: {api_name} {endpoint} - {duration:.2f}s", extra=extra)

class ProductionLoggerConfig:
    """
    Main production logging configuration
    """
    
    @staticmethod
    def setup_production_logging():
        """Setup comprehensive production logging"""
        
        # Root logger configuration
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        
        # Clear any existing handlers
        root_logger.handlers.clear()
        
        # Console handler for container logs
        console_handler = logging.StreamHandler()
        console_formatter = SecurityFormatter(
            '%(timestamp)s %(level)s %(logger)s %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)
        root_logger.addHandler(console_handler)
        
        # File handler for application logs
        app_log_path = os.getenv('LOG_FILE_PATH', '/var/log/monitor-legislativo/app.log')
        if os.getenv('LOG_FILE_ENABLED', 'true').lower() == 'true':
            os.makedirs(os.path.dirname(app_log_path), exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                app_log_path,
                maxBytes=100 * 1024 * 1024,  # 100MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(console_formatter)
            file_handler.setLevel(logging.INFO)
            root_logger.addHandler(file_handler)
        
        # Error file handler
        error_log_path = os.getenv('ERROR_LOG_PATH', '/var/log/monitor-legislativo/error.log')
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_path,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=10,
            encoding='utf-8'
        )
        error_handler.setFormatter(console_formatter)
        error_handler.setLevel(logging.ERROR)
        root_logger.addHandler(error_handler)
        
        # Sentry integration for error tracking
        sentry_dsn = os.getenv('SENTRY_DSN')
        if sentry_dsn:
            sentry_logging = LoggingIntegration(
                level=logging.INFO,
                event_level=logging.ERROR
            )
            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[sentry_logging],
                environment=os.getenv('APP_ENV', 'development'),
                traces_sample_rate=float(os.getenv('SENTRY_TRACES_SAMPLE_RATE', '0.1'))
            )
        
        # Set specific logger levels
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        
        # Setup specialized loggers
        audit_logger = AuditLogger()
        performance_logger = PerformanceLogger()
        
        return {
            'audit': audit_logger,
            'performance': performance_logger,
            'main': logging.getLogger('monitor_legislativo')
        }

# Decorator for audit logging
def audit_log(action: str, resource: str = None):
    """Decorator to automatically log function calls for audit"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            audit_logger = AuditLogger()
            
            # Determine resource from function name if not provided
            audit_resource = resource or func.__name__
            
            try:
                result = func(*args, **kwargs)
                audit_logger.log_access(action, audit_resource, 'success')
                return result
            except Exception as e:
                audit_logger.log_access(action, audit_resource, 'failure', error=str(e))
                raise
        return wrapper
    return decorator

# Decorator for performance logging
def performance_log(threshold: float = 1.0):
    """Decorator to log slow function executions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            import time
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if duration > threshold:
                    performance_logger = PerformanceLogger()
                    performance_logger.logger.warning(
                        f"SLOW_FUNCTION: {func.__name__} took {duration:.2f}s",
                        extra={
                            'performance_type': 'slow_function',
                            'function_name': func.__name__,
                            'duration_ms': round(duration * 1000, 2),
                            'threshold_ms': round(threshold * 1000, 2)
                        }
                    )
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                performance_logger = PerformanceLogger()
                performance_logger.logger.error(
                    f"FUNCTION_ERROR: {func.__name__} failed after {duration:.2f}s",
                    extra={
                        'performance_type': 'function_error',
                        'function_name': func.__name__,
                        'duration_ms': round(duration * 1000, 2),
                        'error': str(e)
                    }
                )
                raise
        return wrapper
    return decorator

# Global logger instances
_loggers = None

def get_production_loggers():
    """Get production logger instances"""
    global _loggers
    if _loggers is None:
        _loggers = ProductionLoggerConfig.setup_production_logging()
    return _loggers

def get_audit_logger() -> AuditLogger:
    """Get audit logger instance"""
    return get_production_loggers()['audit']

def get_performance_logger() -> PerformanceLogger:
    """Get performance logger instance"""
    return get_production_loggers()['performance']

def get_main_logger():
    """Get main application logger"""
    return get_production_loggers()['main']

# Context manager for audit logging
class AuditContext:
    """Context manager for audit logging"""
    
    def __init__(self, action: str, resource: str):
        self.action = action
        self.resource = resource
        self.audit_logger = get_audit_logger()
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now(timezone.utc)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        
        if exc_type is None:
            self.audit_logger.log_access(
                self.action, 
                self.resource, 
                'success',
                duration_ms=round(duration * 1000, 2)
            )
        else:
            self.audit_logger.log_access(
                self.action, 
                self.resource, 
                'failure',
                error=str(exc_val),
                duration_ms=round(duration * 1000, 2)
            )

# Initialize production logging on import
if os.getenv('APP_ENV') == 'production':
    get_production_loggers()