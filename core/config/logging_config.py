"""
Centralized Logging Configuration
Provides structured, consistent logging across all services
"""

import os
import sys
import logging
import logging.config
from pathlib import Path
from typing import Dict, Any, Optional
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        # Create base log object
        log_obj = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process_id': os.getpid(),
            'thread_id': record.thread,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info', 'message']:
                log_obj[key] = value
        
        return json.dumps(log_obj, ensure_ascii=False, default=str)

class StructuredLogger:
    """Enhanced logger with structured logging capabilities"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        
    def info(self, message: str, **kwargs):
        """Log info with additional context"""
        extra = kwargs
        self.logger.info(message, extra=extra)
        
    def error(self, message: str, **kwargs):
        """Log error with additional context"""
        extra = kwargs
        self.logger.error(message, extra=extra)
        
    def warning(self, message: str, **kwargs):
        """Log warning with additional context"""
        extra = kwargs
        self.logger.warning(message, extra=extra)
        
    def debug(self, message: str, **kwargs):
        """Log debug with additional context"""
        extra = kwargs
        self.logger.debug(message, extra=extra)

def get_logging_config(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = True,
    service_name: str = "monitor_legislativo"
) -> Dict[str, Any]:
    """
    Get centralized logging configuration
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional log file path
        json_format: Whether to use JSON formatting
        service_name: Name of the service for log identification
    
    Returns:
        Dictionary configuration for logging.config.dictConfig
    """
    
    # Determine log directory
    log_dir = Path(os.getenv("LOG_DIR", "logs"))
    log_dir.mkdir(exist_ok=True)
    
    # Default log file if not specified
    if not log_file:
        log_file = log_dir / f"{service_name}.log"
    
    # Base configuration
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "detailed": {
                "format": "%(asctime)s [%(levelname)s] %(name)s.%(funcName)s:%(lineno)d: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            }
        },
        "filters": {
            "service_filter": {
                "()": ServiceFilter,
                "service_name": service_name
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": "detailed",
                "stream": sys.stdout,
                "filters": ["service_filter"]
            },
            "error_console": {
                "class": "logging.StreamHandler",
                "level": "ERROR",
                "formatter": "detailed",
                "stream": sys.stderr,
                "filters": ["service_filter"]
            }
        },
        "loggers": {
            # Root logger
            "": {
                "level": level,
                "handlers": ["console"],
                "propagate": False
            },
            # Application loggers
            "core": {
                "level": level,
                "handlers": ["console"],
                "propagate": False
            },
            "web": {
                "level": level,
                "handlers": ["console"],
                "propagate": False
            },
            "desktop": {
                "level": level,
                "handlers": ["console"],
                "propagate": False
            },
            # External libraries
            "uvicorn": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False
            },
            "fastapi": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False
            },
            "httpx": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False
            },
            "urllib3": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False
            }
        }
    }
    
    # Add JSON formatter if requested
    if json_format:
        config["formatters"]["json"] = {
            "()": JSONFormatter
        }
        # Update console handlers to use JSON
        config["handlers"]["console"]["formatter"] = "json"
        config["handlers"]["error_console"]["formatter"] = "json"
    
    # Add file handler if log file specified
    if log_file:
        config["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": level,
            "formatter": "json" if json_format else "detailed",
            "filename": str(log_file),
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 5,
            "encoding": "utf-8",
            "filters": ["service_filter"]
        }
        
        # Add file handler to all loggers
        for logger_name in config["loggers"]:
            if "handlers" in config["loggers"][logger_name]:
                config["loggers"][logger_name]["handlers"].append("file")
    
    return config

class ServiceFilter(logging.Filter):
    """Filter to add service name to log records"""
    
    def __init__(self, service_name: str):
        super().__init__()
        self.service_name = service_name
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add service name to record"""
        record.service_name = self.service_name
        return True

def setup_logging(
    level: str = None,
    service_name: str = "monitor_legislativo",
    json_format: bool = None,
    log_file: str = None
) -> None:
    """
    Setup centralized logging configuration
    
    Args:
        level: Logging level from environment or default to INFO
        service_name: Name of the service
        json_format: Use JSON formatting (default based on environment)
        log_file: Optional log file path
    """
    
    # Get configuration from environment
    if level is None:
        level = os.getenv("LOG_LEVEL", "INFO").upper()
    
    if json_format is None:
        json_format = os.getenv("LOG_FORMAT", "json").lower() == "json"
    
    if log_file is None:
        log_file = os.getenv("LOG_FILE")
    
    # Get logging configuration
    config = get_logging_config(
        level=level,
        log_file=log_file,
        json_format=json_format,
        service_name=service_name
    )
    
    # Apply configuration
    logging.config.dictConfig(config)
    
    # Log initialization
    logger = logging.getLogger(__name__)
    logger.info(
        "Logging initialized",
        service_name=service_name,
        level=level,
        json_format=json_format,
        log_file=log_file
    )

def get_structured_logger(name: str) -> StructuredLogger:
    """
    Get a structured logger instance
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        StructuredLogger instance
    """
    return StructuredLogger(name)

# Module-level setup function for backward compatibility
def configure_logging():
    """Configure logging with default settings"""
    setup_logging()

# Auto-setup when imported (can be disabled with environment variable)
if not os.getenv("DISABLE_AUTO_LOGGING_SETUP"):
    setup_logging()