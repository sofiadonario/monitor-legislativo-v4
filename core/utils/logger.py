"""
Simple logger utility for Monitor Legislativo v4
Provides basic logging functionality for the application
"""

import logging
import sys
from typing import Optional

# Alias for backward compatibility
Logger = logging.getLogger

def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance with standard configuration
    
    Args:
        name: Logger name (usually __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Create console handler
        handler = logging.StreamHandler(sys.stdout)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(handler)
        logger.setLevel(level or logging.INFO)
    
    return logger

def setup_logging(level: str = "INFO") -> None:
    """
    Setup basic logging configuration for the application
    
    Args:
        level: Default log level for the application
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )