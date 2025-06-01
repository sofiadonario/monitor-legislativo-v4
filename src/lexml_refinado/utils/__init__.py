"""
Utilities Module for LexML Refinado Package
===========================================

This module provides utility functions and helper classes for the
Brazilian legislative document analysis system.

Components:
-----------
- ConfigManager: Configuration management and validation
- FileUtils: File I/O operations and path management
- DateUtils: Date parsing and formatting utilities
- TextUtils: Text processing and cleaning utilities
- ValidationUtils: Data validation and quality checks
- LoggingUtils: Structured logging configuration
- CacheUtils: Caching and memoization utilities

Usage:
------
Configuration management:
    >>> from lexml_refinado.utils import ConfigManager
    >>> config = ConfigManager.load_config('config.yaml')

File operations:
    >>> from lexml_refinado.utils import FileUtils
    >>> FileUtils.ensure_directory('/path/to/dir')
    >>> data = FileUtils.load_json('data.json')

Date utilities:
    >>> from lexml_refinado.utils import DateUtils
    >>> date = DateUtils.parse_brazilian_date('14 de junho de 2023')

Text utilities:
    >>> from lexml_refinado.utils import TextUtils
    >>> clean_text = TextUtils.clean_legal_text(raw_text)
"""

from typing import Dict, List, Any, Optional, Union
import warnings

# Core utility components
try:
    from .config_manager import ConfigManager
    from .file_utils import FileUtils
    from .date_utils import DateUtils
    from .text_utils import TextUtils
    from .validation_utils import ValidationUtils
except ImportError as e:
    warnings.warn(f"Core utility components could not be imported: {e}", ImportWarning)

# Advanced utility components (optional)
_advanced_components = {}

try:
    from .logging_utils import LoggingUtils
    _advanced_components['logging'] = True
except ImportError:
    _advanced_components['logging'] = False

try:
    from .cache_utils import CacheUtils
    _advanced_components['caching'] = True
except ImportError:
    _advanced_components['caching'] = False

try:
    from .performance_monitor import PerformanceMonitor
    _advanced_components['performance'] = True
except ImportError:
    _advanced_components['performance'] = False

# Export main components
__all__ = [
    # Core components
    'ConfigManager',
    'FileUtils',
    'DateUtils',
    'TextUtils',
    'ValidationUtils',
    
    # Advanced components (conditionally available)
    'LoggingUtils',
    'CacheUtils',
    'PerformanceMonitor',
    
    # Utility functions
    'get_utils_capabilities',
    'setup_logging',
    'load_config_file',
]

def get_utils_capabilities() -> Dict[str, bool]:
    """
    Get information about available utility capabilities.
    
    Returns:
        Dict mapping component names to availability status
    """
    capabilities = {
        'config_manager': True,
        'file_utils': True,
        'date_utils': True,
        'text_utils': True,
        'validation_utils': True,
    }
    capabilities.update(_advanced_components)
    return capabilities

def setup_logging(
    level: str = 'INFO',
    format_type: str = 'structured',
    log_file: Optional[str] = None
) -> None:
    """
    Setup logging configuration for the package.
    
    Args:
        level: Logging level
        format_type: Format type ('structured' or 'simple')
        log_file: Optional log file path
    """
    if 'logging' in _advanced_components and _advanced_components['logging']:
        LoggingUtils.setup_logging(level, format_type, log_file)
    else:
        # Fallback to basic logging
        import logging
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=log_file
        )

def load_config_file(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    return ConfigManager.load_config(config_path)