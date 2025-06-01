"""
Monitor Legislativo Core Module
Shared functionality for desktop and web applications
"""

__version__ = "4.0.0"
__author__ = "MackIntegridade"

from .api import APIService
from .models import Proposition, SearchResult
from .utils import export_service, cache_manager

__all__ = [
    "APIService",
    "Proposition",
    "SearchResult",
    "export_service",
    "cache_manager"
]