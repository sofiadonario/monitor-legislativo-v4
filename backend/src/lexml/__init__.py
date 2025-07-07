# This file makes the 'lexml' directory a Python package.

"""
LexML Integration Module

This module provides integration with LexML Brasil v1.0 specification,
including SKOS controlled vocabularies, FRBROO document model, and
enhanced academic research capabilities.

Components:
- vocabulary_manager: SKOS vocabulary loading and caching
- urn_parser: LexML URN parsing and validation
- frbroo_model: FRBROO document model implementation
- citation_generator: Enhanced academic citation generation
"""

from .vocabulary_manager import SKOSVocabularyManager
from .exceptions import LexMLError, VocabularyError, URNError

__all__ = [
    'SKOSVocabularyManager',
    'LexMLError',
    'VocabularyError', 
    'URNError'
]