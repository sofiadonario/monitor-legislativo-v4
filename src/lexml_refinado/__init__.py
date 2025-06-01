"""
LexML Refinado - Advanced Brazilian Legislative Document Analysis System
========================================================================

A comprehensive Python package for analyzing Brazilian legislative documents with 
advanced Natural Language Processing, Machine Learning, and statistical analysis capabilities.

Features:
---------
- Multi-level hierarchical document classification
- Specialized parsing for different document types
- Advanced thematic enrichment and topic modeling
- Quality assessment and validation systems
- Integration with Brazilian legal databases
- Support for 134k+ legislative document analysis
- PostgreSQL integration for scalable data storage
- Academic research and analytics support

Core Components:
---------------
- RefinedDocumentClassifier: Hierarchical classification system (3 levels)
- IntegratedParsingSystem: Document-type specific parsing strategies
- ThematicEnrichmentSystem: Advanced thematic analysis and topic modeling
- ParsingQualityController: Automated quality assessment and validation
- EnhancedLexMLStrategy: Main orchestration system for comprehensive analysis
- NLPPipeline: Brazilian Portuguese NLP processing pipeline
- DatabaseManager: PostgreSQL integration and data management
- MLAnalyzer: Machine learning models for document analysis

Usage:
------
Basic document classification:
    >>> from lexml_refinado import RefinedDocumentClassifier
    >>> classifier = RefinedDocumentClassifier()
    >>> result = classifier.classify_document(urn, title, summary)

Complete document analysis:
    >>> from lexml_refinado import EnhancedLexMLStrategy
    >>> analyzer = EnhancedLexMLStrategy()
    >>> results = analyzer.execute_comprehensive_search()

NLP Pipeline:
    >>> from lexml_refinado.nlp import BrazilianLegalNLP
    >>> nlp = BrazilianLegalNLP()
    >>> analysis = nlp.analyze_text(document_text)

Authors: MackIntegridade Research Team
License: MIT
Version: 2.0.0
"""

import sys
import warnings
from typing import Dict, Any

# Version information
__version__ = "2.0.0"
__author__ = "MackIntegridade Research Team"
__email__ = "dev@mackintegridade.com"
__license__ = "MIT"
__url__ = "https://github.com/MackIntegridade/monitor_legislativo_v4"

# Python version check
if sys.version_info < (3, 8):
    warnings.warn(
        "lexml-refinado requires Python 3.8 or higher. "
        f"You are using Python {sys.version_info.major}.{sys.version_info.minor}.",
        UserWarning,
        stacklevel=2
    )

# Core imports
try:
    from .classification_system import RefinedDocumentClassifier
    from .parsing_prompts import IntegratedParsingSystem
    from .thematic_enrichment import ThematicEnrichmentSystem
    from .quality_controller import ParsingQualityController
    from .enhanced_strategy import EnhancedLexMLStrategy
except ImportError as e:
    warnings.warn(
        f"Some core modules could not be imported: {e}. "
        "Please ensure all dependencies are installed.",
        ImportWarning,
        stacklevel=2
    )

# Extended components (optional imports)
_extended_modules = {}

try:
    from . import nlp
    _extended_modules['nlp'] = nlp
except ImportError:
    pass

try:
    from . import ml
    _extended_modules['ml'] = ml
except ImportError:
    pass

try:
    from . import database
    _extended_modules['database'] = database
except ImportError:
    pass

try:
    from . import utils
    _extended_modules['utils'] = utils
except ImportError:
    pass

try:
    from . import cli
    _extended_modules['cli'] = cli
except ImportError:
    pass

# Package metadata
__metadata__ = {
    'name': 'lexml-refinado',
    'version': __version__,
    'description': 'Advanced Brazilian Legislative Document Analysis System',
    'author': __author__,
    'author_email': __email__,
    'license': __license__,
    'url': __url__,
    'python_requires': '>=3.8',
    'keywords': [
        'nlp', 'legal-text-analysis', 'brazilian-legislation',
        'document-classification', 'machine-learning', 'data-mining'
    ]
}

# Core public API
__all__ = [
    # Version and metadata
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__url__',
    '__metadata__',
    
    # Core classes
    'RefinedDocumentClassifier',
    'IntegratedParsingSystem', 
    'ThematicEnrichmentSystem',
    'ParsingQualityController',
    'EnhancedLexMLStrategy',
    
    # Utility functions
    'get_version_info',
    'list_available_modules',
    'configure_logging',
]

def get_version_info() -> Dict[str, Any]:
    """
    Get comprehensive version and system information.
    
    Returns:
        Dict containing version, Python version, and available modules
    """
    import platform
    
    return {
        'lexml_refinado_version': __version__,
        'python_version': sys.version,
        'platform': platform.platform(),
        'available_modules': list(_extended_modules.keys()),
        'core_modules_loaded': len(__all__) > 6,
    }

def list_available_modules() -> Dict[str, str]:
    """
    List all available modules and their descriptions.
    
    Returns:
        Dict mapping module names to descriptions
    """
    descriptions = {
        'classification_system': 'Hierarchical document classification',
        'parsing_prompts': 'Document-specific parsing strategies',
        'thematic_enrichment': 'Advanced thematic analysis',
        'quality_controller': 'Quality assessment and validation',
        'enhanced_strategy': 'Main orchestration system',
        'nlp': 'Brazilian Portuguese NLP pipeline',
        'ml': 'Machine learning models and analyzers',
        'database': 'PostgreSQL integration and management',
        'utils': 'Utility functions and helpers',
        'cli': 'Command-line interface tools',
    }
    
    available = {
        module: descriptions[module] 
        for module in descriptions 
        if module in _extended_modules or module in [
            'classification_system', 'parsing_prompts', 'thematic_enrichment',
            'quality_controller', 'enhanced_strategy'
        ]
    }
    
    return available

def configure_logging(level: str = "INFO", format_style: str = "structured") -> None:
    """
    Configure logging for the package.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_style: Either 'structured' or 'simple'
    """
    import logging
    
    # Configure based on availability of structlog
    try:
        import structlog
        if format_style == "structured":
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.UnicodeDecoder(),
                    structlog.processors.JSONRenderer()
                ],
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
        else:
            # Fall back to simple logging
            logging.basicConfig(
                level=getattr(logging, level.upper()),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
    except ImportError:
        # Use standard logging if structlog not available
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

# Initialize logging with sensible defaults
configure_logging()