"""
Natural Language Processing Module for Brazilian Legislative Documents
====================================================================

This module provides specialized NLP tools for analyzing Brazilian Portuguese
legal and legislative texts, with focus on:

- Text preprocessing and normalization for legal documents
- Named Entity Recognition (NER) for legal entities
- Topic modeling and thematic analysis
- Sentiment analysis adapted for legal contexts
- Document similarity and clustering
- Language model fine-tuning for Portuguese legal text
- Feature extraction for machine learning models

Components:
-----------
- BrazilianLegalNLP: Main NLP pipeline for Portuguese legal texts
- LegalEntityRecognizer: NER system for legal entities (laws, institutions, etc.)
- ThematicAnalyzer: Topic modeling and thematic analysis
- SentimentAnalyzer: Sentiment analysis adapted for legal contexts
- TextPreprocessor: Legal text preprocessing and normalization
- FeatureExtractor: Feature extraction for ML models
- SimilarityCalculator: Document similarity and clustering
- LanguageModelFinetuner: Fine-tuning language models for legal domain

Usage:
------
Basic NLP analysis:
    >>> from lexml_refinado.nlp import BrazilianLegalNLP
    >>> nlp = BrazilianLegalNLP()
    >>> result = nlp.analyze_text("Lei nº 14.133, de 1º de abril de 2021...")

Topic modeling:
    >>> from lexml_refinado.nlp import ThematicAnalyzer
    >>> analyzer = ThematicAnalyzer()
    >>> topics = analyzer.extract_topics(documents)

Named Entity Recognition:
    >>> from lexml_refinado.nlp import LegalEntityRecognizer
    >>> ner = LegalEntityRecognizer()
    >>> entities = ner.extract_entities(text)
"""

from typing import Dict, List, Any, Optional, Union
import warnings

# Core NLP components
try:
    from .brazilian_legal_nlp import BrazilianLegalNLP
    from .text_preprocessor import LegalTextPreprocessor
    from .feature_extractor import LegalFeatureExtractor
except ImportError as e:
    warnings.warn(f"Core NLP components could not be imported: {e}", ImportWarning)

# Advanced NLP components (optional)
_advanced_components = {}

try:
    from .entity_recognition import LegalEntityRecognizer
    _advanced_components['entity_recognition'] = True
except ImportError:
    _advanced_components['entity_recognition'] = False

try:
    from .thematic_analysis import ThematicAnalyzer
    _advanced_components['thematic_analysis'] = True
except ImportError:
    _advanced_components['thematic_analysis'] = False

try:
    from .sentiment_analysis import LegalSentimentAnalyzer
    _advanced_components['sentiment_analysis'] = True
except ImportError:
    _advanced_components['sentiment_analysis'] = False

try:
    from .similarity_analysis import DocumentSimilarityCalculator
    _advanced_components['similarity_analysis'] = True
except ImportError:
    _advanced_components['similarity_analysis'] = False

try:
    from .language_model_finetuner import LanguageModelFinetuner
    _advanced_components['language_model_finetuner'] = True
except ImportError:
    _advanced_components['language_model_finetuner'] = False

# Export main components
__all__ = [
    # Core components
    'BrazilianLegalNLP',
    'LegalTextPreprocessor', 
    'LegalFeatureExtractor',
    
    # Advanced components (conditionally available)
    'LegalEntityRecognizer',
    'ThematicAnalyzer',
    'LegalSentimentAnalyzer',
    'DocumentSimilarityCalculator',
    'LanguageModelFinetuner',
    
    # Utility functions
    'get_nlp_capabilities',
    'create_nlp_pipeline',
    'preprocess_legal_corpus',
]

def get_nlp_capabilities() -> Dict[str, bool]:
    """
    Get information about available NLP capabilities.
    
    Returns:
        Dict mapping component names to availability status
    """
    capabilities = {
        'brazilian_legal_nlp': True,
        'text_preprocessor': True,
        'feature_extractor': True,
    }
    capabilities.update(_advanced_components)
    return capabilities

def create_nlp_pipeline(
    components: Optional[List[str]] = None,
    config: Optional[Dict[str, Any]] = None
) -> 'BrazilianLegalNLP':
    """
    Create a configured NLP pipeline with specified components.
    
    Args:
        components: List of component names to include
        config: Configuration dict for the pipeline
        
    Returns:
        Configured BrazilianLegalNLP instance
    """
    if components is None:
        components = ['preprocessor', 'tokenizer', 'pos_tagger']
    
    if config is None:
        config = {}
    
    return BrazilianLegalNLP(enabled_components=components, **config)

def preprocess_legal_corpus(
    documents: List[str],
    preprocessing_options: Optional[Dict[str, Any]] = None
) -> List[str]:
    """
    Preprocess a corpus of legal documents.
    
    Args:
        documents: List of document texts
        preprocessing_options: Options for preprocessing
        
    Returns:
        List of preprocessed document texts
    """
    preprocessor = LegalTextPreprocessor(**(preprocessing_options or {}))
    return [preprocessor.preprocess(doc) for doc in documents]