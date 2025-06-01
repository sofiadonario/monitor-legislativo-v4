"""
Machine Learning Module for Brazilian Legislative Document Analysis
================================================================

This module provides advanced machine learning capabilities for analyzing
Brazilian legislative documents, with focus on:

- Document classification and categorization
- Topic modeling and thematic analysis
- Anomaly detection in legislative patterns
- Time series forecasting for legislative activity
- Clustering and similarity analysis
- Recommendation systems for related documents
- Statistical modeling and hypothesis testing

Components:
-----------
- DocumentClassifier: Multi-class document classification
- TopicModeler: Advanced topic modeling with LDA, NMF, and BERT
- AnomalyDetector: Detect unusual patterns in legislative data
- TimeSeriesAnalyzer: Forecast legislative activity and trends
- ClusterAnalyzer: Document clustering and similarity analysis
- RecommendationEngine: Content-based recommendation system
- StatisticalAnalyzer: Statistical modeling and testing
- ModelEvaluator: Model performance evaluation and validation

Usage:
------
Document classification:
    >>> from lexml_refinado.ml import DocumentClassifier
    >>> classifier = DocumentClassifier()
    >>> classifier.fit(documents, labels)
    >>> predictions = classifier.predict(new_documents)

Topic modeling:
    >>> from lexml_refinado.ml import TopicModeler
    >>> modeler = TopicModeler(n_topics=10)
    >>> topics = modeler.fit_transform(documents)

Anomaly detection:
    >>> from lexml_refinado.ml import AnomalyDetector
    >>> detector = AnomalyDetector()
    >>> anomalies = detector.detect_anomalies(document_features)

Time series analysis:
    >>> from lexml_refinado.ml import TimeSeriesAnalyzer
    >>> analyzer = TimeSeriesAnalyzer()
    >>> forecast = analyzer.forecast(legislative_activity_data)
"""

from typing import Dict, List, Any, Optional, Union
import warnings

# Core ML components
try:
    from .document_classifier import DocumentClassifier
    from .statistical_analyzer import StatisticalAnalyzer
    from .model_evaluator import ModelEvaluator
except ImportError as e:
    warnings.warn(f"Core ML components could not be imported: {e}", ImportWarning)

# Advanced ML components (optional)
_advanced_components = {}

try:
    from .topic_modeler import TopicModeler
    _advanced_components['topic_modeling'] = True
except ImportError:
    _advanced_components['topic_modeling'] = False

try:
    from .anomaly_detector import AnomalyDetector
    _advanced_components['anomaly_detection'] = True
except ImportError:
    _advanced_components['anomaly_detection'] = False

try:
    from .time_series_analyzer import TimeSeriesAnalyzer
    _advanced_components['time_series_analysis'] = True
except ImportError:
    _advanced_components['time_series_analysis'] = False

try:
    from .cluster_analyzer import ClusterAnalyzer
    _advanced_components['clustering'] = True
except ImportError:
    _advanced_components['clustering'] = False

try:
    from .recommendation_engine import RecommendationEngine
    _advanced_components['recommendations'] = True
except ImportError:
    _advanced_components['recommendations'] = False

# Export main components
__all__ = [
    # Core components
    'DocumentClassifier',
    'StatisticalAnalyzer',
    'ModelEvaluator',
    
    # Advanced components (conditionally available)
    'TopicModeler',
    'AnomalyDetector',
    'TimeSeriesAnalyzer',
    'ClusterAnalyzer',
    'RecommendationEngine',
    
    # Utility functions
    'get_ml_capabilities',
    'create_classification_pipeline',
    'evaluate_model_performance',
]

def get_ml_capabilities() -> Dict[str, bool]:
    """
    Get information about available ML capabilities.
    
    Returns:
        Dict mapping component names to availability status
    """
    capabilities = {
        'document_classifier': True,
        'statistical_analyzer': True,
        'model_evaluator': True,
    }
    capabilities.update(_advanced_components)
    return capabilities

def create_classification_pipeline(
    algorithm: str = 'random_forest',
    preprocessing_steps: Optional[List[str]] = None,
    evaluation_metrics: Optional[List[str]] = None
) -> 'DocumentClassifier':
    """
    Create a configured document classification pipeline.
    
    Args:
        algorithm: Classification algorithm to use
        preprocessing_steps: List of preprocessing steps
        evaluation_metrics: List of evaluation metrics
        
    Returns:
        Configured DocumentClassifier instance
    """
    if preprocessing_steps is None:
        preprocessing_steps = ['tfidf', 'normalize']
    
    if evaluation_metrics is None:
        evaluation_metrics = ['accuracy', 'f1_score', 'precision', 'recall']
    
    return DocumentClassifier(
        algorithm=algorithm,
        preprocessing_steps=preprocessing_steps,
        evaluation_metrics=evaluation_metrics
    )

def evaluate_model_performance(
    y_true: List[Any],
    y_pred: List[Any],
    model_type: str = 'classification'
) -> Dict[str, float]:
    """
    Evaluate model performance with appropriate metrics.
    
    Args:
        y_true: True labels/values
        y_pred: Predicted labels/values
        model_type: Type of model ('classification', 'regression', 'clustering')
        
    Returns:
        Dictionary with performance metrics
    """
    evaluator = ModelEvaluator()
    
    if model_type == 'classification':
        return evaluator.evaluate_classification(y_true, y_pred)
    elif model_type == 'regression':
        return evaluator.evaluate_regression(y_true, y_pred)
    elif model_type == 'clustering':
        return evaluator.evaluate_clustering(y_true, y_pred)
    else:
        raise ValueError(f"Unknown model type: {model_type}")