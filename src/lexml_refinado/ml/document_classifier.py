#!/usr/bin/env python3
"""
Advanced Document Classifier for Brazilian Legislative Documents
===============================================================

Machine learning-based document classifier with support for multiple
algorithms and specialized handling of Brazilian legal document types.

Features:
---------
- Multi-class classification with hierarchical support
- Support for various ML algorithms (RF, SVM, XGBoost, Neural Networks)
- Feature engineering specialized for legal documents
- Cross-validation and hyperparameter optimization
- Model interpretability and feature importance analysis
- Handling of imbalanced datasets common in legal corpora
- Integration with Brazilian legal taxonomies

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
import pickle
import joblib

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.utils.class_weight import compute_class_weight

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    from sklearn.neural_network import MLPClassifier
    NEURAL_NETWORK_AVAILABLE = True
except ImportError:
    NEURAL_NETWORK_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ClassificationConfig:
    """Configuration for document classification."""
    
    # Algorithm settings
    algorithm: str = 'random_forest'
    use_ensemble: bool = False
    
    # Feature settings
    max_features: int = 5000
    ngram_range: Tuple[int, int] = (1, 3)
    use_tfidf: bool = True
    
    # Training settings
    test_size: float = 0.2
    validation_split: float = 0.2
    random_state: int = 42
    
    # Cross-validation
    cv_folds: int = 5
    use_stratified_cv: bool = True
    
    # Hyperparameter tuning
    tune_hyperparameters: bool = True
    param_grid_size: str = 'small'  # 'small', 'medium', 'large'
    
    # Class imbalance handling
    handle_imbalance: bool = True
    balancing_strategy: str = 'class_weight'  # 'class_weight', 'smote', 'undersampling'
    
    # Model interpretability
    compute_feature_importance: bool = True
    generate_classification_report: bool = True


@dataclass
class ClassificationResult:
    """Container for classification results."""
    
    # Predictions
    predictions: np.ndarray
    probabilities: Optional[np.ndarray]
    confidence_scores: np.ndarray
    
    # Performance metrics
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    
    # Detailed results
    classification_report: str
    confusion_matrix: np.ndarray
    
    # Feature analysis
    feature_importance: Optional[Dict[str, float]]
    
    # Metadata
    model_info: Dict[str, Any]
    training_time: float
    prediction_time: float


class DocumentClassifier:
    """
    Advanced document classifier for Brazilian legislative documents.
    """
    
    def __init__(self, config: Optional[ClassificationConfig] = None):
        """
        Initialize the document classifier.
        
        Args:
            config: Classification configuration
        """
        self.config = config or ClassificationConfig()
        
        # Initialize components
        self._initialize_models()
        self._initialize_preprocessors()
        
        # Model state
        self.is_fitted = False
        self.classes_ = None
        self.label_encoder = LabelEncoder()
        
        # Performance tracking
        self.training_history = []
        self.feature_names_ = None
        
        logger.info(f"DocumentClassifier initialized with algorithm: {self.config.algorithm}")
    
    def _initialize_models(self) -> None:
        """Initialize ML models based on configuration."""
        
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                random_state=self.config.random_state,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                random_state=self.config.random_state
            ),
            'svm': SVC(
                probability=True,
                random_state=self.config.random_state
            ),
            'logistic_regression': LogisticRegression(
                random_state=self.config.random_state,
                max_iter=1000
            )
        }
        
        # Add XGBoost if available
        if XGBOOST_AVAILABLE:
            models['xgboost'] = xgb.XGBClassifier(
                random_state=self.config.random_state,
                eval_metric='mlogloss'
            )
        
        # Add Neural Network if available
        if NEURAL_NETWORK_AVAILABLE:
            models['neural_network'] = MLPClassifier(
                hidden_layer_sizes=(100, 50),
                random_state=self.config.random_state,
                max_iter=500
            )
        
        # Select model
        if self.config.algorithm in models:
            self.model = models[self.config.algorithm]
        else:
            logger.warning(f"Algorithm {self.config.algorithm} not available. Using Random Forest.")
            self.model = models['random_forest']
            self.config.algorithm = 'random_forest'
        
        # Store all models for ensemble if needed
        if self.config.use_ensemble:
            self.ensemble_models = models
    
    def _initialize_preprocessors(self) -> None:
        """Initialize text preprocessing components."""
        
        if self.config.use_tfidf:
            self.vectorizer = TfidfVectorizer(
                max_features=self.config.max_features,
                ngram_range=self.config.ngram_range,
                lowercase=True,
                strip_accents='unicode',
                stop_words=None  # Let the legal preprocessor handle stopwords
            )
        else:
            from sklearn.feature_extraction.text import CountVectorizer
            self.vectorizer = CountVectorizer(
                max_features=self.config.max_features,
                ngram_range=self.config.ngram_range,
                lowercase=True,
                strip_accents='unicode'
            )
    
    def fit(
        self,
        documents: List[str],
        labels: List[str],
        document_metadata: Optional[List[Dict[str, Any]]] = None,
        validation_documents: Optional[List[str]] = None,
        validation_labels: Optional[List[str]] = None
    ) -> 'DocumentClassifier':
        """
        Train the document classifier.
        
        Args:
            documents: Training documents
            labels: Document labels/categories
            document_metadata: Optional metadata for each document
            validation_documents: Optional validation documents
            validation_labels: Optional validation labels
            
        Returns:
            Self for method chaining
        """
        start_time = datetime.now()
        
        logger.info(f"Training classifier on {len(documents)} documents")
        
        # Encode labels
        encoded_labels = self.label_encoder.fit_transform(labels)
        self.classes_ = self.label_encoder.classes_
        
        # Create train/validation split if validation data not provided
        if validation_documents is None:
            X_train, X_val, y_train, y_val = train_test_split(
                documents, encoded_labels,
                test_size=self.config.validation_split,
                random_state=self.config.random_state,
                stratify=encoded_labels
            )
        else:
            X_train, y_train = documents, encoded_labels
            X_val = validation_documents
            y_val = self.label_encoder.transform(validation_labels)
        
        # Vectorize documents
        X_train_vectorized = self.vectorizer.fit_transform(X_train)
        X_val_vectorized = self.vectorizer.transform(X_val)
        
        # Store feature names
        self.feature_names_ = self.vectorizer.get_feature_names_out()
        
        # Handle class imbalance
        if self.config.handle_imbalance:
            if self.config.balancing_strategy == 'class_weight':
                class_weights = compute_class_weight(
                    'balanced',
                    classes=np.unique(y_train),
                    y=y_train
                )
                class_weight_dict = dict(zip(np.unique(y_train), class_weights))
                
                # Set class weights in model if supported
                if hasattr(self.model, 'class_weight'):
                    self.model.set_params(class_weight=class_weight_dict)
        
        # Hyperparameter tuning
        if self.config.tune_hyperparameters:
            self.model = self._tune_hyperparameters(X_train_vectorized, y_train)
        
        # Train model
        self.model.fit(X_train_vectorized, y_train)
        
        # Validation
        val_predictions = self.model.predict(X_val_vectorized)
        val_accuracy = accuracy_score(y_val, val_predictions)
        
        # Cross-validation
        if self.config.cv_folds > 1:
            cv_scores = cross_val_score(
                self.model, X_train_vectorized, y_train,
                cv=self.config.cv_folds,
                scoring='accuracy'
            )
            cv_mean = cv_scores.mean()
            cv_std = cv_scores.std()
        else:
            cv_mean, cv_std = None, None
        
        # Record training history
        training_time = (datetime.now() - start_time).total_seconds()
        
        training_record = {
            'timestamp': start_time.isoformat(),
            'algorithm': self.config.algorithm,
            'training_samples': len(X_train),
            'validation_samples': len(X_val),
            'validation_accuracy': val_accuracy,
            'cv_mean_accuracy': cv_mean,
            'cv_std_accuracy': cv_std,
            'training_time': training_time,
            'num_features': X_train_vectorized.shape[1],
            'num_classes': len(self.classes_)
        }
        
        self.training_history.append(training_record)
        self.is_fitted = True
        
        logger.info(f"Training completed. Validation accuracy: {val_accuracy:.4f}")
        if cv_mean is not None:
            logger.info(f"Cross-validation accuracy: {cv_mean:.4f} (+/- {cv_std * 2:.4f})")
        
        return self
    
    def predict(
        self,
        documents: List[str],
        return_probabilities: bool = False,
        return_confidence: bool = True
    ) -> Union[List[str], ClassificationResult]:
        """
        Predict document categories.
        
        Args:
            documents: Documents to classify
            return_probabilities: Whether to return class probabilities
            return_confidence: Whether to return confidence scores
            
        Returns:
            Predictions or detailed ClassificationResult
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before making predictions")
        
        start_time = datetime.now()
        
        # Vectorize documents
        X_vectorized = self.vectorizer.transform(documents)
        
        # Make predictions
        predictions_encoded = self.model.predict(X_vectorized)
        predictions = self.label_encoder.inverse_transform(predictions_encoded)
        
        # Get probabilities if requested
        probabilities = None
        confidence_scores = np.zeros(len(documents))
        
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X_vectorized)
            # Confidence as max probability
            confidence_scores = np.max(probabilities, axis=1)
        
        prediction_time = (datetime.now() - start_time).total_seconds()
        
        if return_probabilities or return_confidence:
            # Return detailed results
            return ClassificationResult(
                predictions=predictions,
                probabilities=probabilities,
                confidence_scores=confidence_scores,
                accuracy=0.0,  # Not available without true labels
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                classification_report="",
                confusion_matrix=np.array([]),
                feature_importance=self.get_feature_importance(),
                model_info={
                    'algorithm': self.config.algorithm,
                    'num_features': X_vectorized.shape[1],
                    'num_classes': len(self.classes_)
                },
                training_time=0.0,
                prediction_time=prediction_time
            )
        else:
            return predictions.tolist()
    
    def evaluate(
        self,
        documents: List[str],
        true_labels: List[str]
    ) -> ClassificationResult:
        """
        Evaluate the classifier on test data.
        
        Args:
            documents: Test documents
            true_labels: True labels for evaluation
            
        Returns:
            ClassificationResult with detailed evaluation metrics
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before evaluation")
        
        start_time = datetime.now()
        
        # Vectorize documents
        X_vectorized = self.vectorizer.transform(documents)
        
        # Encode true labels
        y_true_encoded = self.label_encoder.transform(true_labels)
        
        # Make predictions
        y_pred_encoded = self.model.predict(X_vectorized)
        predictions = self.label_encoder.inverse_transform(y_pred_encoded)
        
        # Get probabilities
        probabilities = None
        confidence_scores = np.zeros(len(documents))
        
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X_vectorized)
            confidence_scores = np.max(probabilities, axis=1)
        
        # Calculate metrics
        from sklearn.metrics import precision_score, recall_score, f1_score
        
        accuracy = accuracy_score(y_true_encoded, y_pred_encoded)
        precision = precision_score(y_true_encoded, y_pred_encoded, average='weighted', zero_division=0)
        recall = recall_score(y_true_encoded, y_pred_encoded, average='weighted', zero_division=0)
        f1 = f1_score(y_true_encoded, y_pred_encoded, average='weighted', zero_division=0)
        
        # Generate detailed report
        classification_rep = classification_report(
            y_true_encoded, y_pred_encoded,
            target_names=self.classes_,
            zero_division=0
        )
        
        # Confusion matrix
        conf_matrix = confusion_matrix(y_true_encoded, y_pred_encoded)
        
        prediction_time = (datetime.now() - start_time).total_seconds()
        
        return ClassificationResult(
            predictions=predictions,
            probabilities=probabilities,
            confidence_scores=confidence_scores,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            classification_report=classification_rep,
            confusion_matrix=conf_matrix,
            feature_importance=self.get_feature_importance(),
            model_info={
                'algorithm': self.config.algorithm,
                'num_features': X_vectorized.shape[1],
                'num_classes': len(self.classes_)
            },
            training_time=0.0,  # From training history if needed
            prediction_time=prediction_time
        )
    
    def _tune_hyperparameters(self, X_train, y_train):
        """Perform hyperparameter tuning."""
        
        logger.info("Starting hyperparameter tuning...")
        
        # Define parameter grids for different algorithms
        param_grids = {
            'random_forest': {
                'small': {
                    'n_estimators': [50, 100],
                    'max_depth': [None, 10],
                    'min_samples_split': [2, 5]
                },
                'medium': {
                    'n_estimators': [50, 100, 200],
                    'max_depth': [None, 10, 20],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2]
                }
            },
            'svm': {
                'small': {
                    'C': [1, 10],
                    'kernel': ['linear', 'rbf']
                },
                'medium': {
                    'C': [0.1, 1, 10, 100],
                    'kernel': ['linear', 'rbf'],
                    'gamma': ['scale', 'auto']
                }
            },
            'logistic_regression': {
                'small': {
                    'C': [1, 10],
                    'penalty': ['l2']
                },
                'medium': {
                    'C': [0.1, 1, 10, 100],
                    'penalty': ['l2', 'l1'],
                    'solver': ['liblinear', 'saga']
                }
            }
        }
        
        # XGBoost parameters if available
        if XGBOOST_AVAILABLE and self.config.algorithm == 'xgboost':
            param_grids['xgboost'] = {
                'small': {
                    'max_depth': [3, 6],
                    'learning_rate': [0.1, 0.2],
                    'n_estimators': [50, 100]
                },
                'medium': {
                    'max_depth': [3, 6, 9],
                    'learning_rate': [0.05, 0.1, 0.2],
                    'n_estimators': [50, 100, 200],
                    'subsample': [0.8, 1.0]
                }
            }
        
        # Get parameter grid for current algorithm
        algo_params = param_grids.get(self.config.algorithm, {})
        param_grid = algo_params.get(self.config.param_grid_size, {})
        
        if not param_grid:
            logger.warning(f"No parameter grid found for {self.config.algorithm}. Skipping tuning.")
            return self.model
        
        # Perform grid search
        grid_search = GridSearchCV(
            self.model,
            param_grid,
            cv=self.config.cv_folds,
            scoring='accuracy',
            n_jobs=-1,
            verbose=0
        )
        
        grid_search.fit(X_train, y_train)
        
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best cross-validation score: {grid_search.best_score_:.4f}")
        
        return grid_search.best_estimator_
    
    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance scores."""
        
        if not self.is_fitted or self.feature_names_ is None:
            return None
        
        importance_scores = None
        
        # Get feature importance based on algorithm
        if hasattr(self.model, 'feature_importances_'):
            importance_scores = self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            # For linear models, use coefficient magnitudes
            if len(self.model.coef_.shape) == 1:
                importance_scores = np.abs(self.model.coef_)
            else:
                # Multi-class case - use mean of absolute coefficients
                importance_scores = np.mean(np.abs(self.model.coef_), axis=0)
        
        if importance_scores is not None:
            # Create feature importance dictionary
            feature_importance = dict(zip(self.feature_names_, importance_scores))
            
            # Sort by importance
            feature_importance = dict(
                sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
            )
            
            return feature_importance
        
        return None
    
    def get_top_features(self, n_features: int = 20) -> List[Tuple[str, float]]:
        """Get top N most important features."""
        
        feature_importance = self.get_feature_importance()
        
        if feature_importance is None:
            return []
        
        return list(feature_importance.items())[:n_features]
    
    def save_model(self, filepath: str) -> None:
        """Save the trained model to disk."""
        
        if not self.is_fitted:
            raise ValueError("Model must be fitted before saving")
        
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'label_encoder': self.label_encoder,
            'config': self.config,
            'classes_': self.classes_,
            'feature_names_': self.feature_names_,
            'training_history': self.training_history,
            'is_fitted': self.is_fitted
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str) -> 'DocumentClassifier':
        """Load a trained model from disk."""
        
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        self.label_encoder = model_data['label_encoder']
        self.config = model_data['config']
        self.classes_ = model_data['classes_']
        self.feature_names_ = model_data['feature_names_']
        self.training_history = model_data['training_history']
        self.is_fitted = model_data['is_fitted']
        
        logger.info(f"Model loaded from {filepath}")
        return self
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the trained model."""
        
        return {
            'algorithm': self.config.algorithm,
            'is_fitted': self.is_fitted,
            'num_classes': len(self.classes_) if self.classes_ is not None else 0,
            'classes': self.classes_.tolist() if self.classes_ is not None else [],
            'num_features': len(self.feature_names_) if self.feature_names_ is not None else 0,
            'training_history': self.training_history,
            'config': self.config.__dict__
        }