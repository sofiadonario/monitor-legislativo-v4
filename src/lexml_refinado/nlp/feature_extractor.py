#!/usr/bin/env python3
"""
Legal Feature Extractor for Brazilian Portuguese
===============================================

Advanced feature extraction from Brazilian legal and legislative documents
for machine learning and statistical analysis applications.

Features:
---------
- TF-IDF and n-gram feature extraction
- Legal-specific feature engineering
- Document structure and complexity features
- Temporal and jurisdictional features
- Thematic and semantic features
- Statistical and linguistic features

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0
"""

import re
import logging
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, date
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

@dataclass
class FeatureExtractionConfig:
    """Configuration for feature extraction."""
    
    # Text features
    include_tfidf: bool = True
    include_ngrams: bool = True
    max_features: int = 1000
    ngram_range: Tuple[int, int] = (1, 3)
    
    # Legal features
    include_legal_structure: bool = True
    include_legal_entities: bool = True
    include_legal_complexity: bool = True
    
    # Temporal features
    include_temporal: bool = True
    
    # Statistical features
    include_statistical: bool = True
    
    # Dimensionality reduction
    apply_svd: bool = False
    svd_components: int = 100
    
    # Normalization
    normalize_features: bool = True


class LegalFeatureExtractor:
    """
    Comprehensive feature extractor for Brazilian legal documents.
    """
    
    def __init__(self, config: Optional[FeatureExtractionConfig] = None):
        """
        Initialize the legal feature extractor.
        
        Args:
            config: Feature extraction configuration
        """
        self.config = config or FeatureExtractionConfig()
        
        # Initialize extractors
        self._initialize_extractors()
        
        # Load legal vocabularies and patterns
        self._load_legal_vocabularies()
        
        # Feature cache for fitted models
        self._feature_cache = {}
        
        logger.info("LegalFeatureExtractor initialized")
    
    def _initialize_extractors(self) -> None:
        """Initialize feature extraction models."""
        
        if self.config.include_tfidf:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=self.config.max_features,
                ngram_range=self.config.ngram_range,
                lowercase=True,
                strip_accents='unicode'
            )
        
        if self.config.include_ngrams:
            self.count_vectorizer = CountVectorizer(
                max_features=self.config.max_features,
                ngram_range=self.config.ngram_range,
                lowercase=True,
                strip_accents='unicode'
            )
        
        if self.config.apply_svd:
            self.svd = TruncatedSVD(
                n_components=self.config.svd_components,
                random_state=42
            )
        
        if self.config.normalize_features:
            self.scaler = StandardScaler()
    
    def _load_legal_vocabularies(self) -> None:
        """Load legal vocabularies and patterns."""
        
        # Legal document types
        self.legal_doc_types = {
            'lei', 'decreto', 'portaria', 'resolucao', 'instrucao_normativa',
            'medida_provisoria', 'emenda_constitucional', 'decreto_legislativo'
        }
        
        # Legal authorities
        self.legal_authorities = {
            'presidencia_republica', 'congresso_nacional', 'senado_federal',
            'camara_deputados', 'stf', 'stj', 'tst', 'tcu', 'cnj',
            'ministerio_publico', 'defensoria_publica', 'advocacia_geral_uniao'
        }
        
        # Transport-specific terms
        self.transport_terms = {
            'combustiveis': ['biodiesel', 'etanol', 'diesel', 'gasolina', 'gnv', 'hidrogenio'],
            'veiculos': ['caminhao', 'onibus', 'veiculo', 'automovel', 'motocicleta'],
            'infraestrutura': ['rodovia', 'estrada', 'porto', 'aeroporto', 'ferrovia'],
            'regulamentacao': ['contran', 'antt', 'denatran', 'detran', 'inmetro'],
            'meio_ambiente': ['emissoes', 'poluicao', 'sustentabilidade', 'carbono'],
            'tributacao': ['icms', 'ipi', 'pis', 'cofins', 'imposto']
        }
        
        # Complexity indicators
        self.complexity_indicators = {
            'conditional_terms': ['se', 'caso', 'quando', 'desde_que', 'salvo', 'exceto'],
            'reference_terms': ['conforme', 'segundo', 'de_acordo', 'nos_termos'],
            'modification_terms': ['alterado', 'revogado', 'incluido', 'vetado'],
            'technical_terms': ['estabelece', 'disciplina', 'regulamenta', 'institui']
        }
        
        # Legal structure patterns
        self.structure_patterns = {
            'artigo': r'\b(art(?:igo)?\.?)\s*(\d+)',
            'inciso': r'\b(inc(?:iso)?\.?)\s*([IVXLCDMivxlcdm]+|\d+)',
            'paragrafo': r'\b(§|par(?:ágrafo)?\.?)\s*(\d+)',
            'alinea': r'\b(alínea|al\.)\s*([a-z])',
            'capitulo': r'\b(cap(?:ítulo)?\.?)\s*([IVXLCDMivxlcdm]+|\d+)',
            'secao': r'\b(seção|sec\.)\s*([IVXLCDMivxlcdm]+|\d+)',
            'titulo': r'\b(título|tít\.)\s*([IVXLCDMivxlcdm]+|\d+)'
        }
    
    def extract_features(
        self,
        documents: Union[str, List[str]],
        document_metadata: Optional[List[Dict[str, Any]]] = None
    ) -> pd.DataFrame:
        """
        Extract comprehensive features from legal documents.
        
        Args:
            documents: Single document or list of documents
            document_metadata: Optional metadata for each document
            
        Returns:
            DataFrame with extracted features
        """
        # Ensure documents is a list
        if isinstance(documents, str):
            documents = [documents]
        
        if document_metadata is None:
            document_metadata = [{}] * len(documents)
        
        # Feature containers
        all_features = []
        
        for i, (doc, metadata) in enumerate(zip(documents, document_metadata)):
            doc_features = {}
            
            # Text-based features
            if self.config.include_tfidf or self.config.include_ngrams:
                text_features = self._extract_text_features(doc, i)
                doc_features.update(text_features)
            
            # Legal structure features
            if self.config.include_legal_structure:
                structure_features = self._extract_structure_features(doc)
                doc_features.update(structure_features)
            
            # Legal entity features
            if self.config.include_legal_entities:
                entity_features = self._extract_entity_features(doc)
                doc_features.update(entity_features)
            
            # Legal complexity features
            if self.config.include_legal_complexity:
                complexity_features = self._extract_complexity_features(doc)
                doc_features.update(complexity_features)
            
            # Temporal features
            if self.config.include_temporal:
                temporal_features = self._extract_temporal_features(doc, metadata)
                doc_features.update(temporal_features)
            
            # Statistical features
            if self.config.include_statistical:
                stats_features = self._extract_statistical_features(doc)
                doc_features.update(stats_features)
            
            # Thematic features
            thematic_features = self._extract_thematic_features(doc)
            doc_features.update(thematic_features)
            
            # Add document ID
            doc_features['document_id'] = metadata.get('id', f'doc_{i}')
            
            all_features.append(doc_features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(all_features)
        
        # Apply post-processing
        if self.config.apply_svd:
            features_df = self._apply_dimensionality_reduction(features_df)
        
        if self.config.normalize_features:
            features_df = self._normalize_features(features_df)
        
        return features_df
    
    def _extract_text_features(self, document: str, doc_index: int) -> Dict[str, Any]:
        """Extract TF-IDF and n-gram features."""
        features = {}
        
        if self.config.include_tfidf:
            # Fit or transform with TF-IDF
            if 'tfidf' not in self._feature_cache:
                # First document - fit the model
                tfidf_matrix = self.tfidf_vectorizer.fit_transform([document])
                self._feature_cache['tfidf'] = True
            else:
                # Subsequent documents - transform only
                tfidf_matrix = self.tfidf_vectorizer.transform([document])
            
            # Get feature names and values
            feature_names = self.tfidf_vectorizer.get_feature_names_out()
            tfidf_scores = tfidf_matrix.toarray()[0]
            
            # Add top features
            top_indices = np.argsort(tfidf_scores)[-50:]  # Top 50 features
            for idx in top_indices:
                if tfidf_scores[idx] > 0:
                    features[f'tfidf_{feature_names[idx]}'] = tfidf_scores[idx]
        
        if self.config.include_ngrams:
            # Similar process for count vectorizer
            if 'count' not in self._feature_cache:
                count_matrix = self.count_vectorizer.fit_transform([document])
                self._feature_cache['count'] = True
            else:
                count_matrix = self.count_vectorizer.transform([document])
            
            # Add n-gram counts
            feature_names = self.count_vectorizer.get_feature_names_out()
            counts = count_matrix.toarray()[0]
            
            # Add significant n-grams
            significant_indices = np.where(counts > 0)[0]
            for idx in significant_indices[:20]:  # Top 20 n-grams
                features[f'ngram_{feature_names[idx]}'] = counts[idx]
        
        return features
    
    def _extract_structure_features(self, document: str) -> Dict[str, Any]:
        """Extract legal document structure features."""
        features = {}
        
        # Count structural elements
        for element_type, pattern in self.structure_patterns.items():
            matches = re.findall(pattern, document, re.IGNORECASE)
            features[f'count_{element_type}'] = len(matches)
            
            # Extract numbers for numerical analysis
            if matches:
                numbers = []
                for match in matches:
                    if isinstance(match, tuple) and len(match) > 1:
                        try:
                            # Try to convert Roman numerals or numbers
                            num_str = match[1]
                            if num_str.isdigit():
                                numbers.append(int(num_str))
                        except (ValueError, IndexError):
                            continue
                
                if numbers:
                    features[f'max_{element_type}_number'] = max(numbers)
                    features[f'avg_{element_type}_number'] = np.mean(numbers)
        
        # Document organization complexity
        total_elements = sum(features.get(f'count_{elem}', 0) for elem in self.structure_patterns.keys())
        features['total_structural_elements'] = total_elements
        
        # Structure complexity score
        element_weights = {
            'artigo': 1.0, 'inciso': 0.5, 'paragrafo': 0.7, 'alinea': 0.3,
            'capitulo': 2.0, 'secao': 1.5, 'titulo': 3.0
        }
        
        complexity_score = sum(
            features.get(f'count_{elem}', 0) * weight
            for elem, weight in element_weights.items()
        )
        features['structural_complexity_score'] = complexity_score
        
        return features
    
    def _extract_entity_features(self, document: str) -> Dict[str, Any]:
        """Extract legal entity features."""
        features = {}
        
        # Count legal document types
        doc_lower = document.lower()
        for doc_type in self.legal_doc_types:
            pattern = doc_type.replace('_', r'\s+')
            count = len(re.findall(rf'\b{pattern}\b', doc_lower))
            features[f'entity_{doc_type}'] = count
        
        # Count legal authorities
        for authority in self.legal_authorities:
            pattern = authority.replace('_', r'\s+')
            count = len(re.findall(rf'\b{pattern}\b', doc_lower))
            features[f'authority_{authority}'] = count
        
        # Extract dates and temporal references
        date_patterns = [
            r'\d{1,2}/\d{1,2}/\d{4}',  # DD/MM/YYYY
            r'\d{4}-\d{2}-\d{2}',      # YYYY-MM-DD
            r'\d{1,2}\s+de\s+\w+\s+de\s+\d{4}'  # DD de Month de YYYY
        ]
        
        total_dates = 0
        for pattern in date_patterns:
            dates = re.findall(pattern, document)
            total_dates += len(dates)
        
        features['date_references'] = total_dates
        
        # Legal citation density
        word_count = len(document.split())
        if word_count > 0:
            features['legal_entity_density'] = sum(
                features.get(f'entity_{dt}', 0) for dt in self.legal_doc_types
            ) / word_count
        else:
            features['legal_entity_density'] = 0
        
        return features
    
    def _extract_complexity_features(self, document: str) -> Dict[str, Any]:
        """Extract legal complexity features."""
        features = {}
        
        doc_lower = document.lower()
        word_count = len(document.split())
        
        # Count complexity indicators
        for category, terms in self.complexity_indicators.items():
            total_count = 0
            for term in terms:
                pattern = term.replace('_', r'\s+')
                count = len(re.findall(rf'\b{pattern}\b', doc_lower))
                total_count += count
            
            features[f'complexity_{category}'] = total_count
            
            # Normalized by document length
            if word_count > 0:
                features[f'complexity_{category}_normalized'] = total_count / word_count
            else:
                features[f'complexity_{category}_normalized'] = 0
        
        # Sentence complexity (average sentence length)
        sentences = re.split(r'[.!?]+', document)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        if sentences:
            avg_sentence_length = np.mean([len(s.split()) for s in sentences])
            features['avg_sentence_length'] = avg_sentence_length
            features['sentence_count'] = len(sentences)
        else:
            features['avg_sentence_length'] = 0
            features['sentence_count'] = 0
        
        # Lexical diversity (unique words / total words)
        words = document.lower().split()
        if words:
            features['lexical_diversity'] = len(set(words)) / len(words)
        else:
            features['lexical_diversity'] = 0
        
        # Overall complexity score
        complexity_components = [
            features.get('complexity_conditional_terms_normalized', 0) * 0.3,
            features.get('complexity_reference_terms_normalized', 0) * 0.2,
            features.get('complexity_technical_terms_normalized', 0) * 0.2,
            (features.get('avg_sentence_length', 0) / 100) * 0.2,  # Normalized
            (1 - features.get('lexical_diversity', 0)) * 0.1  # High diversity = lower complexity
        ]
        
        features['overall_complexity_score'] = sum(complexity_components)
        
        return features
    
    def _extract_temporal_features(self, document: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract temporal features."""
        features = {}
        
        # Extract year from metadata or document
        doc_year = None
        if 'year' in metadata:
            doc_year = metadata['year']
        elif 'date' in metadata:
            try:
                doc_year = pd.to_datetime(metadata['date']).year
            except:
                pass
        
        # Try to extract year from document text
        if doc_year is None:
            year_matches = re.findall(r'\b(19|20)\d{2}\b', document)
            if year_matches:
                doc_year = int(max(year_matches))  # Use the most recent year
        
        if doc_year:
            features['document_year'] = doc_year
            features['document_age'] = datetime.now().year - doc_year
            
            # Temporal categories
            if doc_year >= 2020:
                features['temporal_period'] = 'recent'
            elif doc_year >= 2010:
                features['temporal_period'] = 'modern'
            elif doc_year >= 2000:
                features['temporal_period'] = 'contemporary'
            else:
                features['temporal_period'] = 'historical'
        else:
            features['document_year'] = 0
            features['document_age'] = 0
            features['temporal_period'] = 'unknown'
        
        # Seasonal patterns (if month available)
        if 'month' in metadata:
            features['document_month'] = metadata['month']
            
            if metadata['month'] in [12, 1, 2]:
                features['season'] = 'summer'
            elif metadata['month'] in [3, 4, 5]:
                features['season'] = 'autumn'
            elif metadata['month'] in [6, 7, 8]:
                features['season'] = 'winter'
            else:
                features['season'] = 'spring'
        else:
            features['document_month'] = 0
            features['season'] = 'unknown'
        
        return features
    
    def _extract_statistical_features(self, document: str) -> Dict[str, Any]:
        """Extract statistical features."""
        features = {}
        
        # Basic text statistics
        words = document.split()
        chars = list(document)
        
        features['word_count'] = len(words)
        features['char_count'] = len(chars)
        features['unique_word_count'] = len(set(word.lower() for word in words))
        
        # Word length statistics
        if words:
            word_lengths = [len(word) for word in words]
            features['avg_word_length'] = np.mean(word_lengths)
            features['std_word_length'] = np.std(word_lengths)
            features['max_word_length'] = max(word_lengths)
            features['min_word_length'] = min(word_lengths)
        else:
            features.update({
                'avg_word_length': 0, 'std_word_length': 0,
                'max_word_length': 0, 'min_word_length': 0
            })
        
        # Character frequency analysis
        char_counter = Counter(chars)
        total_chars = sum(char_counter.values())
        
        if total_chars > 0:
            # Vowel/consonant ratio
            vowels = 'aeiouáéíóúâêîôûãõç'
            vowel_count = sum(char_counter.get(v, 0) for v in vowels)
            features['vowel_ratio'] = vowel_count / total_chars
            
            # Punctuation ratio
            punctuation = '.,;:!?()-[]{}"\''
            punct_count = sum(char_counter.get(p, 0) for p in punctuation)
            features['punctuation_ratio'] = punct_count / total_chars
            
            # Digit ratio
            digit_count = sum(char_counter.get(str(d), 0) for d in range(10))
            features['digit_ratio'] = digit_count / total_chars
        else:
            features.update({
                'vowel_ratio': 0, 'punctuation_ratio': 0, 'digit_ratio': 0
            })
        
        # Readability approximation (adapted for Portuguese legal texts)
        sentences = re.split(r'[.!?]+', document)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        if sentences and words:
            avg_words_per_sentence = len(words) / len(sentences)
            # Simplified syllable count (vowel groups)
            vowel_groups = len(re.findall(r'[aeiouáéíóúâêîôûãõç]+', document.lower()))
            avg_syllables_per_word = vowel_groups / len(words) if words else 0
            
            # Adapted Flesch formula
            readability = 248.835 - (1.015 * avg_words_per_sentence) - (84.6 * avg_syllables_per_word)
            features['readability_score'] = max(0, min(100, readability))
        else:
            features['readability_score'] = 0
        
        return features
    
    def _extract_thematic_features(self, document: str) -> Dict[str, Any]:
        """Extract thematic features specific to transport legislation."""
        features = {}
        
        doc_lower = document.lower()
        word_count = len(document.split())
        
        # Count transport-related themes
        for theme, terms in self.transport_terms.items():
            theme_count = 0
            for term in terms:
                count = len(re.findall(rf'\b{term}\b', doc_lower))
                theme_count += count
            
            features[f'theme_{theme}_count'] = theme_count
            
            # Normalized by document length
            if word_count > 0:
                features[f'theme_{theme}_density'] = theme_count / word_count
            else:
                features[f'theme_{theme}_density'] = 0
        
        # Primary theme identification
        theme_scores = {
            theme: features.get(f'theme_{theme}_density', 0)
            for theme in self.transport_terms.keys()
        }
        
        if theme_scores and max(theme_scores.values()) > 0:
            primary_theme = max(theme_scores, key=theme_scores.get)
            features['primary_theme'] = primary_theme
            features['primary_theme_score'] = theme_scores[primary_theme]
        else:
            features['primary_theme'] = 'general'
            features['primary_theme_score'] = 0
        
        # Thematic diversity
        active_themes = sum(1 for score in theme_scores.values() if score > 0)
        features['thematic_diversity'] = active_themes / len(self.transport_terms)
        
        return features
    
    def _apply_dimensionality_reduction(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Apply SVD for dimensionality reduction."""
        # Separate numeric and non-numeric columns
        numeric_cols = features_df.select_dtypes(include=[np.number]).columns
        non_numeric_cols = features_df.select_dtypes(exclude=[np.number]).columns
        
        if len(numeric_cols) == 0:
            return features_df
        
        # Apply SVD to numeric features
        numeric_data = features_df[numeric_cols].fillna(0)
        
        if hasattr(self.svd, 'components_'):
            # Transform with fitted SVD
            reduced_data = self.svd.transform(numeric_data)
        else:
            # Fit and transform
            reduced_data = self.svd.fit_transform(numeric_data)
        
        # Create new DataFrame with reduced dimensions
        reduced_df = pd.DataFrame(
            reduced_data,
            columns=[f'svd_component_{i}' for i in range(reduced_data.shape[1])],
            index=features_df.index
        )
        
        # Add back non-numeric columns
        for col in non_numeric_cols:
            reduced_df[col] = features_df[col]
        
        return reduced_df
    
    def _normalize_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Normalize numeric features."""
        # Separate numeric and non-numeric columns
        numeric_cols = features_df.select_dtypes(include=[np.number]).columns
        non_numeric_cols = features_df.select_dtypes(exclude=[np.number]).columns
        
        if len(numeric_cols) == 0:
            return features_df
        
        # Normalize numeric features
        numeric_data = features_df[numeric_cols].fillna(0)
        
        if hasattr(self.scaler, 'scale_'):
            # Transform with fitted scaler
            normalized_data = self.scaler.transform(numeric_data)
        else:
            # Fit and transform
            normalized_data = self.scaler.fit_transform(numeric_data)
        
        # Create new DataFrame
        normalized_df = pd.DataFrame(
            normalized_data,
            columns=numeric_cols,
            index=features_df.index
        )
        
        # Add back non-numeric columns
        for col in non_numeric_cols:
            normalized_df[col] = features_df[col]
        
        return normalized_df
    
    def get_feature_importance(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Calculate feature importance statistics."""
        numeric_features = features_df.select_dtypes(include=[np.number])
        
        importance_stats = []
        
        for col in numeric_features.columns:
            stats = {
                'feature': col,
                'mean': numeric_features[col].mean(),
                'std': numeric_features[col].std(),
                'variance': numeric_features[col].var(),
                'min': numeric_features[col].min(),
                'max': numeric_features[col].max(),
                'non_zero_count': (numeric_features[col] != 0).sum(),
                'non_zero_ratio': (numeric_features[col] != 0).mean()
            }
            importance_stats.append(stats)
        
        importance_df = pd.DataFrame(importance_stats)
        
        # Sort by variance (high variance = more informative)
        importance_df = importance_df.sort_values('variance', ascending=False)
        
        return importance_df