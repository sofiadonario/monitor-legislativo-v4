#!/usr/bin/env python3
"""
Brazilian Legal NLP Pipeline
============================

Main NLP pipeline specialized for Brazilian Portuguese legal and legislative texts.
Provides comprehensive text analysis capabilities optimized for legal document processing.

Features:
---------
- Legal text preprocessing and normalization
- POS tagging with legal terminology support
- Named Entity Recognition for legal entities
- Topic modeling and thematic analysis
- Legal document classification
- Text similarity and clustering
- Statistical analysis of legal corpora

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0
"""

import re
import logging
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime

import pandas as pd
import numpy as np
from collections import Counter, defaultdict

# NLP libraries
try:
    import spacy
    from spacy import displacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False

try:
    import nltk
    from nltk.tokenize import sent_tokenize, word_tokenize
    from nltk.corpus import stopwords
    from nltk.stem import SnowballStemmer
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False

# Text preprocessing
from unidecode import unidecode

# Statistical analysis
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation
from sklearn.metrics.pairwise import cosine_similarity

# Local imports
from .text_preprocessor import LegalTextPreprocessor
from .feature_extractor import LegalFeatureExtractor

logger = logging.getLogger(__name__)

@dataclass
class NLPAnalysisResult:
    """Container for NLP analysis results."""
    
    # Basic text statistics
    text_length: int
    sentence_count: int
    word_count: int
    unique_words: int
    
    # Legal-specific features
    legal_entities: Dict[str, List[str]]
    legal_references: List[str]
    regulatory_complexity: float
    
    # Topic analysis
    primary_topics: List[str]
    topic_distribution: Dict[str, float]
    
    # Linguistic features
    pos_tags: Dict[str, int]
    readability_score: float
    
    # Metadata
    analysis_timestamp: str
    processing_time: float


class BrazilianLegalNLP:
    """
    Comprehensive NLP pipeline for Brazilian Portuguese legal texts.
    """
    
    def __init__(
        self,
        language: str = 'pt',
        enabled_components: Optional[List[str]] = None,
        load_models: bool = True,
        cache_dir: Optional[str] = None
    ):
        """
        Initialize the Brazilian Legal NLP pipeline.
        
        Args:
            language: Language code (default: 'pt' for Portuguese)
            enabled_components: List of components to enable
            load_models: Whether to load ML models immediately
            cache_dir: Directory for caching models and data
        """
        self.language = language
        self.cache_dir = cache_dir
        
        # Default enabled components
        if enabled_components is None:
            enabled_components = [
                'preprocessor', 'tokenizer', 'pos_tagger', 
                'entity_recognizer', 'topic_analyzer'
            ]
        
        self.enabled_components = enabled_components
        
        # Initialize components
        self._initialize_components()
        
        # Load models if requested
        if load_models:
            self._load_models()
        
        # Legal vocabulary and patterns
        self._load_legal_vocabulary()
        
        logger.info(f"BrazilianLegalNLP initialized with components: {enabled_components}")
    
    def _initialize_components(self) -> None:
        """Initialize NLP components based on available libraries."""
        
        # Text preprocessor
        if 'preprocessor' in self.enabled_components:
            self.preprocessor = LegalTextPreprocessor()
        
        # Feature extractor
        if 'feature_extractor' in self.enabled_components:
            self.feature_extractor = LegalFeatureExtractor()
        
        # SpaCy components
        if SPACY_AVAILABLE and any(comp in self.enabled_components 
                                  for comp in ['pos_tagger', 'entity_recognizer']):
            try:
                # Try to load Portuguese model
                self.nlp = spacy.load("pt_core_news_sm")
                logger.info("Loaded SpaCy Portuguese model")
            except OSError:
                logger.warning("SpaCy Portuguese model not found. Using blank model.")
                self.nlp = spacy.blank("pt")
        
        # NLTK components
        if NLTK_AVAILABLE:
            try:
                self.stemmer = SnowballStemmer('portuguese')
                self.stop_words = set(stopwords.words('portuguese'))
                logger.info("Loaded NLTK Portuguese resources")
            except LookupError:
                logger.warning("NLTK Portuguese resources not found. Download required.")
                self.stemmer = None
                self.stop_words = set()
    
    def _load_models(self) -> None:
        """Load pre-trained models for analysis."""
        
        # Topic modeling components
        if 'topic_analyzer' in self.enabled_components:
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words=list(self.stop_words) if hasattr(self, 'stop_words') else None,
                ngram_range=(1, 2)
            )
            
            self.topic_model = LatentDirichletAllocation(
                n_components=10,
                random_state=42
            )
            
        logger.info("NLP models loaded successfully")
    
    def _load_legal_vocabulary(self) -> None:
        """Load legal vocabulary and patterns for Brazilian legal texts."""
        
        # Legal document types
        self.legal_document_types = {
            'lei': r'\blei\s+n[ºª°]?\s*\d+',
            'decreto': r'\bdecreto\s+n[ºª°]?\s*\d+',
            'portaria': r'\bportaria\s+n[ºª°]?\s*\d+',
            'resolucao': r'\bresolução\s+n[ºª°]?\s*\d+',
            'instrucao_normativa': r'\binstrução\s+normativa\s+n[ºª°]?\s*\d+',
            'medida_provisoria': r'\bmedida\s+provisória\s+n[ºª°]?\s*\d+',
            'emenda_constitucional': r'\bemenda\s+constitucional\s+n[ºª°]?\s*\d+'
        }
        
        # Legal institutions
        self.legal_institutions = {
            'supremo_tribunal_federal', 'stf', 'superior_tribunal_justica', 'stj',
            'tribunal_superior_trabalho', 'tst', 'conselho_nacional_justica', 'cnj',
            'ministerio_publico', 'defensoria_publica', 'advocacia_geral_uniao',
            'tribunal_contas_uniao', 'tcu', 'congresso_nacional', 'senado_federal',
            'camara_deputados', 'presidencia_republica'
        }
        
        # Legal themes for transport sector
        self.transport_themes = {
            'combustiveis': ['biodiesel', 'etanol', 'diesel', 'gasolina', 'gnv', 'hidrogênio'],
            'veiculos': ['caminhão', 'ônibus', 'veículo', 'automóvel', 'motocicleta'],
            'infraestrutura': ['rodovia', 'estrada', 'porto', 'aeroporto', 'ferrovia'],
            'regulamentacao': ['contran', 'antt', 'denatran', 'detran', 'inmetro'],
            'meio_ambiente': ['emissões', 'poluição', 'sustentabilidade', 'carbono'],
            'tributacao': ['icms', 'ipi', 'pis', 'cofins', 'imposto']
        }
        
        # Legal stopwords (domain-specific)
        self.legal_stopwords = {
            'art', 'artigo', 'inc', 'inciso', 'par', 'parágrafo', 'alínea',
            'caput', 'lei', 'decreto', 'portaria', 'considerando', 'resolve',
            'fica', 'revogado', 'alterado', 'incluído', 'vetado'
        }
        
        # Combine with standard stopwords
        if hasattr(self, 'stop_words'):
            self.stop_words.update(self.legal_stopwords)
    
    def analyze_text(
        self, 
        text: str, 
        analysis_type: str = 'comprehensive'
    ) -> NLPAnalysisResult:
        """
        Perform comprehensive NLP analysis on legal text.
        
        Args:
            text: Input text to analyze
            analysis_type: Type of analysis ('basic', 'comprehensive', 'advanced')
            
        Returns:
            NLPAnalysisResult object with analysis results
        """
        start_time = datetime.now()
        
        # Preprocess text
        if hasattr(self, 'preprocessor'):
            processed_text = self.preprocessor.preprocess(text)
        else:
            processed_text = self._basic_preprocessing(text)
        
        # Basic text statistics
        text_stats = self._calculate_text_statistics(processed_text)
        
        # Legal entity extraction
        legal_entities = self._extract_legal_entities(text)
        
        # Legal references
        legal_references = self._extract_legal_references(text)
        
        # Regulatory complexity assessment
        complexity = self._assess_regulatory_complexity(text)
        
        # Topic analysis
        if analysis_type in ['comprehensive', 'advanced']:
            topics, topic_dist = self._analyze_topics([text])
        else:
            topics, topic_dist = [], {}
        
        # POS tagging
        pos_tags = self._pos_tag_analysis(processed_text)
        
        # Readability assessment
        readability = self._calculate_readability(text)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds()
        
        return NLPAnalysisResult(
            text_length=len(text),
            sentence_count=text_stats['sentences'],
            word_count=text_stats['words'],
            unique_words=text_stats['unique_words'],
            legal_entities=legal_entities,
            legal_references=legal_references,
            regulatory_complexity=complexity,
            primary_topics=topics[:5],  # Top 5 topics
            topic_distribution=topic_dist,
            pos_tags=pos_tags,
            readability_score=readability,
            analysis_timestamp=datetime.now().isoformat(),
            processing_time=processing_time
        )
    
    def analyze_corpus(
        self,
        documents: List[str],
        document_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a corpus of legal documents for patterns and insights.
        
        Args:
            documents: List of document texts
            document_ids: Optional list of document identifiers
            
        Returns:
            Comprehensive corpus analysis results
        """
        if document_ids is None:
            document_ids = [f"doc_{i}" for i in range(len(documents))]
        
        # Individual document analyses
        document_analyses = []
        for i, doc in enumerate(documents):
            analysis = self.analyze_text(doc, analysis_type='basic')
            document_analyses.append({
                'id': document_ids[i],
                'analysis': analysis
            })
        
        # Corpus-level statistics
        corpus_stats = self._calculate_corpus_statistics(document_analyses)
        
        # Topic modeling across corpus
        corpus_topics = self._analyze_topics(documents)
        
        # Legal entity frequency analysis
        entity_frequency = self._analyze_entity_frequency(document_analyses)
        
        # Document similarity matrix
        similarity_matrix = self._calculate_document_similarities(documents)
        
        return {
            'corpus_statistics': corpus_stats,
            'document_analyses': document_analyses,
            'corpus_topics': corpus_topics,
            'entity_frequency': entity_frequency,
            'similarity_matrix': similarity_matrix,
            'analysis_timestamp': datetime.now().isoformat(),
            'total_documents': len(documents)
        }
    
    def _basic_preprocessing(self, text: str) -> str:
        """Basic text preprocessing when full preprocessor not available."""
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Normalize case
        text = text.lower()
        
        # Remove special characters (keep Portuguese chars)
        text = re.sub(r'[^\w\sáéíóúâêîôûãõç]', ' ', text)
        
        return text
    
    def _calculate_text_statistics(self, text: str) -> Dict[str, int]:
        """Calculate basic text statistics."""
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        
        return {
            'words': len(words),
            'sentences': len([s for s in sentences if s.strip()]),
            'unique_words': len(set(words)),
            'characters': len(text)
        }
    
    def _extract_legal_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract legal entities using pattern matching."""
        entities = defaultdict(list)
        
        # Extract legal document references
        for doc_type, pattern in self.legal_document_types.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                entities['legal_documents'].extend(matches)
        
        # Extract institutions
        text_lower = text.lower()
        for institution in self.legal_institutions:
            if institution in text_lower:
                entities['institutions'].append(institution)
        
        # Extract dates
        date_patterns = [
            r'\d{1,2}\s+de\s+\w+\s+de\s+\d{4}',  # "14 de junho de 2023"
            r'\d{1,2}/\d{1,2}/\d{4}',             # "14/06/2023"
            r'\d{4}-\d{2}-\d{2}'                  # "2023-06-14"
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, text)
            entities['dates'].extend(matches)
        
        return dict(entities)
    
    def _extract_legal_references(self, text: str) -> List[str]:
        """Extract legal references and citations."""
        references = []
        
        # Look for article references
        article_pattern = r'art(?:igo)?\.?\s*\d+(?:[º°ª])?(?:\s*[-,]\s*\d+(?:[º°ª])?)*'
        articles = re.findall(article_pattern, text, re.IGNORECASE)
        references.extend(articles)
        
        # Look for law references
        law_pattern = r'lei\s+n[º°ª]?\s*\d+(?:[,./]\d+)*(?:\s*de\s+\d{4})?'
        laws = re.findall(law_pattern, text, re.IGNORECASE)
        references.extend(laws)
        
        return references
    
    def _assess_regulatory_complexity(self, text: str) -> float:
        """Assess regulatory complexity of the text."""
        complexity_indicators = {
            'legal_references': len(self._extract_legal_references(text)),
            'conditional_language': len(re.findall(r'\b(se|caso|quando|desde que|salvo|exceto)\b', 
                                                  text, re.IGNORECASE)),
            'technical_terms': len(re.findall(r'\b\w{10,}\b', text)),  # Long technical words
            'nested_clauses': len(re.findall(r'[,;]', text)),
            'legal_jargon': len(re.findall(r'\b(considerando|resolve|fica|revogado|alterado)\b', 
                                          text, re.IGNORECASE))
        }
        
        # Calculate weighted complexity score
        weights = {
            'legal_references': 0.3,
            'conditional_language': 0.2,
            'technical_terms': 0.2,
            'nested_clauses': 0.1,
            'legal_jargon': 0.2
        }
        
        text_length = len(text.split())
        normalized_complexity = sum(
            (count / max(text_length / 100, 1)) * weight
            for (indicator, count), (_, weight) in 
            zip(complexity_indicators.items(), weights.items())
        )
        
        # Scale to 0-1 range
        return min(normalized_complexity / 10, 1.0)
    
    def _analyze_topics(self, documents: List[str]) -> Tuple[List[str], Dict[str, float]]:
        """Perform topic analysis on documents."""
        if not hasattr(self, 'vectorizer') or not hasattr(self, 'topic_model'):
            return [], {}
        
        try:
            # Vectorize documents
            doc_term_matrix = self.vectorizer.fit_transform(documents)
            
            # Fit topic model
            self.topic_model.fit(doc_term_matrix)
            
            # Get top topics
            feature_names = self.vectorizer.get_feature_names_out()
            top_topics = []
            topic_distribution = {}
            
            for topic_idx, topic in enumerate(self.topic_model.components_):
                top_words_idx = topic.argsort()[-5:][::-1]  # Top 5 words
                top_words = [feature_names[i] for i in top_words_idx]
                topic_name = "_".join(top_words[:3])
                top_topics.append(topic_name)
                topic_distribution[f"topic_{topic_idx}"] = float(topic.sum())
            
            return top_topics, topic_distribution
            
        except Exception as e:
            logger.warning(f"Topic analysis failed: {e}")
            return [], {}
    
    def _pos_tag_analysis(self, text: str) -> Dict[str, int]:
        """Perform POS tagging analysis."""
        if SPACY_AVAILABLE and hasattr(self, 'nlp'):
            try:
                doc = self.nlp(text)
                pos_counts = Counter(token.pos_ for token in doc if not token.is_space)
                return dict(pos_counts)
            except Exception as e:
                logger.warning(f"SpaCy POS tagging failed: {e}")
        
        # Fallback to basic analysis
        words = text.split()
        return {'WORD_COUNT': len(words)}
    
    def _calculate_readability(self, text: str) -> float:
        """Calculate readability score adapted for legal texts."""
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        sentences = [s for s in sentences if s.strip()]
        
        if not sentences or not words:
            return 0.0
        
        # Average words per sentence
        avg_words_per_sentence = len(words) / len(sentences)
        
        # Estimate syllables (simplified for Portuguese)
        vowel_pattern = r'[aeiouáéíóúâêîôûãõç]'
        total_syllables = sum(len(re.findall(vowel_pattern, word, re.IGNORECASE)) 
                             for word in words)
        avg_syllables_per_word = total_syllables / len(words) if words else 0
        
        # Adapted Flesch formula for Portuguese legal texts
        # (Higher scores = more readable)
        readability = 248.835 - (1.015 * avg_words_per_sentence) - (84.6 * avg_syllables_per_word)
        
        # Normalize to 0-1 scale (inverted, so higher = more complex)
        normalized_score = max(0, min(1, (100 - max(0, readability)) / 100))
        
        return normalized_score
    
    def _calculate_corpus_statistics(self, document_analyses: List[Dict]) -> Dict[str, Any]:
        """Calculate corpus-level statistics."""
        analyses = [doc['analysis'] for doc in document_analyses]
        
        word_counts = [a.word_count for a in analyses]
        sentence_counts = [a.sentence_count for a in analyses]
        complexity_scores = [a.regulatory_complexity for a in analyses]
        readability_scores = [a.readability_score for a in analyses]
        
        return {
            'total_documents': len(analyses),
            'total_words': sum(word_counts),
            'avg_words_per_document': np.mean(word_counts),
            'avg_sentences_per_document': np.mean(sentence_counts),
            'avg_regulatory_complexity': np.mean(complexity_scores),
            'avg_readability_score': np.mean(readability_scores),
            'complexity_distribution': {
                'low': sum(1 for score in complexity_scores if score < 0.3),
                'medium': sum(1 for score in complexity_scores if 0.3 <= score < 0.7),
                'high': sum(1 for score in complexity_scores if score >= 0.7)
            }
        }
    
    def _analyze_entity_frequency(self, document_analyses: List[Dict]) -> Dict[str, Any]:
        """Analyze frequency of legal entities across the corpus."""
        all_entities = defaultdict(list)
        
        for doc in document_analyses:
            entities = doc['analysis'].legal_entities
            for entity_type, entity_list in entities.items():
                all_entities[entity_type].extend(entity_list)
        
        # Calculate frequencies
        entity_frequencies = {}
        for entity_type, entity_list in all_entities.items():
            entity_frequencies[entity_type] = dict(Counter(entity_list).most_common(10))
        
        return entity_frequencies
    
    def _calculate_document_similarities(self, documents: List[str]) -> np.ndarray:
        """Calculate pairwise document similarities."""
        try:
            # Use TF-IDF for similarity calculation
            vectorizer = TfidfVectorizer(stop_words=list(self.stop_words) if hasattr(self, 'stop_words') else None)
            tfidf_matrix = vectorizer.fit_transform(documents)
            
            # Calculate cosine similarity
            similarity_matrix = cosine_similarity(tfidf_matrix)
            
            return similarity_matrix.tolist()
            
        except Exception as e:
            logger.warning(f"Similarity calculation failed: {e}")
            # Return identity matrix as fallback
            n_docs = len(documents)
            return np.eye(n_docs).tolist()
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Get information about available NLP capabilities."""
        return {
            'spacy_available': SPACY_AVAILABLE and hasattr(self, 'nlp'),
            'nltk_available': NLTK_AVAILABLE and hasattr(self, 'stemmer'),
            'topic_modeling': hasattr(self, 'topic_model'),
            'preprocessor': hasattr(self, 'preprocessor'),
            'feature_extractor': hasattr(self, 'feature_extractor'),
            'legal_vocabulary': hasattr(self, 'legal_document_types')
        }