"""
Text Analysis Engine for Brazilian Legislative Documents
======================================================

Lightweight ML-powered text analysis specifically designed for Brazilian legislative documents
with a focus on transport-related legislation. Uses scikit-learn and basic NLP techniques.

Features:
- Document classification for transport legislation
- Text similarity detection using TF-IDF
- Keyword extraction with transport domain knowledge
- Document clustering and categorization
- Brazilian Portuguese text preprocessing
"""

import re
import string
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from collections import Counter
import unicodedata

# Optional imports with fallbacks
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.cluster import KMeans
    from sklearn.decomposition import TruncatedSVD
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    # Mock classes for when sklearn is not available
    class TfidfVectorizer:
        def __init__(self, **kwargs): pass
        def fit_transform(self, docs): return []
        def transform(self, docs): return []
    class KMeans:
        def __init__(self, **kwargs): pass
        def fit_predict(self, X): return []
    def cosine_similarity(X, Y=None): return []

logger = logging.getLogger(__name__)


@dataclass
class DocumentAnalysis:
    """Analysis results for a legislative document"""
    transport_score: float  # 0-1 probability of being transport-related
    category: str  # Predicted category
    keywords: List[str]  # Extracted keywords
    similarity_scores: Dict[str, float]  # Similarity to other documents
    cluster_id: Optional[int] = None  # Cluster assignment
    confidence: float = 0.0  # Overall confidence score


@dataclass
class TextStats:
    """Basic text statistics"""
    word_count: int
    sentence_count: int
    avg_word_length: float
    complexity_score: float
    transport_keywords_found: int


class BrazilianTextPreprocessor:
    """Brazilian Portuguese text preprocessing for legislative documents"""
    
    def __init__(self):
        # Common Portuguese stopwords
        self.stopwords = {
            'a', 'ao', 'aos', 'aquela', 'aquelas', 'aquele', 'aqueles', 'aquilo', 'as',
            'até', 'com', 'como', 'da', 'das', 'de', 'dela', 'delas', 'dele', 'deles',
            'depois', 'do', 'dos', 'e', 'ela', 'elas', 'ele', 'eles', 'em', 'entre',
            'essa', 'essas', 'esse', 'esses', 'esta', 'estamos', 'estas', 'estava',
            'estavam', 'este', 'esteja', 'estejam', 'estejamos', 'estes', 'esteve',
            'estive', 'estivemos', 'estiver', 'estivera', 'estiveram', 'estiverem',
            'estivermos', 'estivesse', 'estivessem', 'estivéramos', 'estivéssemos',
            'estou', 'está', 'estão', 'eu', 'foi', 'fomos', 'for', 'fora', 'foram',
            'forem', 'formos', 'fosse', 'fossem', 'fui', 'fôramos', 'fôssemos',
            'haja', 'hajam', 'hajamos', 'havemos', 'havia', 'hei', 'houve', 'houvemos',
            'houver', 'houvera', 'houveram', 'houverei', 'houverem', 'houveremos',
            'houveria', 'houveriam', 'houveríamos', 'houverá', 'houverão', 'houvermos',
            'houvesse', 'houvessem', 'houvéramos', 'houvéssemos', 'há', 'hão', 'isso',
            'isto', 'já', 'lhe', 'lhes', 'mais', 'mas', 'me', 'mesmo', 'meu', 'meus',
            'minha', 'minhas', 'muito', 'na', 'nas', 'nem', 'no', 'nos', 'nossa',
            'nossas', 'nosso', 'nossos', 'num', 'numa', 'não', 'nós', 'o', 'os', 'ou',
            'para', 'pela', 'pelas', 'pelo', 'pelos', 'por', 'qual', 'quando', 'que',
            'quem', 'se', 'seja', 'sejam', 'sejamos', 'sem', 'ser', 'será', 'serão',
            'serei', 'seremos', 'seria', 'seriam', 'seríamos', 'sou', 'sua', 'suas',
            'são', 'só', 'também', 'te', 'tem', 'temos', 'tenha', 'tenham', 'tenhamos',
            'tenho', 'ter', 'terá', 'terão', 'terei', 'teremos', 'teria', 'teriam',
            'teríamos', 'teu', 'teus', 'teve', 'tinha', 'tinham', 'tive', 'tivemos',
            'tiver', 'tivera', 'tiveram', 'tiverem', 'tivermos', 'tivesse', 'tivessem',
            'tivéramos', 'tivéssemos', 'tu', 'tua', 'tuas', 'tém', 'tínhamos', 'um',
            'uma', 'você', 'vocês', 'vos', 'à', 'às', 'éramos', 'é'
        }
        
        # Legislative stopwords
        self.legislative_stopwords = {
            'lei', 'decreto', 'portaria', 'resolução', 'artigo', 'art', 'inciso',
            'alínea', 'parágrafo', 'caput', 'federal', 'nacional', 'brasil',
            'república', 'federativa', 'união', 'estado', 'município', 'poder',
            'executivo', 'legislativo', 'judiciário', 'público', 'privado',
            'considera', 'considerando', 'resolve', 'determina', 'estabelece',
            'dispõe', 'regulamenta', 'revoga', 'altera', 'acrescenta'
        }
        
        self.all_stopwords = self.stopwords | self.legislative_stopwords
    
    def normalize_text(self, text: str) -> str:
        """Normalize Brazilian Portuguese text"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove accents but keep ç
        text = unicodedata.normalize('NFD', text)
        text = ''.join(c for c in text if unicodedata.category(c) != 'Mn' or c == 'ç')
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def tokenize(self, text: str) -> List[str]:
        """Tokenize text into words, removing punctuation and stopwords"""
        if not text:
            return []
        
        # Normalize first
        text = self.normalize_text(text)
        
        # Remove punctuation and split
        text = re.sub(f'[{re.escape(string.punctuation)}]', ' ', text)
        words = text.split()
        
        # Filter stopwords and short words
        words = [
            word for word in words 
            if len(word) >= 3 and word not in self.all_stopwords
        ]
        
        return words
    
    def extract_phrases(self, text: str, min_length: int = 2, max_length: int = 4) -> List[str]:
        """Extract meaningful phrases from text"""
        if not text:
            return []
        
        words = self.tokenize(text)
        phrases = []
        
        # Extract n-grams
        for n in range(min_length, max_length + 1):
            for i in range(len(words) - n + 1):
                phrase = ' '.join(words[i:i + n])
                phrases.append(phrase)
        
        return phrases


class TransportClassifier:
    """Transport legislation classifier using keyword-based and ML approaches"""
    
    def __init__(self):
        # Transport-related keywords with weights
        self.transport_keywords = {
            # Core transport terms
            'transporte': 3.0, 'transportes': 3.0, 'mobilidade': 3.0,
            'trânsito': 2.5, 'trafego': 2.5, 'tráfego': 2.5,
            
            # Modal keywords
            'rodoviário': 2.5, 'rodoviaria': 2.5, 'rodovia': 2.5,
            'ferroviário': 2.5, 'ferroviaria': 2.5, 'ferrovia': 2.5,
            'aeroportuário': 2.5, 'aeroporto': 2.5, 'aviação': 2.5, 'aéreo': 2.5,
            'portuário': 2.5, 'porto': 2.5, 'navegação': 2.5, 'aquaviário': 2.5,
            'marítimo': 2.5, 'fluvial': 2.5,
            
            # Infrastructure
            'infraestrutura': 2.0, 'via': 2.0, 'vias': 2.0, 'estrada': 2.0,
            'autoestrada': 2.0, 'terminal': 2.0, 'estação': 2.0,
            
            # Vehicles and equipment
            'veículo': 2.0, 'veiculo': 2.0, 'veículos': 2.0, 'veiculos': 2.0,
            'automóvel': 1.5, 'automovel': 1.5, 'caminhão': 1.5, 'caminhao': 1.5,
            'ônibus': 1.5, 'onibus': 1.5, 'trem': 1.5, 'avião': 1.5, 'aviao': 1.5,
            'navio': 1.5, 'embarcação': 1.5, 'embarcacao': 1.5,
            
            # Logistics and operations
            'logística': 2.0, 'logistica': 2.0, 'carga': 1.5, 'frete': 1.5,
            'passageiro': 1.5, 'passageiros': 1.5, 'urbano': 1.5, 'urbana': 1.5,
            'metropolitano': 1.5, 'metropolitana': 1.5,
            
            # Regulatory terms
            'antt': 3.0, 'antaq': 3.0, 'anac': 3.0, 'dnit': 2.5, 'contran': 2.5,
            'denatran': 2.5, 'sest': 2.0, 'senat': 2.0
        }
        
        self.preprocessor = BrazilianTextPreprocessor()
    
    def classify_document(self, title: str, content: str) -> DocumentAnalysis:
        """Classify a document for transport relevance"""
        # Combine title and content (title weighted more heavily)
        combined_text = f"{title} {title} {content}"  # Title appears twice for weight
        
        # Tokenize and analyze
        words = self.preprocessor.tokenize(combined_text)
        word_counts = Counter(words)
        
        # Calculate transport score
        transport_score = 0.0
        transport_keywords_found = 0
        found_keywords = []
        
        for word, count in word_counts.items():
            if word in self.transport_keywords:
                weight = self.transport_keywords[word]
                transport_score += weight * count
                transport_keywords_found += count
                found_keywords.append(word)
        
        # Normalize score (rough normalization)
        total_words = len(words)
        if total_words > 0:
            transport_score = min(transport_score / total_words * 10, 1.0)
        
        # Determine category
        if transport_score >= 0.3:
            category = "transport"
        elif transport_score >= 0.1:
            category = "transport-related"
        else:
            category = "general"
        
        # Calculate confidence
        confidence = min(transport_score * 2, 1.0)
        
        return DocumentAnalysis(
            transport_score=transport_score,
            category=category,
            keywords=found_keywords[:10],  # Top 10 keywords
            similarity_scores={},
            confidence=confidence
        )


class DocumentSimilarityAnalyzer:
    """Document similarity analysis using TF-IDF and cosine similarity"""
    
    def __init__(self):
        self.preprocessor = BrazilianTextPreprocessor()
        self.vectorizer = None
        self.document_vectors = None
        self.document_ids = []
        
        if SKLEARN_AVAILABLE:
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),
                min_df=2,
                max_df=0.8,
                tokenizer=self.preprocessor.tokenize,
                lowercase=False  # Already handled in tokenizer
            )
    
    def fit_documents(self, documents: List[Dict[str, Any]]):
        """Fit the similarity analyzer on a collection of documents"""
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available, similarity analysis disabled")
            return
        
        if not documents:
            return
        
        # Prepare document texts
        texts = []
        self.document_ids = []
        
        for doc in documents:
            title = doc.get('title', '')
            content = doc.get('content', '') or doc.get('description', '')
            combined = f"{title} {content}"
            texts.append(combined)
            self.document_ids.append(doc.get('id', '') or doc.get('urn', ''))
        
        # Fit vectorizer
        try:
            self.document_vectors = self.vectorizer.fit_transform(texts)
            logger.info(f"Similarity analyzer fitted on {len(documents)} documents")
        except Exception as e:
            logger.error(f"Failed to fit similarity analyzer: {e}")
    
    def find_similar_documents(self, text: str, top_k: int = 5) -> List[Tuple[str, float]]:
        """Find documents similar to the given text"""
        if not SKLEARN_AVAILABLE or self.document_vectors is None:
            return []
        
        try:
            # Vectorize the query text
            query_vector = self.vectorizer.transform([text])
            
            # Calculate similarities
            similarities = cosine_similarity(query_vector, self.document_vectors)[0]
            
            # Get top-k similar documents
            top_indices = np.argsort(similarities)[-top_k:][::-1]
            
            results = []
            for idx in top_indices:
                if similarities[idx] > 0.1:  # Minimum threshold
                    doc_id = self.document_ids[idx] if idx < len(self.document_ids) else f"doc_{idx}"
                    results.append((doc_id, float(similarities[idx])))
            
            return results
            
        except Exception as e:
            logger.error(f"Similarity calculation failed: {e}")
            return []
    
    def cluster_documents(self, n_clusters: int = 8) -> Dict[str, int]:
        """Cluster documents using K-means"""
        if not SKLEARN_AVAILABLE or self.document_vectors is None:
            return {}
        
        try:
            # Reduce dimensionality if needed
            if self.document_vectors.shape[1] > 100:
                svd = TruncatedSVD(n_components=100)
                reduced_vectors = svd.fit_transform(self.document_vectors)
            else:
                reduced_vectors = self.document_vectors.toarray()
            
            # Perform clustering
            kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            cluster_labels = kmeans.fit_predict(reduced_vectors)
            
            # Return document to cluster mapping
            return {
                self.document_ids[i]: int(cluster_labels[i]) 
                for i in range(len(self.document_ids))
            }
            
        except Exception as e:
            logger.error(f"Document clustering failed: {e}")
            return {}


class TextAnalysisEngine:
    """Main text analysis engine combining all components"""
    
    def __init__(self):
        self.preprocessor = BrazilianTextPreprocessor()
        self.transport_classifier = TransportClassifier()
        self.similarity_analyzer = DocumentSimilarityAnalyzer()
        self.initialized = False
        
        logger.info(f"Text Analysis Engine initialized (sklearn available: {SKLEARN_AVAILABLE})")
    
    async def initialize_with_documents(self, documents: List[Dict[str, Any]]):
        """Initialize the engine with a collection of documents"""
        try:
            # Fit similarity analyzer
            self.similarity_analyzer.fit_documents(documents)
            self.initialized = True
            logger.info(f"Text Analysis Engine initialized with {len(documents)} documents")
        except Exception as e:
            logger.error(f"Text Analysis Engine initialization failed: {e}")
    
    def analyze_document(self, title: str, content: str, doc_id: str = "") -> DocumentAnalysis:
        """Perform comprehensive analysis on a document"""
        try:
            # Basic classification
            analysis = self.transport_classifier.classify_document(title, content)
            
            # Add similarity analysis if initialized
            if self.initialized:
                combined_text = f"{title} {content}"
                similar_docs = self.similarity_analyzer.find_similar_documents(combined_text)
                analysis.similarity_scores = {doc_id: score for doc_id, score in similar_docs}
            
            return analysis
            
        except Exception as e:
            logger.error(f"Document analysis failed: {e}")
            return DocumentAnalysis(
                transport_score=0.0,
                category="error",
                keywords=[],
                similarity_scores={}
            )
    
    def get_text_statistics(self, text: str) -> TextStats:
        """Calculate basic text statistics"""
        try:
            if not text:
                return TextStats(0, 0, 0.0, 0.0, 0)
            
            # Word count
            words = self.preprocessor.tokenize(text)
            word_count = len(words)
            
            # Sentence count (rough estimation)
            sentences = re.split(r'[.!?]+', text)
            sentence_count = len([s for s in sentences if s.strip()])
            
            # Average word length
            avg_word_length = sum(len(word) for word in words) / max(word_count, 1)
            
            # Complexity score (based on avg word length and sentence length)
            avg_sentence_length = word_count / max(sentence_count, 1)
            complexity_score = min((avg_word_length * avg_sentence_length) / 50, 1.0)
            
            # Transport keywords found
            transport_keywords_found = sum(
                1 for word in words 
                if word in self.transport_classifier.transport_keywords
            )
            
            return TextStats(
                word_count=word_count,
                sentence_count=sentence_count,
                avg_word_length=avg_word_length,
                complexity_score=complexity_score,
                transport_keywords_found=transport_keywords_found
            )
            
        except Exception as e:
            logger.error(f"Text statistics calculation failed: {e}")
            return TextStats(0, 0, 0.0, 0.0, 0)
    
    def extract_keywords(self, text: str, max_keywords: int = 10) -> List[str]:
        """Extract important keywords from text"""
        try:
            words = self.preprocessor.tokenize(text)
            word_counts = Counter(words)
            
            # Filter by transport relevance and frequency
            scored_words = []
            for word, count in word_counts.items():
                score = count
                if word in self.transport_classifier.transport_keywords:
                    score *= self.transport_classifier.transport_keywords[word]
                scored_words.append((word, score))
            
            # Sort by score and return top keywords
            scored_words.sort(key=lambda x: x[1], reverse=True)
            return [word for word, score in scored_words[:max_keywords]]
            
        except Exception as e:
            logger.error(f"Keyword extraction failed: {e}")
            return []
    
    def batch_analyze_documents(self, documents: List[Dict[str, Any]]) -> List[DocumentAnalysis]:
        """Analyze multiple documents in batch"""
        results = []
        
        for doc in documents:
            title = doc.get('title', '')
            content = doc.get('content', '') or doc.get('description', '')
            doc_id = doc.get('id', '') or doc.get('urn', '')
            
            analysis = self.analyze_document(title, content, doc_id)
            results.append(analysis)
        
        return results
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis engine statistics"""
        return {
            'sklearn_available': SKLEARN_AVAILABLE,
            'initialized': self.initialized,
            'transport_keywords_count': len(self.transport_classifier.transport_keywords),
            'similarity_analyzer_ready': self.similarity_analyzer.document_vectors is not None,
            'document_count': len(self.similarity_analyzer.document_ids)
        }