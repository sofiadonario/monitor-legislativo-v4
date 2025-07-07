"""
Advanced NLP API - Brazilian Portuguese NLP with spaCy and transformers
Specialized for Brazilian legislative documents and transport legislation
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import unicodedata

# spaCy for Portuguese NLP
try:
    import spacy
    from spacy import displacy
    from spacy.matcher import Matcher
    from spacy.util import filter_spans
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    logging.warning("spaCy not available - NLP features will be limited")

# Transformers for modern Portuguese models
try:
    from transformers import pipeline, AutoTokenizer, AutoModel
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers not available - advanced NLP features limited")

# Additional NLP libraries
try:
    import nltk
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    ADDITIONAL_NLP_AVAILABLE = True
except ImportError:
    ADDITIONAL_NLP_AVAILABLE = False
    logging.warning("Additional NLP libraries not available")

logger = logging.getLogger(__name__)

# Router for advanced NLP API
router = APIRouter(prefix="/api/v1/advanced-nlp", tags=["Advanced NLP"])

class NLPTaskType(str, Enum):
    """Types of NLP tasks"""
    ENTITY_EXTRACTION = "entity_extraction"
    SENTIMENT_ANALYSIS = "sentiment_analysis"
    TEXT_CLASSIFICATION = "text_classification"
    SUMMARIZATION = "summarization"
    KEYWORD_EXTRACTION = "keyword_extraction"
    SIMILARITY_ANALYSIS = "similarity_analysis"
    LANGUAGE_DETECTION = "language_detection"
    LEGAL_CLASSIFICATION = "legal_classification"

class EntityType(str, Enum):
    """Brazilian legislative entity types"""
    PERSON = "PERSON"
    ORGANIZATION = "ORG"
    LOCATION = "LOC"
    LAW = "LAW"
    REGULATION = "REGULATION"
    DATE = "DATE"
    MONEY = "MONEY"
    TRANSPORT_MODE = "TRANSPORT_MODE"
    GOVERNMENT_AGENCY = "GOV_AGENCY"
    LEGAL_CONCEPT = "LEGAL_CONCEPT"

@dataclass
class NLPEntity:
    """Extracted entity with Brazilian context"""
    text: str
    label: str
    start: int
    end: int
    confidence: float
    context: str
    properties: Dict[str, Any]

@dataclass
class NLPResult:
    """Comprehensive NLP analysis result"""
    task_type: str
    input_text: str
    entities: List[NLPEntity]
    sentiment: Optional[Dict[str, Any]]
    classification: Optional[Dict[str, Any]]
    keywords: List[Dict[str, Any]]
    summary: Optional[str]
    language: Optional[str]
    processing_time: float
    model_used: str
    confidence_score: float

# Pydantic models for API
class NLPRequest(BaseModel):
    text: str = Field(..., description="Text to analyze")
    tasks: List[NLPTaskType] = Field(default=[NLPTaskType.ENTITY_EXTRACTION], description="NLP tasks to perform")
    language: str = Field(default="pt", description="Language code")
    domain: str = Field(default="legal", description="Domain specialization")
    include_context: bool = Field(default=True, description="Include contextual information")

class NLPResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None
    model_info: Optional[Dict[str, str]] = None

class BrazilianNLPProcessor:
    """Advanced NLP processor specialized for Brazilian Portuguese legislative text"""
    
    def __init__(self):
        self.spacy_model = None
        self.transformers_models = {}
        self.legal_patterns = {}
        self.transport_vocabulary = set()
        self.legal_vocabulary = set()
        
        # Initialize Brazilian legal patterns
        self._init_legal_patterns()
        self._init_vocabularies()
    
    async def initialize(self) -> bool:
        """Initialize NLP models and resources"""
        try:
            # Initialize spaCy Portuguese model
            if SPACY_AVAILABLE:
                try:
                    # Try to load Portuguese model
                    self.spacy_model = spacy.load("pt_core_news_sm")
                    logger.info("✅ spaCy Portuguese model loaded")
                except OSError:
                    logger.warning("Portuguese spaCy model not found, downloading...")
                    # In production, you'd want to download this during deployment
                    # spacy.cli.download("pt_core_news_sm")
                    # For now, we'll create a basic model
                    if spacy.util.is_package("pt_core_news_sm"):
                        self.spacy_model = spacy.load("pt_core_news_sm")
                    else:
                        # Fallback to blank Portuguese model
                        self.spacy_model = spacy.blank("pt")
                        logger.warning("Using blank Portuguese model - limited functionality")
            
            # Initialize transformer models for Portuguese
            if TRANSFORMERS_AVAILABLE:
                try:
                    # Load Brazilian Portuguese BERT model
                    self.transformers_models['bert_portuguese'] = pipeline(
                        "fill-mask",
                        model="neuralmind/bert-base-portuguese-cased",
                        tokenizer="neuralmind/bert-base-portuguese-cased"
                    )
                    
                    # Load sentiment analysis model for Portuguese
                    self.transformers_models['sentiment'] = pipeline(
                        "sentiment-analysis",
                        model="cardiffnlp/twitter-xlm-roberta-base-sentiment",
                        tokenizer="cardiffnlp/twitter-xlm-roberta-base-sentiment"
                    )
                    
                    logger.info("✅ Transformer models for Portuguese loaded")
                except Exception as e:
                    logger.warning(f"Failed to load transformer models: {e}")
            
            # Initialize custom matchers for Brazilian legal text
            if self.spacy_model:
                self._setup_custom_matchers()
            
            return True
            
        except Exception as e:
            logger.error(f"NLP initialization failed: {e}")
            return False
    
    async def process_text(
        self, 
        text: str, 
        tasks: List[NLPTaskType],
        domain: str = "legal"
    ) -> NLPResult:
        """Process text with specified NLP tasks"""
        
        start_time = time.time()
        
        # Initialize result
        result = NLPResult(
            task_type=",".join([task.value for task in tasks]),
            input_text=text[:500] + "..." if len(text) > 500 else text,
            entities=[],
            sentiment=None,
            classification=None,
            keywords=[],
            summary=None,
            language=None,
            processing_time=0.0,
            model_used="spacy+transformers",
            confidence_score=0.0
        )
        
        try:
            # Preprocess text for Brazilian Portuguese
            cleaned_text = self._preprocess_text(text)
            
            # Process with spaCy if available
            doc = None
            if self.spacy_model:
                doc = self.spacy_model(cleaned_text)
            
            # Execute requested tasks
            if NLPTaskType.ENTITY_EXTRACTION in tasks:
                result.entities = await self._extract_entities(cleaned_text, doc, domain)
            
            if NLPTaskType.SENTIMENT_ANALYSIS in tasks:
                result.sentiment = await self._analyze_sentiment(cleaned_text)
            
            if NLPTaskType.TEXT_CLASSIFICATION in tasks:
                result.classification = await self._classify_text(cleaned_text, domain)
            
            if NLPTaskType.KEYWORD_EXTRACTION in tasks:
                result.keywords = await self._extract_keywords(cleaned_text, doc)
            
            if NLPTaskType.SUMMARIZATION in tasks:
                result.summary = await self._summarize_text(cleaned_text)
            
            if NLPTaskType.LANGUAGE_DETECTION in tasks:
                result.language = await self._detect_language(cleaned_text)
            
            if NLPTaskType.LEGAL_CLASSIFICATION in tasks:
                result.classification = await self._classify_legal_document(cleaned_text)
            
            # Calculate overall confidence
            confidences = []
            if result.entities:
                confidences.extend([e.confidence for e in result.entities])
            if result.sentiment:
                confidences.append(result.sentiment.get('confidence', 0.5))
            if result.classification:
                confidences.append(result.classification.get('confidence', 0.5))
            
            result.confidence_score = sum(confidences) / len(confidences) if confidences else 0.5
            result.processing_time = time.time() - start_time
            
            return result
            
        except Exception as e:
            logger.error(f"NLP processing failed: {e}")
            result.processing_time = time.time() - start_time
            raise
    
    async def _extract_entities(self, text: str, doc, domain: str) -> List[NLPEntity]:
        """Extract entities specialized for Brazilian legislative text"""
        entities = []
        
        # Extract standard spaCy entities
        if doc:
            for ent in doc.ents:
                entities.append(NLPEntity(
                    text=ent.text,
                    label=ent.label_,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.8,  # Default confidence for spaCy
                    context=text[max(0, ent.start_char-50):ent.end_char+50],
                    properties={"source": "spacy"}
                ))
        
        # Extract Brazilian legislative specific entities
        legislative_entities = self._extract_legislative_entities(text)
        entities.extend(legislative_entities)
        
        # Extract transport-related entities
        if domain == "transport" or "transport" in domain:
            transport_entities = self._extract_transport_entities(text)
            entities.extend(transport_entities)
        
        # Remove duplicates and overlaps
        entities = self._remove_overlapping_entities(entities)
        
        return entities
    
    async def _analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Analyze sentiment with Portuguese models"""
        
        if not TRANSFORMERS_AVAILABLE or 'sentiment' not in self.transformers_models:
            # Fallback lexicon-based sentiment
            return self._lexicon_sentiment_analysis(text)
        
        try:
            # Use transformer model for sentiment
            result = self.transformers_models['sentiment'](text[:512])  # Limit text length
            
            if result and len(result) > 0:
                sentiment = result[0]
                return {
                    'label': sentiment['label'],
                    'score': sentiment['score'],
                    'confidence': sentiment['score'],
                    'model': 'transformer',
                    'language': 'pt'
                }
        except Exception as e:
            logger.warning(f"Transformer sentiment analysis failed: {e}")
        
        # Fallback to lexicon-based
        return self._lexicon_sentiment_analysis(text)
    
    async def _classify_text(self, text: str, domain: str) -> Dict[str, Any]:
        """Classify text based on domain"""
        
        if domain == "legal":
            return await self._classify_legal_document(text)
        elif domain == "transport":
            return self._classify_transport_document(text)
        else:
            return self._general_classification(text)
    
    async def _extract_keywords(self, text: str, doc) -> List[Dict[str, Any]]:
        """Extract keywords using multiple methods"""
        keywords = []
        
        # Method 1: TF-IDF based extraction
        if ADDITIONAL_NLP_AVAILABLE:
            tfidf_keywords = self._extract_tfidf_keywords(text)
            keywords.extend(tfidf_keywords)
        
        # Method 2: spaCy POS and dependency based
        if doc:
            pos_keywords = self._extract_pos_keywords(doc)
            keywords.extend(pos_keywords)
        
        # Method 3: Domain-specific keywords
        domain_keywords = self._extract_domain_keywords(text)
        keywords.extend(domain_keywords)
        
        # Remove duplicates and sort by score
        unique_keywords = {}
        for kw in keywords:
            key = kw['text'].lower()
            if key not in unique_keywords or kw['score'] > unique_keywords[key]['score']:
                unique_keywords[key] = kw
        
        return sorted(unique_keywords.values(), key=lambda x: x['score'], reverse=True)[:20]
    
    async def _summarize_text(self, text: str) -> str:
        """Summarize text using extractive methods"""
        
        # Simple extractive summarization
        sentences = self._split_sentences(text)
        if len(sentences) <= 3:
            return text
        
        # Score sentences based on keyword frequency
        sentence_scores = self._score_sentences(sentences)
        
        # Select top sentences
        top_sentences = sorted(sentence_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Maintain original order
        selected_indices = sorted([sentences.index(sent) for sent, score in top_sentences])
        summary_sentences = [sentences[i] for i in selected_indices]
        
        return " ".join(summary_sentences)
    
    async def _detect_language(self, text: str) -> str:
        """Detect text language"""
        
        # Simple heuristic for Portuguese detection
        portuguese_indicators = [
            'de', 'da', 'do', 'das', 'dos', 'em', 'na', 'no', 'nas', 'nos',
            'para', 'por', 'com', 'lei', 'decreto', 'artigo', 'parágrafo'
        ]
        
        words = text.lower().split()
        portuguese_count = sum(1 for word in words if word in portuguese_indicators)
        
        if portuguese_count / len(words) > 0.05:  # 5% threshold
            return "pt"
        else:
            return "unknown"
    
    async def _classify_legal_document(self, text: str) -> Dict[str, Any]:
        """Classify Brazilian legal document type"""
        
        # Define legal document patterns
        document_types = {
            'lei': [r'\blei\s+(?:federal\s+)?n[ºo°]?\s*\d+', r'\blei\s+(?:complementar|ordinária)'],
            'decreto': [r'\bdecreto\s+n[ºo°]?\s*\d+', r'\bdecreto\s+(?:federal|estadual|municipal)'],
            'portaria': [r'\bportaria\s+n[ºo°]?\s*\d+'],
            'resolução': [r'\bresolução\s+n[ºo°]?\s*\d+'],
            'medida_provisória': [r'\bmedida\s+provisória\s+n[ºo°]?\s*\d+'],
            'instrução_normativa': [r'\binstrução\s+normativa\s+n[ºo°]?\s*\d+'],
            'parecer': [r'\bparecer\s+(?:jurídico|técnico)', r'\bparecer\s+n[ºo°]?\s*\d+'],
            'súmula': [r'\bsúmula\s+(?:vinculante\s+)?n[ºo°]?\s*\d+']
        }
        
        scores = {}
        text_lower = text.lower()
        
        for doc_type, patterns in document_types.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text_lower))
                score += matches * 10  # Weight pattern matches
            
            # Add keyword-based scoring
            if doc_type == 'lei' and 'lei' in text_lower:
                score += 5
            elif doc_type == 'decreto' and 'decreto' in text_lower:
                score += 5
            
            scores[doc_type] = score
        
        # Find best match
        if scores:
            best_type = max(scores, key=scores.get)
            max_score = scores[best_type]
            
            if max_score > 0:
                confidence = min(1.0, max_score / 20)  # Normalize confidence
                return {
                    'document_type': best_type,
                    'confidence': confidence,
                    'scores': scores,
                    'method': 'pattern_matching'
                }
        
        return {
            'document_type': 'unknown',
            'confidence': 0.0,
            'scores': scores,
            'method': 'pattern_matching'
        }
    
    # Private helper methods
    def _init_legal_patterns(self):
        """Initialize Brazilian legal patterns"""
        self.legal_patterns = {
            'laws': [
                r'Lei\s+(?:Federal\s+)?n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
                r'Decreto\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
                r'Medida\s+Provisória\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
                r'Resolução\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
                r'Portaria\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)'
            ],
            'agencies': [
                r'\b(?:ANTT|ANTAQ|ANAC|DNIT|IBAMA|CONAMA|ANEEL|ANP|ANVISA)\b',
                r'Agência\s+Nacional\s+de\s+\w+',
                r'Ministério\s+(?:dos?\s+)?(?:Transportes?|Meio\s+Ambiente|Infraestrutura)'
            ],
            'locations': [
                r'\b(?:São\s+Paulo|Rio\s+de\s+Janeiro|Brasília|Belo\s+Horizonte)\b',
                r'Estado\s+de\s+\w+',
                r'Município\s+de\s+\w+'
            ]
        }
    
    def _init_vocabularies(self):
        """Initialize domain-specific vocabularies"""
        self.transport_vocabulary = {
            'rodoviário', 'ferroviário', 'aeroviário', 'aquaviário', 'metropolitano',
            'ônibus', 'metrô', 'trem', 'avião', 'navio', 'bicicleta',
            'rodovia', 'ferrovia', 'aeroporto', 'porto', 'terminal', 'estação',
            'transporte', 'mobilidade', 'trânsito', 'tráfego', 'infraestrutura'
        }
        
        self.legal_vocabulary = {
            'artigo', 'parágrafo', 'inciso', 'alínea', 'capítulo', 'seção',
            'título', 'disposições', 'vigência', 'revogação', 'alteração',
            'regulamentação', 'fiscalização', 'penalidades', 'infrações'
        }
    
    def _preprocess_text(self, text: str) -> str:
        """Preprocess Brazilian Portuguese text"""
        # Normalize unicode characters
        text = unicodedata.normalize('NFKC', text)
        
        # Fix common encoding issues
        replacements = {
            'Ã§': 'ç', 'Ã¡': 'á', 'Ã©': 'é', 'Ã­': 'í', 'Ã³': 'ó', 'Ãº': 'ú',
            'Ã ': 'à', 'Ãª': 'ê', 'Ã´': 'ô', 'Ã¢': 'â', 'Ã±': 'ñ', 'Ã¼': 'ü'
        }
        
        for wrong, correct in replacements.items():
            text = text.replace(wrong, correct)
        
        # Clean extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _setup_custom_matchers(self):
        """Setup custom spaCy matchers for Brazilian legal text"""
        if not self.spacy_model:
            return
        
        matcher = Matcher(self.spacy_model.vocab)
        
        # Legal document patterns
        law_pattern = [{"LOWER": "lei"}, {"LOWER": {"IN": ["nº", "n°", "no", "número"]}}, {"IS_DIGIT": True}]
        decree_pattern = [{"LOWER": "decreto"}, {"LOWER": {"IN": ["nº", "n°", "no"]}}, {"IS_DIGIT": True}]
        
        matcher.add("LAW", [law_pattern])
        matcher.add("DECREE", [decree_pattern])
        
        # Store matcher for use in entity extraction
        self.custom_matcher = matcher
    
    def _extract_legislative_entities(self, text: str) -> List[NLPEntity]:
        """Extract Brazilian legislative entities using patterns"""
        entities = []
        
        for pattern_type, patterns in self.legal_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    entity_type = EntityType.LAW if pattern_type == 'laws' else EntityType.ORGANIZATION
                    if pattern_type == 'locations':
                        entity_type = EntityType.LOCATION
                    
                    entities.append(NLPEntity(
                        text=match.group(0),
                        label=entity_type.value,
                        start=match.start(),
                        end=match.end(),
                        confidence=0.9,
                        context=text[max(0, match.start()-50):match.end()+50],
                        properties={"source": "pattern", "type": pattern_type}
                    ))
        
        return entities
    
    def _extract_transport_entities(self, text: str) -> List[NLPEntity]:
        """Extract transport-related entities"""
        entities = []
        
        for word in self.transport_vocabulary:
            pattern = r'\b' + re.escape(word) + r'\b'
            for match in re.finditer(pattern, text, re.IGNORECASE):
                entities.append(NLPEntity(
                    text=match.group(0),
                    label=EntityType.TRANSPORT_MODE.value,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.7,
                    context=text[max(0, match.start()-30):match.end()+30],
                    properties={"source": "vocabulary", "domain": "transport"}
                ))
        
        return entities
    
    def _remove_overlapping_entities(self, entities: List[NLPEntity]) -> List[NLPEntity]:
        """Remove overlapping entities, keeping the one with higher confidence"""
        if not entities:
            return entities
        
        # Sort by start position
        entities.sort(key=lambda x: (x.start, -x.confidence))
        
        non_overlapping = []
        for entity in entities:
            # Check for overlap with existing entities
            overlaps = False
            for existing in non_overlapping:
                if (entity.start < existing.end and entity.end > existing.start):
                    overlaps = True
                    break
            
            if not overlaps:
                non_overlapping.append(entity)
        
        return non_overlapping
    
    def _lexicon_sentiment_analysis(self, text: str) -> Dict[str, Any]:
        """Simple lexicon-based sentiment analysis for Portuguese"""
        
        positive_words = {
            'bom', 'boa', 'excelente', 'ótimo', 'positivo', 'benefício', 'melhoria',
            'progresso', 'avanço', 'sucesso', 'eficaz', 'eficiente', 'adequado'
        }
        
        negative_words = {
            'ruim', 'péssimo', 'negativo', 'problema', 'defeito', 'falha',
            'inadequado', 'ineficaz', 'prejuízo', 'risco', 'dano', 'crítico'
        }
        
        words = text.lower().split()
        positive_count = sum(1 for word in words if word in positive_words)
        negative_count = sum(1 for word in words if word in negative_words)
        
        total_sentiment_words = positive_count + negative_count
        
        if total_sentiment_words == 0:
            return {
                'label': 'NEUTRAL',
                'score': 0.5,
                'confidence': 0.3,
                'model': 'lexicon',
                'positive_words': 0,
                'negative_words': 0
            }
        
        sentiment_score = positive_count / total_sentiment_words
        
        if sentiment_score > 0.6:
            label = 'POSITIVE'
        elif sentiment_score < 0.4:
            label = 'NEGATIVE'
        else:
            label = 'NEUTRAL'
        
        return {
            'label': label,
            'score': sentiment_score,
            'confidence': min(0.8, total_sentiment_words / len(words) * 5),
            'model': 'lexicon',
            'positive_words': positive_count,
            'negative_words': negative_count
        }
    
    def _classify_transport_document(self, text: str) -> Dict[str, Any]:
        """Classify transport-related document"""
        
        transport_categories = {
            'rodoviário': ['rodovia', 'estrada', 'BR-', 'ônibus', 'caminhão', 'automóvel'],
            'ferroviário': ['ferrovia', 'trem', 'linha férrea', 'estação ferroviária'],
            'aeroviário': ['aeroporto', 'avião', 'companhia aérea', 'voo', 'aviação'],
            'aquaviário': ['porto', 'navio', 'navegação', 'hidroviário', 'embarcação'],
            'urbano': ['metrô', 'ônibus urbano', 'mobilidade urbana', 'transporte público']
        }
        
        scores = {}
        text_lower = text.lower()
        
        for category, keywords in transport_categories.items():
            score = sum(text_lower.count(keyword) for keyword in keywords)
            scores[category] = score
        
        if scores:
            best_category = max(scores, key=scores.get)
            max_score = scores[best_category]
            
            if max_score > 0:
                total_score = sum(scores.values())
                confidence = max_score / total_score if total_score > 0 else 0
                
                return {
                    'category': best_category,
                    'confidence': confidence,
                    'scores': scores,
                    'domain': 'transport'
                }
        
        return {
            'category': 'general_transport',
            'confidence': 0.5,
            'scores': scores,
            'domain': 'transport'
        }
    
    def _general_classification(self, text: str) -> Dict[str, Any]:
        """General text classification"""
        return {
            'category': 'general',
            'confidence': 0.5,
            'method': 'default'
        }
    
    def _extract_tfidf_keywords(self, text: str) -> List[Dict[str, Any]]:
        """Extract keywords using TF-IDF"""
        if not ADDITIONAL_NLP_AVAILABLE:
            return []
        
        try:
            # Simple TF-IDF on sentences
            sentences = self._split_sentences(text)
            if len(sentences) < 2:
                return []
            
            vectorizer = TfidfVectorizer(
                stop_words=self._get_portuguese_stopwords(),
                max_features=20,
                ngram_range=(1, 2)
            )
            
            tfidf_matrix = vectorizer.fit_transform(sentences)
            feature_names = vectorizer.get_feature_names_out()
            
            # Get average TF-IDF scores
            mean_scores = np.mean(tfidf_matrix.toarray(), axis=0)
            
            keywords = []
            for i, score in enumerate(mean_scores):
                if score > 0:
                    keywords.append({
                        'text': feature_names[i],
                        'score': float(score),
                        'method': 'tfidf'
                    })
            
            return sorted(keywords, key=lambda x: x['score'], reverse=True)[:10]
            
        except Exception as e:
            logger.warning(f"TF-IDF keyword extraction failed: {e}")
            return []
    
    def _extract_pos_keywords(self, doc) -> List[Dict[str, Any]]:
        """Extract keywords based on POS tags"""
        keywords = []
        
        # Focus on nouns and adjectives
        for token in doc:
            if (token.pos_ in ['NOUN', 'PROPN', 'ADJ'] and 
                not token.is_stop and 
                not token.is_punct and 
                len(token.text) > 3):
                
                keywords.append({
                    'text': token.lemma_,
                    'score': 0.7,  # Default score for POS-based
                    'method': 'pos',
                    'pos': token.pos_
                })
        
        return keywords
    
    def _extract_domain_keywords(self, text: str) -> List[Dict[str, Any]]:
        """Extract domain-specific keywords"""
        keywords = []
        text_lower = text.lower()
        
        # Transport domain keywords
        for word in self.transport_vocabulary:
            if word in text_lower:
                count = text_lower.count(word)
                keywords.append({
                    'text': word,
                    'score': min(1.0, count * 0.2),
                    'method': 'domain',
                    'domain': 'transport',
                    'frequency': count
                })
        
        # Legal domain keywords
        for word in self.legal_vocabulary:
            if word in text_lower:
                count = text_lower.count(word)
                keywords.append({
                    'text': word,
                    'score': min(1.0, count * 0.15),
                    'method': 'domain',
                    'domain': 'legal',
                    'frequency': count
                })
        
        return keywords
    
    def _split_sentences(self, text: str) -> List[str]:
        """Split text into sentences"""
        # Simple sentence splitting for Portuguese
        sentence_endings = r'[.!?]+\s+'
        sentences = re.split(sentence_endings, text)
        return [s.strip() for s in sentences if s.strip()]
    
    def _score_sentences(self, sentences: List[str]) -> Dict[str, float]:
        """Score sentences for summarization"""
        # Simple frequency-based scoring
        word_freq = {}
        for sentence in sentences:
            words = sentence.lower().split()
            for word in words:
                if len(word) > 3 and word not in self._get_portuguese_stopwords():
                    word_freq[word] = word_freq.get(word, 0) + 1
        
        sentence_scores = {}
        for sentence in sentences:
            score = 0
            words = sentence.lower().split()
            for word in words:
                if word in word_freq:
                    score += word_freq[word]
            
            sentence_scores[sentence] = score / len(words) if words else 0
        
        return sentence_scores
    
    def _get_portuguese_stopwords(self) -> Set[str]:
        """Get Portuguese stopwords"""
        return {
            'a', 'o', 'e', 'é', 'de', 'do', 'da', 'dos', 'das', 'em', 'no', 'na', 'nos', 'nas',
            'para', 'por', 'com', 'sem', 'sob', 'sobre', 'ante', 'após', 'até', 'contra',
            'desde', 'entre', 'perante', 'que', 'se', 'lhe', 'me', 'te', 'nos', 'vos',
            'um', 'uma', 'uns', 'umas', 'este', 'esta', 'estes', 'estas', 'esse', 'essa',
            'esses', 'essas', 'aquele', 'aquela', 'aqueles', 'aquelas', 'seu', 'sua',
            'seus', 'suas', 'meu', 'minha', 'meus', 'minhas', 'teu', 'tua', 'teus', 'tuas',
            'nosso', 'nossa', 'nossos', 'nossas', 'vosso', 'vossa', 'vossos', 'vossas'
        }

# Global NLP processor instance
_nlp_processor: Optional[BrazilianNLPProcessor] = None

async def get_nlp_processor() -> BrazilianNLPProcessor:
    """Get or create the global NLP processor"""
    global _nlp_processor
    
    if _nlp_processor is None:
        _nlp_processor = BrazilianNLPProcessor()
        if await _nlp_processor.initialize():
            logger.info("✅ Brazilian Portuguese NLP processor initialized")
        else:
            logger.warning("⚠️ NLP processor initialized with limited functionality")
    
    return _nlp_processor

# API endpoints
@router.post("/process", response_model=NLPResponse)
async def process_text_endpoint(request: NLPRequest) -> NLPResponse:
    """Process text with advanced Brazilian Portuguese NLP"""
    try:
        start_time = time.time()
        nlp_processor = await get_nlp_processor()
        
        result = await nlp_processor.process_text(
            text=request.text,
            tasks=request.tasks,
            domain=request.domain
        )
        
        processing_time = time.time() - start_time
        
        return NLPResponse(
            success=True,
            data=asdict(result),
            processing_time=processing_time,
            model_info={
                "spacy_available": str(SPACY_AVAILABLE),
                "transformers_available": str(TRANSFORMERS_AVAILABLE),
                "language": request.language
            }
        )
        
    except Exception as e:
        logger.error(f"NLP processing failed: {e}")
        return NLPResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def nlp_health_status() -> Dict[str, Any]:
    """Get NLP system health status"""
    try:
        nlp_processor = await get_nlp_processor()
        
        return {
            "status": "healthy",
            "spacy_available": SPACY_AVAILABLE,
            "transformers_available": TRANSFORMERS_AVAILABLE,
            "additional_nlp_available": ADDITIONAL_NLP_AVAILABLE,
            "spacy_model_loaded": nlp_processor.spacy_model is not None,
            "transformer_models_loaded": len(nlp_processor.transformers_models),
            "supported_tasks": [task.value for task in NLPTaskType],
            "supported_languages": ["pt", "pt-BR"]
        }
        
    except Exception as e:
        logger.error(f"NLP health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_nlp_processor"]