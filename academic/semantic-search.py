# Semantic Search and Document Similarity Analysis for Monitor Legislativo v4
# Phase 5 Week 17: Advanced semantic analysis for Brazilian legislative documents
# Uses NLP and machine learning for intelligent document discovery and analysis

import asyncio
import asyncpg
import numpy as np
import json
import logging
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import unicodedata
import pickle
import hashlib
from collections import defaultdict, Counter
import math

logger = logging.getLogger(__name__)

class SimilarityMethod(Enum):
    """Methods for calculating document similarity"""
    COSINE = "cosine"                    # Cosine similarity
    JACCARD = "jaccard"                  # Jaccard similarity
    TF_IDF = "tf_idf"                   # TF-IDF based similarity
    SEMANTIC_EMBEDDING = "semantic_embedding"  # Semantic embeddings
    LEGAL_CONCEPTS = "legal_concepts"    # Legal concept similarity
    CITATION_NETWORK = "citation_network"      # Citation-based similarity

class SemanticFieldType(Enum):
    """Types of semantic fields for analysis"""
    TITLE = "title"
    CONTENT = "content"
    ABSTRACT = "abstract"
    KEYWORDS = "keywords"
    LEGAL_BASIS = "legal_basis"
    SUBJECT_MATTER = "subject_matter"

@dataclass
class SemanticVector:
    """Semantic vector representation of a document"""
    document_id: str
    vector_type: str  # "tf_idf", "word2vec", "bert", etc.
    dimensions: int
    vector_data: np.ndarray
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['vector_data'] = self.vector_data.tolist()
        result['created_at'] = self.created_at.isoformat()
        return result

@dataclass
class DocumentSimilarity:
    """Document similarity result"""
    document1_id: str
    document2_id: str
    similarity_score: float
    similarity_method: SimilarityMethod
    common_features: List[str] = field(default_factory=list)
    explanation: Optional[str] = None
    computed_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['similarity_method'] = self.similarity_method.value
        result['computed_at'] = self.computed_at.isoformat()
        return result

@dataclass
class SemanticSearchResult:
    """Semantic search result"""
    document_id: str
    relevance_score: float
    matching_fields: List[str]
    matching_concepts: List[str]
    explanation: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class LegalConcept:
    """Legal concept for semantic analysis"""
    concept_id: str
    name: str
    description: str
    synonyms: List[str]
    related_concepts: List[str]
    concept_type: str  # "principle", "procedure", "institution", "law_area"
    legal_domain: str  # "transport", "civil", "criminal", "administrative"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class SemanticSearchEngine:
    """
    Advanced semantic search and document similarity analysis for Brazilian legislative documents
    
    Features:
    - Multi-method similarity calculation
    - Legal concept ontology integration
    - Portuguese language NLP processing
    - Transport law domain specialization
    - Citation network analysis
    - Semantic vector storage and retrieval
    - Explanation generation for results
    """
    
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        self.legal_concepts = {}
        self.stopwords_pt = set()
        self.transport_terms = set()
        self.legal_synonyms = {}
        self.concept_vectors = {}
        
        # Initialize Portuguese language processing
        self._initialize_portuguese_nlp()
        self._initialize_legal_concepts()
        self._initialize_transport_vocabulary()
    
    async def initialize(self) -> None:
        """Initialize semantic search system"""
        await self._create_semantic_tables()
        await self._load_legal_concepts()
        logger.info("Semantic search engine initialized")
    
    def _initialize_portuguese_nlp(self) -> None:
        """Initialize Portuguese language processing tools"""
        
        # Common Portuguese stopwords
        self.stopwords_pt = {
            'a', 'ao', 'aos', 'aquela', 'aquelas', 'aquele', 'aqueles', 'aquilo', 'as', 'até',
            'com', 'como', 'da', 'das', 'de', 'dela', 'delas', 'dele', 'deles', 'depois',
            'do', 'dos', 'e', 'ela', 'elas', 'ele', 'eles', 'em', 'entre', 'era', 'eram',
            'essa', 'essas', 'esse', 'esses', 'esta', 'estás', 'estas', 'este', 'estes',
            'eu', 'foi', 'fomos', 'for', 'foram', 'fosse', 'fossem', 'fui', 'há', 'isso',
            'isto', 'já', 'lhe', 'lhes', 'mais', 'mas', 'me', 'mesmo', 'meu', 'meus',
            'minha', 'minhas', 'muito', 'na', 'nas', 'não', 'nem', 'no', 'nos', 'nós',
            'nossa', 'nossas', 'nosso', 'nossos', 'num', 'numa', 'o', 'os', 'ou', 'para',
            'pela', 'pelas', 'pelo', 'pelos', 'por', 'qual', 'quando', 'que', 'quem',
            'são', 'se', 'sem', 'ser', 'seu', 'seus', 'só', 'sua', 'suas', 'também',
            'te', 'tem', 'teu', 'teus', 'tu', 'tua', 'tuas', 'um', 'uma', 'você', 'vocês'
        }
        
        # Legal document specific stopwords
        legal_stopwords = {
            'artigo', 'art', 'inciso', 'parágrafo', 'alínea', 'lei', 'decreto', 'portaria',
            'resolução', 'considera', 'considerando', 'resolve', 'determina', 'estabelece',
            'dispõe', 'regulamenta', 'institui', 'cria', 'revoga', 'altera', 'disciplina'
        }
        
        self.stopwords_pt.update(legal_stopwords)
    
    def _initialize_legal_concepts(self) -> None:
        """Initialize legal concepts ontology"""
        
        # Transport law concepts
        transport_concepts = [
            LegalConcept(
                concept_id="transporte_publico",
                name="Transporte Público",
                description="Serviços de transporte coletivo de passageiros",
                synonyms=["transporte coletivo", "transporte urbano", "sistema de transporte"],
                related_concepts=["mobilidade_urbana", "concessao_transporte", "tarifa_transporte"],
                concept_type="law_area",
                legal_domain="transport"
            ),
            LegalConcept(
                concept_id="mobilidade_urbana",
                name="Mobilidade Urbana",
                description="Política Nacional de Mobilidade Urbana",
                synonyms=["mobilidade", "circulação urbana", "acessibilidade urbana"],
                related_concepts=["transporte_publico", "planejamento_urbano", "sustentabilidade"],
                concept_type="principle",
                legal_domain="transport"
            ),
            LegalConcept(
                concept_id="concessao_transporte",
                name="Concessão de Transporte",
                description="Delegação de serviços de transporte público",
                synonyms=["permissão", "autorização", "delegação", "outorga"],
                related_concepts=["servico_publico", "licitacao", "contrato_administrativo"],
                concept_type="procedure",
                legal_domain="transport"
            ),
            LegalConcept(
                concept_id="antt",
                name="ANTT - Agência Nacional de Transportes Terrestres",
                description="Agência reguladora de transportes terrestres",
                synonyms=["agência nacional transportes terrestres", "antt"],
                related_concepts=["regulacao_transporte", "fiscalizacao", "autorizacao"],
                concept_type="institution",
                legal_domain="transport"
            ),
            LegalConcept(
                concept_id="antaq",
                name="ANTAQ - Agência Nacional de Transportes Aquaviários",
                description="Agência reguladora de transportes aquaviários",
                synonyms=["agência nacional transportes aquaviários", "antaq"],
                related_concepts=["navegacao", "portos", "regulacao_aquaviaria"],
                concept_type="institution",
                legal_domain="transport"
            ),
            LegalConcept(
                concept_id="anac",
                name="ANAC - Agência Nacional de Aviação Civil",
                description="Agência reguladora da aviação civil",
                synonyms=["agência nacional aviação civil", "anac"],
                related_concepts=["aviacao_civil", "aeroportos", "seguranca_voo"],
                concept_type="institution",
                legal_domain="transport"
            )
        ]
        
        for concept in transport_concepts:
            self.legal_concepts[concept.concept_id] = concept
    
    def _initialize_transport_vocabulary(self) -> None:
        """Initialize transport-specific vocabulary"""
        
        self.transport_terms = {
            # Transport modes
            'ônibus', 'metro', 'metrô', 'trem', 'brt', 'vlt', 'bicicleta', 'motocicleta',
            'automóvel', 'caminhão', 'carreta', 'navio', 'embarcação', 'aeronave', 'avião',
            
            # Infrastructure
            'rodovia', 'estrada', 'via', 'rua', 'avenida', 'ferrovia', 'linha férrea',
            'porto', 'aeroporto', 'terminal', 'estação', 'parada', 'ponto de ônibus',
            'ciclovia', 'calçada', 'passarela', 'viaduto', 'ponte', 'túnel',
            
            # Regulatory terms
            'licença', 'autorização', 'permissão', 'concessão', 'licitação', 'edital',
            'contrato', 'termo', 'regulamento', 'norma', 'instrução', 'resolução',
            'portaria', 'decreto', 'lei', 'medida provisória',
            
            # Transport services
            'serviço público', 'transporte coletivo', 'transporte individual',
            'taxi', 'aplicativo', 'fretamento', 'escolar', 'urbano', 'interurbano',
            'internacional', 'carga', 'passageiro', 'turismo',
            
            # Economic terms
            'tarifa', 'preço', 'taxa', 'pedágio', 'subsídio', 'gratuidade',
            'financiamento', 'investimento', 'custo', 'receita', 'bilhetagem',
            
            # Safety and security
            'segurança', 'fiscalização', 'inspeção', 'vistoria', 'multa', 'infração',
            'acidente', 'sinistro', 'seguro', 'responsabilidade', 'habilitação'
        }
        
        # Legal synonyms for transport terms
        self.legal_synonyms = {
            'ônibus': ['autobus', 'coletivo', 'transporte coletivo'],
            'metrô': ['metro', 'metropolitano', 'trem metropolitano'],
            'brt': ['bus rapid transit', 'transito rapido'],
            'vlt': ['veículo leve sobre trilhos', 'tram'],
            'rodovia': ['estrada', 'via expressa', 'autoestrada'],
            'concessão': ['delegação', 'outorga', 'permissão'],
            'licitação': ['concorrência', 'pregão', 'tomada de preços'],
            'tarifa': ['preço público', 'contraprestação', 'valor'],
            'fiscalização': ['controle', 'supervisão', 'monitoramento']
        }
    
    async def _create_semantic_tables(self) -> None:
        """Create semantic search database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Semantic vectors table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS semantic_vectors (
                    vector_id VARCHAR(36) PRIMARY KEY,
                    document_id VARCHAR(100) NOT NULL,
                    vector_type VARCHAR(30) NOT NULL,
                    dimensions INTEGER NOT NULL,
                    vector_data BYTEA NOT NULL,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Document similarities table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS document_similarities (
                    similarity_id VARCHAR(36) PRIMARY KEY,
                    document1_id VARCHAR(100) NOT NULL,
                    document2_id VARCHAR(100) NOT NULL,
                    similarity_score FLOAT NOT NULL,
                    similarity_method VARCHAR(30) NOT NULL,
                    common_features JSONB DEFAULT '[]'::jsonb,
                    explanation TEXT NULL,
                    computed_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Legal concepts table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS legal_concepts (
                    concept_id VARCHAR(50) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    description TEXT NOT NULL,
                    synonyms JSONB DEFAULT '[]'::jsonb,
                    related_concepts JSONB DEFAULT '[]'::jsonb,
                    concept_type VARCHAR(30) NOT NULL,
                    legal_domain VARCHAR(30) NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Semantic search cache
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS semantic_search_cache (
                    cache_id VARCHAR(50) PRIMARY KEY,
                    query_hash VARCHAR(64) NOT NULL,
                    query_text TEXT NOT NULL,
                    search_method VARCHAR(30) NOT NULL,
                    results JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    expires_at TIMESTAMP NOT NULL
                );
            """)
            
            # Document concepts mapping
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS document_concepts (
                    mapping_id VARCHAR(36) PRIMARY KEY,
                    document_id VARCHAR(100) NOT NULL,
                    concept_id VARCHAR(50) NOT NULL,
                    relevance_score FLOAT DEFAULT 0.0,
                    extraction_method VARCHAR(30) NOT NULL,
                    context TEXT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_vectors_document ON semantic_vectors(document_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_vectors_type ON semantic_vectors(vector_type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_similarities_doc1 ON document_similarities(document1_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_similarities_doc2 ON document_similarities(document2_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_similarities_method ON document_similarities(similarity_method);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_concepts_domain ON legal_concepts(legal_domain);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_concepts_type ON legal_concepts(concept_type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_search_cache_hash ON semantic_search_cache(query_hash);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_doc_concepts_doc ON document_concepts(document_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_doc_concepts_concept ON document_concepts(concept_id);")
            
            logger.info("Semantic search tables created successfully")
        
        finally:
            await conn.close()
    
    async def _load_legal_concepts(self) -> None:
        """Load legal concepts into database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            for concept_id, concept in self.legal_concepts.items():
                await conn.execute("""
                    INSERT INTO legal_concepts 
                    (concept_id, name, description, synonyms, related_concepts, concept_type, legal_domain)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (concept_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        synonyms = EXCLUDED.synonyms,
                        related_concepts = EXCLUDED.related_concepts,
                        concept_type = EXCLUDED.concept_type,
                        legal_domain = EXCLUDED.legal_domain,
                        updated_at = NOW()
                """, concept_id, concept.name, concept.description,
                    json.dumps(concept.synonyms), json.dumps(concept.related_concepts),
                    concept.concept_type, concept.legal_domain)
            
            logger.info(f"Loaded {len(self.legal_concepts)} legal concepts")
        
        finally:
            await conn.close()
    
    def preprocess_text(self, text: str) -> List[str]:
        """Preprocess text for semantic analysis"""
        if not text:
            return []
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove accents
        text = unicodedata.normalize('NFD', text)
        text = ''.join(c for c in text if unicodedata.category(c) != 'Mn')
        
        # Remove punctuation and special characters, keep only alphanumeric and spaces
        text = re.sub(r'[^\w\s]', ' ', text)
        
        # Split into tokens
        tokens = text.split()
        
        # Remove stopwords and short tokens
        tokens = [token for token in tokens if token not in self.stopwords_pt and len(token) > 2]
        
        # Apply stemming (simplified Portuguese stemming)
        tokens = [self._portuguese_stem(token) for token in tokens]
        
        return tokens
    
    def _portuguese_stem(self, word: str) -> str:
        """Simple Portuguese stemming algorithm"""
        # Remove common Portuguese suffixes
        suffixes = [
            'ões', 'ção', 'são', 'dade', 'idade', 'mente', 'ante', 'ente', 'inte',
            'ado', 'ada', 'ido', 'ida', 'oso', 'osa', 'ivo', 'iva', 'eiro', 'eira',
            'ar', 'er', 'ir', 'or', 'as', 'es', 'is', 'os', 'um', 'uns', 'uma', 'umas'
        ]
        
        for suffix in sorted(suffixes, key=len, reverse=True):
            if word.endswith(suffix) and len(word) > len(suffix) + 2:
                return word[:-len(suffix)]
        
        return word
    
    def extract_legal_concepts(self, text: str) -> List[Tuple[str, float, str]]:
        """Extract legal concepts from text with relevance scores"""
        
        if not text:
            return []
        
        text_lower = text.lower()
        concepts_found = []
        
        for concept_id, concept in self.legal_concepts.items():
            relevance_score = 0.0
            context_matches = []
            
            # Check main name
            if concept.name.lower() in text_lower:
                relevance_score += 1.0
                context_matches.append(concept.name)
            
            # Check synonyms
            for synonym in concept.synonyms:
                if synonym.lower() in text_lower:
                    relevance_score += 0.8
                    context_matches.append(synonym)
            
            # Check related terms for transport concepts
            if concept.legal_domain == "transport":
                for term in self.transport_terms:
                    if term in text_lower:
                        relevance_score += 0.3
                        if len(context_matches) < 3:  # Limit context matches
                            context_matches.append(term)
            
            # Check legal synonyms
            for main_term, synonyms in self.legal_synonyms.items():
                if main_term in concept.synonyms or main_term.lower() in concept.name.lower():
                    for synonym in synonyms:
                        if synonym.lower() in text_lower:
                            relevance_score += 0.5
                            if len(context_matches) < 3:
                                context_matches.append(synonym)
            
            if relevance_score > 0:
                context = "; ".join(context_matches[:3])  # Limit context
                concepts_found.append((concept_id, relevance_score, context))
        
        # Sort by relevance score
        concepts_found.sort(key=lambda x: x[1], reverse=True)
        return concepts_found
    
    def calculate_tf_idf_vector(self, document_tokens: List[str], 
                               corpus_stats: Dict[str, Any]) -> np.ndarray:
        """Calculate TF-IDF vector for a document"""
        
        # Calculate term frequencies
        doc_length = len(document_tokens)
        tf_dict = Counter(document_tokens)
        
        # Get corpus statistics
        total_docs = corpus_stats.get('total_docs', 1)
        doc_frequencies = corpus_stats.get('doc_frequencies', {})
        vocabulary = corpus_stats.get('vocabulary', [])
        
        # Create TF-IDF vector
        tfidf_vector = np.zeros(len(vocabulary))
        
        for i, term in enumerate(vocabulary):
            if term in tf_dict:
                # Term frequency
                tf = tf_dict[term] / doc_length
                
                # Inverse document frequency
                df = doc_frequencies.get(term, 1)
                idf = math.log(total_docs / df)
                
                # TF-IDF score
                tfidf_vector[i] = tf * idf
        
        return tfidf_vector
    
    def cosine_similarity(self, vector1: np.ndarray, vector2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors"""
        
        # Handle zero vectors
        norm1 = np.linalg.norm(vector1)
        norm2 = np.linalg.norm(vector2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        # Calculate cosine similarity
        similarity = np.dot(vector1, vector2) / (norm1 * norm2)
        return float(similarity)
    
    def jaccard_similarity(self, set1: Set[str], set2: Set[str]) -> float:
        """Calculate Jaccard similarity between two sets"""
        
        if not set1 and not set2:
            return 1.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    async def compute_document_similarity(self, doc1_id: str, doc2_id: str,
                                        method: SimilarityMethod = SimilarityMethod.TF_IDF) -> DocumentSimilarity:
        """Compute similarity between two documents"""
        
        # Check if similarity already computed
        existing_similarity = await self._get_cached_similarity(doc1_id, doc2_id, method)
        if existing_similarity:
            return existing_similarity
        
        if method == SimilarityMethod.TF_IDF:
            similarity = await self._compute_tfidf_similarity(doc1_id, doc2_id)
        elif method == SimilarityMethod.COSINE:
            similarity = await self._compute_cosine_similarity(doc1_id, doc2_id)
        elif method == SimilarityMethod.JACCARD:
            similarity = await self._compute_jaccard_similarity(doc1_id, doc2_id)
        elif method == SimilarityMethod.LEGAL_CONCEPTS:
            similarity = await self._compute_legal_concept_similarity(doc1_id, doc2_id)
        else:
            raise ValueError(f"Unsupported similarity method: {method}")
        
        # Cache the result
        await self._cache_similarity(similarity)
        
        return similarity
    
    async def _compute_tfidf_similarity(self, doc1_id: str, doc2_id: str) -> DocumentSimilarity:
        """Compute TF-IDF based similarity"""
        
        # Get document vectors
        vector1 = await self._get_document_vector(doc1_id, "tf_idf")
        vector2 = await self._get_document_vector(doc2_id, "tf_idf")
        
        if vector1 is None or vector2 is None:
            # Generate vectors if they don't exist
            await self._generate_document_vectors([doc1_id, doc2_id])
            vector1 = await self._get_document_vector(doc1_id, "tf_idf")
            vector2 = await self._get_document_vector(doc2_id, "tf_idf")
        
        if vector1 is None or vector2 is None:
            similarity_score = 0.0
            explanation = "Could not generate document vectors"
            common_features = []
        else:
            similarity_score = self.cosine_similarity(vector1.vector_data, vector2.vector_data)
            
            # Find common high-value features
            threshold = 0.1  # Minimum TF-IDF value to consider
            common_indices = np.where((vector1.vector_data > threshold) & (vector2.vector_data > threshold))[0]
            common_features = [f"feature_{i}" for i in common_indices[:10]]  # Top 10 common features
            
            explanation = f"TF-IDF cosine similarity based on {len(common_indices)} common features"
        
        return DocumentSimilarity(
            document1_id=doc1_id,
            document2_id=doc2_id,
            similarity_score=similarity_score,
            similarity_method=SimilarityMethod.TF_IDF,
            common_features=common_features,
            explanation=explanation
        )
    
    async def _compute_legal_concept_similarity(self, doc1_id: str, doc2_id: str) -> DocumentSimilarity:
        """Compute similarity based on legal concepts"""
        
        # Get legal concepts for both documents
        concepts1 = await self._get_document_concepts(doc1_id)
        concepts2 = await self._get_document_concepts(doc2_id)
        
        if not concepts1 or not concepts2:
            similarity_score = 0.0
            common_features = []
            explanation = "No legal concepts found in one or both documents"
        else:
            # Calculate concept-based similarity
            concept_set1 = set(concept['concept_id'] for concept in concepts1)
            concept_set2 = set(concept['concept_id'] for concept in concepts2)
            
            # Jaccard similarity of concepts
            jaccard_sim = self.jaccard_similarity(concept_set1, concept_set2)
            
            # Weighted similarity based on concept relevance scores
            common_concepts = concept_set1.intersection(concept_set2)
            if common_concepts:
                weight1 = sum(c['relevance_score'] for c in concepts1 if c['concept_id'] in common_concepts)
                weight2 = sum(c['relevance_score'] for c in concepts2 if c['concept_id'] in common_concepts)
                total_weight1 = sum(c['relevance_score'] for c in concepts1)
                total_weight2 = sum(c['relevance_score'] for c in concepts2)
                
                weighted_sim = (weight1 / total_weight1 + weight2 / total_weight2) / 2 if total_weight1 > 0 and total_weight2 > 0 else 0
                similarity_score = (jaccard_sim + weighted_sim) / 2
            else:
                similarity_score = 0.0
            
            common_features = list(common_concepts)
            explanation = f"Legal concept similarity based on {len(common_concepts)} common concepts"
        
        return DocumentSimilarity(
            document1_id=doc1_id,
            document2_id=doc2_id,
            similarity_score=similarity_score,
            similarity_method=SimilarityMethod.LEGAL_CONCEPTS,
            common_features=common_features,
            explanation=explanation
        )
    
    async def semantic_search(self, query: str, max_results: int = 20,
                            similarity_threshold: float = 0.1,
                            search_fields: List[SemanticFieldType] = None) -> List[SemanticSearchResult]:
        """Perform semantic search on documents"""
        
        if not query.strip():
            return []
        
        # Check cache first
        cache_key = self._generate_search_cache_key(query, max_results, similarity_threshold, search_fields)
        cached_results = await self._get_cached_search(cache_key)
        if cached_results:
            return cached_results
        
        # Preprocess query
        query_tokens = self.preprocess_text(query)
        query_concepts = self.extract_legal_concepts(query)
        
        search_fields = search_fields or [SemanticFieldType.TITLE, SemanticFieldType.CONTENT]
        
        # Perform multi-method search
        results = []
        
        # 1. TF-IDF vector search
        tfidf_results = await self._tfidf_vector_search(query_tokens, max_results // 2)
        results.extend(tfidf_results)
        
        # 2. Legal concept search
        if query_concepts:
            concept_results = await self._legal_concept_search(query_concepts, max_results // 2)
            results.extend(concept_results)
        
        # 3. Keyword search with synonyms
        keyword_results = await self._enhanced_keyword_search(query, query_tokens, max_results // 2)
        results.extend(keyword_results)
        
        # Merge and rank results
        merged_results = self._merge_search_results(results, max_results, similarity_threshold)
        
        # Cache results
        await self._cache_search_results(cache_key, merged_results)
        
        return merged_results
    
    async def _tfidf_vector_search(self, query_tokens: List[str], max_results: int) -> List[SemanticSearchResult]:
        """Search using TF-IDF vectors"""
        
        # This would require a more complex implementation with a proper vector database
        # For now, return empty results as a placeholder
        return []
    
    async def _legal_concept_search(self, query_concepts: List[Tuple[str, float, str]], 
                                  max_results: int) -> List[SemanticSearchResult]:
        """Search based on legal concepts"""
        
        if not query_concepts:
            return []
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Extract concept IDs and weights
            concept_ids = [concept[0] for concept in query_concepts]
            concept_weights = {concept[0]: concept[1] for concept in query_concepts}
            
            # Find documents with these concepts
            documents = await conn.fetch("""
                SELECT 
                    dc.document_id,
                    array_agg(dc.concept_id) as concepts,
                    array_agg(dc.relevance_score) as scores,
                    sum(dc.relevance_score) as total_score
                FROM document_concepts dc
                WHERE dc.concept_id = ANY($1)
                GROUP BY dc.document_id
                ORDER BY total_score DESC
                LIMIT $2
            """, concept_ids, max_results)
            
            results = []
            for doc in documents:
                doc_concepts = doc['concepts']
                doc_scores = doc['scores']
                
                # Calculate relevance score
                relevance_score = 0.0
                matching_concepts = []
                
                for i, concept_id in enumerate(doc_concepts):
                    if concept_id in concept_weights:
                        query_weight = concept_weights[concept_id]
                        doc_weight = doc_scores[i]
                        relevance_score += query_weight * doc_weight
                        matching_concepts.append(concept_id)
                
                if relevance_score > 0:
                    # Get concept names for explanation
                    concept_names = [self.legal_concepts[cid].name for cid in matching_concepts 
                                   if cid in self.legal_concepts]
                    
                    explanation = f"Matched legal concepts: {', '.join(concept_names)}"
                    
                    results.append(SemanticSearchResult(
                        document_id=doc['document_id'],
                        relevance_score=relevance_score,
                        matching_fields=["legal_concepts"],
                        matching_concepts=matching_concepts,
                        explanation=explanation
                    ))
            
            return results
        
        finally:
            await conn.close()
    
    async def _enhanced_keyword_search(self, original_query: str, query_tokens: List[str],
                                     max_results: int) -> List[SemanticSearchResult]:
        """Enhanced keyword search with synonyms and transport terms"""
        
        # Expand query with synonyms
        expanded_terms = set(query_tokens)
        
        for token in query_tokens:
            if token in self.legal_synonyms:
                expanded_terms.update(self.legal_synonyms[token])
        
        # Add transport-specific terms if relevant
        transport_score = sum(1 for term in query_tokens if term in self.transport_terms)
        if transport_score > 0:
            expanded_terms.update(term for term in self.transport_terms 
                                 if any(term in original_query.lower() for term in query_tokens))
        
        # This would integrate with the existing search system
        # For now, return empty results as a placeholder
        return []
    
    def _merge_search_results(self, results: List[SemanticSearchResult], 
                            max_results: int, threshold: float) -> List[SemanticSearchResult]:
        """Merge and rank search results from different methods"""
        
        # Group results by document ID
        doc_results = defaultdict(list)
        for result in results:
            doc_results[result.document_id].append(result)
        
        # Merge results for each document
        merged_results = []
        for doc_id, doc_result_list in doc_results.items():
            if len(doc_result_list) == 1:
                merged_results.append(doc_result_list[0])
            else:
                # Combine multiple results for the same document
                combined_score = max(r.relevance_score for r in doc_result_list)
                combined_fields = list(set(field for r in doc_result_list for field in r.matching_fields))
                combined_concepts = list(set(concept for r in doc_result_list for concept in r.matching_concepts))
                combined_explanation = " | ".join(set(r.explanation for r in doc_result_list))
                
                merged_results.append(SemanticSearchResult(
                    document_id=doc_id,
                    relevance_score=combined_score,
                    matching_fields=combined_fields,
                    matching_concepts=combined_concepts,
                    explanation=combined_explanation
                ))
        
        # Filter by threshold and sort by relevance
        filtered_results = [r for r in merged_results if r.relevance_score >= threshold]
        filtered_results.sort(key=lambda x: x.relevance_score, reverse=True)
        
        return filtered_results[:max_results]
    
    async def _get_document_vector(self, document_id: str, vector_type: str) -> Optional[SemanticVector]:
        """Get semantic vector for a document"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            vector_data = await conn.fetchrow("""
                SELECT * FROM semantic_vectors 
                WHERE document_id = $1 AND vector_type = $2
            """, document_id, vector_type)
            
            if vector_data:
                # Deserialize vector data
                vector_array = pickle.loads(vector_data['vector_data'])
                
                return SemanticVector(
                    document_id=vector_data['document_id'],
                    vector_type=vector_data['vector_type'],
                    dimensions=vector_data['dimensions'],
                    vector_data=vector_array,
                    metadata=json.loads(vector_data['metadata']),
                    created_at=vector_data['created_at']
                )
            
            return None
        
        finally:
            await conn.close()
    
    async def _get_document_concepts(self, document_id: str) -> List[Dict[str, Any]]:
        """Get legal concepts for a document"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            concepts = await conn.fetch("""
                SELECT * FROM document_concepts 
                WHERE document_id = $1
                ORDER BY relevance_score DESC
            """, document_id)
            
            return [dict(concept) for concept in concepts]
        
        finally:
            await conn.close()
    
    async def _generate_document_vectors(self, document_ids: List[str]) -> None:
        """Generate semantic vectors for documents"""
        # This would require integration with the document storage system
        # and implementation of actual vector generation algorithms
        pass
    
    def _generate_search_cache_key(self, query: str, max_results: int, 
                                 threshold: float, search_fields: List[SemanticFieldType]) -> str:
        """Generate cache key for search query"""
        
        fields_str = ",".join(sorted([f.value for f in search_fields])) if search_fields else ""
        cache_input = f"{query}|{max_results}|{threshold}|{fields_str}"
        return hashlib.sha256(cache_input.encode()).hexdigest()
    
    async def _get_cached_search(self, cache_key: str) -> Optional[List[SemanticSearchResult]]:
        """Get cached search results"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            cached = await conn.fetchrow("""
                SELECT results FROM semantic_search_cache 
                WHERE cache_id = $1 AND expires_at > NOW()
            """, cache_key)
            
            if cached:
                results_data = json.loads(cached['results'])
                return [SemanticSearchResult(**result) for result in results_data]
            
            return None
        
        finally:
            await conn.close()
    
    async def _cache_search_results(self, cache_key: str, results: List[SemanticSearchResult]) -> None:
        """Cache search results"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            results_json = json.dumps([result.to_dict() for result in results])
            expires_at = datetime.now() + timedelta(hours=24)  # Cache for 24 hours
            
            await conn.execute("""
                INSERT INTO semantic_search_cache 
                (cache_id, query_hash, query_text, search_method, results, expires_at)
                VALUES ($1, $2, '', 'semantic', $3, $4)
                ON CONFLICT (cache_id) DO UPDATE SET
                    results = EXCLUDED.results,
                    expires_at = EXCLUDED.expires_at
            """, cache_key, cache_key, results_json, expires_at)
        
        finally:
            await conn.close()
    
    async def _get_cached_similarity(self, doc1_id: str, doc2_id: str, 
                                   method: SimilarityMethod) -> Optional[DocumentSimilarity]:
        """Get cached similarity result"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Check both directions
            similarity_data = await conn.fetchrow("""
                SELECT * FROM document_similarities 
                WHERE ((document1_id = $1 AND document2_id = $2) 
                       OR (document1_id = $2 AND document2_id = $1))
                  AND similarity_method = $3
            """, doc1_id, doc2_id, method.value)
            
            if similarity_data:
                return DocumentSimilarity(
                    document1_id=similarity_data['document1_id'],
                    document2_id=similarity_data['document2_id'],
                    similarity_score=similarity_data['similarity_score'],
                    similarity_method=SimilarityMethod(similarity_data['similarity_method']),
                    common_features=json.loads(similarity_data['common_features']),
                    explanation=similarity_data['explanation'],
                    computed_at=similarity_data['computed_at']
                )
            
            return None
        
        finally:
            await conn.close()
    
    async def _cache_similarity(self, similarity: DocumentSimilarity) -> None:
        """Cache similarity result"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            similarity_id = str(uuid.uuid4())
            
            await conn.execute("""
                INSERT INTO document_similarities 
                (similarity_id, document1_id, document2_id, similarity_score, 
                 similarity_method, common_features, explanation, computed_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, similarity_id, similarity.document1_id, similarity.document2_id,
                similarity.similarity_score, similarity.similarity_method.value,
                json.dumps(similarity.common_features), similarity.explanation,
                similarity.computed_at)
        
        finally:
            await conn.close()

# Factory function for easy creation
async def create_semantic_search_engine(db_config: Dict[str, str]) -> SemanticSearchEngine:
    """Create and initialize semantic search engine"""
    engine = SemanticSearchEngine(db_config)
    await engine.initialize()
    return engine

# Export main classes
__all__ = [
    'SemanticSearchEngine',
    'SemanticVector',
    'DocumentSimilarity',
    'SemanticSearchResult',
    'LegalConcept',
    'SimilarityMethod',
    'SemanticFieldType',
    'create_semantic_search_engine'
]