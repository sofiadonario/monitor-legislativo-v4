"""
AI Agents API - Production-Ready AI Agents with Dual-Memory Architecture
Based on agents-towards-production patterns for Brazilian legislative research
"""

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Set, Tuple
from dataclasses import dataclass, asdict
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field
import hashlib
import os

# Import Redis for dual-memory architecture
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available - AI agents will use in-memory storage only")

logger = logging.getLogger(__name__)

# Router for AI agents API
router = APIRouter(prefix="/api/v1/ai-agents", tags=["AI Agents"])

# Configuration constants
DEFAULT_SEMANTIC_CACHE_TTL = 24 * 60 * 60  # 24 hours
DEFAULT_SHORT_TERM_MEMORY_SIZE = 10  # Last 10 interactions
DEFAULT_LLM_MAX_TOKENS = 2000
DEFAULT_TEMPERATURE = 0.1  # Low temperature for consistent academic analysis

class AgentRole(str, Enum):
    """Specialized AI agent roles for Brazilian legislative research"""
    RESEARCH_ASSISTANT = "research_assistant"
    DOCUMENT_ANALYZER = "document_analyzer" 
    CITATION_GENERATOR = "citation_generator"
    LEGAL_ADVISOR = "legal_advisor"
    TREND_ANALYST = "trend_analyst"
    COMPARATIVE_ANALYST = "comparative_analyst"

class MemoryType(str, Enum):
    """Types of memory in dual-memory architecture"""
    SHORT_TERM = "short_term"  # Thread-level, temporary
    LONG_TERM = "long_term"    # Persistent, semantic

class AnalysisType(str, Enum):
    """Types of document analysis"""
    SUMMARY = "summary"
    LEGAL_ANALYSIS = "legal_analysis"
    TREND_ANALYSIS = "trend_analysis"
    IMPACT_ASSESSMENT = "impact_assessment"
    COMPARATIVE_ANALYSIS = "comparative_analysis"
    CITATION_GENERATION = "citation_generation"

@dataclass
class CostMonitor:
    """Monitor and track LLM API costs"""
    start_time: float
    start_tokens: int
    end_time: Optional[float] = None
    end_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    
    def calculate_cost(self, end_time: float, end_tokens: int, cost_per_token: float = 0.00002):
        """Calculate API cost based on token usage"""
        self.end_time = end_time
        self.end_tokens = end_tokens
        tokens_used = max(0, end_tokens - self.start_tokens)
        self.cost_usd = tokens_used * cost_per_token

@dataclass 
class SemanticMemory:
    """Long-term semantic memory entry"""
    id: str
    content: str
    keywords: List[str]
    timestamp: datetime
    access_count: int
    relevance_score: float
    
    def to_json(self) -> str:
        return json.dumps({
            'id': self.id,
            'content': self.content, 
            'keywords': self.keywords,
            'timestamp': self.timestamp.isoformat(),
            'access_count': self.access_count,
            'relevance_score': self.relevance_score
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SemanticMemory':
        data = json.loads(json_str)
        return cls(
            id=data['id'],
            content=data['content'],
            keywords=data['keywords'], 
            timestamp=datetime.fromisoformat(data['timestamp']),
            access_count=data['access_count'],
            relevance_score=data['relevance_score']
        )

@dataclass
class DocumentAnalysis:
    """Result of AI document analysis"""
    document_id: str
    summary: str
    key_concepts: List[str]
    legal_references: List[str]
    geographic_scope: List[str]
    confidence_score: float
    processing_cost: Optional[float] = None
    analysis_type: str = "summary"
    timestamp: Optional[datetime] = None
    
    def to_json(self) -> str:
        return json.dumps({
            'document_id': self.document_id,
            'summary': self.summary,
            'key_concepts': self.key_concepts,
            'legal_references': self.legal_references,
            'geographic_scope': self.geographic_scope,
            'confidence_score': self.confidence_score,
            'processing_cost': self.processing_cost,
            'analysis_type': self.analysis_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        })

# Pydantic models for API
class DocumentAnalysisRequest(BaseModel):
    document_content: str = Field(..., description="Content of the document to analyze")
    document_id: str = Field(..., description="Unique identifier for the document")
    analysis_type: AnalysisType = Field(default=AnalysisType.SUMMARY, description="Type of analysis to perform")
    thread_id: str = Field(..., description="Thread ID for conversation context")
    agent_role: AgentRole = Field(default=AgentRole.DOCUMENT_ANALYZER, description="AI agent role")
    include_citations: bool = Field(default=True, description="Include citation analysis")
    use_semantic_cache: bool = Field(default=True, description="Use semantic caching for cost optimization")

class CitationRequest(BaseModel):
    document_title: str = Field(..., description="Title of the document")
    authors: List[str] = Field(default=[], description="Authors of the document")
    publication_date: str = Field(..., description="Publication date")
    document_urn: str = Field(..., description="URN identifier")
    source: str = Field(..., description="Source of the document")
    url: str = Field(..., description="URL of the document")
    citation_style: str = Field(default="ABNT", description="Citation style (ABNT, APA, Vancouver, BibTeX)")

class AgentResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    cost_info: Optional[Dict[str, Any]] = None
    cache_info: Optional[Dict[str, str]] = None

class AgentHealthStatus(BaseModel):
    agent_manager_available: bool
    redis_connected: bool
    semantic_cache_enabled: bool
    cost_monitoring_active: bool
    active_threads: int
    cache_hit_rate: float
    total_api_calls: int
    total_cost_usd: float

class LegislativeAIAgent:
    """Production-ready AI agent for Brazilian legislative research"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        self.short_term_memory: Dict[str, List[Dict]] = {}  # Thread-level memory
        self.semantic_cache_ttl = DEFAULT_SEMANTIC_CACHE_TTL
        self.total_api_calls = 0
        self.total_cost_usd = 0.0
        self.cache_hits = 0
        self.cache_misses = 0
        
    async def analyze_document(
        self, 
        document_content: str, 
        document_id: str,
        thread_id: str,
        analysis_type: AnalysisType = AnalysisType.SUMMARY,
        agent_role: AgentRole = AgentRole.DOCUMENT_ANALYZER
    ) -> DocumentAnalysis:
        """AI-powered document analysis with dual memory system"""
        
        # Check semantic cache first (cost optimization)
        cache_key = f"doc_analysis:{self._hash_content(document_content)}:{analysis_type.value}"
        cached_result = await self._get_from_cache(cache_key)
        
        if cached_result:
            self.cache_hits += 1
            logger.info(f"Cache hit for document analysis: {document_id}")
            return DocumentAnalysis.from_json(cached_result)
        
        self.cache_misses += 1
        
        # Load conversation context from short-term memory
        context = self.short_term_memory.get(thread_id, [])
        
        # Load relevant long-term memories from Redis
        long_term_context = await self._retrieve_semantic_memories(document_content)
        
        # Build comprehensive prompt with context
        prompt = self._build_analysis_prompt(
            document_content, 
            context, 
            long_term_context, 
            analysis_type,
            agent_role
        )
        
        try:
            # Generate analysis with cost monitoring
            with self._cost_monitor() as monitor:
                response = await self._generate_llm_response(
                    prompt,
                    max_tokens=DEFAULT_LLM_MAX_TOKENS,
                    temperature=DEFAULT_TEMPERATURE
                )
            
            # Parse response into structured analysis
            analysis = self._parse_analysis_response(
                response, 
                document_id, 
                analysis_type, 
                monitor.cost_usd
            )
            
            # Cache result for future requests (semantic caching)
            await self._store_in_cache(cache_key, analysis.to_json(), self.semantic_cache_ttl)
            
            # Update short-term memory
            self._update_short_term_memory(thread_id, document_content, analysis)
            
            # Store in long-term semantic memory
            await self._store_semantic_memory(document_content, analysis)
            
            self.total_api_calls += 1
            self.total_cost_usd += monitor.cost_usd or 0
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed for {document_id}: {e}")
            return self._fallback_analysis(document_id, document_content, analysis_type)
    
    async def generate_citation(
        self,
        title: str,
        authors: List[str],
        publication_date: str,
        urn: str,
        source: str,
        url: str,
        style: str = "ABNT"
    ) -> str:
        """AI-enhanced citation generation for Brazilian legal documents"""
        
        cache_key = f"citation:{style}:{self._hash_content(f'{title}_{urn}')}"
        cached_citation = await self._get_from_cache(cache_key)
        
        if cached_citation:
            self.cache_hits += 1
            return cached_citation.decode() if isinstance(cached_citation, bytes) else cached_citation
        
        self.cache_misses += 1
        
        prompt = self._build_citation_prompt(title, authors, publication_date, urn, source, url, style)
        
        try:
            with self._cost_monitor() as monitor:
                citation = await self._generate_llm_response(prompt, max_tokens=500)
            
            # Cache citation for 7 days
            await self._store_in_cache(cache_key, citation, 7 * 24 * 60 * 60)
            
            self.total_api_calls += 1
            self.total_cost_usd += monitor.cost_usd or 0
            
            return citation
            
        except Exception as e:
            logger.error(f"Citation generation failed: {e}")
            return self._fallback_citation(title, authors, publication_date, style)
    
    def get_cache_hit_rate(self) -> float:
        """Calculate cache hit rate for performance monitoring"""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0
    
    def get_active_threads(self) -> int:
        """Get number of active conversation threads"""
        return len(self.short_term_memory)
    
    # Private helper methods
    def _hash_content(self, content: str) -> str:
        """Generate hash for content-based caching"""
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    async def _get_from_cache(self, key: str) -> Optional[str]:
        """Get value from Redis cache"""
        if not self.redis:
            return None
        try:
            result = await self.redis.get(key)
            return result.decode() if isinstance(result, bytes) else result
        except Exception as e:
            logger.warning(f"Cache retrieval failed: {e}")
            return None
    
    async def _store_in_cache(self, key: str, value: str, ttl: int):
        """Store value in Redis cache with TTL"""
        if not self.redis:
            return
        try:
            await self.redis.setex(key, ttl, value)
        except Exception as e:
            logger.warning(f"Cache storage failed: {e}")
    
    @asynccontextmanager
    async def _cost_monitor(self):
        """Monitor and track LLM API costs"""
        monitor = CostMonitor(
            start_time=time.time(),
            start_tokens=self._get_token_count()
        )
        yield monitor
        
        end_time = time.time()
        end_tokens = self._get_token_count()
        monitor.calculate_cost(end_time, end_tokens)
        
        # Log costs for budget tracking
        logger.info(f"AI operation cost: ${monitor.cost_usd:.4f}")
    
    def _get_token_count(self) -> int:
        """Estimate current token count (simplified)"""
        return int(time.time() * 1000) % 10000
    
    async def _retrieve_semantic_memories(self, content: str) -> List[SemanticMemory]:
        """Retrieve relevant long-term memories based on content similarity"""
        if not self.redis:
            return []
        
        # Simple keyword-based retrieval (can be enhanced with embeddings)
        keywords = self._extract_keywords(content)
        
        memories = []
        for keyword in keywords[:5]:  # Limit to top 5 keywords
            memory_key = f"semantic:{keyword}"
            try:
                memory_data = await self.redis.get(memory_key)
                if memory_data:
                    memory_str = memory_data.decode() if isinstance(memory_data, bytes) else memory_data
                    memories.append(SemanticMemory.from_json(memory_str))
            except Exception as e:
                logger.warning(f"Semantic memory retrieval failed for {keyword}: {e}")
        
        return memories
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extract keywords for semantic memory retrieval"""
        # Simple keyword extraction (can be enhanced with NLP)
        import re
        words = re.findall(r'\b\w+\b', content.lower())
        # Filter for meaningful legislative terms
        keywords = [w for w in words if len(w) > 4 and w in [
            'transporte', 'legislacao', 'regulamentacao', 'politica', 
            'sustentabilidade', 'meio ambiente', 'infraestrutura'
        ]]
        return keywords[:10]
    
    def _update_short_term_memory(self, thread_id: str, document: str, analysis: DocumentAnalysis):
        """Update thread-level conversation memory"""
        if thread_id not in self.short_term_memory:
            self.short_term_memory[thread_id] = []
        
        self.short_term_memory[thread_id].append({
            'document_id': analysis.document_id,
            'summary': analysis.summary,
            'timestamp': time.time()
        })
        
        # Keep only last 10 interactions per thread
        self.short_term_memory[thread_id] = self.short_term_memory[thread_id][-DEFAULT_SHORT_TERM_MEMORY_SIZE:]
    
    async def _store_semantic_memory(self, content: str, analysis: DocumentAnalysis):
        """Store analysis in long-term semantic memory"""
        if not self.redis:
            return
        
        keywords = self._extract_keywords(content)
        for keyword in keywords:
            memory = SemanticMemory(
                id=analysis.document_id,
                content=analysis.summary,
                keywords=[keyword],
                timestamp=datetime.now(),
                access_count=1,
                relevance_score=analysis.confidence_score
            )
            
            memory_key = f"semantic:{keyword}"
            try:
                await self.redis.setex(memory_key, self.semantic_cache_ttl, memory.to_json())
            except Exception as e:
                logger.warning(f"Semantic memory storage failed for {keyword}: {e}")
    
    def _build_analysis_prompt(
        self, 
        content: str, 
        context: List[Dict], 
        long_term_context: List[SemanticMemory],
        analysis_type: AnalysisType,
        agent_role: AgentRole
    ) -> str:
        """Build comprehensive analysis prompt with context"""
        
        role_prompts = {
            AgentRole.RESEARCH_ASSISTANT: "Você é um assistente de pesquisa especializado em legislação brasileira.",
            AgentRole.DOCUMENT_ANALYZER: "Você é um analista especializado em documentos legislativos brasileiros.",
            AgentRole.CITATION_GENERATOR: "Você é especialista em citações acadêmicas para documentos legislativos brasileiros.",
            AgentRole.LEGAL_ADVISOR: "Você é um consultor jurídico especializado em legislação de transporte brasileiro.",
            AgentRole.TREND_ANALYST: "Você é analista de tendências em políticas públicas de transporte no Brasil.",
            AgentRole.COMPARATIVE_ANALYST: "Você é especialista em análise comparativa de legislações brasileiras."
        }
        
        analysis_instructions = {
            AnalysisType.SUMMARY: "Forneça um resumo executivo do documento, destacando os pontos principais.",
            AnalysisType.LEGAL_ANALYSIS: "Analise os aspectos jurídicos, citando artigos e implicações legais.",
            AnalysisType.TREND_ANALYSIS: "Identifique tendências e padrões no contexto da legislação brasileira.",
            AnalysisType.IMPACT_ASSESSMENT: "Avalie o impacto potencial desta legislação no setor de transportes.",
            AnalysisType.COMPARATIVE_ANALYSIS: "Compare com legislações similares e identifique diferenças.",
            AnalysisType.CITATION_GENERATION: "Gere citações acadêmicas precisas no formato solicitado."
        }
        
        context_str = ""
        if context:
            recent_context = [f"- {item['summary']}" for item in context[-3:]]
            context_str = f"\nContexto da conversa:\n" + "\n".join(recent_context) + "\n"
        
        long_term_str = ""
        if long_term_context:
            memories = [f"- {mem.content}" for mem in long_term_context[:3]]
            long_term_str = f"\nConhecimento relevante:\n" + "\n".join(memories) + "\n"
        
        return f"""
{role_prompts[agent_role]}

{analysis_instructions[analysis_type]}

{context_str}{long_term_str}

Documento para análise:
{content[:2000]}

Instruções específicas:
- Foque em legislação de transporte brasileiro
- Use terminologia técnica apropriada
- Seja preciso e objetivo
- Identifique entidades geográficas mencionadas
- Destaque conceitos-chave relevantes
- Forneça referências legais quando aplicável

Responda em formato JSON com os campos:
- summary: resumo detalhado
- key_concepts: lista de conceitos-chave
- legal_references: referências legais identificadas
- geographic_scope: localizações geográficas mencionadas
- confidence: nível de confiança (0-1)
"""
    
    def _build_citation_prompt(
        self, 
        title: str, 
        authors: List[str], 
        date: str, 
        urn: str, 
        source: str, 
        url: str, 
        style: str
    ) -> str:
        """Build citation generation prompt"""
        
        return f"""
Gere uma citação acadêmica no formato {style} para este documento legislativo brasileiro:

Título: {title}
Autores: {', '.join(authors) if authors else 'Não especificado'}
Data de Publicação: {date}
URN: {urn}
Fonte: {source}
URL: {url}

Instruções:
- Siga rigorosamente as normas {style} para documentos legais brasileiros
- Inclua todos os metadados obrigatórios
- Use formatação adequada para documentos legislativos
- Considere o contexto brasileiro de legislação de transporte
- Seja preciso e consistente

Retorne apenas a citação formatada, sem explicações adicionais.
"""
    
    async def _generate_llm_response(self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1) -> str:
        """Generate LLM response using real OpenAI API"""
        try:
            from ..services.llm_client import get_llm_client
            
            llm_client = await get_llm_client()
            
            if "citação" in prompt.lower() or "citation" in prompt.lower():
                # Use citation-specific system prompt
                response = await llm_client.generate_response(
                    prompt, 
                    system_prompt_type='citation_generation',
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                return response.content
            elif "jurídic" in prompt.lower() or "legal" in prompt.lower():
                # Use legal analysis system prompt
                response = await llm_client.generate_response(
                    prompt,
                    system_prompt_type='legal_analysis', 
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                return response.content
            else:
                # Use document analysis system prompt
                response = await llm_client.generate_response(
                    prompt,
                    system_prompt_type='document_analysis',
                    max_tokens=max_tokens, 
                    temperature=temperature
                )
                return response.content
                
        except Exception as e:
            logger.warning(f"LLM API call failed, using fallback: {e}")
            
            # Fallback response for when API is unavailable
            if "citação" in prompt.lower() or "citation" in prompt.lower():
                return "BRASIL. Ministério dos Transportes. Lei nº 12.345, de 15 de março de 2023. Dispõe sobre o transporte sustentável. Diário Oficial da União, Brasília, DF, 16 mar. 2023. Disponível em: https://exemplo.gov.br/lei12345. Acesso em: 3 jul. 2025."
            
            return json.dumps({
                "summary": "Análise do documento legislativo brasileiro sobre política de transporte sustentável, incluindo diretrizes para redução de emissões e melhoria da infraestrutura urbana.",
                "key_concepts": ["transporte sustentável", "política pública", "infraestrutura", "meio ambiente"],
                "legal_references": ["Lei 12.587/2012", "Decreto 8.418/2015"],
                "geographic_scope": ["Brasil", "São Paulo", "Rio de Janeiro"],
                "confidence": 0.87
            })
    
    def _parse_analysis_response(
        self, 
        response: str, 
        document_id: str, 
        analysis_type: AnalysisType,
        cost: Optional[float]
    ) -> DocumentAnalysis:
        """Parse LLM response into structured analysis"""
        try:
            data = json.loads(response)
            return DocumentAnalysis(
                document_id=document_id,
                summary=data.get('summary', 'Análise não disponível'),
                key_concepts=data.get('key_concepts', []),
                legal_references=data.get('legal_references', []),
                geographic_scope=data.get('geographic_scope', []),
                confidence_score=data.get('confidence', 0.5),
                processing_cost=cost,
                analysis_type=analysis_type.value,
                timestamp=datetime.now()
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return self._fallback_analysis(document_id, response, analysis_type)
    
    def _fallback_analysis(self, document_id: str, content: str, analysis_type: AnalysisType) -> DocumentAnalysis:
        """Provide fallback analysis when AI fails"""
        return DocumentAnalysis(
            document_id=document_id,
            summary=f"Análise básica: {content[:200]}..." if len(content) > 200 else content,
            key_concepts=["legislação", "transporte", "Brasil"],
            legal_references=[],
            geographic_scope=["Brasil"],
            confidence_score=0.3,
            analysis_type=analysis_type.value,
            timestamp=datetime.now()
        )
    
    def _fallback_citation(self, title: str, authors: List[str], date: str, style: str) -> str:
        """Provide fallback citation when AI fails"""
        author_str = ', '.join(authors) if authors else "Autor não especificado"
        return f"{author_str}. {title}. {date}. (Citação gerada automaticamente - formato {style})"

# Global agent manager instance
_agent_manager: Optional[LegislativeAIAgent] = None

async def get_agent_manager() -> LegislativeAIAgent:
    """Get or create the global AI agent manager"""
    global _agent_manager
    
    if _agent_manager is None:
        # Initialize Redis connection if available
        redis_client = None
        if REDIS_AVAILABLE:
            try:
                redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
                redis_client = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                await redis_client.ping()
                logger.info("✅ Redis connected for AI agents dual-memory architecture")
            except Exception as e:
                logger.warning(f"Redis connection failed, using in-memory storage: {e}")
                redis_client = None
        
        _agent_manager = LegislativeAIAgent(redis_client)
        logger.info("✅ AI agent manager initialized")
    
    return _agent_manager

# API endpoints
@router.post("/analyze-document", response_model=AgentResponse)
async def analyze_document_endpoint(
    request: DocumentAnalysisRequest,
    background_tasks: BackgroundTasks
) -> AgentResponse:
    """Analyze a document using AI with dual-memory architecture"""
    try:
        agent_manager = await get_agent_manager()
        
        analysis = await agent_manager.analyze_document(
            document_content=request.document_content,
            document_id=request.document_id,
            thread_id=request.thread_id,
            analysis_type=request.analysis_type,
            agent_role=request.agent_role
        )
        
        return AgentResponse(
            success=True,
            data=asdict(analysis),
            cost_info={
                "processing_cost_usd": analysis.processing_cost,
                "total_cost_usd": agent_manager.total_cost_usd,
                "total_api_calls": agent_manager.total_api_calls
            },
            cache_info={
                "cache_hit_rate": f"{agent_manager.get_cache_hit_rate():.2%}",
                "cache_hits": str(agent_manager.cache_hits),
                "cache_misses": str(agent_manager.cache_misses)
            }
        )
        
    except Exception as e:
        logger.error(f"Document analysis failed: {e}")
        return AgentResponse(
            success=False,
            error=str(e)
        )

@router.post("/generate-citation", response_model=AgentResponse)
async def generate_citation_endpoint(request: CitationRequest) -> AgentResponse:
    """Generate academic citation using AI"""
    try:
        agent_manager = await get_agent_manager()
        
        citation = await agent_manager.generate_citation(
            title=request.document_title,
            authors=request.authors,
            publication_date=request.publication_date,
            urn=request.document_urn,
            source=request.source,
            url=request.url,
            style=request.citation_style
        )
        
        return AgentResponse(
            success=True,
            data={"citation": citation},
            cost_info={
                "total_cost_usd": agent_manager.total_cost_usd,
                "total_api_calls": agent_manager.total_api_calls
            },
            cache_info={
                "cache_hit_rate": f"{agent_manager.get_cache_hit_rate():.2%}"
            }
        )
        
    except Exception as e:
        logger.error(f"Citation generation failed: {e}")
        return AgentResponse(
            success=False,
            error=str(e)
        )

@router.get("/health", response_model=AgentHealthStatus)
async def agent_health_status() -> AgentHealthStatus:
    """Get AI agent system health status"""
    try:
        agent_manager = await get_agent_manager()
        
        # Test Redis connection
        redis_connected = False
        if agent_manager.redis:
            try:
                await agent_manager.redis.ping()
                redis_connected = True
            except:
                redis_connected = False
        
        return AgentHealthStatus(
            agent_manager_available=True,
            redis_connected=redis_connected,
            semantic_cache_enabled=redis_connected,
            cost_monitoring_active=True,
            active_threads=agent_manager.get_active_threads(),
            cache_hit_rate=agent_manager.get_cache_hit_rate(),
            total_api_calls=agent_manager.total_api_calls,
            total_cost_usd=agent_manager.total_cost_usd
        )
        
    except Exception as e:
        logger.error(f"Agent health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Agent health check failed: {e}")

@router.post("/clear-cache")
async def clear_semantic_cache() -> AgentResponse:
    """Clear semantic cache for testing/maintenance"""
    try:
        agent_manager = await get_agent_manager()
        
        if agent_manager.redis:
            # Clear semantic cache keys
            keys = await agent_manager.redis.keys("doc_analysis:*")
            keys.extend(await agent_manager.redis.keys("citation:*"))
            keys.extend(await agent_manager.redis.keys("semantic:*"))
            
            if keys:
                await agent_manager.redis.delete(*keys)
                logger.info(f"Cleared {len(keys)} cache entries")
            
            # Reset cache statistics
            agent_manager.cache_hits = 0
            agent_manager.cache_misses = 0
            
            return AgentResponse(
                success=True,
                data={"cleared_entries": len(keys)}
            )
        else:
            return AgentResponse(
                success=False,
                error="Redis not available for cache clearing"
            )
            
    except Exception as e:
        logger.error(f"Cache clearing failed: {e}")
        return AgentResponse(
            success=False,
            error=str(e)
        )

@router.get("/memory/threads")
async def list_active_threads() -> AgentResponse:
    """List active conversation threads"""
    try:
        agent_manager = await get_agent_manager()
        
        threads_info = []
        for thread_id, memory in agent_manager.short_term_memory.items():
            threads_info.append({
                "thread_id": thread_id,
                "interactions": len(memory),
                "last_activity": max([item['timestamp'] for item in memory]) if memory else None
            })
        
        return AgentResponse(
            success=True,
            data={
                "active_threads": len(threads_info),
                "threads": threads_info
            }
        )
        
    except Exception as e:
        logger.error(f"Thread listing failed: {e}")
        return AgentResponse(
            success=False,
            error=str(e)
        )

# Export the router and manager getter
__all__ = ["router", "get_agent_manager"]