"""
LLM Client Service - OpenAI integration for Monitor Legislativo v4
Production-ready client with cost monitoring and Portuguese optimization
"""

import asyncio
import json
import logging
import time
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

try:
    import openai
    from openai import AsyncOpenAI
    import tiktoken
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("OpenAI libraries not available - LLM features will be limited")

logger = logging.getLogger(__name__)

@dataclass
class LLMResponse:
    """LLM response with metadata"""
    content: str
    model: str
    tokens_used: int
    cost_usd: float
    processing_time: float
    finish_reason: str

@dataclass
class CostTracker:
    """Track daily LLM costs"""
    date: str
    total_cost: float
    request_count: int
    token_count: int
    
class LLMClient:
    """Production LLM client with Portuguese optimization"""
    
    def __init__(self):
        self.client = None
        self.model = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
        self.max_tokens = int(os.getenv('OPENAI_MAX_TOKENS', '2000'))
        self.temperature = float(os.getenv('OPENAI_TEMPERATURE', '0.1'))
        self.max_daily_cost = float(os.getenv('MAX_DAILY_AI_COST_USD', '2.00'))
        
        # Cost tracking
        self.daily_costs: Dict[str, CostTracker] = {}
        
        # Token pricing (per 1K tokens)
        self.pricing = {
            'gpt-3.5-turbo': {'input': 0.0015, 'output': 0.002},
            'gpt-3.5-turbo-1106': {'input': 0.001, 'output': 0.002},
            'gpt-4': {'input': 0.03, 'output': 0.06},
            'gpt-4-turbo': {'input': 0.01, 'output': 0.03}
        }
        
        # Initialize tokenizer
        try:
            self.tokenizer = tiktoken.encoding_for_model(self.model)
        except:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
        # Portuguese prompts optimization
        self.system_prompts = {
            'document_analysis': """Você é um assistente de pesquisa especializado em legislação brasileira de transporte. 
Analise documentos legislativos com foco em:
- Precisão jurídica e técnica
- Contexto brasileiro de regulamentação
- Terminologia específica do setor de transportes
- Identificação de entidades geográficas (estados, municípios)
- Referências a órgãos reguladores (ANTT, ANTAQ, ANAC, DNIT)

Responda sempre em português brasileiro, usando linguagem técnica apropriada.""",
            
            'citation_generation': """Você é especialista em citações acadêmicas para documentos legislativos brasileiros.
Gere citações precisas seguindo as normas ABNT, APA, Vancouver ou BibTeX.
Considere as especificidades de documentos jurídicos brasileiros:
- Leis, decretos, portarias, resoluções
- Diário Oficial da União
- Órgãos públicos e agências reguladoras
- URNs do sistema LexML quando disponíveis

Mantenha rigor acadêmico e formatação impecável.""",
            
            'legal_analysis': """Você é consultor jurídico especializado em direito administrativo e regulamentação de transportes no Brasil.
Analise documentos considerando:
- Hierarquia normativa brasileira
- Competências dos órgãos reguladores
- Impactos setoriais e regionais
- Conformidade com marcos regulatórios
- Aspectos de implementação prática

Forneça análises juridicamente fundamentadas e contextualmente relevantes."""
        }
    
    async def initialize(self) -> bool:
        """Initialize OpenAI client"""
        if not OPENAI_AVAILABLE:
            logger.error("OpenAI libraries not installed")
            return False
        
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            logger.error("OPENAI_API_KEY not configured")
            return False
        
        try:
            self.client = AsyncOpenAI(api_key=api_key)
            
            # Test connection
            await self.client.models.list()
            logger.info(f"✅ OpenAI client initialized with model: {self.model}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            return False
    
    async def generate_response(
        self,
        prompt: str,
        system_prompt_type: str = 'document_analysis',
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        """Generate LLM response with cost tracking"""
        
        if not self.client:
            raise RuntimeError("LLM client not initialized")
        
        # Check daily cost limit
        today = datetime.now().strftime('%Y-%m-%d')
        if today in self.daily_costs:
            if self.daily_costs[today].total_cost >= self.max_daily_cost:
                raise RuntimeError(f"Daily cost limit ${self.max_daily_cost} exceeded")
        
        # Prepare messages
        system_prompt = self.system_prompts.get(system_prompt_type, self.system_prompts['document_analysis'])
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        # Count input tokens
        input_tokens = self._count_tokens(system_prompt + prompt)
        
        # API parameters
        params = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature or self.temperature,
            "top_p": 0.9,
            "frequency_penalty": 0.0,
            "presence_penalty": 0.0
        }
        
        start_time = time.time()
        
        try:
            # Make API call
            response = await self.client.chat.completions.create(**params)
            
            processing_time = time.time() - start_time
            
            # Extract response data
            content = response.choices[0].message.content
            finish_reason = response.choices[0].finish_reason
            output_tokens = response.usage.completion_tokens
            total_tokens = response.usage.total_tokens
            
            # Calculate cost
            cost = self._calculate_cost(input_tokens, output_tokens)
            
            # Update cost tracking
            self._update_cost_tracking(today, cost, total_tokens)
            
            # Log for monitoring
            logger.info(f"LLM request: {input_tokens}→{output_tokens} tokens, ${cost:.4f}, {processing_time:.2f}s")
            
            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=total_tokens,
                cost_usd=cost,
                processing_time=processing_time,
                finish_reason=finish_reason
            )
            
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            raise
    
    async def analyze_document(self, content: str, analysis_type: str = 'summary') -> Dict[str, Any]:
        """Analyze Brazilian legislative document"""
        
        prompt = f"""
Analise este documento legislativo brasileiro e forneça:

Tipo de análise: {analysis_type}

Documento:
{content[:3000]}

Forneça a resposta em formato JSON com os seguintes campos:
- summary: resumo detalhado do documento
- key_concepts: lista de conceitos-chave
- legal_references: referências legais identificadas (leis, decretos, etc.)
- geographic_scope: localidades geográficas mencionadas
- transport_aspects: aspectos relacionados a transporte (se aplicável)
- regulatory_entities: órgãos reguladores mencionados
- confidence: nível de confiança da análise (0-1)

Use terminologia técnica precisa e contexto brasileiro.
"""
        
        response = await self.generate_response(prompt, 'document_analysis')
        
        try:
            # Parse JSON response
            result = json.loads(response.content)
            result['processing_metadata'] = {
                'model': response.model,
                'tokens_used': response.tokens_used,
                'cost_usd': response.cost_usd,
                'processing_time': response.processing_time
            }
            return result
            
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            return {
                'summary': response.content,
                'key_concepts': [],
                'legal_references': [],
                'geographic_scope': [],
                'transport_aspects': [],
                'regulatory_entities': [],
                'confidence': 0.7,
                'processing_metadata': {
                    'model': response.model,
                    'tokens_used': response.tokens_used,
                    'cost_usd': response.cost_usd,
                    'processing_time': response.processing_time
                }
            }
    
    async def generate_citation(
        self,
        title: str,
        authors: List[str],
        date: str,
        urn: str,
        source: str,
        url: str,
        style: str = 'ABNT'
    ) -> str:
        """Generate academic citation"""
        
        authors_str = ', '.join(authors) if authors else 'Autor não especificado'
        
        prompt = f"""
Gere uma citação acadêmica no formato {style} para este documento legislativo brasileiro:

Título: {title}
Autores: {authors_str}
Data: {date}
URN: {urn}
Fonte: {source}
URL: {url}

Instruções específicas para {style}:
- Siga rigorosamente as normas {style} para documentos legais brasileiros
- Use formatação adequada para legislação (negrito, itálico quando necessário)
- Inclua todos os elementos obrigatórios
- Considere que é um documento oficial brasileiro
- Para ABNT: use NBR 6023:2018
- Para APA: use 7ª edição
- Para Vancouver: use formato numérico
- Para BibTeX: use tipo @misc ou @legislation

Retorne apenas a citação formatada, sem explicações.
"""
        
        response = await self.generate_response(prompt, 'citation_generation')
        return response.content.strip()
    
    async def legal_analysis(self, content: str, focus_area: str = 'transport') -> Dict[str, Any]:
        """Perform legal analysis of Brazilian legislation"""
        
        prompt = f"""
Realize uma análise jurídica deste documento da legislação brasileira com foco em {focus_area}:

{content[:3000]}

Forneça análise em formato JSON com:
- legal_classification: classificação jurídica do documento
- regulatory_hierarchy: posição na hierarquia normativa
- competence_analysis: análise de competências dos órgãos
- implementation_aspects: aspectos de implementação
- sectoral_impact: impactos setoriais identificados
- compliance_requirements: requisitos de conformidade
- related_legislation: legislação relacionada ou citada
- risk_assessment: avaliação de riscos regulatórios
- recommendations: recomendações técnicas
- confidence_score: nível de confiança (0-1)

Seja preciso e tecnicamente rigoroso na análise jurídica.
"""
        
        response = await self.generate_response(prompt, 'legal_analysis')
        
        try:
            result = json.loads(response.content)
            result['analysis_metadata'] = {
                'focus_area': focus_area,
                'model': response.model,
                'cost_usd': response.cost_usd
            }
            return result
        except json.JSONDecodeError:
            return {
                'legal_classification': 'Análise não disponível',
                'analysis_text': response.content,
                'confidence_score': 0.5
            }
    
    def get_daily_costs(self, days: int = 7) -> Dict[str, CostTracker]:
        """Get daily cost tracking for last N days"""
        end_date = datetime.now()
        costs = {}
        
        for i in range(days):
            date = (end_date - timedelta(days=i)).strftime('%Y-%m-%d')
            costs[date] = self.daily_costs.get(date, CostTracker(date, 0.0, 0, 0))
        
        return costs
    
    def get_cost_summary(self) -> Dict[str, Any]:
        """Get cost summary and projections"""
        today = datetime.now().strftime('%Y-%m-%d')
        today_costs = self.daily_costs.get(today, CostTracker(today, 0.0, 0, 0))
        
        # Calculate monthly projection
        days_in_month = 30
        monthly_projection = today_costs.total_cost * days_in_month
        
        return {
            'today_cost': today_costs.total_cost,
            'today_requests': today_costs.request_count,
            'monthly_projection': monthly_projection,
            'daily_limit': self.max_daily_cost,
            'budget_usage_percent': (today_costs.total_cost / self.max_daily_cost) * 100,
            'cost_per_request': today_costs.total_cost / max(1, today_costs.request_count)
        }
    
    # Private helper methods
    def _count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        try:
            return len(self.tokenizer.encode(text))
        except:
            # Fallback estimation
            return len(text.split()) * 1.3
    
    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate API cost based on token usage"""
        pricing = self.pricing.get(self.model, self.pricing['gpt-3.5-turbo'])
        
        input_cost = (input_tokens / 1000) * pricing['input']
        output_cost = (output_tokens / 1000) * pricing['output']
        
        return input_cost + output_cost
    
    def _update_cost_tracking(self, date: str, cost: float, tokens: int):
        """Update daily cost tracking"""
        if date not in self.daily_costs:
            self.daily_costs[date] = CostTracker(date, 0.0, 0, 0)
        
        tracker = self.daily_costs[date]
        tracker.total_cost += cost
        tracker.request_count += 1
        tracker.token_count += tokens

# Global LLM client instance
_llm_client: Optional[LLMClient] = None

async def get_llm_client() -> LLMClient:
    """Get or initialize the global LLM client"""
    global _llm_client
    
    if _llm_client is None:
        _llm_client = LLMClient()
        if await _llm_client.initialize():
            logger.info("✅ LLM client ready for Brazilian legislative analysis")
        else:
            logger.error("❌ LLM client initialization failed")
            raise RuntimeError("Failed to initialize LLM client")
    
    return _llm_client

# Export client getter
__all__ = ["get_llm_client", "LLMClient", "LLMResponse"]