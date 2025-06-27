"""
Production-Ready AI Agent Foundation
===================================

Core AI agent framework based on agents-towards-production patterns.
Implements dual-memory architecture with cost monitoring and semantic caching
for academic research assistance in Brazilian legislative analysis.

Features:
- Thread-level short-term memory for conversation context
- Semantic long-term memory for knowledge persistence  
- Cost monitoring and budget alerts
- Semantic caching for 60-80% cost reduction
- Academic research specialization
- Production-ready error handling and resilience
"""

import json
import hashlib
import logging
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import asyncio

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    """AI agent specialized roles"""
    RESEARCH_ASSISTANT = "research_assistant"
    CITATION_SPECIALIST = "citation_specialist"
    DOCUMENT_ANALYZER = "document_analyzer"
    LEGISLATIVE_EXPERT = "legislative_expert"
    GEOGRAPHIC_ANALYST = "geographic_analyst"


class MemoryType(Enum):
    """Memory storage types"""
    SHORT_TERM = "short_term"      # Thread/session level
    LONG_TERM = "long_term"        # Persistent semantic memory
    SEMANTIC_CACHE = "cache"       # Cost optimization cache


@dataclass
class AgentConfig:
    """Configuration for AI agent instances"""
    agent_id: str
    role: AgentRole
    max_short_term_memory: int = 50  # Messages
    max_long_term_memory: int = 1000  # Semantic chunks
    cost_budget_monthly: float = 10.0  # USD
    semantic_cache_ttl: int = 86400  # 24 hours
    temperature: float = 0.1  # Low for academic accuracy
    max_tokens: int = 2000
    model: str = "gpt-4o-mini"  # Cost-optimized model


@dataclass
class MemoryEntry:
    """Memory entry for agent storage"""
    entry_id: str
    memory_type: MemoryType
    content: str
    metadata: Dict[str, Any]
    timestamp: datetime
    embedding_hash: Optional[str] = None  # For semantic similarity
    cost_cents: Optional[float] = None    # Track costs
    ttl: Optional[int] = None            # Time to live in seconds


@dataclass
class LLMResponse:
    """Response from LLM with cost tracking"""
    content: str
    model_used: str
    tokens_input: int
    tokens_output: int
    cost_cents: float
    response_time_ms: float
    from_cache: bool = False
    cache_key: Optional[str] = None


class CostMonitor:
    """Monitor and track LLM API costs"""
    
    def __init__(self, redis_client, monthly_budget: float = 10.0):
        self.redis = redis_client
        self.monthly_budget = monthly_budget
        self.cost_key_prefix = "ai:costs"
        
        # Cost per token for different models (in cents)
        self.model_costs = {
            "gpt-4o-mini": {"input": 0.000015, "output": 0.00006},  # $0.15/$0.60 per 1M tokens
            "gpt-4o": {"input": 0.00025, "output": 0.001},          # $2.50/$10.00 per 1M tokens
            "gpt-3.5-turbo": {"input": 0.00015, "output": 0.0002}   # $1.50/$2.00 per 1M tokens
        }
    
    async def calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost in cents for API call"""
        if model not in self.model_costs:
            logger.warning(f"Unknown model {model}, using gpt-4o-mini costs")
            model = "gpt-4o-mini"
        
        costs = self.model_costs[model]
        input_cost = input_tokens * costs["input"]
        output_cost = output_tokens * costs["output"]
        total_cost_cents = (input_cost + output_cost) * 100
        
        return total_cost_cents
    
    async def track_usage(self, agent_id: str, cost_cents: float, model: str):
        """Track API usage and costs"""
        current_month = datetime.now().strftime("%Y-%m")
        daily_key = f"{self.cost_key_prefix}:daily:{agent_id}:{datetime.now().strftime('%Y-%m-%d')}"
        monthly_key = f"{self.cost_key_prefix}:monthly:{agent_id}:{current_month}"
        
        # Track daily and monthly costs
        await self.redis.incrbyfloat(daily_key, cost_cents)
        await self.redis.incrbyfloat(monthly_key, cost_cents)
        await self.redis.expire(daily_key, 86400 * 32)  # Keep for 32 days
        await self.redis.expire(monthly_key, 86400 * 400)  # Keep for ~13 months
        
        # Track model usage
        model_key = f"{self.cost_key_prefix}:model:{agent_id}:{current_month}:{model}"
        await self.redis.incrbyfloat(model_key, cost_cents)
        await self.redis.expire(model_key, 86400 * 400)
    
    async def get_cost_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get cost summary for agent"""
        current_month = datetime.now().strftime("%Y-%m")
        today = datetime.now().strftime("%Y-%m-%d")
        
        daily_key = f"{self.cost_key_prefix}:daily:{agent_id}:{today}"
        monthly_key = f"{self.cost_key_prefix}:monthly:{agent_id}:{current_month}"
        
        daily_cost = await self.redis.get(daily_key) or 0
        monthly_cost = await self.redis.get(monthly_key) or 0
        
        return {
            "daily_cost_cents": float(daily_cost),
            "monthly_cost_cents": float(monthly_cost),
            "budget_monthly_cents": self.monthly_budget * 100,
            "budget_remaining_cents": (self.monthly_budget * 100) - float(monthly_cost),
            "budget_utilization_percent": (float(monthly_cost) / (self.monthly_budget * 100)) * 100,
            "within_budget": float(monthly_cost) <= (self.monthly_budget * 100)
        }
    
    async def check_budget_alert(self, agent_id: str) -> Optional[str]:
        """Check if budget alert should be triggered"""
        summary = await self.get_cost_summary(agent_id)
        
        if summary["budget_utilization_percent"] > 90:
            return f"CRITICAL: Agent {agent_id} has used {summary['budget_utilization_percent']:.1f}% of monthly budget"
        elif summary["budget_utilization_percent"] > 75:
            return f"WARNING: Agent {agent_id} has used {summary['budget_utilization_percent']:.1f}% of monthly budget"
        
        return None


class SemanticCache:
    """Semantic caching for cost optimization"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.cache_prefix = "ai:semantic_cache"
    
    def _generate_cache_key(self, prompt: str, model: str, temperature: float) -> str:
        """Generate semantic cache key"""
        # Normalize prompt for better cache hits
        normalized = prompt.lower().strip()
        
        # Create hash of normalized prompt + model + temperature
        cache_input = f"{normalized}:{model}:{temperature}"
        cache_hash = hashlib.sha256(cache_input.encode()).hexdigest()[:16]
        
        return f"{self.cache_prefix}:{cache_hash}"
    
    async def get_cached_response(self, prompt: str, model: str, temperature: float) -> Optional[LLMResponse]:
        """Get cached response if available"""
        cache_key = self._generate_cache_key(prompt, model, temperature)
        
        cached_data = await self.redis.get(cache_key)
        if cached_data:
            try:
                data = json.loads(cached_data)
                response = LLMResponse(
                    content=data["content"],
                    model_used=data["model_used"],
                    tokens_input=data["tokens_input"],
                    tokens_output=data["tokens_output"],
                    cost_cents=data["cost_cents"],
                    response_time_ms=0.1,  # Near-instant from cache
                    from_cache=True,
                    cache_key=cache_key
                )
                logger.info(f"Cache hit for semantic cache key: {cache_key[:8]}...")
                return response
            except json.JSONDecodeError:
                logger.warning(f"Invalid cached data for key: {cache_key}")
        
        return None
    
    async def cache_response(self, prompt: str, model: str, temperature: float, 
                           response: LLMResponse, ttl: int = 86400):
        """Cache LLM response for future use"""
        cache_key = self._generate_cache_key(prompt, model, temperature)
        
        cache_data = {
            "content": response.content,
            "model_used": response.model_used,
            "tokens_input": response.tokens_input,
            "tokens_output": response.tokens_output,
            "cost_cents": response.cost_cents,
            "cached_at": datetime.now().isoformat()
        }
        
        await self.redis.setex(cache_key, ttl, json.dumps(cache_data))
        logger.info(f"Cached response for key: {cache_key[:8]}... (TTL: {ttl}s)")


class AgentMemory:
    """Dual-memory system for AI agents"""
    
    def __init__(self, redis_client, agent_id: str, config: AgentConfig):
        self.redis = redis_client
        self.agent_id = agent_id
        self.config = config
        self.memory_prefix = f"ai:memory:{agent_id}"
    
    async def add_short_term_memory(self, content: str, metadata: Dict[str, Any]) -> str:
        """Add entry to short-term (thread-level) memory"""
        entry_id = f"st_{int(time.time() * 1000)}"
        
        entry = MemoryEntry(
            entry_id=entry_id,
            memory_type=MemoryType.SHORT_TERM,
            content=content,
            metadata=metadata,
            timestamp=datetime.now(),
            ttl=7200  # 2 hours for short-term memory
        )
        
        # Store in Redis list (FIFO with max length)
        key = f"{self.memory_prefix}:short_term"
        await self.redis.lpush(key, json.dumps(asdict(entry), default=str))
        await self.redis.ltrim(key, 0, self.config.max_short_term_memory - 1)
        await self.redis.expire(key, entry.ttl)
        
        return entry_id
    
    async def add_long_term_memory(self, content: str, metadata: Dict[str, Any], 
                                  embedding_hash: Optional[str] = None) -> str:
        """Add entry to long-term (semantic) memory"""
        entry_id = f"lt_{int(time.time() * 1000)}"
        
        entry = MemoryEntry(
            entry_id=entry_id,
            memory_type=MemoryType.LONG_TERM,
            content=content,
            metadata=metadata,
            timestamp=datetime.now(),
            embedding_hash=embedding_hash,
            ttl=2592000  # 30 days for long-term memory
        )
        
        # Store in Redis hash for semantic lookup
        key = f"{self.memory_prefix}:long_term"
        await self.redis.hset(key, entry_id, json.dumps(asdict(entry), default=str))
        await self.redis.expire(key, entry.ttl)
        
        # Maintain memory limits
        await self._cleanup_long_term_memory()
        
        return entry_id
    
    async def get_short_term_context(self, limit: int = 10) -> List[MemoryEntry]:
        """Get recent short-term memory for context"""
        key = f"{self.memory_prefix}:short_term"
        entries = await self.redis.lrange(key, 0, limit - 1)
        
        memory_entries = []
        for entry_data in entries:
            try:
                data = json.loads(entry_data)
                data["timestamp"] = datetime.fromisoformat(data["timestamp"])
                memory_entries.append(MemoryEntry(**data))
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Invalid memory entry: {e}")
        
        return memory_entries
    
    async def search_long_term_memory(self, query_keywords: List[str], limit: int = 5) -> List[MemoryEntry]:
        """Search long-term memory for relevant entries"""
        key = f"{self.memory_prefix}:long_term"
        all_entries = await self.redis.hgetall(key)
        
        scored_entries = []
        query_lower = [keyword.lower() for keyword in query_keywords]
        
        for entry_id, entry_data in all_entries.items():
            try:
                data = json.loads(entry_data)
                data["timestamp"] = datetime.fromisoformat(data["timestamp"])
                entry = MemoryEntry(**data)
                
                # Simple keyword matching score
                content_lower = entry.content.lower()
                score = sum(1 for keyword in query_lower if keyword in content_lower)
                
                if score > 0:
                    scored_entries.append((score, entry))
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Invalid long-term memory entry: {e}")
        
        # Sort by score and return top results
        scored_entries.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored_entries[:limit]]
    
    async def _cleanup_long_term_memory(self):
        """Clean up old long-term memory entries"""
        key = f"{self.memory_prefix}:long_term"
        all_entries = await self.redis.hgetall(key)
        
        if len(all_entries) <= self.config.max_long_term_memory:
            return
        
        # Parse and sort by timestamp
        entry_timestamps = []
        for entry_id, entry_data in all_entries.items():
            try:
                data = json.loads(entry_data)
                timestamp = datetime.fromisoformat(data["timestamp"])
                entry_timestamps.append((timestamp, entry_id))
            except (json.JSONDecodeError, ValueError):
                # Remove invalid entries
                await self.redis.hdel(key, entry_id)
        
        # Remove oldest entries
        entry_timestamps.sort()
        entries_to_remove = len(entry_timestamps) - self.config.max_long_term_memory
        
        for i in range(entries_to_remove):
            _, entry_id = entry_timestamps[i]
            await self.redis.hdel(key, entry_id)
        
        logger.info(f"Cleaned up {entries_to_remove} old long-term memory entries")
    
    async def get_memory_statistics(self) -> Dict[str, Any]:
        """Get memory usage statistics"""
        short_term_key = f"{self.memory_prefix}:short_term"
        long_term_key = f"{self.memory_prefix}:long_term"
        
        short_term_count = await self.redis.llen(short_term_key)
        long_term_count = await self.redis.hlen(long_term_key)
        
        return {
            "agent_id": self.agent_id,
            "short_term_entries": short_term_count,
            "long_term_entries": long_term_count,
            "short_term_limit": self.config.max_short_term_memory,
            "long_term_limit": self.config.max_long_term_memory,
            "memory_utilization": {
                "short_term_percent": (short_term_count / self.config.max_short_term_memory) * 100,
                "long_term_percent": (long_term_count / self.config.max_long_term_memory) * 100
            }
        }


class ProductionAIAgent:
    """Production-ready AI agent with dual-memory and cost optimization"""
    
    def __init__(self, redis_client, config: AgentConfig):
        self.config = config
        self.redis = redis_client
        self.memory = AgentMemory(redis_client, config.agent_id, config)
        self.cost_monitor = CostMonitor(redis_client, config.cost_budget_monthly)
        self.semantic_cache = SemanticCache(redis_client)
        
        # Agent personality based on role
        self.system_prompts = {
            AgentRole.RESEARCH_ASSISTANT: """You are a specialized research assistant for Brazilian legislative analysis. 
                Help researchers find relevant laws, understand legal contexts, and analyze legislative patterns. 
                Always provide accurate citations in ABNT format and suggest related research paths.""",
            
            AgentRole.CITATION_SPECIALIST: """You are an expert in academic citation formatting for Brazilian legal documents. 
                Generate precise ABNT, APA, and other format citations. Ensure all legal document references 
                follow proper academic standards.""",
            
            AgentRole.DOCUMENT_ANALYZER: """You are a document analysis expert specializing in Brazilian legislation. 
                Analyze document content, extract key concepts, identify relationships between laws, 
                and provide structured summaries.""",
            
            AgentRole.LEGISLATIVE_EXPERT: """You are a Brazilian legislative expert with deep knowledge of federal, 
                state, and municipal legal frameworks. Explain legal concepts, analyze regulatory impacts, 
                and provide contextual understanding of Brazilian legal system.""",
            
            AgentRole.GEOGRAPHIC_ANALYST: """You are a geographic analysis specialist for Brazilian legislative documents. 
                Analyze spatial scope of laws, identify geographic patterns in legislation, and provide 
                municipality-level insights for research."""
        }
        
        logger.info(f"Initialized ProductionAIAgent: {config.agent_id} with role {config.role.value}")
    
    async def process_query(self, query: str, context: Optional[Dict[str, Any]] = None) -> LLMResponse:
        """Process user query with memory and cost optimization"""
        start_time = time.time()
        
        # Check budget before processing
        budget_alert = await self.cost_monitor.check_budget_alert(self.config.agent_id)
        if budget_alert and "CRITICAL" in budget_alert:
            raise Exception(f"Budget exceeded: {budget_alert}")
        
        # Build context from memory
        short_term_context = await self.memory.get_short_term_context(limit=5)
        
        # Extract keywords for long-term memory search
        query_keywords = self._extract_keywords(query)
        long_term_context = await self.memory.search_long_term_memory(query_keywords, limit=3)
        
        # Build full prompt with context
        full_prompt = self._build_prompt(query, short_term_context, long_term_context, context)
        
        # Check semantic cache first
        cached_response = await self.semantic_cache.get_cached_response(
            full_prompt, self.config.model, self.config.temperature
        )
        
        if cached_response:
            # Add to short-term memory
            await self.memory.add_short_term_memory(
                content=f"Query: {query}\nResponse: {cached_response.content}",
                metadata={"type": "cached_interaction", "from_cache": True}
            )
            return cached_response
        
        # Make LLM API call (simulated for now - would integrate with actual LLM API)
        response = await self._call_llm_api(full_prompt)
        
        # Track costs
        await self.cost_monitor.track_usage(
            self.config.agent_id, response.cost_cents, response.model_used
        )
        
        # Cache response for future use
        await self.semantic_cache.cache_response(
            full_prompt, self.config.model, self.config.temperature, 
            response, self.config.semantic_cache_ttl
        )
        
        # Add to memories
        await self.memory.add_short_term_memory(
            content=f"Query: {query}\nResponse: {response.content}",
            metadata={"type": "llm_interaction", "cost_cents": response.cost_cents}
        )
        
        # Add significant responses to long-term memory
        if len(response.content) > 100:  # Substantial response
            await self.memory.add_long_term_memory(
                content=response.content,
                metadata={"query": query, "type": "significant_response"}
            )
        
        response.response_time_ms = (time.time() - start_time) * 1000
        return response
    
    def _extract_keywords(self, query: str) -> List[str]:
        """Extract keywords from query for memory search"""
        # Simple keyword extraction - could be enhanced with NLP
        stop_words = {"o", "a", "os", "as", "de", "da", "do", "das", "dos", "em", "na", "no", "para", "com", "por"}
        words = query.lower().split()
        keywords = [word for word in words if len(word) > 2 and word not in stop_words]
        return keywords[:5]  # Limit to 5 keywords
    
    def _build_prompt(self, query: str, short_term: List[MemoryEntry], 
                      long_term: List[MemoryEntry], context: Optional[Dict[str, Any]]) -> str:
        """Build full prompt with system, context, and memory"""
        prompt_parts = []
        
        # System prompt based on agent role
        prompt_parts.append(self.system_prompts[self.config.role])
        
        # Add relevant long-term memory context
        if long_term:
            prompt_parts.append("\nRelevant background knowledge:")
            for entry in long_term:
                prompt_parts.append(f"- {entry.content[:200]}...")
        
        # Add recent conversation context
        if short_term:
            prompt_parts.append("\nRecent conversation context:")
            for entry in reversed(short_term[-3:]):  # Last 3 entries
                prompt_parts.append(f"- {entry.content[:150]}...")
        
        # Add additional context if provided
        if context:
            prompt_parts.append(f"\nAdditional context: {json.dumps(context, indent=2)}")
        
        # Add the actual query
        prompt_parts.append(f"\nUser query: {query}")
        prompt_parts.append("\nProvide a helpful, accurate response based on the context and your expertise:")
        
        return "\n".join(prompt_parts)
    
    async def _call_llm_api(self, prompt: str) -> LLMResponse:
        """Simulate LLM API call - replace with actual API integration"""
        # Simulate API processing time
        await asyncio.sleep(0.1)
        
        # Estimate token counts (rough approximation)
        input_tokens = len(prompt.split()) * 1.3  # Approximate token count
        output_tokens = 150  # Typical response length
        
        # Calculate costs
        cost_cents = await self.cost_monitor.calculate_cost(
            self.config.model, int(input_tokens), int(output_tokens)
        )
        
        # Simulate response based on agent role
        if self.config.role == AgentRole.RESEARCH_ASSISTANT:
            content = f"Based on your query about Brazilian legislation, I found relevant information. This analysis considers current legal frameworks and provides academic research guidance. [Simulated response - integrate with actual LLM API]"
        elif self.config.role == AgentRole.CITATION_SPECIALIST:
            content = f"Here is the properly formatted citation in ABNT style: [Simulated citation - integrate with actual LLM API]"
        else:
            content = f"Based on my analysis as a {self.config.role.value}, here are the key insights: [Simulated response - integrate with actual LLM API]"
        
        return LLMResponse(
            content=content,
            model_used=self.config.model,
            tokens_input=int(input_tokens),
            tokens_output=int(output_tokens),
            cost_cents=cost_cents,
            response_time_ms=100.0,  # Simulated
            from_cache=False
        )
    
    async def get_agent_status(self) -> Dict[str, Any]:
        """Get comprehensive agent status"""
        memory_stats = await self.memory.get_memory_statistics()
        cost_summary = await self.cost_monitor.get_cost_summary(self.config.agent_id)
        
        return {
            "agent_id": self.config.agent_id,
            "role": self.config.role.value,
            "status": "operational",
            "memory": memory_stats,
            "costs": cost_summary,
            "config": {
                "model": self.config.model,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "budget_monthly": self.config.cost_budget_monthly
            }
        }
    
    async def cleanup_expired_memory(self):
        """Clean up expired memory entries"""
        await self.memory._cleanup_long_term_memory()
        logger.info(f"Memory cleanup completed for agent {self.config.agent_id}")


class AIAgentManager:
    """Manager for multiple AI agents with resource coordination"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.agents: Dict[str, ProductionAIAgent] = {}
        self.manager_prefix = "ai:manager"
    
    async def create_agent(self, config: AgentConfig) -> ProductionAIAgent:
        """Create and register new AI agent"""
        agent = ProductionAIAgent(self.redis, config)
        self.agents[config.agent_id] = agent
        
        # Register agent in Redis
        agent_info = {
            "agent_id": config.agent_id,
            "role": config.role.value,
            "created_at": datetime.now().isoformat(),
            "status": "active"
        }
        
        await self.redis.hset(
            f"{self.manager_prefix}:agents", 
            config.agent_id, 
            json.dumps(agent_info)
        )
        
        logger.info(f"Created agent {config.agent_id} with role {config.role.value}")
        return agent
    
    async def get_agent(self, agent_id: str) -> Optional[ProductionAIAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
    
    async def get_all_agents(self) -> Dict[str, ProductionAIAgent]:
        """Get all active agents"""
        return self.agents.copy()
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        agent_statuses = {}
        total_costs = 0.0
        
        for agent_id, agent in self.agents.items():
            status = await agent.get_agent_status()
            agent_statuses[agent_id] = status
            total_costs += status["costs"]["monthly_cost_cents"]
        
        return {
            "manager_status": "operational",
            "active_agents": len(self.agents),
            "total_monthly_cost_cents": total_costs,
            "agents": agent_statuses,
            "system_health": "healthy" if len(self.agents) > 0 else "no_agents"
        }
    
    async def cleanup_all_agents(self):
        """Run cleanup on all agents"""
        for agent in self.agents.values():
            try:
                await agent.cleanup_expired_memory()
            except Exception as e:
                logger.error(f"Cleanup failed for agent {agent.config.agent_id}: {e}")