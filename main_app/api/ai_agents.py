"""
AI Agents API Endpoints
=======================

FastAPI endpoints for production-ready AI agents with dual-memory architecture.
Provides research assistance, cost monitoring, and semantic caching for
Brazilian legislative analysis.

Features:
- Agent creation and management
- Query processing with memory context
- Cost monitoring and budget tracking
- Memory management and optimization
- Health checks and performance metrics
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import logging
import sys
from pathlib import Path

# Import AI agent components
sys.path.append(str(Path(__file__).parent.parent.parent / "core"))

try:
    from ai.agent_foundation import (
        ProductionAIAgent,
        AIAgentManager,
        AgentConfig,
        AgentRole,
        LLMResponse
    )
    from ai.redis_memory_manager import RedisMemoryManager
    from cache.redis_config import get_redis_client
    AI_AGENTS_AVAILABLE = True
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"AI agents not available: {e}")
    AI_AGENTS_AVAILABLE = False
    
    # Mock classes for when AI agents are not available
    class ProductionAIAgent:
        def __init__(self, *args, **kwargs): pass
        async def process_query(self, query): return None
        async def get_agent_status(self): return {}
    
    class AIAgentManager:
        def __init__(self, *args, **kwargs): pass
        async def create_agent(self, config): return None
        async def get_agent(self, agent_id): return None
        async def get_system_status(self): return {}
    
    class AgentConfig:
        def __init__(self, **kwargs): pass
    
    class AgentRole:
        RESEARCH_ASSISTANT = "research_assistant"
        CITATION_SPECIALIST = "citation_specialist"
        DOCUMENT_ANALYZER = "document_analyzer"
        LEGISLATIVE_EXPERT = "legislative_expert"
        GEOGRAPHIC_ANALYST = "geographic_analyst"
    
    class LLMResponse:
        def __init__(self, **kwargs): pass
    
    class RedisMemoryManager:
        def __init__(self, *args, **kwargs): pass

logger = logging.getLogger(__name__)

# Global AI agent manager
_agent_manager: Optional[AIAgentManager] = None
_memory_manager: Optional[RedisMemoryManager] = None


async def get_agent_manager() -> AIAgentManager:
    """Dependency to get initialized AI agent manager"""
    global _agent_manager, _memory_manager
    
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents service not available")
    
    if _agent_manager is None:
        try:
            redis_client = await get_redis_client()
            _agent_manager = AIAgentManager(redis_client)
            _memory_manager = RedisMemoryManager(redis_client)
            
            # Initialize Redis structure for AI agents
            await _memory_manager.initialize_ai_redis_structure()
            
            logger.info("AI agent manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AI agent manager: {e}")
            raise HTTPException(status_code=503, detail="AI agent manager initialization failed")
    
    return _agent_manager


async def get_memory_manager() -> RedisMemoryManager:
    """Dependency to get initialized memory manager"""
    global _memory_manager
    
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI memory manager service not available")
    
    if _memory_manager is None:
        # Initialize through agent manager
        await get_agent_manager()
    
    return _memory_manager


# Request/Response Models
class CreateAgentRequest(BaseModel):
    """Request model for creating AI agent"""
    agent_id: str = Field(..., description="Unique identifier for the agent")
    role: str = Field(..., description="Agent role (research_assistant, citation_specialist, etc.)")
    max_short_term_memory: int = Field(50, description="Maximum short-term memory entries")
    max_long_term_memory: int = Field(1000, description="Maximum long-term memory entries")
    cost_budget_monthly: float = Field(10.0, description="Monthly budget in USD")
    temperature: float = Field(0.1, description="LLM temperature for responses")
    model: str = Field("gpt-4o-mini", description="LLM model to use")


class QueryRequest(BaseModel):
    """Request model for agent query"""
    query: str = Field(..., description="User query for the agent")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context for the query")
    include_memory: bool = Field(True, description="Include memory context in response")


class QueryResponse(BaseModel):
    """Response model for agent query"""
    agent_id: str
    query: str
    response: str
    model_used: str
    tokens_input: int
    tokens_output: int
    cost_cents: float
    response_time_ms: float
    from_cache: bool
    memory_context_used: bool


class AgentStatusResponse(BaseModel):
    """Response model for agent status"""
    agent_id: str
    role: str
    status: str
    memory_stats: Dict[str, Any]
    cost_summary: Dict[str, Any]
    configuration: Dict[str, Any]


class SystemStatusResponse(BaseModel):
    """Response model for system status"""
    manager_status: str
    active_agents: int
    total_monthly_cost_cents: float
    system_health: str
    agents: Dict[str, Any]


class MemorySearchRequest(BaseModel):
    """Request model for memory search"""
    agent_id: str = Field(..., description="Agent ID to search memory for")
    keywords: List[str] = Field(..., description="Keywords to search for")
    limit: int = Field(20, description="Maximum number of results")


class MemoryOptimizationRequest(BaseModel):
    """Request model for memory optimization"""
    agent_id: str = Field(..., description="Agent ID to optimize memory for")
    remove_duplicates: bool = Field(True, description="Remove duplicate memory entries")
    cleanup_expired: bool = Field(True, description="Clean up expired entries")


# Create router
router = APIRouter(prefix="/api/v1/ai", tags=["AI Agents"])


@router.post("/agents", response_model=Dict[str, str])
async def create_agent(
    request: CreateAgentRequest,
    manager: AIAgentManager = Depends(get_agent_manager)
):
    """
    Create a new AI agent with specified configuration
    
    Args:
        request: Agent creation request
        
    Returns:
        Agent creation confirmation
    """
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents service not available")
    
    try:
        # Validate role
        if request.role not in [role.value for role in AgentRole]:
            raise HTTPException(status_code=400, detail=f"Invalid role: {request.role}")
        
        # Create agent config
        config = AgentConfig(
            agent_id=request.agent_id,
            role=AgentRole(request.role),
            max_short_term_memory=request.max_short_term_memory,
            max_long_term_memory=request.max_long_term_memory,
            cost_budget_monthly=request.cost_budget_monthly,
            temperature=request.temperature,
            model=request.model
        )
        
        # Create agent
        agent = await manager.create_agent(config)
        
        # Initialize memory indexes
        memory_manager = await get_memory_manager()
        await memory_manager.create_memory_indexes(request.agent_id)
        
        return {
            "status": "success",
            "message": f"Agent {request.agent_id} created successfully",
            "agent_id": request.agent_id,
            "role": request.role
        }
        
    except Exception as e:
        logger.error(f"Agent creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Agent creation failed: {str(e)}")


@router.post("/agents/{agent_id}/query", response_model=QueryResponse)
async def query_agent(
    agent_id: str,
    request: QueryRequest,
    manager: AIAgentManager = Depends(get_agent_manager)
):
    """
    Send query to AI agent and get response with memory context
    
    Args:
        agent_id: ID of the agent to query
        request: Query request
        
    Returns:
        Agent response with metadata
    """
    if not AI_AGENTS_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI agents service not available")
    
    try:
        # Get agent
        agent = await manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        # Process query
        response = await agent.process_query(request.query, request.context)
        
        return QueryResponse(
            agent_id=agent_id,
            query=request.query,
            response=response.content,
            model_used=response.model_used,
            tokens_input=response.tokens_input,
            tokens_output=response.tokens_output,
            cost_cents=response.cost_cents,
            response_time_ms=response.response_time_ms,
            from_cache=response.from_cache,
            memory_context_used=request.include_memory
        )
        
    except Exception as e:
        logger.error(f"Query processing failed for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Query processing failed: {str(e)}")


@router.get("/agents/{agent_id}/status", response_model=AgentStatusResponse)
async def get_agent_status(
    agent_id: str,
    manager: AIAgentManager = Depends(get_agent_manager)
):
    """
    Get comprehensive status of AI agent
    
    Args:
        agent_id: ID of the agent
        
    Returns:
        Agent status including memory and cost information
    """
    try:
        agent = await manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        status = await agent.get_agent_status()
        
        return AgentStatusResponse(
            agent_id=status["agent_id"],
            role=status["role"],
            status=status["status"],
            memory_stats=status["memory"],
            cost_summary=status["costs"],
            configuration=status["config"]
        )
        
    except Exception as e:
        logger.error(f"Status retrieval failed for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Status retrieval failed: {str(e)}")


@router.get("/system/status", response_model=SystemStatusResponse)
async def get_system_status(
    manager: AIAgentManager = Depends(get_agent_manager)
):
    """
    Get overall AI agent system status
    
    Returns:
        System status including all agents and performance metrics
    """
    try:
        status = await manager.get_system_status()
        
        return SystemStatusResponse(
            manager_status=status["manager_status"],
            active_agents=status["active_agents"],
            total_monthly_cost_cents=status["total_monthly_cost_cents"],
            system_health=status["system_health"],
            agents=status["agents"]
        )
        
    except Exception as e:
        logger.error(f"System status retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"System status retrieval failed: {str(e)}")


@router.post("/memory/search")
async def search_agent_memory(
    request: MemorySearchRequest,
    memory_manager: RedisMemoryManager = Depends(get_memory_manager)
):
    """
    Search agent memory using keywords
    
    Args:
        request: Memory search request
        
    Returns:
        Relevant memory entries
    """
    try:
        results = await memory_manager.search_memory_by_keywords(
            request.agent_id, request.keywords, request.limit
        )
        
        return {
            "status": "success",
            "agent_id": request.agent_id,
            "keywords": request.keywords,
            "results_count": len(results),
            "memory_entries": results
        }
        
    except Exception as e:
        logger.error(f"Memory search failed for agent {request.agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Memory search failed: {str(e)}")


@router.post("/memory/optimize")
async def optimize_agent_memory(
    request: MemoryOptimizationRequest,
    background_tasks: BackgroundTasks,
    memory_manager: RedisMemoryManager = Depends(get_memory_manager)
):
    """
    Optimize agent memory storage and performance
    
    Args:
        request: Memory optimization request
        background_tasks: Background task manager
        
    Returns:
        Optimization results
    """
    try:
        # Run cleanup if requested
        if request.cleanup_expired:
            cleanup_results = await memory_manager.cleanup_expired_memory(request.agent_id)
        else:
            cleanup_results = {}
        
        # Run optimization in background if requested
        if request.remove_duplicates:
            background_tasks.add_task(
                memory_manager.optimize_memory_storage,
                request.agent_id
            )
            optimization_scheduled = True
        else:
            optimization_scheduled = False
        
        return {
            "status": "success",
            "agent_id": request.agent_id,
            "cleanup_results": cleanup_results,
            "optimization_scheduled": optimization_scheduled,
            "message": "Memory optimization completed"
        }
        
    except Exception as e:
        logger.error(f"Memory optimization failed for agent {request.agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Memory optimization failed: {str(e)}")


@router.get("/memory/performance/{agent_id}")
async def get_memory_performance(
    agent_id: str,
    memory_manager: RedisMemoryManager = Depends(get_memory_manager)
):
    """
    Get memory performance statistics for agent
    
    Args:
        agent_id: ID of the agent
        
    Returns:
        Memory performance metrics
    """
    try:
        stats = await memory_manager.get_memory_performance_stats(agent_id)
        
        return {
            "status": "success",
            "performance_stats": stats
        }
        
    except Exception as e:
        logger.error(f"Performance stats retrieval failed for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Performance stats retrieval failed: {str(e)}")


@router.post("/memory/backup/{agent_id}")
async def backup_agent_memory(
    agent_id: str,
    memory_manager: RedisMemoryManager = Depends(get_memory_manager)
):
    """
    Create backup of agent memory
    
    Args:
        agent_id: ID of the agent
        
    Returns:
        Backup confirmation with backup ID
    """
    try:
        backup_id = await memory_manager.backup_agent_memory(agent_id)
        
        return {
            "status": "success",
            "agent_id": agent_id,
            "backup_id": backup_id,
            "message": "Memory backup created successfully"
        }
        
    except Exception as e:
        logger.error(f"Memory backup failed for agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Memory backup failed: {str(e)}")


@router.get("/roles")
async def get_available_roles():
    """
    Get available AI agent roles and their descriptions
    
    Returns:
        List of available roles with descriptions
    """
    roles = [
        {
            "role": "research_assistant",
            "name": "Research Assistant",
            "description": "Specialized in Brazilian legislative research, finding relevant laws, and analyzing legal contexts"
        },
        {
            "role": "citation_specialist", 
            "name": "Citation Specialist",
            "description": "Expert in academic citation formatting for Brazilian legal documents (ABNT, APA, etc.)"
        },
        {
            "role": "document_analyzer",
            "name": "Document Analyzer", 
            "description": "Analyzes document content, extracts key concepts, and identifies relationships between laws"
        },
        {
            "role": "legislative_expert",
            "name": "Legislative Expert",
            "description": "Brazilian legislative expert with deep knowledge of federal, state, and municipal frameworks"
        },
        {
            "role": "geographic_analyst",
            "name": "Geographic Analyst",
            "description": "Specializes in spatial analysis of Brazilian legislative documents and geographic scope"
        }
    ]
    
    return {
        "available_roles": roles,
        "total_roles": len(roles)
    }


@router.get("/health")
async def ai_agents_health_check():
    """
    Health check endpoint for AI agents service
    
    Returns:
        Service health status and capabilities
    """
    try:
        if not AI_AGENTS_AVAILABLE:
            return {
                "status": "unavailable",
                "ai_agents_available": False,
                "message": "AI agents service not available"
            }
        
        # Try to get agent manager
        try:
            manager = await get_agent_manager()
            system_status = await manager.get_system_status()
            
            return {
                "status": "healthy",
                "ai_agents_available": True,
                "active_agents": system_status["active_agents"],
                "system_health": system_status["system_health"],
                "features_available": [
                    "agent_creation",
                    "query_processing",
                    "memory_management", 
                    "cost_monitoring",
                    "semantic_caching"
                ],
                "supported_roles": [role.value for role in AgentRole]
            }
            
        except Exception as e:
            return {
                "status": "degraded",
                "ai_agents_available": True,
                "error": str(e),
                "message": "AI agents service experiencing issues"
            }
        
    except Exception as e:
        logger.error(f"AI agents health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }