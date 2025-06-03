"""
Query Side of CQRS for Monitor Legislativo v4
Handles read operations and complex queries

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Type, Callable, Union
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import uuid

from .read_models import (
    PropositionReadModel,
    UserReadModel,
    AnalyticsReadModel,
    TrendingTopicsReadModel
)

logger = logging.getLogger(__name__)

@dataclass
class Query(ABC):
    """Base query class"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class QueryResult:
    """Query result wrapper"""
    data: Any
    total_count: Optional[int] = None
    page: Optional[int] = None
    page_size: Optional[int] = None
    execution_time_ms: Optional[float] = None
    cached: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

class QueryHandler(ABC):
    """Base query handler"""
    
    @abstractmethod
    async def handle(self, query: Query) -> QueryResult:
        """Handle the query"""
        pass

class QueryBus:
    """Query bus for dispatching queries to handlers"""
    
    def __init__(self):
        self.handlers: Dict[Type[Query], QueryHandler] = {}
        self.middleware: List[Callable] = []
        self.cache_enabled = True
        self.cache: Dict[str, QueryResult] = {}
        self.cache_ttl = 300  # 5 minutes
        
    def register_handler(self, query_type: Type[Query], handler: QueryHandler) -> None:
        """Register a query handler"""
        self.handlers[query_type] = handler
        logger.info(f"Registered handler for {query_type.__name__}")
    
    def add_middleware(self, middleware: Callable) -> None:
        """Add middleware to query pipeline"""
        self.middleware.append(middleware)
    
    async def dispatch(self, query: Query) -> QueryResult:
        """Dispatch query to appropriate handler"""
        query_type = type(query)
        
        if query_type not in self.handlers:
            raise ValueError(f"No handler registered for {query_type.__name__}")
        
        # Check cache first
        cache_key = self._get_cache_key(query)
        if self.cache_enabled and cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if self._is_cache_valid(cached_result):
                logger.debug(f"Cache hit for query {query_type.__name__}")
                cached_result.cached = True
                return cached_result
        
        handler = self.handlers[query_type]
        
        # Apply middleware
        async def execute():
            return await handler.handle(query)
        
        for middleware in self.middleware:
            execute = middleware(execute, query)
        
        try:
            start_time = datetime.now()
            result = await execute()
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result.execution_time_ms = execution_time
            
            # Cache result
            if self.cache_enabled:
                self.cache[cache_key] = result
            
            logger.info(f"Query {query_type.__name__} executed in {execution_time:.2f}ms")
            return result
            
        except Exception as e:
            logger.error(f"Error executing query {query_type.__name__}: {e}")
            raise
    
    def _get_cache_key(self, query: Query) -> str:
        """Generate cache key for query"""
        import hashlib
        query_data = f"{type(query).__name__}:{query.__dict__}"
        return hashlib.md5(query_data.encode()).hexdigest()
    
    def _is_cache_valid(self, result: QueryResult) -> bool:
        """Check if cached result is still valid"""
        if not hasattr(result, '_cached_at'):
            return False
        
        age = (datetime.now() - result._cached_at).total_seconds()
        return age < self.cache_ttl
    
    def clear_cache(self) -> None:
        """Clear query cache"""
        self.cache.clear()
        logger.info("Query cache cleared")

# Query Definitions

@dataclass
class GetPropositionQuery(Query):
    """Query to get a specific proposition"""
    proposition_id: str
    include_related: bool = False

@dataclass
class SearchPropositionsQuery(Query):
    """Query to search propositions with filters"""
    search_text: Optional[str] = None
    source: Optional[str] = None
    proposition_type: Optional[str] = None
    status: Optional[str] = None
    year: Optional[int] = None
    author: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    sort_by: str = "created_at"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 20

@dataclass
class GetUserAlertsQuery(Query):
    """Query to get user alerts"""
    active_only: bool = True
    include_results: bool = False

@dataclass
class GetAnalyticsQuery(Query):
    """Query to get analytics data"""
    metric_type: str  # "propositions", "searches", "users", "alerts"
    period: str = "month"  # "day", "week", "month", "year"
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    group_by: Optional[str] = None

@dataclass
class GetTrendingTopicsQuery(Query):
    """Query to get trending topics"""
    period: str = "week"
    limit: int = 10
    min_mentions: int = 5

@dataclass
class GetPropositionStatsQuery(Query):
    """Query to get proposition statistics"""
    source: Optional[str] = None
    include_trends: bool = True

@dataclass
class GetUserActivityQuery(Query):
    """Query to get user activity"""
    target_user_id: Optional[str] = None
    activity_type: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = 50

@dataclass
class AdvancedSearchQuery(Query):
    """Advanced search with complex filters"""
    filters: Dict[str, Any] = field(default_factory=dict)
    aggregations: List[str] = field(default_factory=list)
    facets: List[str] = field(default_factory=list)
    sort_criteria: List[Dict[str, str]] = field(default_factory=list)
    page: int = 1
    page_size: int = 20

# Query Handlers

class GetPropositionHandler(QueryHandler):
    """Handler for getting single proposition"""
    
    async def handle(self, query: GetPropositionQuery) -> QueryResult:
        """Get proposition by ID"""
        try:
            proposition_id = query.proposition_id
            
            # Simulate database query
            proposition_data = {
                "id": proposition_id,
                "source": "camara",
                "type": "PL",
                "number": "1234",
                "year": 2024,
                "title": "Sample Proposition Title",
                "summary": "This is a sample proposition summary",
                "author": "Deputy Sample",
                "status": "active",
                "keywords": ["education", "public policy"],
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            # Create read model
            read_model = PropositionReadModel(**proposition_data)
            
            # Include related data if requested
            related_data = {}
            if query.include_related:
                related_data = {
                    "related_propositions": [],
                    "amendments": [],
                    "voting_history": []
                }
            
            return QueryResult(
                data={
                    "proposition": read_model.to_dict(),
                    **related_data
                },
                metadata={"include_related": query.include_related}
            )
            
        except Exception as e:
            logger.error(f"Error getting proposition {query.proposition_id}: {e}")
            raise

class SearchPropositionsHandler(QueryHandler):
    """Handler for searching propositions"""
    
    async def handle(self, query: SearchPropositionsQuery) -> QueryResult:
        """Search propositions with filters"""
        try:
            # Build search criteria
            criteria = {}
            if query.search_text:
                criteria["search_text"] = query.search_text
            if query.source:
                criteria["source"] = query.source
            if query.proposition_type:
                criteria["type"] = query.proposition_type
            if query.status:
                criteria["status"] = query.status
            if query.year:
                criteria["year"] = query.year
            if query.author:
                criteria["author"] = query.author
            if query.keywords:
                criteria["keywords"] = query.keywords
            
            # Simulate search results
            sample_propositions = []
            for i in range(min(query.page_size, 15)):  # Mock up to 15 results
                prop_data = {
                    "id": f"prop_sample_{i}",
                    "source": query.source or "camara",
                    "type": query.proposition_type or "PL",
                    "number": f"{1000 + i}",
                    "year": query.year or 2024,
                    "title": f"Sample Proposition {i+1}",
                    "summary": f"This is sample proposition {i+1} summary",
                    "author": f"Deputy {i+1}",
                    "status": query.status or "active",
                    "keywords": query.keywords or ["sample", "test"],
                    "created_at": (datetime.now() - timedelta(days=i)).isoformat(),
                    "updated_at": datetime.now().isoformat(),
                    "relevance_score": 1.0 - (i * 0.1)
                }
                sample_propositions.append(PropositionReadModel(**prop_data).to_dict())
            
            # Calculate pagination
            total_count = 150  # Mock total
            total_pages = (total_count + query.page_size - 1) // query.page_size
            
            return QueryResult(
                data=sample_propositions,
                total_count=total_count,
                page=query.page,
                page_size=query.page_size,
                metadata={
                    "search_criteria": criteria,
                    "total_pages": total_pages,
                    "has_next": query.page < total_pages,
                    "has_prev": query.page > 1
                }
            )
            
        except Exception as e:
            logger.error(f"Error searching propositions: {e}")
            raise

class GetUserAlertsHandler(QueryHandler):
    """Handler for getting user alerts"""
    
    async def handle(self, query: GetUserAlertsQuery) -> QueryResult:
        """Get user alerts"""
        try:
            user_id = query.user_id
            
            # Simulate alerts data
            alerts = []
            for i in range(3):  # Mock 3 alerts
                alert_data = {
                    "id": f"alert_{user_id}_{i}",
                    "user_id": user_id,
                    "name": f"Alert {i+1}",
                    "query": f"sample query {i+1}",
                    "frequency": "daily",
                    "enabled": True if query.active_only else (i % 2 == 0),
                    "created_at": (datetime.now() - timedelta(days=i*7)).isoformat(),
                    "last_triggered": datetime.now().isoformat(),
                    "results_count": 5 + i
                }
                
                if query.include_results:
                    alert_data["recent_results"] = [
                        {"proposition_id": f"prop_{j}", "title": f"Result {j+1}"}
                        for j in range(3)
                    ]
                
                alerts.append(alert_data)
            
            return QueryResult(
                data=alerts,
                total_count=len(alerts),
                metadata={
                    "active_only": query.active_only,
                    "include_results": query.include_results
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting user alerts: {e}")
            raise

class GetAnalyticsHandler(QueryHandler):
    """Handler for analytics queries"""
    
    async def handle(self, query: GetAnalyticsQuery) -> QueryResult:
        """Get analytics data"""
        try:
            metric_type = query.metric_type
            period = query.period
            
            # Generate mock analytics data
            if metric_type == "propositions":
                data = self._generate_proposition_analytics(period)
            elif metric_type == "searches":
                data = self._generate_search_analytics(period)
            elif metric_type == "users":
                data = self._generate_user_analytics(period)
            else:
                data = {"message": f"Analytics for {metric_type} not implemented"}
            
            analytics_model = AnalyticsReadModel(
                metric_type=metric_type,
                period=period,
                data=data,
                generated_at=datetime.now()
            )
            
            return QueryResult(
                data=analytics_model.to_dict(),
                metadata={
                    "period": period,
                    "date_range": {
                        "from": query.date_from.isoformat() if query.date_from else None,
                        "to": query.date_to.isoformat() if query.date_to else None
                    }
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting analytics: {e}")
            raise
    
    def _generate_proposition_analytics(self, period: str) -> Dict[str, Any]:
        """Generate mock proposition analytics"""
        return {
            "total_propositions": 1250,
            "new_this_period": 45,
            "by_source": {
                "camara": 850,
                "senado": 400
            },
            "by_status": {
                "active": 1100,
                "archived": 150
            },
            "trend": [
                {"date": "2024-01-01", "count": 10},
                {"date": "2024-01-02", "count": 15},
                {"date": "2024-01-03", "count": 12}
            ]
        }
    
    def _generate_search_analytics(self, period: str) -> Dict[str, Any]:
        """Generate mock search analytics"""
        return {
            "total_searches": 2500,
            "unique_users": 180,
            "avg_results_per_search": 12.5,
            "popular_terms": [
                {"term": "education", "count": 450},
                {"term": "health", "count": 380},
                {"term": "economy", "count": 320}
            ]
        }
    
    def _generate_user_analytics(self, period: str) -> Dict[str, Any]:
        """Generate mock user analytics"""
        return {
            "total_users": 520,
            "active_users": 340,
            "new_users": 25,
            "retention_rate": 0.85,
            "activity_by_day": [
                {"day": "Monday", "users": 280},
                {"day": "Tuesday", "users": 320},
                {"day": "Wednesday", "users": 340}
            ]
        }

class GetTrendingTopicsHandler(QueryHandler):
    """Handler for trending topics"""
    
    async def handle(self, query: GetTrendingTopicsQuery) -> QueryResult:
        """Get trending topics"""
        try:
            # Generate mock trending topics
            trending_topics = []
            topics = ["Education Reform", "Healthcare Policy", "Economic Development", 
                     "Environmental Protection", "Digital Governance"]
            
            for i, topic in enumerate(topics[:query.limit]):
                topic_data = {
                    "topic": topic,
                    "mentions": query.min_mentions + (20 - i * 3),
                    "trend_score": 1.0 - (i * 0.15),
                    "related_propositions": 5 + i,
                    "sentiment": "positive" if i % 2 == 0 else "neutral"
                }
                trending_topics.append(topic_data)
            
            trending_model = TrendingTopicsReadModel(
                period=query.period,
                topics=trending_topics,
                generated_at=datetime.now()
            )
            
            return QueryResult(
                data=trending_model.to_dict(),
                metadata={
                    "period": query.period,
                    "min_mentions": query.min_mentions
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting trending topics: {e}")
            raise

# Query Middleware

async def caching_middleware(next_handler, query: Query):
    """Caching middleware for queries"""
    # Cache logic is handled in QueryBus
    return await next_handler()

async def performance_middleware(next_handler, query: Query):
    """Performance monitoring middleware"""
    start_time = datetime.now()
    query_name = type(query).__name__
    
    try:
        result = await next_handler()
        duration = (datetime.now() - start_time).total_seconds()
        
        # Log slow queries
        if duration > 1.0:  # > 1 second
            logger.warning(f"Slow query detected: {query_name} took {duration:.3f}s")
        
        return result
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Query {query_name} failed after {duration:.3f}s: {e}")
        raise

async def authorization_middleware(next_handler, query: Query):
    """Authorization middleware for queries"""
    # Basic authorization - could be expanded with role-based access
    if not query.user_id:
        logger.warning(f"Query {type(query).__name__} executed without user context")
    
    return await next_handler()

# Global query bus instance
query_bus = QueryBus()

# Register handlers
query_bus.register_handler(GetPropositionQuery, GetPropositionHandler())
query_bus.register_handler(SearchPropositionsQuery, SearchPropositionsHandler())
query_bus.register_handler(GetUserAlertsQuery, GetUserAlertsHandler())
query_bus.register_handler(GetAnalyticsQuery, GetAnalyticsHandler())
query_bus.register_handler(GetTrendingTopicsQuery, GetTrendingTopicsHandler())

# Add middleware
query_bus.add_middleware(performance_middleware)
query_bus.add_middleware(caching_middleware)
query_bus.add_middleware(authorization_middleware)