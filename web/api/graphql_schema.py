"""
GraphQL Schema for Monitor Legislativo v4
Provides flexible query capabilities for legislative data

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import strawberry
from typing import List, Optional, Dict, Any
import strawberry.scalars
from datetime import datetime
from enum import Enum

# GraphQL Types
@strawberry.enum
class DataSourceType(Enum):
    CAMARA = "camara"
    SENADO = "senado"
    PLANALTO = "planalto"
    AGENCIES = "agencies"

@strawberry.enum
class PropositionStatusType(Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    APPROVED = "approved"
    REJECTED = "rejected"
    PROCESSING = "processing"

@strawberry.type
class Author:
    id: str
    name: str
    party: Optional[str]
    state: Optional[str]
    
@strawberry.type
class Proposition:
    id: str
    source: DataSourceType
    type: str
    number: str
    year: int
    title: str
    summary: Optional[str]
    status: PropositionStatusType
    author: Optional[Author]
    created_at: datetime
    updated_at: Optional[datetime]
    url: Optional[str]
    keywords: List[str]
    
@strawberry.type
class SearchStats:
    total_results: int
    sources_queried: List[str]
    query_time_ms: float
    cache_hit: bool

@strawberry.type
class SearchResult:
    propositions: List[Proposition]
    stats: SearchStats
    
@strawberry.type
class TrendItem:
    keyword: str
    count: int
    growth_rate: float
    sources: List[str]

@strawberry.type
class SourceCount:
    source: str
    count: int

@strawberry.type
class StatusCount:
    status: str
    count: int

@strawberry.type
class Analytics:
    total_propositions: int
    by_source: List[SourceCount]
    by_status: List[StatusCount]
    trends: List[TrendItem]
    last_updated: datetime

# Query resolvers
@strawberry.type
class Query:
    @strawberry.field
    async def search_propositions(
        self,
        query: str,
        sources: Optional[List[DataSourceType]] = None,
        status: Optional[PropositionStatusType] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0
    ) -> SearchResult:
        """
        Search propositions with flexible filtering
        """
        # Import here to avoid circular imports
        from core.api.api_service import APIService
        
        api_service = APIService()
        
        # Convert GraphQL types to service parameters
        source_list = [s.value for s in sources] if sources else None
        
        # Perform search
        results = await api_service.search_async(
            query=query,
            sources=source_list,
            limit=limit
        )
        
        # Filter by status if provided
        if status:
            results = [r for r in results if r.status == status.value]
            
        # Filter by date range if provided
        if start_date or end_date:
            filtered = []
            for r in results:
                if start_date and r.created_at < start_date:
                    continue
                if end_date and r.created_at > end_date:
                    continue
                filtered.append(r)
            results = filtered
        
        # Apply pagination
        total = len(results)
        results = results[offset:offset + limit]
        
        # Convert to GraphQL types
        propositions = []
        for r in results:
            author = None
            if hasattr(r, 'author') and r.author:
                author = Author(
                    id=r.author.get('id', ''),
                    name=r.author.get('name', ''),
                    party=r.author.get('party'),
                    state=r.author.get('state')
                )
                
            propositions.append(Proposition(
                id=r.id,
                source=DataSourceType(r.source),
                type=r.type,
                number=r.number,
                year=r.year,
                title=r.title,
                summary=r.summary,
                status=PropositionStatusType(r.status),
                author=author,
                created_at=r.created_at,
                updated_at=r.updated_at,
                url=r.url,
                keywords=r.keywords or []
            ))
        
        stats = SearchStats(
            total_results=total,
            sources_queried=source_list or ['all'],
            query_time_ms=0.0,  # TODO: Implement timing
            cache_hit=False  # TODO: Implement cache detection
        )
        
        return SearchResult(propositions=propositions, stats=stats)
    
    @strawberry.field
    async def get_proposition(self, id: str, source: DataSourceType) -> Optional[Proposition]:
        """
        Get a specific proposition by ID and source
        """
        # TODO: Implement direct proposition lookup
        results = await self.search_propositions(
            query=f"id:{id}",
            sources=[source],
            limit=1
        )
        
        if results.propositions:
            return results.propositions[0]
        return None
    
    @strawberry.field
    async def get_analytics(self) -> Analytics:
        """
        Get system analytics and trends
        """
        # TODO: Implement real analytics
        # For now, return mock data
        return Analytics(
            total_propositions=15420,
            by_source={
                "camara": 8234,
                "senado": 4521,
                "planalto": 1893,
                "agencies": 772
            },
            by_status={
                "active": 3421,
                "processing": 5234,
                "approved": 4521,
                "rejected": 1244,
                "archived": 1000
            },
            trends=[
                TrendItem(
                    keyword="saúde",
                    count=342,
                    growth_rate=0.15,
                    sources=["camara", "senado"]
                ),
                TrendItem(
                    keyword="educação",
                    count=298,
                    growth_rate=0.08,
                    sources=["camara", "planalto"]
                ),
                TrendItem(
                    keyword="meio ambiente",
                    count=256,
                    growth_rate=0.22,
                    sources=["agencies", "senado"]
                )
            ],
            last_updated=datetime.now()
        )
    
    @strawberry.field
    async def search_authors(self, name: str, limit: int = 20) -> List[Author]:
        """
        Search for proposition authors
        """
        # TODO: Implement author search
        # Mock data for now
        return [
            Author(
                id="dep-001",
                name="João Silva",
                party="PT",
                state="SP"
            ),
            Author(
                id="sen-002", 
                name="Maria Santos",
                party="PSDB",
                state="RJ"
            )
        ]

# Mutation resolvers
@strawberry.type
class Mutation:
    @strawberry.mutation
    async def track_proposition(self, proposition_id: str, source: DataSourceType) -> bool:
        """
        Track a proposition for notifications
        """
        # TODO: Implement proposition tracking
        return True
    
    @strawberry.mutation
    async def export_search_results(
        self,
        query: str,
        format: str = "json",
        email: Optional[str] = None
    ) -> str:
        """
        Export search results in various formats
        """
        # TODO: Implement export functionality
        return f"export-{datetime.now().timestamp()}.{format}"

# Create schema
schema = strawberry.Schema(query=Query, mutation=Mutation)