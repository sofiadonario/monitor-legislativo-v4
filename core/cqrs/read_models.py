"""
Read Models for CQRS in Monitor Legislativo v4
Optimized data structures for queries

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime
from abc import ABC, abstractmethod

class ReadModel(ABC):
    """Base read model"""
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        pass

@dataclass
class PropositionReadModel(ReadModel):
    """Read model for propositions optimized for queries"""
    id: str
    source: str
    type: str
    number: str
    year: int
    title: str
    summary: str
    author: str
    status: str
    keywords: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    
    # Query-optimized fields
    search_text: Optional[str] = None  # Pre-computed search text
    relevance_score: float = 0.0
    view_count: int = 0
    alert_count: int = 0  # How many alerts match this proposition
    
    # Denormalized data for fast access
    author_info: Optional[Dict[str, Any]] = None
    source_info: Optional[Dict[str, Any]] = None
    related_count: int = 0
    
    def __post_init__(self):
        """Post-initialization processing"""
        if not self.search_text:
            # Pre-compute search text for faster full-text search
            self.search_text = f"{self.title} {self.summary} {self.author} {' '.join(self.keywords)}".lower()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "source": self.source,
            "type": self.type,
            "number": self.number,
            "year": self.year,
            "title": self.title,
            "summary": self.summary,
            "author": self.author,
            "status": self.status,
            "keywords": self.keywords,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "relevance_score": self.relevance_score,
            "view_count": self.view_count,
            "alert_count": self.alert_count,
            "author_info": self.author_info,
            "source_info": self.source_info,
            "related_count": self.related_count
        }
    
    def matches_search(self, search_term: str) -> bool:
        """Check if proposition matches search term"""
        if not search_term:
            return True
        
        search_term = search_term.lower()
        return search_term in (self.search_text or "")
    
    def increment_view(self):
        """Increment view count"""
        self.view_count += 1

@dataclass
class UserReadModel(ReadModel):
    """Read model for users"""
    id: str
    email: str
    name: str
    role: str = "user"
    created_at: str = ""
    last_login: Optional[str] = None
    
    # Activity metrics
    total_searches: int = 0
    total_alerts: int = 0
    active_alerts: int = 0
    last_activity: Optional[str] = None
    
    # Preferences (denormalized)
    preferences: Dict[str, Any] = field(default_factory=dict)
    
    # Computed fields
    activity_score: float = 0.0
    user_tier: str = "basic"  # basic, premium, admin
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "total_searches": self.total_searches,
            "total_alerts": self.total_alerts,
            "active_alerts": self.active_alerts,
            "last_activity": self.last_activity,
            "preferences": self.preferences,
            "activity_score": self.activity_score,
            "user_tier": self.user_tier
        }
    
    def is_active(self) -> bool:
        """Check if user is active"""
        if not self.last_activity:
            return False
        
        last_activity_date = datetime.fromisoformat(self.last_activity)
        days_since_activity = (datetime.now() - last_activity_date).days
        
        return days_since_activity <= 30  # Active within last 30 days

@dataclass
class AnalyticsReadModel(ReadModel):
    """Read model for analytics data"""
    metric_type: str
    period: str
    data: Dict[str, Any]
    generated_at: datetime
    
    # Metadata
    total_records: Optional[int] = None
    data_quality: float = 1.0  # 0.0 to 1.0
    confidence_level: float = 0.95
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "metric_type": self.metric_type,
            "period": self.period,
            "data": self.data,
            "generated_at": self.generated_at.isoformat(),
            "total_records": self.total_records,
            "data_quality": self.data_quality,
            "confidence_level": self.confidence_level
        }
    
    def is_fresh(self, max_age_hours: int = 24) -> bool:
        """Check if analytics data is fresh"""
        age_hours = (datetime.now() - self.generated_at).total_seconds() / 3600
        return age_hours <= max_age_hours

@dataclass
class TrendingTopicsReadModel(ReadModel):
    """Read model for trending topics"""
    period: str
    topics: List[Dict[str, Any]]
    generated_at: datetime
    
    # Algorithm metadata
    algorithm_version: str = "1.0"
    confidence_threshold: float = 0.5
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "period": self.period,
            "topics": self.topics,
            "generated_at": self.generated_at.isoformat(),
            "algorithm_version": self.algorithm_version,
            "confidence_threshold": self.confidence_threshold
        }
    
    def get_top_topics(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top N topics"""
        return sorted(self.topics, key=lambda x: x.get("trend_score", 0), reverse=True)[:limit]

@dataclass
class SearchResultReadModel(ReadModel):
    """Read model for search results with aggregations"""
    query: str
    results: List[PropositionReadModel]
    total_count: int
    execution_time_ms: float
    
    # Aggregations
    source_facets: Dict[str, int] = field(default_factory=dict)
    type_facets: Dict[str, int] = field(default_factory=dict)
    year_facets: Dict[str, int] = field(default_factory=dict)
    status_facets: Dict[str, int] = field(default_factory=dict)
    
    # Search metadata
    search_suggestions: List[str] = field(default_factory=list)
    related_queries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "query": self.query,
            "results": [result.to_dict() for result in self.results],
            "total_count": self.total_count,
            "execution_time_ms": self.execution_time_ms,
            "facets": {
                "source": self.source_facets,
                "type": self.type_facets,
                "year": self.year_facets,
                "status": self.status_facets
            },
            "search_suggestions": self.search_suggestions,
            "related_queries": self.related_queries
        }

@dataclass
class AlertReadModel(ReadModel):
    """Read model for user alerts"""
    id: str
    user_id: str
    name: str
    query: str
    frequency: str
    enabled: bool
    created_at: str
    
    # Execution data
    last_executed: Optional[str] = None
    last_results_count: int = 0
    total_executions: int = 0
    
    # Performance metrics
    avg_execution_time_ms: float = 0.0
    success_rate: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "query": self.query,
            "frequency": self.frequency,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_executed": self.last_executed,
            "last_results_count": self.last_results_count,
            "total_executions": self.total_executions,
            "avg_execution_time_ms": self.avg_execution_time_ms,
            "success_rate": self.success_rate
        }
    
    def is_due_for_execution(self) -> bool:
        """Check if alert is due for execution"""
        if not self.enabled or not self.last_executed:
            return True
        
        last_exec = datetime.fromisoformat(self.last_executed)
        now = datetime.now()
        
        if self.frequency == "hourly":
            return (now - last_exec).total_seconds() >= 3600
        elif self.frequency == "daily":
            return (now - last_exec).days >= 1
        elif self.frequency == "weekly":
            return (now - last_exec).days >= 7
        
        return False

@dataclass
class DashboardReadModel(ReadModel):
    """Read model for dashboard data"""
    user_id: str
    widgets: List[Dict[str, Any]]
    layout: Dict[str, Any]
    last_updated: datetime
    
    # Performance data
    load_time_ms: float = 0.0
    cache_hit_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "user_id": self.user_id,
            "widgets": self.widgets,
            "layout": self.layout,
            "last_updated": self.last_updated.isoformat(),
            "load_time_ms": self.load_time_ms,
            "cache_hit_rate": self.cache_hit_rate
        }
    
    def get_widget(self, widget_id: str) -> Optional[Dict[str, Any]]:
        """Get specific widget by ID"""
        for widget in self.widgets:
            if widget.get("id") == widget_id:
                return widget
        return None

@dataclass
class ReportReadModel(ReadModel):
    """Read model for generated reports"""
    id: str
    title: str
    type: str  # "analytics", "export", "summary"
    parameters: Dict[str, Any]
    generated_at: datetime
    file_path: Optional[str] = None
    
    # Report metadata
    record_count: int = 0
    file_size_bytes: int = 0
    format: str = "json"
    
    # Access control
    visibility: str = "private"  # private, shared, public
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "parameters": self.parameters,
            "generated_at": self.generated_at.isoformat(),
            "file_path": self.file_path,
            "record_count": self.record_count,
            "file_size_bytes": self.file_size_bytes,
            "format": self.format,
            "visibility": self.visibility,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }
    
    def is_expired(self) -> bool:
        """Check if report is expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at

# Read Model Factory
class ReadModelFactory:
    """Factory for creating read models"""
    
    @staticmethod
    def create_proposition_read_model(data: Dict[str, Any]) -> PropositionReadModel:
        """Create proposition read model from raw data"""
        return PropositionReadModel(
            id=data["id"],
            source=data["source"],
            type=data["type"],
            number=data["number"],
            year=data["year"],
            title=data["title"],
            summary=data["summary"],
            author=data["author"],
            status=data["status"],
            keywords=data.get("keywords", []),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", "")
        )
    
    @staticmethod
    def create_user_read_model(data: Dict[str, Any]) -> UserReadModel:
        """Create user read model from raw data"""
        return UserReadModel(
            id=data["id"],
            email=data["email"],
            name=data["name"],
            role=data.get("role", "user"),
            created_at=data.get("created_at", ""),
            last_login=data.get("last_login"),
            preferences=data.get("preferences", {})
        )
    
    @staticmethod
    def create_analytics_read_model(metric_type: str, period: str, data: Dict[str, Any]) -> AnalyticsReadModel:
        """Create analytics read model"""
        return AnalyticsReadModel(
            metric_type=metric_type,
            period=period,
            data=data,
            generated_at=datetime.now()
        )