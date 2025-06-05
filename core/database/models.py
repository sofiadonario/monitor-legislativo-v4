"""
Optimized SQLAlchemy Database Models
High-performance database layer with strategic indexing
"""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, JSON, 
    Index, ForeignKey, Table, func, text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import expression
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()

# Association tables for many-to-many relationships
proposition_keywords = Table(
    'proposition_keywords',
    Base.metadata,
    Column('proposition_id', String, ForeignKey('propositions.id'), primary_key=True),
    Column('keyword_id', Integer, ForeignKey('keywords.id'), primary_key=True),
    # Index for faster lookups
    Index('idx_prop_keywords_prop', 'proposition_id'),
    Index('idx_prop_keywords_keyword', 'keyword_id')
)

proposition_authors = Table(
    'proposition_authors',
    Base.metadata,
    Column('proposition_id', String, ForeignKey('propositions.id'), primary_key=True),
    Column('author_id', Integer, ForeignKey('authors.id'), primary_key=True),
    # Index for faster lookups
    Index('idx_prop_authors_prop', 'proposition_id'),
    Index('idx_prop_authors_author', 'author_id')
)

class Author(Base):
    """Author/Politician model with optimized indexing"""
    __tablename__ = 'authors'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    external_id = Column(String(50), unique=True, index=True)  # ID from external system
    name = Column(String(200), nullable=False, index=True)
    normalized_name = Column(String(200), index=True)  # For fuzzy matching
    type = Column(String(50), nullable=False, index=True)  # Deputado, Senador, etc.
    party = Column(String(20), index=True)
    state = Column(String(2), index=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    propositions = relationship("Proposition", secondary=proposition_authors, back_populates="authors")
    
    # Composite indexes for common queries
    __table_args__ = (
        Index('idx_author_party_state', 'party', 'state'),
        Index('idx_author_type_name', 'type', 'name'),
        Index('idx_author_search', 'normalized_name', 'party', 'state'),
    )
    
    def __repr__(self):
        return f"<Author(name='{self.name}', party='{self.party}', state='{self.state}')>"

class Keyword(Base):
    """Keyword model for semantic search"""
    __tablename__ = 'keywords'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    term = Column(String(100), nullable=False, unique=True, index=True)
    normalized_term = Column(String(100), index=True)  # Lowercased, stemmed
    frequency = Column(Integer, default=0, index=True)  # Usage frequency
    category = Column(String(50), index=True)  # Topic category
    
    # Relationships
    propositions = relationship("Proposition", secondary=proposition_keywords, back_populates="keywords")
    
    def __repr__(self):
        return f"<Keyword(term='{self.term}', frequency={self.frequency})>"

class DataSource(Base):
    """Data source configuration"""
    __tablename__ = 'data_sources'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False, unique=True, index=True)
    display_name = Column(String(100), nullable=False)
    base_url = Column(String(500))
    api_key = Column(String(200))
    is_active = Column(Boolean, default=True, index=True)
    
    # Health monitoring
    last_health_check = Column(DateTime)
    is_healthy = Column(Boolean, default=True, index=True)
    avg_response_time = Column(Integer)  # milliseconds
    
    # Relationships
    propositions = relationship("Proposition", back_populates="source")
    
    def __repr__(self):
        return f"<DataSource(name='{self.name}', healthy={self.is_healthy})>"

class Proposition(Base):
    """Main proposition model with advanced indexing"""
    __tablename__ = 'propositions'
    
    # Primary key - using composite key for better distribution
    id = Column(String(100), primary_key=True)  # Format: SOURCE_TYPE_NUMBER_YEAR
    
    # Core fields with strategic indexing
    type = Column(String(50), nullable=False, index=True)
    number = Column(String(20), nullable=False)
    year = Column(Integer, nullable=False, index=True)
    title = Column(Text, nullable=False)
    summary = Column(Text)
    full_text = Column(Text)  # For full-text search
    
    # Status and metadata
    status = Column(String(50), nullable=False, index=True)
    source_id = Column(Integer, ForeignKey('data_sources.id'), nullable=False, index=True)
    external_id = Column(String(100), index=True)  # ID in external system
    url = Column(String(1000))
    full_text_url = Column(String(1000))
    
    # Timestamps with timezone awareness
    publication_date = Column(DateTime, nullable=False, index=True)
    last_update = Column(DateTime, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # JSON fields for flexible data
    attachments = Column(JSON)  # Use JSONB for PostgreSQL
    extra_data = Column(JSON)
    
    # Search optimization
    search_vector = Column(Text)  # Pre-computed search text
    popularity_score = Column(Integer, default=0, index=True)  # For ranking
    
    # Relationships
    source = relationship("DataSource", back_populates="propositions")
    authors = relationship("Author", secondary=proposition_authors, back_populates="propositions")
    keywords = relationship("Keyword", secondary=proposition_keywords, back_populates="propositions")
    search_logs = relationship("SearchLog", back_populates="proposition")
    
    # Advanced indexing strategy
    __table_args__ = (
        # Composite indexes for common queries
        Index('idx_prop_source_year', 'source_id', 'year'),
        Index('idx_prop_type_status', 'type', 'status'),
        Index('idx_prop_date_source', 'publication_date', 'source_id'),
        Index('idx_prop_year_type', 'year', 'type'),
        Index('idx_prop_status_date', 'status', 'publication_date'),
        
        # Search optimization indexes
        Index('idx_prop_search_vector', 'search_vector'),
        Index('idx_prop_popularity', 'popularity_score', 'publication_date'),
        
        # Performance indexes
        Index('idx_prop_updated', 'updated_at'),
        Index('idx_prop_external', 'source_id', 'external_id'),
        
        # Partial indexes for active propositions (PostgreSQL only)
        # Index('idx_prop_active', 'publication_date', postgresql_where=text("status = 'ACTIVE'")),
    )
    
    def __repr__(self):
        return f"<Proposition(id='{self.id}', type='{self.type}', title='{self.title[:50]}...')>"

class SearchLog(Base):
    """Search analytics and performance tracking"""
    __tablename__ = 'search_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(50), index=True)  # User session
    query = Column(Text, nullable=False)
    normalized_query = Column(Text, index=True)  # Processed query
    filters = Column(JSON)  # Search filters applied
    
    # Results
    total_results = Column(Integer, index=True)
    results_returned = Column(Integer)
    page = Column(Integer, default=1)
    
    # Performance metrics
    search_time_ms = Column(Integer, index=True)  # Search duration
    source_used = Column(String(50), index=True)  # elasticsearch, database, cache
    
    # User interaction
    clicked_proposition_id = Column(String(100), ForeignKey('propositions.id'), index=True)
    click_position = Column(Integer)  # Position in results
    
    # Metadata
    user_agent = Column(String(500))
    ip_address = Column(String(45), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    proposition = relationship("Proposition", back_populates="search_logs")
    
    # Indexes for analytics
    __table_args__ = (
        Index('idx_search_time_query', 'timestamp', 'normalized_query'),
        Index('idx_search_performance', 'search_time_ms', 'total_results'),
        Index('idx_search_session', 'session_id', 'timestamp'),
        Index('idx_search_clicks', 'clicked_proposition_id', 'click_position'),
    )

class CacheEntry(Base):
    """Optimized cache storage"""
    __tablename__ = 'cache_entries'
    
    key = Column(String(200), primary_key=True)
    value = Column(Text, nullable=False)  # JSON-encoded data
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    hit_count = Column(Integer, default=0)
    size_bytes = Column(Integer)
    
    # Cleanup index
    __table_args__ = (
        Index('idx_cache_cleanup', 'expires_at', 'created_at'),
        Index('idx_cache_stats', 'hit_count', 'size_bytes'),
    )

class PerformanceMetric(Base):
    """System performance metrics storage"""
    __tablename__ = 'performance_metrics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Integer, nullable=False)  # Store as integer (ms, bytes, etc.)
    metric_type = Column(String(50), nullable=False, index=True)  # response_time, memory_usage, etc.
    component = Column(String(50), index=True)  # api, database, cache, etc.
    
    # Context
    request_id = Column(String(50), index=True)
    endpoint = Column(String(200), index=True)
    
    # Metadata
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    additional_data = Column(JSON)
    
    # Time-series indexes
    __table_args__ = (
        Index('idx_metrics_time_series', 'metric_name', 'timestamp'),
        Index('idx_metrics_component', 'component', 'metric_type', 'timestamp'),
        Index('idx_metrics_endpoint', 'endpoint', 'timestamp'),
    )

# Database optimization utilities
class DatabaseOptimizer:
    """Database optimization and maintenance utilities"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def analyze_slow_queries(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Analyze slow search queries"""
        try:
            slow_queries = self.session.query(SearchLog).filter(
                SearchLog.search_time_ms > 1000  # Queries taking more than 1 second
            ).order_by(SearchLog.search_time_ms.desc()).limit(limit).all()
            
            return [
                {
                    'query': log.query,
                    'search_time_ms': log.search_time_ms,
                    'total_results': log.total_results,
                    'timestamp': log.timestamp.isoformat()
                }
                for log in slow_queries
            ]
        except Exception as e:
            logger.error(f"Error analyzing slow queries: {e}")
            return []
    
    def get_index_usage_stats(self) -> Dict[str, Any]:
        """Get database index usage statistics (PostgreSQL specific)"""
        try:
            # This would be PostgreSQL-specific query
            # For SQLite, we'd use different approach
            return {
                'total_indexes': 'Not available for SQLite',
                'unused_indexes': 'Not available for SQLite',
                'most_used_indexes': 'Not available for SQLite'
            }
        except Exception as e:
            logger.error(f"Error getting index stats: {e}")
            return {}
    
    def optimize_search_vectors(self):
        """Update search vectors for all propositions"""
        try:
            propositions = self.session.query(Proposition).all()
            
            for prop in propositions:
                # Create search vector from title, summary, and keywords
                search_parts = [prop.title, prop.summary or '']
                if prop.keywords:
                    search_parts.extend([kw.term for kw in prop.keywords])
                
                prop.search_vector = ' '.join(search_parts).lower()
            
            self.session.commit()
            logger.info(f"Updated search vectors for {len(propositions)} propositions")
            
        except Exception as e:
            logger.error(f"Error updating search vectors: {e}")
            self.session.rollback()
    
    def cleanup_expired_cache(self):
        """Remove expired cache entries"""
        try:
            now = datetime.utcnow()
            deleted_count = self.session.query(CacheEntry).filter(
                CacheEntry.expires_at < now
            ).delete()
            
            self.session.commit()
            logger.info(f"Cleaned up {deleted_count} expired cache entries")
            
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")
            self.session.rollback()
    
    def update_popularity_scores(self):
        """Update popularity scores based on search analytics"""
        try:
            # Get click counts for each proposition
            click_stats = self.session.query(
                SearchLog.clicked_proposition_id,
                func.count(SearchLog.id).label('click_count')
            ).filter(
                SearchLog.clicked_proposition_id.isnot(None),
                SearchLog.timestamp >= datetime.utcnow().replace(day=1)  # This month
            ).group_by(SearchLog.clicked_proposition_id).all()
            
            # Update popularity scores
            for prop_id, click_count in click_stats:
                self.session.query(Proposition).filter(
                    Proposition.id == prop_id
                ).update({'popularity_score': click_count})
            
            self.session.commit()
            logger.info(f"Updated popularity scores for {len(click_stats)} propositions")
            
        except Exception as e:
            logger.error(f"Error updating popularity scores: {e}")
            self.session.rollback()

# Query optimization helpers
class OptimizedQueries:
    """Pre-optimized database queries with aggressive eager loading"""
    
    @staticmethod
    def search_propositions(session: Session, query: str, filters: Dict[str, Any] = None, 
                          limit: int = 25, offset: int = 0) -> List[Proposition]:
        """Optimized proposition search with filters and eager loading"""
        
        from sqlalchemy.orm import joinedload, selectinload, contains_eager
        
        # CRITICAL: Eliminate N+1 queries with aggressive eager loading
        base_query = session.query(Proposition).options(
            # Eager load relationships to avoid N+1 queries
            joinedload(Proposition.source),               # Small, always needed
            selectinload(Proposition.authors),            # Medium collection
            selectinload(Proposition.keywords),           # Medium collection  
            selectinload(Proposition.search_logs)         # Large collection, load separately
        )
        
        # Apply text search
        if query:
            base_query = base_query.filter(
                Proposition.search_vector.contains(query.lower())
            )
        
        # Apply filters
        if filters:
            if filters.get('year'):
                base_query = base_query.filter(Proposition.year == filters['year'])
            
            if filters.get('type'):
                base_query = base_query.filter(Proposition.type == filters['type'])
            
            if filters.get('status'):
                base_query = base_query.filter(Proposition.status == filters['status'])
            
            if filters.get('source_id'):
                base_query = base_query.filter(Proposition.source_id == filters['source_id'])
            
            if filters.get('date_from'):
                base_query = base_query.filter(Proposition.publication_date >= filters['date_from'])
            
            if filters.get('date_to'):
                base_query = base_query.filter(Proposition.publication_date <= filters['date_to'])
        
        # Order by relevance (popularity + recency)
        base_query = base_query.order_by(
            Proposition.popularity_score.desc(),
            Proposition.publication_date.desc()
        )
        
        # Apply pagination
        return base_query.offset(offset).limit(limit).all()
    
    @staticmethod
    def get_trending_propositions(session: Session, days: int = 7, limit: int = 10) -> List[Proposition]:
        """Get trending propositions based on recent activity with eager loading"""
        
        from sqlalchemy.orm import joinedload, selectinload
        
        cutoff_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date.replace(day=cutoff_date.day - days)
        
        # Get propositions with most clicks in the period - OPTIMIZED with eager loading
        trending = session.query(Proposition).options(
            joinedload(Proposition.source),      # Always needed for display
            selectinload(Proposition.authors),   # For trending display
            selectinload(Proposition.keywords)   # For trending context
        ).join(SearchLog).filter(
            SearchLog.clicked_proposition_id == Proposition.id,
            SearchLog.timestamp >= cutoff_date
        ).group_by(Proposition.id).order_by(
            func.count(SearchLog.id).desc(),
            Proposition.publication_date.desc()
        ).limit(limit).all()
        
        return trending
    
    @staticmethod
    def get_search_analytics(session: Session, days: int = 30) -> Dict[str, Any]:
        """Get search performance analytics"""
        
        cutoff_date = datetime.utcnow().replace(day=datetime.utcnow().day - days)
        
        # Query analytics
        analytics = session.query(
            func.count(SearchLog.id).label('total_searches'),
            func.avg(SearchLog.search_time_ms).label('avg_search_time'),
            func.max(SearchLog.search_time_ms).label('max_search_time'),
            func.count(SearchLog.clicked_proposition_id).label('total_clicks')
        ).filter(SearchLog.timestamp >= cutoff_date).first()
        
        # Top queries
        top_queries = session.query(
            SearchLog.normalized_query,
            func.count(SearchLog.id).label('frequency')
        ).filter(
            SearchLog.timestamp >= cutoff_date,
            SearchLog.normalized_query.isnot(None)
        ).group_by(SearchLog.normalized_query).order_by(
            func.count(SearchLog.id).desc()
        ).limit(10).all()
        
        return {
            'total_searches': analytics.total_searches or 0,
            'avg_search_time_ms': float(analytics.avg_search_time or 0),
            'max_search_time_ms': analytics.max_search_time or 0,
            'total_clicks': analytics.total_clicks or 0,
            'click_through_rate': (analytics.total_clicks / analytics.total_searches * 100) if analytics.total_searches else 0,
            'top_queries': [{'query': q.normalized_query, 'count': q.frequency} for q in top_queries]
        }


class KeyRotationLog(Base):
    """Audit trail for cryptographic key operations"""
    __tablename__ = 'key_rotation_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(255), nullable=False, index=True)
    key_type = Column(String(50), nullable=False, index=True)
    operation = Column(String(50), nullable=False)  # generate, rotate, compromise, cleanup
    timestamp = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    details = Column(JSON)  # Additional operation details
    performed_by = Column(String(100), nullable=False)  # User or 'system'
    
    # Composite index for audit queries
    __table_args__ = (
        Index('idx_key_rotation_type_time', 'key_type', 'timestamp'),
        Index('idx_key_rotation_operation', 'operation', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<KeyRotationLog(key_id={self.key_id}, operation={self.operation}, timestamp={self.timestamp})>"


class SecurityEvent(Base):
    """Security event log for SIEM integration and threat analysis"""
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(100), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    threat_level = Column(Integer, nullable=False, index=True)  # 1-5 scale
    user_id = Column(String(50), ForeignKey('users.id'), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True, index=True)  # IPv6 ready
    user_agent = Column(Text, nullable=True)
    endpoint = Column(String(255), nullable=True, index=True)
    method = Column(String(10), nullable=True)
    status_code = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)  # JSON string
    geo_location = Column(Text, nullable=True)  # JSON string
    risk_score = Column(Float, nullable=False, default=0.0, index=True)
    indicators = Column(Text, nullable=True)  # JSON array
    raw_data = Column(Text, nullable=True)  # For forensics
    
    # Relationships
    user = relationship("User", backref="security_events")
    
    # Composite indexes for security queries
    __table_args__ = (
        Index('idx_security_event_type_time', 'event_type', 'timestamp'),
        Index('idx_security_event_user_time', 'user_id', 'timestamp'),
        Index('idx_security_event_ip_time', 'ip_address', 'timestamp'),
        Index('idx_security_event_threat', 'threat_level', 'timestamp'),
        Index('idx_security_event_risk', 'risk_score', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<SecurityEvent(event_id={self.event_id}, type={self.event_type}, threat={self.threat_level})>"