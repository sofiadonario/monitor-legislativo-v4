from sqlalchemy import Column, BigInteger, String, Text, Integer, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from src.models import Base


class SearchCache(Base):
    __tablename__ = 'search_cache'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    query_hash = Column(String(64), nullable=False, unique=True)
    query_text = Column(Text)
    result_data = Column(JSONB)
    result_count = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (
        UniqueConstraint('query_hash', name='idx_query_hash_unique'),
    )