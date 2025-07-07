from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.sql import func
from src.models import Base


class SchemaMigrations(Base):
    __tablename__ = 'schema_migrations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), unique=True, nullable=False)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    checksum = Column(String(64))
    success = Column(Boolean, default=True)
    error_message = Column(Text)