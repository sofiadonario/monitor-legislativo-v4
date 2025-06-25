# Phase 1: Core Infrastructure Implementation Plan
**Timeline**: Weeks 1-4  
**Budget**: $0 (development environment only)  
**Goal**: Establish two-tier foundation with Docker development environment

## Overview

Phase 1 creates the foundational infrastructure for the two-tier architecture while preserving all existing functionality. This phase focuses on local development environment setup, database schema extensions, and basic service separation.

## Week-by-Week Implementation

---

## WEEK 1: Docker Environment Setup

### Objectives
- Create multi-service Docker development environment
- Establish service networking and communication
- Set up volume management for data persistence
- Document development workflow

### Deliverables

#### 1. Docker Compose Configuration (`docker-compose.yml`)
```yaml
version: '3.8'

networks:
  legislativo:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
  prefect_data:

services:
  # Database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: legislativo
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - legislativo
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 30s
      timeout: 10s
      retries: 5

  # Redis Cache
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - legislativo
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  # TIER 1: Data Collection Service
  collector:
    build:
      context: ./services/collector
      dockerfile: Dockerfile
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@postgres:5432/legislativo
      - REDIS_URL=redis://redis:6379
      - PREFECT_API_URL=http://prefect:4200/api
    volumes:
      - ./services/collector:/app
      - ./data:/app/data
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      prefect:
        condition: service_started
    networks:
      - legislativo
    restart: unless-stopped

  # Prefect Orchestration
  prefect:
    image: prefecthq/prefect:2-python3.11
    command: prefect server start --host 0.0.0.0
    environment:
      - PREFECT_SERVER_API_HOST=0.0.0.0
      - PREFECT_API_DATABASE_CONNECTION_URL=postgresql://postgres:postgres@postgres:5432/prefect
    ports:
      - "4200:4200"
    volumes:
      - prefect_data:/root/.prefect
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - legislativo

  # TIER 2: Analytics Platform
  api:
    build:
      context: ./main_app
      dockerfile: Dockerfile
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@postgres:5432/legislativo
      - REDIS_URL=redis://redis:6379
    ports:
      - "8000:8000"
    volumes:
      - ./main_app:/app
      - ./core:/app/core
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - legislativo
    restart: unless-stopped

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "3000:3000"
    volumes:
      - ./src:/app/src
      - ./public:/app/public
    environment:
      - REACT_APP_API_URL=http://localhost:8000
      - REACT_APP_ANALYTICS_URL=http://localhost:3838
    depends_on:
      - api
    networks:
      - legislativo

  analytics:
    build:
      context: ./r-shiny-app
      dockerfile: Dockerfile
    ports:
      - "3838:3838"
    volumes:
      - ./r-shiny-app:/srv/shiny-server
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@postgres:5432/legislativo
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - legislativo

  # Development Tools
  pgadmin:
    image: dpage/pgadmin4:latest
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@legislativo.dev
      PGADMIN_DEFAULT_PASSWORD: admin
    ports:
      - "5050:80"
    depends_on:
      - postgres
    networks:
      - legislativo
    profiles:
      - dev-tools

  redis-commander:
    image: rediscommander/redis-commander:latest
    environment:
      - REDIS_HOSTS=local:redis:6379
    ports:
      - "8081:8081"
    depends_on:
      - redis
    networks:
      - legislativo
    profiles:
      - dev-tools
```

#### 2. Service Directory Structure
```
services/
├── collector/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── src/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── flows/
│   │   │   ├── __init__.py
│   │   │   ├── lexml_collection.py
│   │   │   └── data_processing.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── lexml_client.py
│   │   │   └── database_service.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── retry_handler.py
│   │       └── validation.py
│   └── config/
│       └── settings.py
│
└── analytics/
    ├── Dockerfile
    ├── requirements.txt
    └── src/
        ├── __init__.py
        ├── main.py
        └── modules/
            ├── __init__.py
            ├── dashboard.py
            └── exports.py
```

#### 3. Development Scripts
**`scripts/dev-setup.sh`**:
```bash
#!/bin/bash
set -e

echo "🚀 Setting up Monitor Legislativo v4 Development Environment"

# Check dependencies
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "❌ Docker Compose is required but not installed."; exit 1; }

# Create necessary directories
mkdir -p data/{raw,processed,exports}
mkdir -p logs
mkdir -p migrations

# Copy environment template
if [ ! -f .env.development ]; then
    cp .env.example .env.development
    echo "📝 Created .env.development from template"
fi

# Build and start services
echo "🔨 Building Docker services..."
docker-compose build

echo "🌱 Starting development environment..."
docker-compose up -d postgres redis prefect

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
docker-compose run --rm api python -c "
import time
import asyncio
from core.database.supabase_config import get_database_manager

async def wait_for_db():
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            db_manager = await get_database_manager()
            if await db_manager.test_connection():
                print('✅ Database is ready')
                return True
        except Exception as e:
            print(f'⏳ Attempt {attempt + 1}/{max_attempts}: {e}')
            time.sleep(2)
    return False

if asyncio.run(wait_for_db()):
    print('🎉 Development environment is ready!')
else:
    print('❌ Failed to connect to database')
    exit(1)
"

echo "🌟 Development environment setup complete!"
echo ""
echo "Available services:"
echo "  Frontend:     http://localhost:3000"
echo "  API:          http://localhost:8000"
echo "  R Shiny:      http://localhost:3838"
echo "  Prefect:      http://localhost:4200"
echo "  PgAdmin:      http://localhost:5050 (with --profile dev-tools)"
echo "  Redis UI:     http://localhost:8081 (with --profile dev-tools)"
echo ""
echo "To start all services: docker-compose up -d"
echo "To view logs: docker-compose logs -f [service_name]"
echo "To stop: docker-compose down"
```

### Technical Tasks

#### Day 1-2: Docker Configuration
- [ ] Create `docker-compose.yml` with all services
- [ ] Set up Docker networks and volumes
- [ ] Configure health checks for all services
- [ ] Test service startup and networking

#### Day 3-4: Service Dockerization
- [ ] Create `Dockerfile` for collector service
- [ ] Create `Dockerfile.frontend` for React application
- [ ] Update existing R Shiny Dockerfile if needed
- [ ] Test all service builds

#### Day 5-7: Development Tooling
- [ ] Create development setup scripts
- [ ] Configure hot-reload for development
- [ ] Set up development database with sample data
- [ ] Document development workflow

---

## WEEK 2: Database Schema Migration

### Objectives
- Extend existing PostgreSQL schema for two-tier architecture
- Create migration scripts from current Supabase schema
- Set up performance optimizations (indexes, views)
- Implement database connection management for both tiers

### Deliverables

#### 1. Extended Database Schema (`migrations/001_two_tier_schema.sql`)
```sql
-- Monitor Legislativo v4 - Two-Tier Architecture Schema
-- Extends existing schema with collection and analytics tables

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For similarity search
CREATE EXTENSION IF NOT EXISTS "unaccent"; -- For Portuguese text search

-- Search terms management for automated collection
CREATE TABLE IF NOT EXISTS search_terms (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    term VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    cql_query TEXT,
    description TEXT,
    active BOOLEAN DEFAULT true,
    collection_frequency VARCHAR(20) DEFAULT 'monthly', -- daily, weekly, monthly, custom
    priority INTEGER DEFAULT 1, -- 1=highest, 5=lowest
    next_collection TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    
    CONSTRAINT valid_frequency CHECK (collection_frequency IN ('daily', 'weekly', 'monthly', 'custom')),
    CONSTRAINT valid_priority CHECK (priority BETWEEN 1 AND 5)
);

-- Enhanced legislative documents table
CREATE TABLE IF NOT EXISTS legislative_documents (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    urn VARCHAR(500) UNIQUE NOT NULL, -- URN:LEX identifier
    document_type VARCHAR(100) NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    summary TEXT,
    metadata JSONB,
    search_term_id INTEGER REFERENCES search_terms(id),
    source_api VARCHAR(50), -- lexml, camara, senado, etc.
    language VARCHAR(10) DEFAULT 'pt-BR',
    
    -- Temporal information
    document_date DATE,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    published_at TIMESTAMP WITH TIME ZONE,
    
    -- Academic and research fields
    citation_count INTEGER DEFAULT 0,
    academic_relevance_score NUMERIC(5,2),
    keywords TEXT[], -- Array of extracted keywords
    
    -- Quality and validation
    validation_status VARCHAR(20) DEFAULT 'pending', -- pending, validated, rejected
    validation_notes TEXT,
    validated_by VARCHAR(100),
    validated_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_validation_status CHECK (validation_status IN ('pending', 'validated', 'rejected'))
);

-- Document versions for change tracking
CREATE TABLE IF NOT EXISTS document_versions (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT REFERENCES legislative_documents(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    content TEXT,
    metadata JSONB,
    changes JSONB, -- Detailed change information
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    
    UNIQUE(document_id, version_number)
);

-- Collection execution logs
CREATE TABLE IF NOT EXISTS collection_logs (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    search_term_id INTEGER REFERENCES search_terms(id),
    collection_type VARCHAR(50), -- scheduled, manual, retry
    status VARCHAR(50) NOT NULL, -- running, completed, failed, timeout
    
    -- Execution details
    records_collected INTEGER DEFAULT 0,
    records_new INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_skipped INTEGER DEFAULT 0,
    execution_time_ms INTEGER,
    
    -- Error handling
    error_message TEXT,
    error_type VARCHAR(100),
    retry_count INTEGER DEFAULT 0,
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- API response details
    api_response_size INTEGER,
    api_response_time_ms INTEGER,
    api_rate_limit_remaining INTEGER,
    
    CONSTRAINT valid_status CHECK (status IN ('running', 'completed', 'failed', 'timeout'))
);

-- Performance and analytics tracking
CREATE TABLE IF NOT EXISTS search_analytics (
    id BIGSERIAL PRIMARY KEY,
    query_hash VARCHAR(64) NOT NULL,
    query_params JSONB,
    result_count INTEGER,
    execution_time_ms INTEGER,
    cache_hit BOOLEAN DEFAULT false,
    user_session_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- User behavior tracking
    results_clicked INTEGER DEFAULT 0,
    results_exported BOOLEAN DEFAULT false,
    export_format VARCHAR(20),
    time_spent_ms INTEGER
);

-- Academic research datasets and exports
CREATE TABLE IF NOT EXISTS research_datasets (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    doi VARCHAR(100) UNIQUE, -- Digital Object Identifier
    
    -- Dataset composition
    query_criteria JSONB,
    document_count INTEGER,
    date_range DATERANGE,
    
    -- Academic metadata
    created_by_orcid VARCHAR(50), -- ORCID researcher identifier
    created_by_name VARCHAR(255),
    institution VARCHAR(255),
    license VARCHAR(100) DEFAULT 'CC BY 4.0',
    
    -- Publication status
    status VARCHAR(20) DEFAULT 'draft', -- draft, published, archived
    published_at TIMESTAMP WITH TIME ZONE,
    version VARCHAR(10) DEFAULT '1.0',
    
    -- File information
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    file_format VARCHAR(20),
    checksum VARCHAR(64),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_dataset_status CHECK (status IN ('draft', 'published', 'archived'))
);

-- Performance Indexes
-- Full-text search on Portuguese content
CREATE INDEX IF NOT EXISTS idx_documents_content_search 
ON legislative_documents USING GIN (to_tsvector('portuguese', content));

CREATE INDEX IF NOT EXISTS idx_documents_title_search 
ON legislative_documents USING GIN (to_tsvector('portuguese', title));

-- URN and document type indexes
CREATE INDEX IF NOT EXISTS idx_documents_urn ON legislative_documents(urn);
CREATE INDEX IF NOT EXISTS idx_documents_type ON legislative_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_documents_date ON legislative_documents(document_date);
CREATE INDEX IF NOT EXISTS idx_documents_collected ON legislative_documents(collected_at);

-- JSONB metadata indexes
CREATE INDEX IF NOT EXISTS idx_documents_metadata ON legislative_documents USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_documents_keywords ON legislative_documents USING GIN (keywords);

-- Search terms and collection indexes
CREATE INDEX IF NOT EXISTS idx_search_terms_active ON search_terms(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_search_terms_next_collection ON search_terms(next_collection) WHERE active = true;

-- Collection logs indexes
CREATE INDEX IF NOT EXISTS idx_collection_logs_term ON collection_logs(search_term_id);
CREATE INDEX IF NOT EXISTS idx_collection_logs_status ON collection_logs(status);
CREATE INDEX IF NOT EXISTS idx_collection_logs_started ON collection_logs(started_at);

-- Analytics indexes
CREATE INDEX IF NOT EXISTS idx_search_analytics_query ON search_analytics(query_hash);
CREATE INDEX IF NOT EXISTS idx_search_analytics_created ON search_analytics(created_at);

-- Performance Views
-- Dashboard summary view (materialized for performance)
CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_summary AS
SELECT 
    COUNT(*) as total_documents,
    COUNT(*) FILTER (WHERE document_date >= CURRENT_DATE - INTERVAL '30 days') as documents_last_30_days,
    COUNT(*) FILTER (WHERE collected_at >= CURRENT_DATE - INTERVAL '7 days') as new_documents_week,
    COUNT(DISTINCT document_type) as document_types,
    COUNT(DISTINCT source_api) as active_sources,
    AVG(academic_relevance_score) as avg_relevance_score,
    MAX(collected_at) as last_collection,
    COUNT(*) FILTER (WHERE validation_status = 'validated') as validated_documents,
    COUNT(*) FILTER (WHERE validation_status = 'pending') as pending_validation
FROM legislative_documents;

-- Collection performance view
CREATE MATERIALIZED VIEW IF NOT EXISTS collection_performance AS
SELECT 
    st.term,
    st.category,
    COUNT(cl.*) as total_collections,
    COUNT(*) FILTER (WHERE cl.status = 'completed') as successful_collections,
    COUNT(*) FILTER (WHERE cl.status = 'failed') as failed_collections,
    AVG(cl.execution_time_ms) as avg_execution_time,
    SUM(cl.records_collected) as total_records_collected,
    MAX(cl.completed_at) as last_collection
FROM search_terms st
LEFT JOIN collection_logs cl ON st.id = cl.search_term_id
WHERE st.active = true
GROUP BY st.id, st.term, st.category;

-- Search analytics view
CREATE MATERIALIZED VIEW IF NOT EXISTS search_patterns AS
SELECT 
    query_hash,
    COUNT(*) as query_frequency,
    AVG(result_count) as avg_results,
    AVG(execution_time_ms) as avg_execution_time,
    SUM(results_clicked) as total_clicks,
    COUNT(*) FILTER (WHERE cache_hit = true) as cache_hits,
    COUNT(*) FILTER (WHERE results_exported = true) as exports
FROM search_analytics 
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY query_hash
ORDER BY query_frequency DESC;

-- Triggers for automatic updates
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers
CREATE TRIGGER update_search_terms_modtime 
    BEFORE UPDATE ON search_terms 
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_documents_modtime 
    BEFORE UPDATE ON legislative_documents 
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_datasets_modtime 
    BEFORE UPDATE ON research_datasets 
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW dashboard_summary;
    REFRESH MATERIALIZED VIEW collection_performance;
    REFRESH MATERIALIZED VIEW search_patterns;
END;
$$ LANGUAGE plpgsql;

-- Insert sample search terms for development
INSERT INTO search_terms (term, category, cql_query, description, collection_frequency, priority) VALUES
('transporte urbano', 'Transport', 'title any "transporte urbano" OR subject any "mobilidade urbana"', 'Urban transportation and mobility legislation', 'weekly', 1),
('mobilidade sustentável', 'Environment', 'title any "mobilidade sustentável" OR subject any "transporte verde"', 'Sustainable mobility and green transportation', 'monthly', 2),
('transporte público', 'Public Policy', 'title any "transporte público" OR subject any "ônibus" OR subject any "metrô"', 'Public transportation systems', 'weekly', 1),
('infraestrutura viária', 'Infrastructure', 'title any "infraestrutura" AND (subject any "rodovia" OR subject any "estrada")', 'Road infrastructure legislation', 'monthly', 3),
('regulamentação ANTT', 'Regulatory', 'autoridade exact "ANTT" OR subject any "agência nacional de transportes"', 'ANTT regulatory framework', 'daily', 1)
ON CONFLICT DO NOTHING;

COMMENT ON TABLE search_terms IS 'Configuration for automated legislative data collection';
COMMENT ON TABLE legislative_documents IS 'Main repository for collected legislative documents with academic metadata';
COMMENT ON TABLE collection_logs IS 'Audit trail for all data collection activities';
COMMENT ON TABLE search_analytics IS 'User search behavior and performance analytics';
COMMENT ON TABLE research_datasets IS 'Academic research datasets with DOI and citation support';
```

#### 2. Database Manager Extensions (`core/database/two_tier_manager.py`)
```python
"""
Two-Tier Database Manager for Monitor Legislativo v4
Extends existing Supabase configuration with collection and analytics capabilities
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
from sqlalchemy import text, func
from sqlalchemy.ext.asyncio import AsyncSession
from core.database.supabase_config import DatabaseManager as BaseManager, get_database_manager

logger = logging.getLogger(__name__)


class TwoTierDatabaseManager(BaseManager):
    """Extended database manager for two-tier architecture"""
    
    async def create_search_term(self, term_data: Dict[str, Any]) -> int:
        """Create a new search term for automated collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    INSERT INTO search_terms (
                        term, category, cql_query, description, 
                        collection_frequency, priority, created_by
                    ) VALUES (
                        :term, :category, :cql_query, :description,
                        :frequency, :priority, :created_by
                    ) RETURNING id
                """), term_data)
                
                search_term_id = result.scalar()
                await session.commit()
                
                logger.info(f"Created search term {search_term_id}: {term_data['term']}")
                return search_term_id
                
        except Exception as e:
            logger.error(f"Failed to create search term: {e}")
            raise
    
    async def get_active_search_terms(self) -> List[Dict[str, Any]]:
        """Get all active search terms for collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term, category, cql_query, collection_frequency, priority,
                           next_collection
                    FROM search_terms 
                    WHERE active = true 
                    ORDER BY priority ASC, next_collection ASC NULLS FIRST
                """))
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get active search terms: {e}")
            return []
    
    async def store_collected_documents(self, documents: List[Dict[str, Any]], 
                                      search_term_id: int, source_api: str) -> Dict[str, int]:
        """Store collected documents with deduplication"""
        stats = {'new': 0, 'updated': 0, 'skipped': 0}
        
        try:
            async with self.session_factory() as session:
                for doc in documents:
                    result = await session.execute(text("""
                        INSERT INTO legislative_documents (
                            urn, document_type, title, content, metadata,
                            search_term_id, source_api, document_date
                        ) VALUES (
                            :urn, :document_type, :title, :content, :metadata,
                            :search_term_id, :source_api, :document_date
                        )
                        ON CONFLICT (urn) DO UPDATE SET
                            content = EXCLUDED.content,
                            metadata = EXCLUDED.metadata,
                            updated_at = NOW()
                        RETURNING (xmax = 0) as is_new
                    """), {
                        'urn': doc['urn'],
                        'document_type': doc.get('document_type', 'Unknown'),
                        'title': doc['title'],
                        'content': doc.get('content'),
                        'metadata': json.dumps(doc.get('metadata', {})),
                        'search_term_id': search_term_id,
                        'source_api': source_api,
                        'document_date': doc.get('document_date')
                    })
                    
                    is_new = result.scalar()
                    if is_new:
                        stats['new'] += 1
                    else:
                        stats['updated'] += 1
                
                await session.commit()
                logger.info(f"Stored documents - New: {stats['new']}, Updated: {stats['updated']}")
                
        except Exception as e:
            logger.error(f"Failed to store documents: {e}")
            stats['skipped'] = len(documents)
            
        return stats
    
    async def log_collection_execution(self, log_data: Dict[str, Any]) -> int:
        """Log collection execution details"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    INSERT INTO collection_logs (
                        search_term_id, collection_type, status, records_collected,
                        records_new, records_updated, records_skipped,
                        execution_time_ms, error_message, error_type,
                        started_at, completed_at, api_response_time_ms
                    ) VALUES (
                        :search_term_id, :collection_type, :status, :records_collected,
                        :records_new, :records_updated, :records_skipped,
                        :execution_time_ms, :error_message, :error_type,
                        :started_at, :completed_at, :api_response_time_ms
                    ) RETURNING id
                """), log_data)
                
                log_id = result.scalar()
                await session.commit()
                return log_id
                
        except Exception as e:
            logger.error(f"Failed to log collection execution: {e}")
            return -1
    
    async def update_search_term_schedule(self, search_term_id: int, 
                                        next_collection: datetime) -> bool:
        """Update next collection time for a search term"""
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    UPDATE search_terms 
                    SET next_collection = :next_collection, updated_at = NOW()
                    WHERE id = :id
                """), {
                    'id': search_term_id,
                    'next_collection': next_collection
                })
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update search term schedule: {e}")
            return False
    
    async def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get comprehensive dashboard summary"""
        try:
            async with self.session_factory() as session:
                # Refresh materialized view
                await session.execute(text("SELECT refresh_analytics_views()"))
                
                # Get dashboard data
                result = await session.execute(text("""
                    SELECT * FROM dashboard_summary
                """))
                
                summary = dict(result.fetchone()._mapping) if result.rowcount > 0 else {}
                
                # Get collection performance
                perf_result = await session.execute(text("""
                    SELECT * FROM collection_performance 
                    ORDER BY last_collection DESC NULLS LAST
                    LIMIT 10
                """))
                
                summary['collection_performance'] = [
                    dict(row._mapping) for row in perf_result.fetchall()
                ]
                
                # Get recent search patterns
                patterns_result = await session.execute(text("""
                    SELECT * FROM search_patterns
                    LIMIT 20
                """))
                
                summary['search_patterns'] = [
                    dict(row._mapping) for row in patterns_result.fetchall()
                ]
                
                return summary
                
        except Exception as e:
            logger.error(f"Failed to get dashboard summary: {e}")
            return {}
    
    async def track_search_analytics(self, analytics_data: Dict[str, Any]) -> bool:
        """Track search analytics for performance monitoring"""
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    INSERT INTO search_analytics (
                        query_hash, query_params, result_count, execution_time_ms,
                        cache_hit, user_session_id
                    ) VALUES (
                        :query_hash, :query_params, :result_count, :execution_time_ms,
                        :cache_hit, :user_session_id
                    )
                """), analytics_data)
                
                await session.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to track search analytics: {e}")
            return False


# Singleton instance for two-tier operations
_two_tier_manager: Optional[TwoTierDatabaseManager] = None


async def get_two_tier_manager() -> TwoTierDatabaseManager:
    """Get or create two-tier database manager singleton"""
    global _two_tier_manager
    if _two_tier_manager is None:
        # Get base manager first
        base_manager = await get_database_manager()
        
        # Create two-tier manager with same engine and session factory
        _two_tier_manager = TwoTierDatabaseManager()
        _two_tier_manager.engine = base_manager.engine
        _two_tier_manager.session_factory = base_manager.session_factory
        
        # Test connection and initialize schema
        if await _two_tier_manager.test_connection():
            logger.info("Two-tier database manager initialized successfully")
        else:
            logger.warning("Two-tier database manager initialized in fallback mode")
    
    return _two_tier_manager
```

### Technical Tasks

#### Day 1-3: Schema Design and Implementation
- [ ] Design extended database schema for two-tier architecture
- [ ] Create migration SQL files with proper indexes and constraints
- [ ] Implement materialized views for dashboard performance
- [ ] Add sample data for development and testing

#### Day 4-5: Database Manager Extensions
- [ ] Extend existing DatabaseManager with two-tier operations
- [ ] Implement search term management functions
- [ ] Add document storage with deduplication logic
- [ ] Create collection logging and analytics tracking

#### Day 6-7: Performance Optimization
- [ ] Add appropriate database indexes for query performance
- [ ] Implement materialized view refresh strategies
- [ ] Test database performance with sample data
- [ ] Document database optimization guidelines

---

## WEEK 3: Prefect Collection Service

### Objectives
- Implement Prefect-based workflow orchestration for automated collection
- Integrate with existing LexML service patterns
- Create admin interface for search term management
- Add comprehensive monitoring and error handling

### Deliverables

#### 1. Collector Service Structure (`services/collector/`)

**`services/collector/Dockerfile`**:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create data directories
RUN mkdir -p /app/data/{raw,processed,exports,logs}

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Run the collector service
CMD ["python", "-m", "src.main"]
```

**`services/collector/requirements.txt`**:
```
# Workflow orchestration
prefect==2.14.11
prefect-sqlalchemy==0.2.4

# Database
asyncpg==0.29.0
sqlalchemy[asyncio]==2.0.23

# HTTP clients
httpx==0.25.2
aiohttp==3.9.1

# Data processing
pandas==2.1.4
lxml==4.9.3
beautifulsoup4==4.12.2

# Utilities
python-dateutil==2.8.2
pydantic==2.5.2
tqdm==4.66.1

# Configuration
python-dotenv==1.0.0
PyYAML==6.0.1

# Monitoring
prometheus-client==0.19.0
```

**`services/collector/src/main.py`**:
```python
"""
Monitor Legislativo v4 - Collector Service
Automated data collection with Prefect orchestration
"""

import asyncio
import logging
import os
from pathlib import Path
from prefect import serve
from flows.lexml_collection import daily_collection_flow, manual_collection_flow
from flows.data_processing import data_validation_flow, export_generation_flow
from config.settings import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/logs/collector.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


async def main():
    """Main entry point for collector service"""
    settings = get_settings()
    logger.info("🚀 Starting Monitor Legislativo Collector Service")
    
    # Ensure data directories exist
    for directory in ['raw', 'processed', 'exports', 'logs']:
        Path(f'/app/data/{directory}').mkdir(parents=True, exist_ok=True)
    
    # Start Prefect deployments
    await serve(
        daily_collection_flow.to_deployment(
            name="daily-collection",
            cron="0 6 * * *",  # Daily at 6 AM
            tags=["collection", "daily", "automated"]
        ),
        manual_collection_flow.to_deployment(
            name="manual-collection",
            tags=["collection", "manual", "on-demand"]
        ),
        data_validation_flow.to_deployment(
            name="data-validation",
            cron="0 2 * * *",  # Daily at 2 AM
            tags=["validation", "quality", "automated"]
        ),
        export_generation_flow.to_deployment(
            name="export-generation",
            cron="0 4 * * *",  # Daily at 4 AM
            tags=["export", "cache", "automated"]
        ),
        limit=10,  # Maximum concurrent flow runs
        pause_on_shutdown=False
    )


if __name__ == "__main__":
    asyncio.run(main())
```

**`services/collector/src/flows/lexml_collection.py`**:
```python
"""
LexML Collection Flows
Automated collection workflows using Prefect
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner
from services.lexml_client import LexMLCollectionClient
from services.database_service import CollectionDatabaseService
from utils.retry_handler import with_retry
from utils.validation import validate_document

logger = logging.getLogger(__name__)


@task(retries=3, retry_delay_seconds=[1, 2, 4])
async def collect_search_term_data(search_term: Dict[str, Any], 
                                 max_records: int = 500) -> Dict[str, Any]:
    """Collect data for a single search term"""
    logger = get_run_logger()
    client = LexMLCollectionClient()
    
    start_time = datetime.now()
    
    try:
        logger.info(f"Collecting data for term: {search_term['term']}")
        
        # Determine collection parameters
        collection_params = {
            'query': search_term.get('cql_query', search_term['term']),
            'max_records': max_records,
            'start_record': 1
        }
        
        # If weekly/daily collection, limit to recent documents
        if search_term['collection_frequency'] in ['daily', 'weekly']:
            days_back = 1 if search_term['collection_frequency'] == 'daily' else 7
            since_date = datetime.now() - timedelta(days=days_back)
            collection_params['date_from'] = since_date.strftime('%Y-%m-%d')
        
        # Execute collection
        documents = await client.collect_documents(**collection_params)
        
        # Validate documents
        validated_docs = []
        for doc in documents:
            if validate_document(doc):
                validated_docs.append(doc)
        
        execution_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return {
            'search_term_id': search_term['id'],
            'documents': validated_docs,
            'total_collected': len(documents),
            'total_validated': len(validated_docs),
            'execution_time_ms': int(execution_time),
            'collection_params': collection_params
        }
        
    except Exception as e:
        logger.error(f"Collection failed for {search_term['term']}: {e}")
        execution_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return {
            'search_term_id': search_term['id'],
            'documents': [],
            'total_collected': 0,
            'total_validated': 0,
            'execution_time_ms': int(execution_time),
            'error': str(e),
            'error_type': type(e).__name__
        }


@task
async def store_collection_results(collection_result: Dict[str, Any]) -> Dict[str, Any]:
    """Store collection results in database"""
    logger = get_run_logger()
    db_service = CollectionDatabaseService()
    
    start_time = datetime.now()
    
    try:
        # Store documents
        storage_stats = await db_service.store_collected_documents(
            documents=collection_result['documents'],
            search_term_id=collection_result['search_term_id'],
            source_api='lexml'
        )
        
        # Log collection execution
        log_data = {
            'search_term_id': collection_result['search_term_id'],
            'collection_type': 'scheduled',
            'status': 'completed' if not collection_result.get('error') else 'failed',
            'records_collected': collection_result['total_collected'],
            'records_new': storage_stats['new'],
            'records_updated': storage_stats['updated'],
            'records_skipped': storage_stats['skipped'],
            'execution_time_ms': collection_result['execution_time_ms'],
            'error_message': collection_result.get('error'),
            'error_type': collection_result.get('error_type'),
            'started_at': start_time,
            'completed_at': datetime.now()
        }
        
        log_id = await db_service.log_collection_execution(log_data)
        
        # Update next collection time
        await db_service.update_next_collection_time(
            collection_result['search_term_id']
        )
        
        logger.info(f"Stored {storage_stats['new']} new, {storage_stats['updated']} updated documents")
        
        return {
            'success': True,
            'storage_stats': storage_stats,
            'log_id': log_id
        }
        
    except Exception as e:
        logger.error(f"Failed to store collection results: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@flow(task_runner=ConcurrentTaskRunner(max_workers=3))
async def daily_collection_flow() -> Dict[str, Any]:
    """Daily automated collection flow"""
    logger = get_run_logger()
    db_service = CollectionDatabaseService()
    
    logger.info("🌅 Starting daily collection flow")
    
    # Get search terms due for collection
    search_terms = await db_service.get_terms_due_for_collection()
    
    if not search_terms:
        logger.info("No search terms due for collection")
        return {'status': 'completed', 'terms_processed': 0}
    
    logger.info(f"Processing {len(search_terms)} search terms")
    
    # Collect data for all terms concurrently
    collection_tasks = []
    for term in search_terms:
        task = collect_search_term_data(term)
        collection_tasks.append(task)
    
    # Wait for all collections to complete
    collection_results = await asyncio.gather(*collection_tasks, return_exceptions=True)
    
    # Store results
    storage_tasks = []
    for result in collection_results:
        if isinstance(result, Exception):
            logger.error(f"Collection task failed: {result}")
            continue
        
        task = store_collection_results(result)
        storage_tasks.append(task)
    
    # Wait for all storage operations
    storage_results = await asyncio.gather(*storage_tasks, return_exceptions=True)
    
    # Calculate summary
    total_new = sum(r.get('storage_stats', {}).get('new', 0) 
                   for r in storage_results 
                   if isinstance(r, dict) and r.get('success'))
    
    total_updated = sum(r.get('storage_stats', {}).get('updated', 0) 
                       for r in storage_results 
                       if isinstance(r, dict) and r.get('success'))
    
    logger.info(f"✅ Daily collection completed: {total_new} new, {total_updated} updated documents")
    
    return {
        'status': 'completed',
        'terms_processed': len(search_terms),
        'total_new_documents': total_new,
        'total_updated_documents': total_updated,
        'collection_results': collection_results,
        'storage_results': storage_results
    }


@flow
async def manual_collection_flow(search_term_ids: List[int], 
                               max_records: int = 1000) -> Dict[str, Any]:
    """Manual collection flow for specific search terms"""
    logger = get_run_logger()
    db_service = CollectionDatabaseService()
    
    logger.info(f"🔧 Starting manual collection for terms: {search_term_ids}")
    
    # Get search terms
    search_terms = await db_service.get_search_terms(search_term_ids)
    
    if not search_terms:
        logger.warning("No valid search terms found")
        return {'status': 'no_terms', 'terms_processed': 0}
    
    # Collect data for specified terms
    collection_tasks = []
    for term in search_terms:
        task = collect_search_term_data(term, max_records)
        collection_tasks.append(task)
    
    collection_results = await asyncio.gather(*collection_tasks)
    
    # Store results
    storage_tasks = []
    for result in collection_results:
        task = store_collection_results(result)
        storage_tasks.append(task)
    
    storage_results = await asyncio.gather(*storage_tasks)
    
    # Calculate summary
    total_new = sum(r.get('storage_stats', {}).get('new', 0) 
                   for r in storage_results if r.get('success'))
    
    total_updated = sum(r.get('storage_stats', {}).get('updated', 0) 
                       for r in storage_results if r.get('success'))
    
    logger.info(f"✅ Manual collection completed: {total_new} new, {total_updated} updated documents")
    
    return {
        'status': 'completed',
        'terms_processed': len(search_terms),
        'total_new_documents': total_new,
        'total_updated_documents': total_updated
    }
```

### Technical Tasks

#### Day 1-3: Prefect Service Setup
- [ ] Create collector service Docker configuration
- [ ] Implement basic Prefect flows for LexML collection
- [ ] Set up workflow orchestration and scheduling
- [ ] Add error handling and retry mechanisms

#### Day 4-5: LexML Client Integration
- [ ] Integrate with existing `core/api/lexml_service.py`
- [ ] Implement collection client with proper retry logic
- [ ] Add data validation and quality checks
- [ ] Test collection workflows with real LexML data

#### Day 6-7: Admin Interface
- [ ] Create FastAPI endpoints for search term management
- [ ] Add admin interface for collection monitoring
- [ ] Implement manual collection triggers
- [ ] Add collection status dashboard

---

## WEEK 4: Service Integration & Testing

### Objectives
- Integrate collector service with existing FastAPI backend
- Test end-to-end data flow (collection → storage → analytics)
- Optimize performance and prepare for cloud deployment
- Document development and deployment procedures

### Deliverables

#### 1. Service Integration (`main_app/gateway_router.py` updates)
```python
"""
Enhanced Gateway Router with Two-Tier Integration
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Dict, Any, Optional
import asyncio
import logging
from core.database.two_tier_manager import get_two_tier_manager
from services.lexml_client import LexMLCollectionClient
from prefect.deployments import run_deployment

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Two-Tier API"])


@router.get("/admin/search-terms")
async def get_search_terms(
    active_only: bool = True,
    db_manager=Depends(get_two_tier_manager)
) -> List[Dict[str, Any]]:
    """Get all search terms for collection management"""
    try:
        if active_only:
            terms = await db_manager.get_active_search_terms()
        else:
            # Implement get_all_search_terms method
            terms = await db_manager.get_all_search_terms()
        return terms
    except Exception as e:
        logger.error(f"Failed to get search terms: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/admin/search-terms")
async def create_search_term(
    term_data: Dict[str, Any],
    db_manager=Depends(get_two_tier_manager)
) -> Dict[str, Any]:
    """Create new search term for automated collection"""
    try:
        # Validate required fields
        required_fields = ['term', 'category', 'collection_frequency']
        for field in required_fields:
            if field not in term_data:
                raise HTTPException(400, f"Missing required field: {field}")
        
        # Create search term
        term_id = await db_manager.create_search_term(term_data)
        
        return {
            'success': True,
            'search_term_id': term_id,
            'message': f"Created search term: {term_data['term']}"
        }
        
    except Exception as e:
        logger.error(f"Failed to create search term: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/admin/collection/trigger")
async def trigger_manual_collection(
    search_term_ids: List[int],
    max_records: int = 1000,
    background_tasks: BackgroundTasks = BackgroundTasks()
) -> Dict[str, Any]:
    """Trigger manual collection for specific search terms"""
    try:
        # Trigger Prefect flow
        flow_run = await run_deployment(
            name="manual-collection/manual-collection",
            parameters={
                'search_term_ids': search_term_ids,
                'max_records': max_records
            }
        )
        
        return {
            'success': True,
            'flow_run_id': str(flow_run.id),
            'message': f"Triggered collection for {len(search_term_ids)} search terms"
        }
        
    except Exception as e:
        logger.error(f"Failed to trigger manual collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/dashboard")
async def get_dashboard_analytics(
    db_manager=Depends(get_two_tier_manager)
) -> Dict[str, Any]:
    """Get comprehensive dashboard analytics"""
    try:
        summary = await db_manager.get_dashboard_summary()
        return {
            'success': True,
            'data': summary,
            'last_updated': summary.get('last_collection')
        }
    except Exception as e:
        logger.error(f"Failed to get dashboard analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collection/status")
async def get_collection_status(
    limit: int = 50,
    db_manager=Depends(get_two_tier_manager)
) -> Dict[str, Any]:
    """Get recent collection execution status"""
    try:
        # This would be implemented in the database manager
        logs = await db_manager.get_recent_collection_logs(limit)
        return {
            'success': True,
            'collection_logs': logs
        }
    except Exception as e:
        logger.error(f"Failed to get collection status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
```

#### 2. Integration Testing (`tests/integration/two_tier_tests.py`)
```python
"""
Two-Tier Architecture Integration Tests
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from core.database.two_tier_manager import get_two_tier_manager
from services.collector.src.flows.lexml_collection import daily_collection_flow
from services.collector.src.services.lexml_client import LexMLCollectionClient


class TestTwoTierIntegration:
    """Integration tests for two-tier architecture"""
    
    @pytest.fixture
    async def db_manager(self):
        """Get database manager for testing"""
        return await get_two_tier_manager()
    
    async def test_search_term_lifecycle(self, db_manager):
        """Test complete search term lifecycle"""
        # Create test search term
        term_data = {
            'term': 'test transporte',
            'category': 'Test',
            'cql_query': 'title any "transporte"',
            'description': 'Test search term',
            'collection_frequency': 'daily',
            'priority': 5,
            'created_by': 'test_user'
        }
        
        term_id = await db_manager.create_search_term(term_data)
        assert term_id > 0
        
        # Verify term was created
        active_terms = await db_manager.get_active_search_terms()
        test_term = next((t for t in active_terms if t['id'] == term_id), None)
        assert test_term is not None
        assert test_term['term'] == term_data['term']
        
        # Clean up
        await db_manager.deactivate_search_term(term_id)
    
    async def test_document_collection_and_storage(self, db_manager):
        """Test document collection and storage"""
        # Create test search term
        term_data = {
            'term': 'mobilidade urbana',
            'category': 'Transport',
            'collection_frequency': 'manual',
            'priority': 1,
            'created_by': 'test_user'
        }
        
        term_id = await db_manager.create_search_term(term_data)
        
        # Test LexML client
        client = LexMLCollectionClient()
        documents = await client.collect_documents(
            query='title any "mobilidade"',
            max_records=5
        )
        
        assert len(documents) > 0
        assert all('urn' in doc for doc in documents)
        assert all('title' in doc for doc in documents)
        
        # Test document storage
        storage_stats = await db_manager.store_collected_documents(
            documents=documents,
            search_term_id=term_id,
            source_api='lexml'
        )
        
        assert storage_stats['new'] > 0 or storage_stats['updated'] > 0
        
        # Clean up
        await db_manager.deactivate_search_term(term_id)
    
    async def test_collection_flow_execution(self):
        """Test Prefect collection flow execution"""
        # This would require Prefect server to be running
        # For now, test the flow logic directly
        
        # Create mock search terms
        mock_terms = [
            {
                'id': 1,
                'term': 'test term',
                'collection_frequency': 'daily',
                'cql_query': 'title any "test"'
            }
        ]
        
        # Mock the flow execution (in real test, would use Prefect test utilities)
        # This is a simplified version for demonstration
        collection_result = {
            'search_term_id': 1,
            'documents': [],
            'total_collected': 0,
            'total_validated': 0,
            'execution_time_ms': 100
        }
        
        assert collection_result['search_term_id'] == 1
        assert isinstance(collection_result['execution_time_ms'], int)
    
    async def test_dashboard_analytics(self, db_manager):
        """Test dashboard analytics generation"""
        summary = await db_manager.get_dashboard_summary()
        
        # Verify summary structure
        expected_keys = [
            'total_documents', 'documents_last_30_days',
            'new_documents_week', 'document_types',
            'collection_performance', 'search_patterns'
        ]
        
        for key in expected_keys:
            assert key in summary or summary == {}  # Empty if no data
    
    async def test_performance_benchmarks(self, db_manager):
        """Test system performance benchmarks"""
        start_time = datetime.now()
        
        # Test database query performance
        active_terms = await db_manager.get_active_search_terms()
        query_time = (datetime.now() - start_time).total_seconds()
        
        # Should be under 100ms for reasonable dataset
        assert query_time < 0.1
        
        # Test collection client performance
        client = LexMLCollectionClient()
        start_time = datetime.now()
        
        documents = await client.collect_documents(
            query='title any "lei"',
            max_records=10
        )
        
        collection_time = (datetime.now() - start_time).total_seconds()
        
        # Should be under 5 seconds for 10 documents
        assert collection_time < 5.0
        assert len(documents) <= 10


if __name__ == "__main__":
    asyncio.run(pytest.main([__file__]))
```

#### 3. Development Documentation (`docs/development-guide.md`)
```markdown
# Monitor Legislativo v4 - Development Guide

## Two-Tier Architecture Overview

The system is now split into two main tiers:

### TIER 1: Data Collection Service
- **Purpose**: Automated collection of Brazilian legislative data
- **Technology**: Python + Prefect + PostgreSQL
- **Location**: `services/collector/`
- **Responsibilities**:
  - Scheduled LexML API collection
  - Data validation and deduplication
  - Error handling and retry logic
  - Collection monitoring and logging

### TIER 2: Analytics Dashboard Platform
- **Purpose**: Real-time analytics and research interface
- **Technology**: React + FastAPI + R Shiny
- **Location**: `main_app/`, `src/`, `r-shiny-app/`
- **Responsibilities**:
  - User interface and interactions
  - Real-time search and analytics
  - Report generation and exports
  - Authentication and authorization

## Development Environment Setup

### Prerequisites
- Docker and Docker Compose
- Git
- Node.js 18+ (for frontend development)
- Python 3.11+ (for backend development)

### Quick Start
```bash
# Clone repository
git clone <repository-url>
cd monitor_legislativo_v4

# Setup development environment
chmod +x scripts/dev-setup.sh
./scripts/dev-setup.sh

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Service URLs
- Frontend: http://localhost:3000
- API: http://localhost:8000
- R Shiny: http://localhost:3838
- Prefect: http://localhost:4200
- PgAdmin: http://localhost:5050 (with --profile dev-tools)

## Development Workflow

### 1. Frontend Development
```bash
# Start frontend in development mode
cd src/
npm install
npm run dev

# The frontend will proxy API calls to localhost:8000
```

### 2. Backend Development
```bash
# Start API service with hot reload
docker-compose up -d postgres redis
cd main_app/
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Collector Development
```bash
# Start collector service
docker-compose up -d postgres redis prefect
cd services/collector/
pip install -r requirements.txt
python -m src.main
```

### 4. Database Operations
```bash
# Run database migrations
docker-compose exec postgres psql -U postgres -d legislativo -f /docker-entrypoint-initdb.d/001_two_tier_schema.sql

# Access PostgreSQL
docker-compose exec postgres psql -U postgres -d legislativo

# View PgAdmin
docker-compose --profile dev-tools up -d pgadmin
# Visit http://localhost:5050 (admin@legislativo.dev / admin)
```

## Testing

### Unit Tests
```bash
# Backend tests
cd main_app/
python -m pytest tests/ -v

# Frontend tests
cd src/
npm test
```

### Integration Tests
```bash
# Two-tier integration tests
python -m pytest tests/integration/two_tier_tests.py -v

# End-to-end tests
docker-compose up -d
python -m pytest tests/integration/ -v
```

### Performance Tests
```bash
# Database performance
python tests/performance/db_performance_test.py

# API performance
python tests/performance/api_load_test.py
```

## Data Management

### Search Terms
```bash
# Add new search term via API
curl -X POST http://localhost:8000/api/v1/admin/search-terms \
  -H "Content-Type: application/json" \
  -d '{
    "term": "transporte sustentável",
    "category": "Environment",
    "collection_frequency": "weekly",
    "priority": 2
  }'

# Trigger manual collection
curl -X POST http://localhost:8000/api/v1/admin/collection/trigger \
  -H "Content-Type: application/json" \
  -d '{"search_term_ids": [1, 2], "max_records": 100}'
```

### Database Maintenance
```bash
# Refresh analytics views
docker-compose exec postgres psql -U postgres -d legislativo -c "SELECT refresh_analytics_views();"

# Clean up expired cache
docker-compose exec api python -c "
import asyncio
from core.database.two_tier_manager import get_two_tier_manager
asyncio.run(get_two_tier_manager().cleanup_expired_cache())
"
```

## Deployment Preparation

### Environment Configuration
```bash
# Copy environment template
cp .env.example .env.production

# Update production settings
vi .env.production
```

### Build for Production
```bash
# Build all services
docker-compose -f docker-compose.prod.yml build

# Test production build
docker-compose -f docker-compose.prod.yml up -d
```

### Monitoring
```bash
# View system health
curl http://localhost:8000/health

# View collection status
curl http://localhost:8000/api/v1/collection/status

# View analytics dashboard
curl http://localhost:8000/api/v1/analytics/dashboard
```

## Common Issues and Solutions

### Database Connection Issues
- Ensure PostgreSQL is running: `docker-compose ps postgres`
- Check connection string in `.env` file
- Verify database initialization: `docker-compose logs postgres`

### Prefect Issues
- Check Prefect server: `docker-compose logs prefect`
- Verify flows are deployed: Visit http://localhost:4200
- Check collector service logs: `docker-compose logs collector`

### Performance Issues
- Monitor database queries with PgAdmin
- Check Redis cache hit rates
- Use `docker stats` to monitor resource usage

## Contributing

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes and test thoroughly
3. Update documentation as needed
4. Submit pull request with clear description
5. Ensure all tests pass and performance benchmarks are met
```

### Technical Tasks

#### Day 1-2: Service Integration
- [ ] Update FastAPI backend to work with collector service
- [ ] Add API endpoints for collection management
- [ ] Integrate two-tier database manager with existing services
- [ ] Test service communication and data flow

#### Day 3-4: End-to-End Testing
- [ ] Create comprehensive integration tests
- [ ] Test data collection and storage workflows
- [ ] Verify dashboard analytics generation
- [ ] Performance testing and optimization

#### Day 5-7: Documentation and Deployment Prep
- [ ] Create development and deployment documentation
- [ ] Set up monitoring and health checks
- [ ] Prepare production configuration files
- [ ] Test deployment on Render.com staging environment

## Success Criteria for Phase 1

### Technical Milestones
- [ ] Docker development environment running all services
- [ ] Extended PostgreSQL schema with two-tier architecture
- [ ] Prefect-based collection service operational
- [ ] Integration between collection and analytics tiers
- [ ] Comprehensive test suite covering all components
- [ ] Documentation for development and deployment

### Performance Benchmarks
- [ ] Database query response time < 100ms
- [ ] LexML collection time < 5 seconds for 10 documents
- [ ] Full service startup time < 2 minutes
- [ ] Memory usage < 1GB for all services combined
- [ ] CPU usage < 50% during normal operations

### Functional Requirements
- [ ] Automated search term management
- [ ] Manual and scheduled collection workflows
- [ ] Document deduplication and versioning
- [ ] Collection monitoring and error handling
- [ ] Dashboard analytics with real-time data
- [ ] Export functionality preserved and enhanced

## Phase 1 Conclusion

Phase 1 establishes the foundational infrastructure for the two-tier architecture while preserving all existing functionality. The system now has automated data collection capabilities, enhanced database schema, and improved monitoring - setting the stage for production deployment in Phase 2.

The next phase will focus on deploying the collection service to production, optimizing performance, and adding advanced collection features like intelligent scheduling and quality validation.