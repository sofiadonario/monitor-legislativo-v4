# Monitor Legislativo v4 - Two-Tier Architecture Implementation Roadmap

## Executive Summary

This PRD outlines the 20-week migration from the current single-tier Monitor Legislativo v4 system to a sophisticated two-tier architecture optimized for academic research and ultra-budget deployment. The migration preserves all existing functionality while adding automated data collection, advanced analytics, and improved scalability.

## Current State Analysis

### Existing Architecture
- **Frontend**: React 18.3.1 + TypeScript + Vite (deployed to GitHub Pages)
- **Backend**: FastAPI 0.104.1 + Python 3.11 (deployed to Railway $7/month)
- **Database**: Supabase PostgreSQL (free tier)
- **Analytics**: R Shiny application with authentication
- **Data Sources**: LexML Brasil API + Brazilian government APIs + CSV fallback

### Current Strengths
✅ Working React/FastAPI integration with real data  
✅ Supabase database with AsyncPG driver  
✅ Three-tier search fallback (APIs → CSV)  
✅ R Shiny analytics with Shibboleth authentication  
✅ Export functionality (CSV, Excel, JSON)  
✅ Performance monitoring and caching  
✅ Academic research focus with proper citations  

### Current Limitations
❌ Manual data collection requiring user searches  
❌ Single-tier architecture limits independent scaling  
❌ Limited automated data aggregation  
❌ No scheduled collection workflows  
❌ Basic caching without intelligent invalidation  
❌ R Shiny runs separately from main application  

## Target Two-Tier Architecture

### TIER 1: Automated Data Collection Service
**Purpose**: Continuous, scheduled collection of Brazilian legislative data  
**Technology**: Python + Prefect + PostgreSQL + Docker  
**Deployment**: Render.com Background Worker ($7/month)

**Key Features**:
- Scheduled LexML API collection (daily/weekly/monthly)
- Admin interface for search term management
- Intelligent retry mechanisms for government APIs
- Data deduplication and versioning
- Export cache generation
- Collection monitoring and alerting

### TIER 2: Analytics Dashboard Platform
**Purpose**: Real-time analytics and research interface  
**Technology**: React + FastAPI + R Shiny + nginx reverse proxy  
**Deployment**: Render.com Web Service ($7/month) + GitHub Pages (free)

**Key Features**:
- Real-time dashboard with live data
- Embedded R Shiny visualizations via iframe
- Advanced search with cached results
- Academic report generation
- Multi-user authentication (Shibboleth/ORCID)
- DOI generation for research datasets

## Implementation Timeline (20 Weeks)

---

## PHASE 1: Core Infrastructure (Weeks 1-4)
**Budget**: $0 (development environment)  
**Goal**: Establish two-tier foundation with Docker development environment

### Week 1: Docker Environment Setup
**Deliverables**:
- [ ] `docker-compose.yml` for local development
- [ ] `services/collector/` directory structure
- [ ] `services/analytics/` directory structure  
- [ ] Updated development documentation

**Technical Tasks**:
- Create multi-service Docker configuration
- Set up service networking and volumes
- Configure environment variable management
- Test local development workflow

### Week 2: Database Schema Migration
**Deliverables**:
- [ ] Extended PostgreSQL schema for two-tier architecture
- [ ] Migration scripts from current Supabase schema
- [ ] Database connection management for both tiers
- [ ] Performance optimization with indexes and views

**Technical Tasks**:
- Extend `core/database/supabase_config.py` with new schema
- Add search_terms, collection_logs, document_versions tables
- Create materialized views for dashboard performance
- Set up pg_search extension for full-text search

### Week 3: Prefect Collection Service
**Deliverables**:
- [ ] Prefect-based LexML collection workflows
- [ ] Integration with existing `core/api/lexml_service.py`
- [ ] Collection monitoring and error handling
- [ ] Admin interface for search term management

**Technical Tasks**:
- Create `services/collector/prefect_flows.py`
- Implement retry mechanisms for government APIs
- Add collection status tracking and logging
- Build FastAPI admin endpoints for term management

### Week 4: Service Integration & Testing
**Deliverables**:
- [ ] Integrated two-tier system running locally
- [ ] Data flow testing (collection → storage → analytics)
- [ ] Performance benchmarks and optimization
- [ ] Documentation and deployment guide

**Technical Tasks**:
- Update `main_app/main.py` for service orchestration
- Test end-to-end data flow
- Optimize database queries and caching
- Prepare for cloud deployment

---

## PHASE 2: Data Collection Service (Weeks 5-8)
**Budget**: $7/month (Render.com Background Worker)  
**Goal**: Production-ready automated data collection

### Week 5: Production Collection Infrastructure
**Deliverables**:
- [ ] Production Prefect deployment on Render.com
- [ ] Comprehensive error handling and alerting
- [ ] Government API integration with all 15 sources
- [ ] Data validation and quality checks

### Week 6: Search Term Management System
**Deliverables**:
- [ ] Admin web interface for search term configuration
- [ ] CQL query builder and validator
- [ ] Collection scheduling and priority management
- [ ] Performance monitoring dashboard

### Week 7: Data Processing & Storage
**Deliverables**:
- [ ] Incremental data updates with deduplication
- [ ] Document versioning and change tracking
- [ ] Automated CSV/JSON export generation
- [ ] Data archival and cleanup processes

### Week 8: Collection Monitoring & Optimization
**Deliverables**:
- [ ] Collection success/failure monitoring
- [ ] Performance optimization and bottleneck identification
- [ ] Automated alerting for collection issues
- [ ] Load testing and capacity planning

---

## PHASE 3: Analytics Dashboard (Weeks 9-12)
**Budget**: $14/month (Collection + Analytics services)  
**Goal**: Enhanced analytics platform with R Shiny integration

### Week 9: React Frontend Enhancement
**Deliverables**:
- [ ] Enhanced React components for two-tier data
- [ ] Real-time dashboard with WebSocket updates
- [ ] Advanced search interface with saved queries
- [ ] Mobile-responsive design improvements

### Week 10: R Shiny Integration
**Deliverables**:
- [ ] nginx reverse proxy configuration
- [ ] Embedded R Shiny visualizations via iframe
- [ ] Seamless authentication between React and Shiny
- [ ] Data sharing between frontend and analytics

### Week 11: Caching & Performance
**Deliverables**:
- [ ] Multi-layer caching strategy (Redis + PostgreSQL + Browser)
- [ ] Intelligent cache invalidation based on data updates
- [ ] Performance optimization for dashboard queries
- [ ] CDN integration for static assets

### Week 12: Advanced Analytics Features
**Deliverables**:
- [ ] Parameterized R Markdown report generation
- [ ] Interactive data exploration tools
- [ ] Export functionality for research datasets
- [ ] Performance analytics and user behavior tracking

---

## PHASE 4: Production Optimization (Weeks 13-16)
**Budget**: $14/month (optimized for production load)  
**Goal**: Production-ready system with monitoring and security

### Week 13: nginx Reverse Proxy & Load Balancing
**Deliverables**:
- [ ] Production nginx configuration
- [ ] SSL termination and security headers
- [ ] Load balancing between services
- [ ] Health checks and automatic failover

### Week 14: Database Optimization
**Deliverables**:
- [ ] Query optimization and index tuning
- [ ] Materialized view refresh strategies
- [ ] Connection pooling optimization
- [ ] Backup and disaster recovery procedures

### Week 15: Monitoring & Alerting
**Deliverables**:
- [ ] Comprehensive application monitoring (Prometheus + Grafana)
- [ ] Log aggregation and analysis
- [ ] Performance dashboards and SLA tracking
- [ ] Automated alerting for system issues

### Week 16: Security & Compliance
**Deliverables**:
- [ ] Security audit and penetration testing
- [ ] Data privacy compliance (LGPD)
- [ ] API rate limiting and abuse prevention
- [ ] Security documentation and procedures

---

## PHASE 5: Academic Features (Weeks 17-20)
**Budget**: $14/month (academic research features)  
**Goal**: Full academic research platform with collaboration tools

### Week 17: Research Data Management
**Deliverables**:
- [ ] DOI generation for research datasets
- [ ] Dataset versioning and lineage tracking
- [ ] Academic citation export (BibTeX, RIS, etc.)
- [ ] Research data repository integration

### Week 18: User Authentication & Authorization
**Deliverables**:
- [ ] Shibboleth SSO integration for universities
- [ ] ORCID integration for researcher identification
- [ ] Role-based access control (student, researcher, admin)
- [ ] Multi-tenant support for different institutions

### Week 19: Collaboration Features
**Deliverables**:
- [ ] Shared research projects and workspaces
- [ ] Collaborative annotation and note-taking
- [ ] Version control for saved searches and reports
- [ ] Research team management and permissions

### Week 20: Documentation & Launch
**Deliverables**:
- [ ] Comprehensive user documentation
- [ ] API documentation with examples
- [ ] Training materials and video tutorials
- [ ] Official launch and academic community outreach

---

## Technical Architecture Details

### Service Communication
```yaml
# Docker Compose Network Configuration
networks:
  legislativo:
    driver: bridge

services:
  # TIER 1: Data Collection
  collector:
    build: ./services/collector
    networks: [legislativo]
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - PREFECT_API_URL=http://prefect:4200/api
    
  prefect:
    image: prefecthq/prefect:2-python3.11
    networks: [legislativo]
    ports: ["4200:4200"]
    
  # TIER 2: Analytics Platform  
  frontend:
    build: ./services/frontend
    networks: [legislativo]
    ports: ["3000:3000"]
    
  api:
    build: ./main_app
    networks: [legislativo]
    ports: ["8000:8000"]
    
  analytics:
    build: ./r-shiny-app
    networks: [legislativo]
    ports: ["3838:3838"]
    
  nginx:
    image: nginx:alpine
    networks: [legislativo]
    ports: ["80:80", "443:443"]
    volumes: ["./nginx.conf:/etc/nginx/nginx.conf"]
```

### Database Schema Extensions
```sql
-- Extended schema for two-tier architecture
CREATE TABLE search_terms (
    id SERIAL PRIMARY KEY,
    term VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    cql_query TEXT,
    active BOOLEAN DEFAULT true,
    collection_frequency VARCHAR(20) DEFAULT 'monthly',
    priority INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE TABLE legislative_documents (
    id BIGSERIAL PRIMARY KEY,
    urn VARCHAR(255) UNIQUE NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    metadata JSONB,
    search_term_id INTEGER REFERENCES search_terms(id),
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE collection_logs (
    id BIGSERIAL PRIMARY KEY,
    search_term_id INTEGER REFERENCES search_terms(id),
    status VARCHAR(50),
    records_collected INTEGER,
    execution_time_ms INTEGER,
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Performance indexes
CREATE INDEX idx_documents_urn ON legislative_documents(urn);
CREATE INDEX idx_documents_type ON legislative_documents(document_type);
CREATE INDEX idx_documents_collected ON legislative_documents(collected_at);
CREATE INDEX gin_content_search ON legislative_documents USING GIN (to_tsvector('portuguese', content));
CREATE INDEX gin_metadata ON legislative_documents USING GIN (metadata);
```

### Prefect Workflow Example
```python
from prefect import flow, task
from prefect.task_runners import ConcurrentTaskRunner
import httpx
import asyncio

@task(retries=3, retry_delay_seconds=[1, 2, 4])
async def collect_lexml_data(search_term: str, max_records: int = 100):
    """Collect data from LexML Brasil API"""
    async with httpx.AsyncClient() as client:
        params = {
            'operation': 'searchRetrieve',
            'version': '1.1',
            'query': search_term,
            'maximumRecords': max_records
        }
        response = await client.get(
            'https://www.lexml.gov.br/busca/SRU',
            params=params,
            timeout=30.0
        )
        return parse_sru_response(response.content)

@task
def validate_and_store_data(data: list, search_term_id: int):
    """Validate and store collected data"""
    with get_db_connection() as conn:
        for record in data:
            conn.execute("""
                INSERT INTO legislative_documents (urn, title, content, metadata, search_term_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (urn) DO UPDATE SET
                    content = EXCLUDED.content,
                    metadata = EXCLUDED.metadata,
                    updated_at = CURRENT_TIMESTAMP
            """, (record['urn'], record['title'], record['content'], 
                  json.dumps(record['metadata']), search_term_id))

@flow(task_runner=ConcurrentTaskRunner())
def daily_collection_flow():
    """Daily collection workflow for all active search terms"""
    search_terms = get_active_search_terms()
    for term in search_terms:
        data = collect_lexml_data(term.query, 200)
        validate_and_store_data(data, term.id)
```

## Success Metrics

### Technical KPIs
- **Data Collection Success Rate**: >95%
- **Dashboard Load Time**: <2 seconds
- **API Response Time**: <500ms
- **Database Query Performance**: <100ms average
- **System Uptime**: >99.5%

### Academic KPIs  
- **Research Dataset Citations**: Track DOI usage
- **User Engagement**: Active researchers and institutions
- **Data Freshness**: <24 hours for critical legislation
- **Export Usage**: Academic paper references
- **Collaboration**: Multi-user project adoption

### Budget KPIs
- **Total Monthly Cost**: <$16/month
- **Cost per Active User**: <$2/month
- **Infrastructure Efficiency**: >90% resource utilization
- **Free Tier Optimization**: Maximize free service usage

## Risk Mitigation

### Technical Risks
- **Government API Changes**: Comprehensive error handling and fallback strategies
- **Database Performance**: Query optimization and proper indexing
- **Service Dependencies**: Health checks and automatic recovery
- **Data Quality**: Validation and human review processes

### Academic Risks
- **Data Accuracy**: Multiple source verification and academic peer review
- **Citation Compliance**: Automated citation generation and validation
- **Privacy Compliance**: LGPD compliance and data anonymization
- **Institutional Access**: Flexible authentication supporting multiple SSO providers

### Budget Risks
- **Cost Overruns**: Monitoring and automated scaling limits
- **Service Availability**: Multi-cloud strategy and vendor diversification
- **Performance Degradation**: Proactive monitoring and optimization
- **Free Tier Limitations**: Graceful degradation and user communication

## Deployment Strategy

### Development Environment
- Local Docker Compose for full-stack development
- PostgreSQL container with sample data
- Hot-reload for all services during development
- Integrated testing and debugging tools

### Staging Environment  
- Render.com staging services ($7/month)
- Production-like data and configuration
- Automated testing and performance benchmarks
- User acceptance testing with academic partners

### Production Environment
- Render.com production services ($14/month)
- High availability configuration
- Automated backups and disaster recovery
- 24/7 monitoring and alerting

## Conclusion

This implementation roadmap transforms Monitor Legislativo v4 from a single-tier application into a sophisticated two-tier academic research platform while maintaining ultra-budget constraints and preserving all existing functionality. The phased approach ensures continuous system availability and provides clear milestones for tracking progress.

The resulting system will provide automated data collection, advanced analytics, and comprehensive research tools that position Monitor Legislativo v4 as a leading platform for Brazilian legislative research within the academic community.