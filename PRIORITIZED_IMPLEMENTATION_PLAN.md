# Monitor Legislativo v4 - Prioritized Implementation Plan

## Priority 1: Immediate Improvements (1-2 weeks)

### 1.1 Enhanced Monitoring and Health Check Dashboard

**What needs to be implemented:**
- Real-time status monitoring for all 14 data sources
- Historical uptime tracking
- Alert system for failures
- Response time metrics

**Where in the codebase:**
- Create `/core/monitoring/health_dashboard.py`
- Extend `/core/utils/monitoring.py`
- Add API endpoints in `/web/api/monitoring_routes.py`

**Implementation steps:**
```python
# 1. Create health check service
/core/monitoring/health_check_service.py
- Implement periodic health checks for each source
- Store results in Redis with timestamps
- Calculate uptime percentages

# 2. Extend monitoring utilities
/core/utils/monitoring.py
- Add HealthMetrics class
- Implement alert thresholds
- Create notification system

# 3. Build dashboard API
/web/api/monitoring_routes.py
- GET /api/health/status - Current status grid
- GET /api/health/history - Historical data
- GET /api/health/metrics - Performance metrics
- WebSocket endpoint for real-time updates
```

**Expected benefits:**
- Immediate visibility into system health
- Proactive issue detection
- Reduced downtime
- Better incident response

### 1.2 Scraper Resilience Improvements

**What needs to be implemented:**
- Multiple fallback strategies for each scraper
- Automatic URL discovery
- Cached results with warnings
- Manual intervention queue

**Where in the codebase:**
- Update `/core/api/regulatory_base.py`
- Create `/core/utils/fallback_manager.py`
- Enhance existing scrapers in `/core/api/regulatory_agencies.py`

**Implementation steps:**
```python
# 1. Create fallback manager
/core/utils/fallback_manager.py
class FallbackManager:
    def __init__(self):
        self.strategies = {
            'primary': 'gov.br portal',
            'secondary': 'agency domain',
            'tertiary': 'cached results',
            'quaternary': 'manual queue'
        }
    
    async def execute_with_fallback(self, source, query):
        for strategy in self.strategies:
            try:
                return await self.attempt_strategy(source, query, strategy)
            except Exception as e:
                logger.warning(f"Strategy {strategy} failed: {e}")
        return self.queue_for_manual(source, query)

# 2. Update regulatory base
/core/api/regulatory_base.py
- Integrate FallbackManager
- Add alternative URL discovery
- Implement smart retry logic
```

**Expected benefits:**
- 90%+ uptime for scrapers
- Graceful degradation
- Automatic recovery
- Clear failure tracking

### 1.3 Search Optimization

**What needs to be implemented:**
- Unified search interface
- Pre-indexed common queries
- Smart cache invalidation

**Where in the codebase:**
- Create `/core/search/search_engine.py`
- Update `/core/utils/smart_cache.py`
- Modify `/core/api/api_service.py`

**Implementation steps:**
```python
# 1. Create search engine
/core/search/search_engine.py
- Implement in-memory search index
- Add fuzzy matching
- Support Portuguese stemming

# 2. Enhance caching
/core/utils/smart_cache.py
- Implement query result caching
- Add cache warming for common queries
- Smart TTL based on source update frequency

# 3. Update API service
/core/api/api_service.py
- Route searches through new engine
- Add search result ranking
- Implement result deduplication
```

**Expected benefits:**
- 10x faster search performance
- Better search relevance
- Reduced API load
- Improved user experience

## Priority 2: Medium-term Enhancements (1-2 months)

### 2.1 Performance Optimizations

**What needs to be implemented:**
- Adaptive caching strategy
- Parallel processing optimization
- Resource usage monitoring

**Where in the codebase:**
- Update `/core/utils/performance_optimizer.py`
- Enhance `/core/utils/cache_manager.py`
- Modify `/core/api/api_service.py`

**Implementation steps:**
```python
# 1. Implement adaptive caching
cache_config = {
    "legislative_apis": {
        "ttl": 3600,  # 1 hour
        "strategy": "time-based"
    },
    "regulatory_scrapers": {
        "ttl": 86400,  # 24 hours
        "strategy": "adaptive",
        "min_ttl": 3600,
        "max_ttl": 604800  # 1 week
    }
}

# 2. Optimize parallel processing
async def search_all_optimized(query, sources):
    # Group by data type
    api_sources = [s for s in sources if s in LEGISLATIVE_APIS]
    scraper_sources = [s for s in sources if s in REGULATORY_SCRAPERS]
    
    # Process in optimal order
    tasks = []
    
    # Fast APIs first
    for source in api_sources:
        tasks.append(search_api(source, query))
    
    # Then scrapers with circuit breaker check
    for source in scraper_sources:
        if circuit_breaker[source].is_closed():
            tasks.append(search_scraper(source, query))
    
    return await asyncio.gather(*tasks, return_exceptions=True)
```

**Expected benefits:**
- 50% reduction in response times
- Better resource utilization
- Improved scalability
- Lower infrastructure costs

### 2.2 Error Recovery Strategies

**What needs to be implemented:**
- Smart retry mechanisms
- Automatic URL updates
- Error pattern recognition

**Where in the codebase:**
- Create `/core/utils/smart_retry.py`
- Update `/core/api/base_service.py`
- Enhance error handling across all services

**Implementation steps:**
```python
# 1. Create smart retry system
/core/utils/smart_retry.py
class SmartRetry:
    def __init__(self):
        self.strategies = {
            404: self.handle_not_found,
            503: self.handle_service_unavailable,
            "timeout": self.handle_timeout,
            "ssl": self.handle_ssl_error
        }
    
    async def handle_not_found(self, source):
        # Try alternative URLs
        for alt_url in FALLBACK_URLS[source]:
            result = await attempt_scrape(alt_url)
            if result:
                # Update primary URL for future
                update_primary_url(source, alt_url)
                return result
        return None

# 2. Implement error pattern learning
- Track error frequencies
- Identify patterns
- Adjust strategies automatically
```

**Expected benefits:**
- Self-healing capabilities
- Reduced manual intervention
- Better error insights
- Improved reliability

### 2.3 Security Improvements

**What needs to be implemented:**
- Certificate pinning for government sites
- Adaptive rate limiting
- Data privacy compliance

**Where in the codebase:**
- Create `/core/security/certificate_manager.py`
- Update `/core/utils/session_factory.py`
- Add `/core/security/rate_limiter.py`

**Implementation steps:**
```python
# 1. Implement certificate pinning
/core/security/certificate_manager.py
- Store government certificates
- Validate on each request
- Fallback to standard validation

# 2. Add adaptive rate limiting
/core/security/rate_limiter.py
- Monitor response times
- Adjust request rates dynamically
- Respect robots.txt

# 3. Ensure LGPD compliance
- Add data retention policies
- Implement user consent
- Create audit logs
```

**Expected benefits:**
- Enhanced security posture
- Legal compliance
- Better relationship with sources
- Reduced blocking risk

## Priority 3: Long-term Strategy (3-6 months)

### 3.1 API Gateway Implementation

**What needs to be implemented:**
- Unified REST API for all sources
- GraphQL interface
- WebSocket support for real-time updates

**Where in the codebase:**
- Create `/gateway/` directory structure
- New API layer above existing services
- Authentication and rate limiting

**Implementation steps:**
```yaml
Gateway Architecture:
  1. API Layer:
     - REST endpoints
     - GraphQL schema
     - WebSocket handlers
  2. Middleware:
     - Authentication
     - Rate limiting
     - Request validation
  3. Backend Integration:
     - Service orchestration
     - Response transformation
     - Error handling
```

**Expected benefits:**
- Unified interface
- Better developer experience
- Monetization opportunities
- Enhanced control

### 3.2 Machine Learning Integration

**What needs to be implemented:**
- HTML structure change detection
- Optimal scraping time prediction
- Automatic proposition classification

**Where in the codebase:**
- Create `/ml/` directory
- Integration points in scrapers
- New ML-powered endpoints

**Implementation steps:**
- Train models on historical scraping data
- Implement structure change detection
- Create classification pipeline
- Add prediction APIs

**Expected benefits:**
- Proactive adaptation to changes
- Better scraping efficiency
- Enhanced data quality
- Reduced maintenance

### 3.3 Advanced Data Pipeline

**What needs to be implemented:**
- Complete data pipeline architecture
- Document storage solution
- Real-time processing capabilities

**Where in the codebase:**
- New `/pipeline/` infrastructure
- Integration with existing services
- New storage backends

**Implementation steps:**
```yaml
Pipeline Components:
  1. Collection Layer:
     - Enhanced API clients
     - Intelligent scrapers
  2. Processing Layer:
     - Data normalization
     - Deduplication
     - Enrichment
  3. Storage Layer:
     - PostgreSQL for metadata
     - S3 for documents
     - Redis for caching
  4. Delivery Layer:
     - GraphQL API
     - REST compatibility
     - WebSocket streams
```

**Expected benefits:**
- Scalable architecture
- Better data quality
- Real-time capabilities
- Future-proof design

## Implementation Timeline

### Week 1-2:
- [ ] Health check dashboard
- [ ] Basic monitoring improvements
- [ ] Initial fallback strategies

### Week 3-4:
- [ ] Complete scraper resilience
- [ ] Search optimization
- [ ] Performance monitoring

### Month 2:
- [ ] Adaptive caching
- [ ] Parallel processing optimization
- [ ] Smart retry mechanisms

### Month 3:
- [ ] Security improvements
- [ ] Error recovery completion
- [ ] API gateway planning

### Month 4-6:
- [ ] API gateway implementation
- [ ] ML integration
- [ ] Advanced pipeline development

## Success Metrics

1. **Immediate (2 weeks):**
   - 95%+ uptime for legislative APIs
   - 80%+ uptime for scrapers
   - <5s average response time

2. **Medium-term (2 months):**
   - 90%+ uptime for all sources
   - <3s average response time
   - 50% reduction in manual interventions

3. **Long-term (6 months):**
   - 99%+ uptime overall
   - <1s average response time
   - Full API gateway operational
   - ML-powered adaptations

## Resource Requirements

### Technical:
- Redis instance for caching
- Monitoring infrastructure
- ML training resources

### Human:
- 1-2 developers full-time
- DevOps support
- ML engineer (month 3+)

### Budget Considerations:
- Infrastructure costs
- Third-party services
- Training and documentation