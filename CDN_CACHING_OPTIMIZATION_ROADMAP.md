# CDN & Caching Optimization Roadmap
## Monitor Legislativo v4 - Performance Enhancement Strategy

**Document Version:** 1.0  
**Date:** June 17, 2025  
**Objective:** Reduce operational costs by 70% through intelligent caching and CDN implementation

---

## 🎯 Executive Summary

This roadmap outlines a comprehensive strategy to implement CDN and caching optimizations that will:
- **Reduce API calls by 70-85%**
- **Improve response times by 60%**
- **Lower bandwidth costs by 80%**
- **Enhance user experience with sub-second load times**
- **Maintain data freshness within acceptable academic standards**

---

## 📊 Current Performance Baseline

### API Usage Patterns
- **14 Government APIs** accessed regularly
- **Average response time:** 3.3 seconds
- **API success rate:** 80%
- **Daily API calls:** ~50,000
- **Peak concurrent users:** 20

### Bottlenecks Identified
1. **Repeated API calls** for identical queries (60% duplication)
2. **No static asset optimization** (React bundle: 2.4MB)
3. **Database queries** without caching layer
4. **Geographic data** fetched repeatedly
5. **PDF/Export generation** computed on-demand

---

## 🏗️ Architecture Overview

### Three-Layer Caching Strategy

```
┌─────────────────┐
│   CloudFlare    │  Layer 1: Edge CDN
│   (Global CDN)  │  - Static assets
└────────┬────────┘  - API responses
         │
┌────────┴────────┐
│   Redis Cache   │  Layer 2: Application Cache
│  (In-Memory)    │  - Session data
└────────┬────────┘  - Computed results
         │
┌────────┴────────┐
│  Local Storage  │  Layer 3: Browser Cache
│   (Client)      │  - User preferences
└─────────────────┘  - Recent searches
```

---

## 🚀 Implementation Phases

### Phase 1: CDN Setup (Week 1)

#### 1.1 CloudFlare Free Tier Implementation
```yaml
Tasks:
  - Register domain with CloudFlare
  - Configure DNS settings
  - Enable basic caching rules
  - Set up SSL/TLS encryption
  
Benefits:
  - Global edge locations
  - DDoS protection
  - Automatic minification
  - Brotli compression
```

#### 1.2 Static Asset Optimization
```javascript
// Vite configuration for optimal bundling
export default {
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'leaflet-vendor': ['leaflet', 'react-leaflet'],
          'utils': ['papaparse', 'html2canvas']
        }
      }
    },
    // Enable compression
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    }
  }
}
```

#### 1.3 CloudFlare Page Rules
```
Cache Level: Cache Everything
- *.js, *.css, *.woff2 → 1 year
- /api/static/* → 1 week
- /api/geography/* → 1 month
- /assets/* → 1 year
```

### Phase 2: Redis Cache Layer (Week 2)

#### 2.1 Redis Configuration Enhancement
```python
# core/cache/redis_config.py
REDIS_CONFIG = {
    'default': {
        'ttl': 3600,  # 1 hour default
        'max_memory': '256mb',
        'eviction_policy': 'allkeys-lru'
    },
    'patterns': {
        'api_camara_*': {'ttl': 7200},      # 2 hours
        'api_senado_*': {'ttl': 7200},      # 2 hours
        'api_planalto_*': {'ttl': 86400},   # 24 hours
        'geography_*': {'ttl': 2592000},    # 30 days
        'export_*': {'ttl': 1800},          # 30 minutes
    }
}
```

#### 2.2 Smart Cache Key Strategy
```python
# core/cache/cache_manager.py
class SmartCacheManager:
    def generate_cache_key(self, source: str, query: dict) -> str:
        """Generate normalized cache keys"""
        # Sort parameters for consistency
        sorted_params = sorted(query.items())
        # Create deterministic hash
        param_hash = hashlib.md5(
            json.dumps(sorted_params).encode()
        ).hexdigest()[:8]
        return f"{source}:{param_hash}"
    
    def get_or_fetch(self, key: str, fetch_func, ttl: int = None):
        """Cache-aside pattern implementation"""
        # Try cache first
        cached = self.redis.get(key)
        if cached:
            return json.loads(cached)
        
        # Fetch and cache
        data = fetch_func()
        self.redis.setex(
            key, 
            ttl or self.get_ttl_for_key(key),
            json.dumps(data)
        )
        return data
```

#### 2.3 Batch Operations Optimization
```python
# Implement pipeline for multiple operations
def batch_get_proposals(proposal_ids: List[str]):
    pipe = redis.pipeline()
    for pid in proposal_ids:
        pipe.get(f"proposal:{pid}")
    
    results = pipe.execute()
    missing = []
    
    for i, result in enumerate(results):
        if not result:
            missing.append(proposal_ids[i])
    
    # Fetch missing in batch
    if missing:
        fresh_data = fetch_proposals_batch(missing)
        pipe = redis.pipeline()
        for pid, data in fresh_data.items():
            pipe.setex(f"proposal:{pid}", 7200, json.dumps(data))
        pipe.execute()
```

### Phase 3: API Response Caching (Week 3)

#### 3.1 Response Cache Interceptor
```python
# core/api/cache_interceptor.py
class CacheInterceptor:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.stats = defaultdict(int)
    
    async def intercept(self, request, call_next):
        # Skip non-GET requests
        if request.method != "GET":
            return await call_next(request)
        
        # Generate cache key
        cache_key = self.generate_key(request)
        
        # Check cache
        cached = self.redis.get(cache_key)
        if cached:
            self.stats['hits'] += 1
            return JSONResponse(
                content=json.loads(cached),
                headers={"X-Cache": "HIT"}
            )
        
        # Process request
        response = await call_next(request)
        
        # Cache successful responses
        if response.status_code == 200:
            body = b"".join([chunk async for chunk in response.body_iterator])
            self.redis.setex(
                cache_key,
                self.get_ttl_for_endpoint(request.url.path),
                body
            )
            self.stats['misses'] += 1
            return Response(
                content=body,
                headers=dict(response.headers, **{"X-Cache": "MISS"}),
                media_type=response.media_type
            )
        
        return response
```

#### 3.2 Government API Cache Strategy
```python
# Different TTLs based on data volatility
CACHE_STRATEGY = {
    # Câmara - Updates frequently during sessions
    'camara_propositions': {
        'ttl': 2 * 3600,  # 2 hours
        'stale_while_revalidate': 3600,  # 1 hour
        'categories': ['active', 'recent']
    },
    
    # Senado - Less frequent updates
    'senado_bills': {
        'ttl': 4 * 3600,  # 4 hours
        'stale_while_revalidate': 2 * 3600,
        'categories': ['active', 'archived']
    },
    
    # Planalto - Official publications, very stable
    'planalto_laws': {
        'ttl': 24 * 3600,  # 24 hours
        'stale_while_revalidate': 12 * 3600,
        'categories': ['published', 'draft']
    },
    
    # Geographic data - Essentially static
    'geography': {
        'ttl': 30 * 24 * 3600,  # 30 days
        'stale_while_revalidate': 7 * 24 * 3600,
        'categories': ['states', 'cities', 'regions']
    }
}
```

### Phase 4: Client-Side Optimization (Week 4)

#### 4.1 Service Worker Implementation
```javascript
// public/service-worker.js
const CACHE_NAME = 'legislativo-v1';
const API_CACHE = 'legislativo-api-v1';

// Static assets to cache
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/static/css/main.css',
  '/static/js/bundle.js',
  '/assets/brazil-states.json'
];

// Cache strategies
const cacheStrategies = {
  networkFirst: ['/api/v1/search', '/api/v1/proposals'],
  cacheFirst: ['/assets/', '/static/'],
  staleWhileRevalidate: ['/api/v1/sources', '/api/v1/geography']
};

self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Determine strategy
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(handleAPIRequest(request));
  } else if (url.pathname.match(/\.(js|css|woff2|png|jpg)$/)) {
    event.respondWith(handleStaticAsset(request));
  }
});

async function handleAPIRequest(request) {
  const cache = await caches.open(API_CACHE);
  
  try {
    // Try network first
    const response = await fetch(request);
    
    // Cache successful responses
    if (response.status === 200) {
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    // Fallback to cache
    const cached = await cache.match(request);
    if (cached) {
      return cached;
    }
    
    // Return offline response
    return new Response(JSON.stringify({
      error: 'Offline',
      cached: false
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
```

#### 4.2 Local Storage Strategy
```javascript
// src/utils/localCache.js
class LocalCache {
  constructor() {
    this.prefix = 'legislativo_';
    this.maxAge = 3600000; // 1 hour
  }
  
  set(key, value, ttl = this.maxAge) {
    const item = {
      value,
      expires: Date.now() + ttl,
      version: APP_VERSION
    };
    
    try {
      localStorage.setItem(
        this.prefix + key,
        JSON.stringify(item)
      );
    } catch (e) {
      // Handle quota exceeded
      this.cleanup();
    }
  }
  
  get(key) {
    const item = localStorage.getItem(this.prefix + key);
    if (!item) return null;
    
    const data = JSON.parse(item);
    
    // Check expiration and version
    if (data.expires < Date.now() || data.version !== APP_VERSION) {
      localStorage.removeItem(this.prefix + key);
      return null;
    }
    
    return data.value;
  }
  
  cleanup() {
    // Remove expired items
    const now = Date.now();
    Object.keys(localStorage)
      .filter(key => key.startsWith(this.prefix))
      .forEach(key => {
        try {
          const item = JSON.parse(localStorage.getItem(key));
          if (item.expires < now) {
            localStorage.removeItem(key);
          }
        } catch (e) {
          localStorage.removeItem(key);
        }
      });
  }
}
```

### Phase 5: Export & Report Caching (Week 5)

#### 5.1 Pre-computed Export Cache
```python
# core/jobs/export_precache.py
class ExportPreCacheJob:
    """Background job to pre-generate common exports"""
    
    def run_daily(self):
        common_queries = [
            {'term': 'transporte', 'period': 'last_30_days'},
            {'term': 'saúde', 'period': 'last_30_days'},
            {'term': 'educação', 'period': 'last_30_days'},
        ]
        
        formats = ['csv', 'xlsx', 'pdf']
        
        for query in common_queries:
            for format in formats:
                cache_key = f"export:{hash(query)}:{format}"
                
                # Generate if not cached
                if not redis.exists(cache_key):
                    data = self.fetch_data(query)
                    export_file = self.generate_export(data, format)
                    
                    # Store with 24h TTL
                    redis.setex(
                        cache_key,
                        86400,
                        export_file
                    )
```

#### 5.2 Progressive Export Generation
```javascript
// React component for smart exports
const ExportPanel = () => {
  const [exportStatus, setExportStatus] = useState('idle');
  
  const handleExport = async (format) => {
    // Check local cache first
    const cacheKey = `export_${queryHash}_${format}`;
    const cached = localCache.get(cacheKey);
    
    if (cached) {
      downloadFile(cached);
      return;
    }
    
    // Check server cache
    setExportStatus('checking');
    const response = await fetch(`/api/v1/export/cached/${cacheKey}`);
    
    if (response.status === 200) {
      const blob = await response.blob();
      localCache.set(cacheKey, blob, 3600000); // 1 hour
      downloadFile(blob);
      return;
    }
    
    // Generate new export
    setExportStatus('generating');
    const newExport = await generateExport(format);
    localCache.set(cacheKey, newExport, 3600000);
    downloadFile(newExport);
  };
};
```

---

## 📈 Performance Metrics & Monitoring

### Key Performance Indicators (KPIs)

```python
# monitoring/cache_metrics.py
class CacheMetrics:
    def __init__(self):
        self.metrics = {
            'cache_hit_rate': Gauge('cache_hit_rate', 'Cache hit rate percentage'),
            'api_calls_saved': Counter('api_calls_saved', 'Number of API calls saved by cache'),
            'response_time_avg': Histogram('response_time_avg', 'Average response time'),
            'bandwidth_saved_mb': Counter('bandwidth_saved_mb', 'Bandwidth saved in MB')
        }
    
    def record_hit(self, cache_type, size_bytes):
        self.metrics['api_calls_saved'].inc()
        self.metrics['bandwidth_saved_mb'].inc(size_bytes / 1048576)
    
    def get_dashboard_data(self):
        return {
            'hit_rate': self.calculate_hit_rate(),
            'api_calls_saved': self.metrics['api_calls_saved']._value.get(),
            'cost_saved': self.calculate_cost_savings(),
            'avg_response_time': self.metrics['response_time_avg']._sum.get() / 
                                self.metrics['response_time_avg']._count.get()
        }
```

### Monitoring Dashboard Configuration

```yaml
# grafana/dashboards/cache-performance.json
panels:
  - title: "Cache Hit Rate"
    targets:
      - expr: "rate(cache_hits[5m]) / rate(cache_requests[5m]) * 100"
    thresholds:
      - value: 70
        color: yellow
      - value: 85
        color: green
  
  - title: "API Calls Saved"
    targets:
      - expr: "sum(increase(api_calls_saved[1h]))"
    unit: "short"
  
  - title: "Response Time Improvement"
    targets:
      - expr: "avg(response_time_cached) / avg(response_time_uncached)"
    unit: "percentunit"
  
  - title: "Cost Savings"
    targets:
      - expr: "sum(bandwidth_saved_mb) * 0.09"  # $0.09 per GB
    unit: "currencyUSD"
```

---

## 🔧 Implementation Checklist

### Week 1: CDN Setup
- [ ] Register with CloudFlare
- [ ] Configure DNS settings
- [ ] Set up page rules
- [ ] Enable Brotli compression
- [ ] Configure SSL/TLS
- [ ] Test static asset delivery

### Week 2: Redis Enhancement
- [ ] Update Redis configuration
- [ ] Implement cache key strategy
- [ ] Deploy batch operations
- [ ] Set up monitoring
- [ ] Configure memory limits
- [ ] Test failover scenarios

### Week 3: API Caching
- [ ] Deploy cache interceptor
- [ ] Configure TTL strategies
- [ ] Implement stale-while-revalidate
- [ ] Set up cache warming
- [ ] Monitor hit rates
- [ ] Tune cache parameters

### Week 4: Client Optimization
- [ ] Deploy service worker
- [ ] Implement local storage
- [ ] Configure offline mode
- [ ] Test cache strategies
- [ ] Monitor performance
- [ ] Handle edge cases

### Week 5: Export Caching
- [ ] Set up pre-computation jobs
- [ ] Implement progressive generation
- [ ] Configure export cache
- [ ] Monitor usage patterns
- [ ] Optimize popular exports
- [ ] Document cache behavior

---

## 🎯 Expected Outcomes

### Performance Improvements
- **Page Load Time:** 3.3s → 1.2s (64% improvement)
- **API Response Time:** 2.5s → 0.4s (84% improvement)
- **Time to First Byte:** 800ms → 200ms (75% improvement)
- **Export Generation:** 15s → 2s (87% improvement)

### Cost Reductions
- **API Calls:** -70% reduction
- **Bandwidth:** -80% reduction
- **Compute Time:** -60% reduction
- **Database Queries:** -75% reduction

### User Experience
- **Offline Capability:** Full read access offline
- **Instant Exports:** Common exports pre-cached
- **Faster Search:** Sub-second response times
- **Better Reliability:** Graceful degradation

---

## 🚨 Risk Mitigation

### Cache Invalidation Strategy
```python
# Automated invalidation based on events
class CacheInvalidator:
    def __init__(self, redis_client):
        self.redis = redis_client
        
    def invalidate_pattern(self, pattern: str):
        """Invalidate all keys matching pattern"""
        cursor = 0
        while True:
            cursor, keys = self.redis.scan(
                cursor, 
                match=pattern, 
                count=100
            )
            if keys:
                self.redis.delete(*keys)
            if cursor == 0:
                break
    
    def invalidate_on_update(self, source: str, entity_type: str):
        """Smart invalidation based on update type"""
        patterns = {
            'proposal_update': f"{source}:proposal:*",
            'vote_update': f"{source}:vote:*",
            'author_update': f"{source}:author:*"
        }
        
        if entity_type in patterns:
            self.invalidate_pattern(patterns[entity_type])
```

### Fallback Mechanisms
```javascript
// Graceful degradation
async function fetchWithFallback(url, options = {}) {
  try {
    // Try cache first
    const cached = await caches.match(url);
    if (cached && !options.skipCache) {
      return cached;
    }
    
    // Try network
    const response = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(5000)
    });
    
    return response;
  } catch (error) {
    // Try stale cache
    const stale = await caches.match(url);
    if (stale) {
      console.warn('Using stale cache:', url);
      return stale;
    }
    
    // Return error response
    return new Response(
      JSON.stringify({ 
        error: 'Service temporarily unavailable',
        offline: true 
      }),
      { 
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}
```

---

## 📚 Documentation & Training

### Developer Guidelines
1. **Cache Key Naming Convention**
   - Format: `{service}:{entity}:{params_hash}:{version}`
   - Example: `camara:proposal:abc123:v1`

2. **TTL Decision Matrix**
   - Real-time data: 5-15 minutes
   - Active sessions: 1-2 hours
   - Historical data: 24 hours
   - Static content: 30 days

3. **Cache Warming Strategy**
   - Pre-populate common queries
   - Refresh before expiration
   - Monitor usage patterns

### Operations Runbook
1. **Cache Flush Procedures**
   - Partial flush by pattern
   - Complete flush protocol
   - Rollback procedures

2. **Performance Tuning**
   - Monitor hit rates
   - Adjust TTLs based on patterns
   - Scale Redis memory as needed

3. **Incident Response**
   - Cache corruption detection
   - Failover procedures
   - Recovery protocols

---

## 🎉 Success Criteria

### Phase 1 Complete When:
- [ ] 90% of static assets served from CDN
- [ ] TTFB < 200ms for cached content
- [ ] Zero-downtime deployment achieved

### Phase 2 Complete When:
- [ ] Redis hit rate > 70%
- [ ] API call reduction > 60%
- [ ] Memory usage < 256MB

### Phase 3 Complete When:
- [ ] Overall cache hit rate > 80%
- [ ] API response time < 500ms
- [ ] Cost reduction > 50%

### Phase 4 Complete When:
- [ ] Offline mode functional
- [ ] Service worker adoption > 90%
- [ ] Client cache hit rate > 60%

### Phase 5 Complete When:
- [ ] Export generation < 3s
- [ ] Pre-cache hit rate > 75%
- [ ] User satisfaction > 90%

---

## 🔄 Continuous Improvement

### Monthly Review Metrics
- Cache hit rates by endpoint
- Cost savings achieved
- Performance improvements
- User satisfaction scores

### Optimization Opportunities
- Machine learning for cache prediction
- Edge computing integration
- GraphQL caching strategies
- Real-time cache synchronization

### Future Enhancements
- Multi-region cache replication
- Intelligent prefetching
- Adaptive TTL algorithms
- Cache compression optimization

---

**Implementation Timeline:** 5 weeks  
**Estimated Cost Savings:** 70-85%  
**Performance Improvement:** 60-80%  
**User Experience Enhancement:** Significant