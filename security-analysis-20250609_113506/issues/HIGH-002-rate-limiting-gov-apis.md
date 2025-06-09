# 🟡 HIGH-002: Enhanced Rate Limiting for Government APIs

## 📊 Issue Details
- **Severity**: HIGH
- **CVSS Score**: 7.2
- **Category**: API Security & Compliance
- **Discovery Date**: 2025-06-09
- **Status**: OPEN

## 🎯 Summary
Government APIs (ANTT, DOU, DNIT, Câmara, Senado) require more sophisticated rate limiting to ensure compliance with terms of service and prevent API throttling.

## 📍 Location
**Files**: `core/api/*.py`, `core/utils/rate_limiter.py`  
**Services Affected**: All government API integrations

## 🔍 Detailed Description
Current rate limiting implementation is basic and may not be sufficient for high-volume production usage with Brazilian government APIs.

**Current Implementation:**
```python
# Basic rate limiting in base_service.py
rate_limit = 1 req/sec  # Too conservative for some APIs
```

**Issues Identified:**
1. **Static Rate Limits**: Not adaptive to API capacity
2. **No Queue Management**: Requests fail instead of queuing
3. **Missing Burst Handling**: Cannot handle legitimate traffic spikes
4. **No Priority System**: All requests treated equally
5. **Lack of Backoff Strategy**: No intelligent retry timing

## 💥 Impact Assessment

### Operational Risks:
1. **Data Collection Delays**: Slow legislative monitoring updates
2. **API Blocking**: Risk of being temporarily banned by government APIs
3. **Service Degradation**: Poor user experience during peak usage
4. **Compliance Violations**: Potential violation of API terms of service
5. **Resource Waste**: Inefficient API usage patterns

### Business Impact:
- Reduced system reliability for critical transport policy monitoring
- Potential delays in regulatory compliance reporting
- Degraded user experience during high-traffic periods

## 🚨 Remediation Steps

### ⚡ Immediate Actions (0-24 hours):

1. **Implement Adaptive Rate Limiting**:
   ```python
   # core/utils/enhanced_rate_limiter.py
   class AdaptiveRateLimiter:
       def __init__(self, base_rate: float, burst_capacity: int = 10):
           self.base_rate = base_rate
           self.burst_capacity = burst_capacity
           self.token_bucket = burst_capacity
           self.last_refill = time.time()
       
       async def acquire(self, priority: int = 1) -> bool:
           """Acquire rate limit token with priority support"""
           self._refill_tokens()
           
           if self.token_bucket >= priority:
               self.token_bucket -= priority
               return True
           return False
   ```

2. **Add Request Queue System**:
   ```python
   # Implement priority queue for government API requests
   class APIRequestQueue:
       def __init__(self):
           self.priority_queue = asyncio.PriorityQueue()
           self.processing = False
       
       async def enqueue_request(self, request, priority=5):
           await self.priority_queue.put((priority, request))
           if not self.processing:
               asyncio.create_task(self._process_queue())
   ```

### 🛡️ Enhanced Implementation (1-7 days):

3. **API-Specific Rate Configurations**:
   ```python
   API_RATE_CONFIGS = {
       "ANTT": {
           "base_rate": 1.0,  # 1 req/sec
           "burst_capacity": 5,
           "daily_limit": 1000,
           "retry_after_header": "Retry-After"
       },
       "DOU": {
           "base_rate": 2.0,  # 2 req/sec
           "burst_capacity": 10,
           "daily_limit": 5000,
           "respect_rate_limit_headers": True
       },
       "CAMARA": {
           "base_rate": 1.0,
           "burst_capacity": 3,
           "daily_limit": 2000,
           "backoff_strategy": "exponential"
       }
   }
   ```

4. **Intelligent Backoff Strategy**:
   ```python
   async def exponential_backoff_retry(self, func, max_retries=5):
       for attempt in range(max_retries):
           try:
               return await func()
           except RateLimitExceeded as e:
               if attempt == max_retries - 1:
                   raise
               
               # Calculate backoff time
               base_delay = 2 ** attempt
               jitter = random.uniform(0.1, 0.5)
               delay = base_delay + jitter
               
               # Respect server's rate limit headers
               if hasattr(e, 'retry_after'):
                   delay = max(delay, e.retry_after)
               
               await asyncio.sleep(delay)
   ```

5. **Monitor and Alert System**:
   ```python
   class RateLimitMonitor:
       def __init__(self):
           self.metrics = defaultdict(dict)
       
       def record_rate_limit_hit(self, api_name: str, retry_after: int):
           self.metrics[api_name]['rate_limit_hits'] += 1
           self.metrics[api_name]['last_retry_after'] = retry_after
           
           # Alert if hitting rate limits frequently
           if self.metrics[api_name]['rate_limit_hits'] > 10:
               self._send_alert(f"Frequent rate limiting on {api_name}")
   ```

### 🔐 Production Hardening (1-4 weeks):

6. **Circuit Breaker Integration**:
   ```python
   # Integrate with existing circuit breaker
   @circuit_breaker(failure_threshold=5, timeout=60)
   async def api_call_with_rate_limit(self, api_func, *args, **kwargs):
       await self.rate_limiter.acquire()
       return await api_func(*args, **kwargs)
   ```

7. **Distributed Rate Limiting**:
   ```python
   # For multi-instance deployments
   class RedisRateLimiter:
       def __init__(self, redis_client):
           self.redis = redis_client
       
       async def is_allowed(self, key: str, limit: int, window: int):
           current = await self.redis.incr(key)
           if current == 1:
               await self.redis.expire(key, window)
           return current <= limit
   ```

## ✅ Verification Steps
- [ ] Adaptive rate limiting implemented for all government APIs
- [ ] Request queue system functional with priority support
- [ ] API-specific rate configurations applied
- [ ] Exponential backoff strategy working
- [ ] Rate limit monitoring and alerting active
- [ ] Circuit breaker integration completed
- [ ] Distributed rate limiting configured for production

## 📋 Testing
```bash
# Test rate limiting with burst requests
python -m pytest tests/integration/test_rate_limiting.py

# Load test to verify queue behavior
python -m pytest tests/performance/test_api_load.py

# Test government API compliance
python -m pytest tests/integration/test_gov_api_compliance.py

# Verify circuit breaker integration
python -m pytest tests/unit/test_circuit_breaker_rate_limit.py
```

## 🎯 API-Specific Requirements

### ANTT (Agência Nacional de Transportes Terrestres)
- **Rate Limit**: 1 request/second
- **Daily Limit**: 1,000 requests
- **Required Headers**: User-Agent with contact info
- **Backoff**: Respect HTTP 429 responses

### DOU (Diário Oficial da União)  
- **Rate Limit**: 2 requests/second
- **Daily Limit**: 5,000 requests
- **Special Handling**: Large document downloads
- **Cache Strategy**: Aggressive caching for published documents

### Câmara dos Deputados
- **Rate Limit**: 1 request/second  
- **Daily Limit**: 2,000 requests
- **API Key**: Required for higher limits
- **Session Management**: Persistent sessions recommended

### Senado Federal
- **Rate Limit**: 1 request/second
- **Daily Limit**: 2,000 requests
- **Format Preference**: JSON over XML
- **Error Handling**: Graceful degradation to fallback endpoints

### DNIT (Departamento Nacional de Infraestrutura)
- **Rate Limit**: 0.5 requests/second
- **Daily Limit**: 500 requests
- **Geographic Data**: Special handling for large GIS datasets
- **Timeout**: Extended timeouts for large files

## 📞 Related Configurations
- Update `core/config/api_endpoints.py` with new rate limit configs
- Modify `core/utils/cache_manager.py` for better cache utilization
- Enhance `monitoring/prometheus.yml` with rate limit metrics

## 🕐 Timeline
- **Discovery**: 2025-06-09 11:35:06
- **Implementation Start**: Within 24 hours
- **Phase 1 Complete**: Within 7 days
- **Production Deployment**: Within 2 weeks
- **Performance Review**: 2025-06-23

---

**⚠️ Priority: HIGH - Critical for production compliance with government APIs**