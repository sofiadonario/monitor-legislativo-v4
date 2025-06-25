# API Rate Limiting and Abuse Prevention System for Monitor Legislativo v4
# Phase 4 Week 16: Comprehensive rate limiting with intelligent abuse detection
# Protects API endpoints from abuse while maintaining service availability

import asyncio
import aioredis
import time
import json
import logging
import hashlib
import ipaddress
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import re
from collections import defaultdict
import math

logger = logging.getLogger(__name__)

class RateLimitType(Enum):
    """Types of rate limiting strategies"""
    FIXED_WINDOW = "fixed_window"        # Fixed time window
    SLIDING_WINDOW = "sliding_window"    # Sliding time window
    TOKEN_BUCKET = "token_bucket"        # Token bucket algorithm
    LEAKY_BUCKET = "leaky_bucket"       # Leaky bucket algorithm
    ADAPTIVE = "adaptive"               # Adaptive rate limiting

class AbusePattern(Enum):
    """Types of abuse patterns detected"""
    BRUTE_FORCE = "brute_force"         # Repeated failed attempts
    SCRAPING = "scraping"               # Automated data extraction
    DOS_ATTACK = "dos_attack"           # Denial of service attempt
    SPAM_QUERIES = "spam_queries"       # Repetitive search queries
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # High resource consumption
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"    # Unusual geographic pattern
    USER_AGENT_SPOOFING = "user_agent_spoofing"  # Suspicious user agents

@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    rule_id: str
    endpoint_pattern: str  # Regex pattern for matching endpoints
    limit_type: RateLimitType
    requests_per_window: int
    window_seconds: int
    burst_allowance: int = 0  # Additional requests allowed in burst
    whitelist_ips: List[str] = field(default_factory=list)
    blacklist_ips: List[str] = field(default_factory=list)
    user_agent_patterns: List[str] = field(default_factory=list)  # Suspicious patterns
    enabled: bool = True
    priority: int = 1  # Higher priority rules take precedence
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['limit_type'] = self.limit_type.value
        return result

@dataclass
class RateLimitStatus:
    """Current rate limit status for a client"""
    client_id: str
    endpoint: str
    requests_made: int
    limit_exceeded: bool
    reset_time: datetime
    retry_after_seconds: int
    tokens_remaining: int = 0  # For token bucket
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['reset_time'] = self.reset_time.isoformat()
        return result

@dataclass
class AbuseAlert:
    """Abuse detection alert"""
    alert_id: str
    client_id: str
    pattern_type: AbusePattern
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any]
    detected_at: datetime
    endpoint: str
    action_taken: str  # warn, throttle, block, captcha
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['pattern_type'] = self.pattern_type.value
        result['detected_at'] = self.detected_at.isoformat()
        return result

class RateLimitManager:
    """
    Comprehensive rate limiting and abuse prevention system for Monitor Legislativo v4
    
    Features:
    - Multiple rate limiting algorithms
    - Adaptive rate limiting based on system load
    - Intelligent abuse pattern detection
    - Geographic and user agent analysis
    - Integration with security monitoring
    - Academic research protection (prevent scraping)
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client = None
        self.rate_limit_rules = {}
        self.client_states = {}  # In-memory cache for client states
        self.abuse_patterns = defaultdict(list)
        self.geographic_cache = {}
        
        # Initialize default rules for Monitor Legislativo
        self._initialize_default_rules()
    
    async def initialize(self) -> None:
        """Initialize Redis connection and load rules"""
        self.redis_client = await aioredis.from_url(self.redis_url)
        await self._load_rules_from_redis()
        logger.info("Rate limiting system initialized")
    
    def _initialize_default_rules(self) -> None:
        """Initialize default rate limiting rules for Monitor Legislativo"""
        
        # General API rate limit
        self.rate_limit_rules["general_api"] = RateLimitRule(
            rule_id="general_api",
            endpoint_pattern=r"/api/v1/.*",
            limit_type=RateLimitType.SLIDING_WINDOW,
            requests_per_window=100,
            window_seconds=60,
            burst_allowance=20,
            priority=1
        )
        
        # Search API - more restrictive to prevent scraping
        self.rate_limit_rules["search_api"] = RateLimitRule(
            rule_id="search_api",
            endpoint_pattern=r"/api/v1/(search|documents/search)",
            limit_type=RateLimitType.TOKEN_BUCKET,
            requests_per_window=30,
            window_seconds=60,
            burst_allowance=10,
            user_agent_patterns=[
                r".*bot.*", r".*scraper.*", r".*crawler.*", 
                r"python-requests.*", r"curl.*", r"wget.*"
            ],
            priority=2
        )
        
        # Admin API - very restrictive
        self.rate_limit_rules["admin_api"] = RateLimitRule(
            rule_id="admin_api",
            endpoint_pattern=r"/api/v1/admin/.*",
            limit_type=RateLimitType.FIXED_WINDOW,
            requests_per_window=10,
            window_seconds=60,
            burst_allowance=0,
            priority=3
        )
        
        # Analytics API - moderate limits
        self.rate_limit_rules["analytics_api"] = RateLimitRule(
            rule_id="analytics_api",
            endpoint_pattern=r"/api/v1/analytics/.*",
            limit_type=RateLimitType.SLIDING_WINDOW,
            requests_per_window=50,
            window_seconds=300,  # 5 minutes
            burst_allowance=5,
            priority=2
        )
        
        # Health check - very permissive
        self.rate_limit_rules["health_check"] = RateLimitRule(
            rule_id="health_check",
            endpoint_pattern=r"/api/v1/(health|status)",
            limit_type=RateLimitType.FIXED_WINDOW,
            requests_per_window=1000,
            window_seconds=60,
            burst_allowance=100,
            priority=0
        )
    
    async def _load_rules_from_redis(self) -> None:
        """Load rate limiting rules from Redis"""
        try:
            rules_data = await self.redis_client.get("rate_limit_rules")
            if rules_data:
                rules_dict = json.loads(rules_data)
                for rule_id, rule_data in rules_dict.items():
                    rule_data['limit_type'] = RateLimitType(rule_data['limit_type'])
                    self.rate_limit_rules[rule_id] = RateLimitRule(**rule_data)
                logger.info(f"Loaded {len(rules_dict)} rate limiting rules from Redis")
        
        except Exception as e:
            logger.warning(f"Could not load rules from Redis: {e}, using defaults")
    
    async def save_rules_to_redis(self) -> None:
        """Save rate limiting rules to Redis"""
        try:
            rules_dict = {rule_id: rule.to_dict() for rule_id, rule in self.rate_limit_rules.items()}
            await self.redis_client.set("rate_limit_rules", json.dumps(rules_dict))
            logger.info("Rate limiting rules saved to Redis")
        
        except Exception as e:
            logger.error(f"Could not save rules to Redis: {e}")
    
    async def check_rate_limit(self, client_id: str, endpoint: str, 
                             user_agent: str = "", ip_address: str = "") -> RateLimitStatus:
        """Check if client has exceeded rate limits"""
        
        # Find applicable rule
        applicable_rule = self._find_applicable_rule(endpoint)
        if not applicable_rule or not applicable_rule.enabled:
            # No rate limiting for this endpoint
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=0,
                limit_exceeded=False,
                reset_time=datetime.now() + timedelta(seconds=60),
                retry_after_seconds=0
            )
        
        # Check whitelist/blacklist
        if self._is_whitelisted(ip_address, applicable_rule):
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=0,
                limit_exceeded=False,
                reset_time=datetime.now() + timedelta(seconds=applicable_rule.window_seconds),
                retry_after_seconds=0
            )
        
        if self._is_blacklisted(ip_address, applicable_rule):
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=999999,
                limit_exceeded=True,
                reset_time=datetime.now() + timedelta(hours=24),
                retry_after_seconds=86400
            )
        
        # Check for suspicious user agents
        if self._is_suspicious_user_agent(user_agent, applicable_rule):
            # Apply stricter limits for suspicious agents
            applicable_rule = self._create_strict_rule(applicable_rule)
        
        # Apply rate limiting algorithm
        if applicable_rule.limit_type == RateLimitType.FIXED_WINDOW:
            return await self._check_fixed_window(client_id, endpoint, applicable_rule)
        elif applicable_rule.limit_type == RateLimitType.SLIDING_WINDOW:
            return await self._check_sliding_window(client_id, endpoint, applicable_rule)
        elif applicable_rule.limit_type == RateLimitType.TOKEN_BUCKET:
            return await self._check_token_bucket(client_id, endpoint, applicable_rule)
        elif applicable_rule.limit_type == RateLimitType.ADAPTIVE:
            return await self._check_adaptive_limit(client_id, endpoint, applicable_rule)
        else:
            return await self._check_fixed_window(client_id, endpoint, applicable_rule)
    
    def _find_applicable_rule(self, endpoint: str) -> Optional[RateLimitRule]:
        """Find the most specific rule applicable to the endpoint"""
        matching_rules = []
        
        for rule in self.rate_limit_rules.values():
            if re.match(rule.endpoint_pattern, endpoint):
                matching_rules.append(rule)
        
        if not matching_rules:
            return None
        
        # Return highest priority rule
        return max(matching_rules, key=lambda r: r.priority)
    
    def _is_whitelisted(self, ip_address: str, rule: RateLimitRule) -> bool:
        """Check if IP is whitelisted"""
        if not ip_address or not rule.whitelist_ips:
            return False
        
        try:
            client_ip = ipaddress.ip_address(ip_address)
            for whitelist_ip in rule.whitelist_ips:
                if "/" in whitelist_ip:  # CIDR notation
                    if client_ip in ipaddress.ip_network(whitelist_ip):
                        return True
                else:  # Single IP
                    if client_ip == ipaddress.ip_address(whitelist_ip):
                        return True
        except ValueError:
            pass
        
        return False
    
    def _is_blacklisted(self, ip_address: str, rule: RateLimitRule) -> bool:
        """Check if IP is blacklisted"""
        if not ip_address or not rule.blacklist_ips:
            return False
        
        try:
            client_ip = ipaddress.ip_address(ip_address)
            for blacklist_ip in rule.blacklist_ips:
                if "/" in blacklist_ip:  # CIDR notation
                    if client_ip in ipaddress.ip_network(blacklist_ip):
                        return True
                else:  # Single IP
                    if client_ip == ipaddress.ip_address(blacklist_ip):
                        return True
        except ValueError:
            pass
        
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str, rule: RateLimitRule) -> bool:
        """Check if user agent matches suspicious patterns"""
        if not user_agent or not rule.user_agent_patterns:
            return False
        
        for pattern in rule.user_agent_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        
        return False
    
    def _create_strict_rule(self, original_rule: RateLimitRule) -> RateLimitRule:
        """Create a stricter version of the rule for suspicious clients"""
        return RateLimitRule(
            rule_id=f"{original_rule.rule_id}_strict",
            endpoint_pattern=original_rule.endpoint_pattern,
            limit_type=original_rule.limit_type,
            requests_per_window=max(1, original_rule.requests_per_window // 4),  # 1/4 of normal limit
            window_seconds=original_rule.window_seconds,
            burst_allowance=0,  # No burst for suspicious clients
            priority=original_rule.priority
        )
    
    async def _check_fixed_window(self, client_id: str, endpoint: str, rule: RateLimitRule) -> RateLimitStatus:
        """Check fixed window rate limit"""
        current_time = int(time.time())
        window_start = (current_time // rule.window_seconds) * rule.window_seconds
        
        key = f"rate_limit:fixed:{rule.rule_id}:{client_id}:{window_start}"
        
        try:
            current_count = await self.redis_client.get(key)
            current_count = int(current_count) if current_count else 0
            
            # Check if limit exceeded
            total_allowed = rule.requests_per_window + rule.burst_allowance
            limit_exceeded = current_count >= total_allowed
            
            if not limit_exceeded:
                # Increment counter
                pipe = self.redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, rule.window_seconds)
                await pipe.execute()
                current_count += 1
            
            reset_time = datetime.fromtimestamp(window_start + rule.window_seconds)
            retry_after = max(0, (window_start + rule.window_seconds) - current_time)
            
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=current_count,
                limit_exceeded=limit_exceeded,
                reset_time=reset_time,
                retry_after_seconds=retry_after if limit_exceeded else 0
            )
        
        except Exception as e:
            logger.error(f"Redis error in fixed window check: {e}")
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=0,
                limit_exceeded=False,
                reset_time=datetime.now() + timedelta(seconds=rule.window_seconds),
                retry_after_seconds=0
            )
    
    async def _check_sliding_window(self, client_id: str, endpoint: str, rule: RateLimitRule) -> RateLimitStatus:
        """Check sliding window rate limit using sorted sets"""
        current_time = time.time()
        window_start = current_time - rule.window_seconds
        
        key = f"rate_limit:sliding:{rule.rule_id}:{client_id}"
        
        try:
            # Remove old entries
            await self.redis_client.zremrangebyscore(key, 0, window_start)
            
            # Count current requests in window
            current_count = await self.redis_client.zcard(key)
            
            # Check if limit exceeded
            total_allowed = rule.requests_per_window + rule.burst_allowance
            limit_exceeded = current_count >= total_allowed
            
            if not limit_exceeded:
                # Add current request
                request_id = f"{current_time}:{hashlib.md5(f'{client_id}{current_time}'.encode()).hexdigest()[:8]}"
                pipe = self.redis_client.pipeline()
                pipe.zadd(key, {request_id: current_time})
                pipe.expire(key, rule.window_seconds + 1)
                await pipe.execute()
                current_count += 1
            
            # Calculate when window will have space
            if limit_exceeded:
                oldest_requests = await self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest_requests:
                    oldest_time = oldest_requests[0][1]
                    retry_after = max(0, int(oldest_time + rule.window_seconds - current_time))
                else:
                    retry_after = rule.window_seconds
            else:
                retry_after = 0
            
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=current_count,
                limit_exceeded=limit_exceeded,
                reset_time=datetime.fromtimestamp(current_time + retry_after),
                retry_after_seconds=retry_after
            )
        
        except Exception as e:
            logger.error(f"Redis error in sliding window check: {e}")
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=0,
                limit_exceeded=False,
                reset_time=datetime.now() + timedelta(seconds=rule.window_seconds),
                retry_after_seconds=0
            )
    
    async def _check_token_bucket(self, client_id: str, endpoint: str, rule: RateLimitRule) -> RateLimitStatus:
        """Check token bucket rate limit"""
        current_time = time.time()
        key = f"rate_limit:token:{rule.rule_id}:{client_id}"
        
        try:
            # Get current bucket state
            bucket_data = await self.redis_client.hmget(key, "tokens", "last_refill")
            
            tokens = float(bucket_data[0]) if bucket_data[0] else rule.requests_per_window
            last_refill = float(bucket_data[1]) if bucket_data[1] else current_time
            
            # Calculate token refill
            time_passed = current_time - last_refill
            tokens_to_add = (time_passed / rule.window_seconds) * rule.requests_per_window
            
            # Cap at bucket capacity (with burst allowance)
            max_tokens = rule.requests_per_window + rule.burst_allowance
            tokens = min(max_tokens, tokens + tokens_to_add)
            
            # Check if request can be served
            limit_exceeded = tokens < 1
            
            if not limit_exceeded:
                tokens -= 1
            
            # Update bucket state
            pipe = self.redis_client.pipeline()
            pipe.hmset(key, {"tokens": tokens, "last_refill": current_time})
            pipe.expire(key, rule.window_seconds * 2)
            await pipe.execute()
            
            # Calculate retry after
            if limit_exceeded:
                tokens_needed = 1 - tokens
                retry_after = int(math.ceil(tokens_needed * rule.window_seconds / rule.requests_per_window))
            else:
                retry_after = 0
            
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=max_tokens - int(tokens),
                limit_exceeded=limit_exceeded,
                reset_time=datetime.fromtimestamp(current_time + retry_after),
                retry_after_seconds=retry_after,
                tokens_remaining=int(tokens)
            )
        
        except Exception as e:
            logger.error(f"Redis error in token bucket check: {e}")
            return RateLimitStatus(
                client_id=client_id,
                endpoint=endpoint,
                requests_made=0,
                limit_exceeded=False,
                reset_time=datetime.now() + timedelta(seconds=rule.window_seconds),
                retry_after_seconds=0,
                tokens_remaining=rule.requests_per_window
            )
    
    async def _check_adaptive_limit(self, client_id: str, endpoint: str, rule: RateLimitRule) -> RateLimitStatus:
        """Check adaptive rate limit based on system load"""
        # Get system load metrics (simplified version)
        system_load = await self._get_system_load()
        
        # Adjust limits based on load
        if system_load > 0.8:  # High load
            adjusted_rule = RateLimitRule(
                rule_id=f"{rule.rule_id}_adaptive",
                endpoint_pattern=rule.endpoint_pattern,
                limit_type=RateLimitType.SLIDING_WINDOW,
                requests_per_window=max(1, rule.requests_per_window // 2),
                window_seconds=rule.window_seconds,
                burst_allowance=0,
                priority=rule.priority
            )
        elif system_load < 0.3:  # Low load
            adjusted_rule = RateLimitRule(
                rule_id=f"{rule.rule_id}_adaptive",
                endpoint_pattern=rule.endpoint_pattern,
                limit_type=RateLimitType.SLIDING_WINDOW,
                requests_per_window=int(rule.requests_per_window * 1.5),
                window_seconds=rule.window_seconds,
                burst_allowance=rule.burst_allowance * 2,
                priority=rule.priority
            )
        else:  # Normal load
            adjusted_rule = rule
        
        return await self._check_sliding_window(client_id, endpoint, adjusted_rule)
    
    async def _get_system_load(self) -> float:
        """Get system load metric (simplified)"""
        try:
            # In a real implementation, this would check CPU, memory, database connections, etc.
            # For now, return a mock value
            load_key = "system:load"
            load_value = await self.redis_client.get(load_key)
            return float(load_value) if load_value else 0.5
        except:
            return 0.5  # Default moderate load
    
    async def detect_abuse_patterns(self, client_id: str, endpoint: str, 
                                  user_agent: str = "", ip_address: str = "",
                                  request_data: Dict[str, Any] = None) -> Optional[AbuseAlert]:
        """Detect abuse patterns in client behavior"""
        
        # Track client behavior
        await self._track_client_behavior(client_id, endpoint, user_agent, ip_address, request_data)
        
        # Check for various abuse patterns
        abuse_alerts = []
        
        # Check for brute force attacks
        brute_force_alert = await self._detect_brute_force(client_id, endpoint)
        if brute_force_alert:
            abuse_alerts.append(brute_force_alert)
        
        # Check for scraping behavior
        scraping_alert = await self._detect_scraping(client_id, endpoint, user_agent)
        if scraping_alert:
            abuse_alerts.append(scraping_alert)
        
        # Check for DoS patterns
        dos_alert = await self._detect_dos_patterns(client_id, endpoint)
        if dos_alert:
            abuse_alerts.append(dos_alert)
        
        # Check for spam queries
        spam_alert = await self._detect_spam_queries(client_id, endpoint, request_data)
        if spam_alert:
            abuse_alerts.append(spam_alert)
        
        # Return highest severity alert
        if abuse_alerts:
            return max(abuse_alerts, key=lambda a: self._get_severity_score(a.severity))
        
        return None
    
    async def _track_client_behavior(self, client_id: str, endpoint: str, 
                                   user_agent: str, ip_address: str, request_data: Dict[str, Any]) -> None:
        """Track client behavior for abuse detection"""
        current_time = time.time()
        
        # Track request patterns
        behavior_key = f"behavior:{client_id}:requests"
        request_info = {
            "timestamp": current_time,
            "endpoint": endpoint,
            "user_agent": user_agent,
            "ip_address": ip_address
        }
        
        try:
            # Add to behavior timeline
            await self.redis_client.zadd(behavior_key, {json.dumps(request_info): current_time})
            await self.redis_client.expire(behavior_key, 3600)  # Keep 1 hour of history
            
            # Remove old entries (older than 1 hour)
            await self.redis_client.zremrangebyscore(behavior_key, 0, current_time - 3600)
        
        except Exception as e:
            logger.error(f"Error tracking client behavior: {e}")
    
    async def _detect_brute_force(self, client_id: str, endpoint: str) -> Optional[AbuseAlert]:
        """Detect brute force attack patterns"""
        if not any(pattern in endpoint for pattern in ["/auth", "/login", "/admin"]):
            return None
        
        # Check for rapid repeated requests to auth endpoints
        behavior_key = f"behavior:{client_id}:requests"
        current_time = time.time()
        
        try:
            # Get requests in last 5 minutes
            recent_requests = await self.redis_client.zrangebyscore(
                behavior_key, current_time - 300, current_time
            )
            
            auth_requests = []
            for request_data in recent_requests:
                try:
                    request_info = json.loads(request_data)
                    if any(pattern in request_info.get("endpoint", "") for pattern in ["/auth", "/login", "/admin"]):
                        auth_requests.append(request_info)
                except:
                    continue
            
            if len(auth_requests) > 20:  # More than 20 auth requests in 5 minutes
                return AbuseAlert(
                    alert_id=f"brute_force_{client_id}_{int(current_time)}",
                    client_id=client_id,
                    pattern_type=AbusePattern.BRUTE_FORCE,
                    severity="high",
                    confidence=0.85,
                    evidence={
                        "auth_requests_count": len(auth_requests),
                        "time_window": "5_minutes",
                        "endpoints": list(set(r.get("endpoint") for r in auth_requests))
                    },
                    detected_at=datetime.now(),
                    endpoint=endpoint,
                    action_taken="throttle"
                )
        
        except Exception as e:
            logger.error(f"Error detecting brute force: {e}")
        
        return None
    
    async def _detect_scraping(self, client_id: str, endpoint: str, user_agent: str) -> Optional[AbuseAlert]:
        """Detect web scraping patterns"""
        behavior_key = f"behavior:{client_id}:requests"
        current_time = time.time()
        
        try:
            # Get requests in last 10 minutes
            recent_requests = await self.redis_client.zrangebyscore(
                behavior_key, current_time - 600, current_time
            )
            
            search_requests = []
            for request_data in recent_requests:
                try:
                    request_info = json.loads(request_data)
                    if "search" in request_info.get("endpoint", ""):
                        search_requests.append(request_info)
                except:
                    continue
            
            # Check for scraping indicators
            scraping_score = 0
            
            # High frequency of search requests
            if len(search_requests) > 50:
                scraping_score += 0.4
            
            # Bot-like user agent
            bot_patterns = ["bot", "crawler", "scraper", "spider", "python", "curl", "wget"]
            if any(pattern in user_agent.lower() for pattern in bot_patterns):
                scraping_score += 0.3
            
            # Uniform timing pattern (very regular intervals)
            if len(search_requests) > 10:
                timestamps = [r.get("timestamp", 0) for r in search_requests[-10:]]
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if intervals and max(intervals) - min(intervals) < 2:  # Very uniform timing
                    scraping_score += 0.3
            
            if scraping_score > 0.6:
                return AbuseAlert(
                    alert_id=f"scraping_{client_id}_{int(current_time)}",
                    client_id=client_id,
                    pattern_type=AbusePattern.SCRAPING,
                    severity="medium" if scraping_score < 0.8 else "high",
                    confidence=scraping_score,
                    evidence={
                        "search_requests_count": len(search_requests),
                        "user_agent": user_agent,
                        "scraping_score": scraping_score,
                        "time_window": "10_minutes"
                    },
                    detected_at=datetime.now(),
                    endpoint=endpoint,
                    action_taken="captcha" if scraping_score > 0.8 else "warn"
                )
        
        except Exception as e:
            logger.error(f"Error detecting scraping: {e}")
        
        return None
    
    async def _detect_dos_patterns(self, client_id: str, endpoint: str) -> Optional[AbuseAlert]:
        """Detect denial of service attack patterns"""
        behavior_key = f"behavior:{client_id}:requests"
        current_time = time.time()
        
        try:
            # Get requests in last 2 minutes
            recent_requests = await self.redis_client.zrangebyscore(
                behavior_key, current_time - 120, current_time
            )
            
            if len(recent_requests) > 200:  # More than 200 requests in 2 minutes
                return AbuseAlert(
                    alert_id=f"dos_{client_id}_{int(current_time)}",
                    client_id=client_id,
                    pattern_type=AbusePattern.DOS_ATTACK,
                    severity="critical",
                    confidence=0.9,
                    evidence={
                        "requests_count": len(recent_requests),
                        "time_window": "2_minutes",
                        "rate_per_second": len(recent_requests) / 120
                    },
                    detected_at=datetime.now(),
                    endpoint=endpoint,
                    action_taken="block"
                )
        
        except Exception as e:
            logger.error(f"Error detecting DoS patterns: {e}")
        
        return None
    
    async def _detect_spam_queries(self, client_id: str, endpoint: str, 
                                 request_data: Dict[str, Any]) -> Optional[AbuseAlert]:
        """Detect spam query patterns"""
        if not request_data or "query" not in request_data:
            return None
        
        query = request_data.get("query", "")
        if not query:
            return None
        
        # Track query patterns
        query_key = f"queries:{client_id}"
        current_time = time.time()
        
        try:
            # Add current query
            await self.redis_client.zadd(query_key, {query: current_time})
            await self.redis_client.expire(query_key, 1800)  # 30 minutes
            
            # Get recent queries
            recent_queries = await self.redis_client.zrangebyscore(
                query_key, current_time - 600, current_time  # Last 10 minutes
            )
            
            # Check for spam patterns
            if len(recent_queries) > 5:
                # Check for repetitive queries
                query_counts = {}
                for q in recent_queries:
                    query_counts[q] = query_counts.get(q, 0) + 1
                
                max_count = max(query_counts.values())
                if max_count > 10:  # Same query repeated more than 10 times
                    return AbuseAlert(
                        alert_id=f"spam_queries_{client_id}_{int(current_time)}",
                        client_id=client_id,
                        pattern_type=AbusePattern.SPAM_QUERIES,
                        severity="medium",
                        confidence=0.7,
                        evidence={
                            "repeated_query": max(query_counts, key=query_counts.get),
                            "repetition_count": max_count,
                            "unique_queries": len(query_counts),
                            "total_queries": len(recent_queries)
                        },
                        detected_at=datetime.now(),
                        endpoint=endpoint,
                        action_taken="throttle"
                    )
        
        except Exception as e:
            logger.error(f"Error detecting spam queries: {e}")
        
        return None
    
    def _get_severity_score(self, severity: str) -> int:
        """Get numeric score for severity level"""
        scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return scores.get(severity, 0)
    
    async def add_to_blacklist(self, ip_address: str, reason: str, duration_hours: int = 24) -> None:
        """Add IP to temporary blacklist"""
        blacklist_key = f"blacklist:ip:{ip_address}"
        
        try:
            blacklist_data = {
                "ip_address": ip_address,
                "reason": reason,
                "blacklisted_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(hours=duration_hours)).isoformat()
            }
            
            await self.redis_client.setex(
                blacklist_key, 
                duration_hours * 3600, 
                json.dumps(blacklist_data)
            )
            
            logger.info(f"Added {ip_address} to blacklist for {duration_hours} hours: {reason}")
        
        except Exception as e:
            logger.error(f"Error adding to blacklist: {e}")
    
    async def is_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is currently blacklisted"""
        blacklist_key = f"blacklist:ip:{ip_address}"
        
        try:
            blacklist_data = await self.redis_client.get(blacklist_key)
            return blacklist_data is not None
        
        except Exception as e:
            logger.error(f"Error checking blacklist: {e}")
            return False
    
    async def get_client_status(self, client_id: str) -> Dict[str, Any]:
        """Get comprehensive status for a client"""
        current_time = time.time()
        
        # Get rate limit status for all rules
        status = {
            "client_id": client_id,
            "timestamp": datetime.now().isoformat(),
            "rate_limits": {},
            "recent_requests": 0,
            "abuse_alerts": [],
            "blacklisted": False
        }
        
        try:
            # Check recent request count
            behavior_key = f"behavior:{client_id}:requests"
            recent_requests = await self.redis_client.zcount(
                behavior_key, current_time - 300, current_time  # Last 5 minutes
            )
            status["recent_requests"] = recent_requests
            
            # Get rate limit status for each rule
            for rule_id, rule in self.rate_limit_rules.items():
                try:
                    if rule.limit_type == RateLimitType.FIXED_WINDOW:
                        window_start = (int(current_time) // rule.window_seconds) * rule.window_seconds
                        key = f"rate_limit:fixed:{rule.rule_id}:{client_id}:{window_start}"
                        count = await self.redis_client.get(key)
                        status["rate_limits"][rule_id] = {
                            "requests_made": int(count) if count else 0,
                            "limit": rule.requests_per_window + rule.burst_allowance,
                            "window_seconds": rule.window_seconds,
                            "reset_time": datetime.fromtimestamp(window_start + rule.window_seconds).isoformat()
                        }
                    
                    elif rule.limit_type == RateLimitType.SLIDING_WINDOW:
                        key = f"rate_limit:sliding:{rule.rule_id}:{client_id}"
                        count = await self.redis_client.zcard(key)
                        status["rate_limits"][rule_id] = {
                            "requests_made": count,
                            "limit": rule.requests_per_window + rule.burst_allowance,
                            "window_seconds": rule.window_seconds
                        }
                
                except Exception as e:
                    logger.debug(f"Error getting status for rule {rule_id}: {e}")
            
            # Check for recent abuse alerts
            alert_key = f"alerts:{client_id}"
            alert_data = await self.redis_client.get(alert_key)
            if alert_data:
                try:
                    status["abuse_alerts"] = json.loads(alert_data)
                except:
                    pass
            
        except Exception as e:
            logger.error(f"Error getting client status: {e}")
        
        return status

# Factory function for easy creation
async def create_rate_limit_manager(redis_url: str = "redis://localhost:6379") -> RateLimitManager:
    """Create and initialize rate limit manager"""
    manager = RateLimitManager(redis_url)
    await manager.initialize()
    return manager

# Export main classes
__all__ = [
    'RateLimitManager',
    'RateLimitRule',
    'RateLimitStatus',
    'AbuseAlert',
    'RateLimitType',
    'AbusePattern',
    'create_rate_limit_manager'
]