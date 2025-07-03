"""
Performance Optimization API - Search and caching performance enhancements
Provides comprehensive performance optimization for better scalability
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import hashlib

# Performance monitoring libraries
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not available - system monitoring will be limited")

# Redis for caching optimization
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available - caching optimizations will be limited")

logger = logging.getLogger(__name__)

# Router for performance optimization API
router = APIRouter(prefix="/api/v1/performance-optimization", tags=["Performance Optimization"])

class CacheStrategy(str, Enum):
    """Cache strategies"""
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"
    ADAPTIVE = "adaptive"

class OptimizationLevel(str, Enum):
    """Optimization levels"""
    BASIC = "basic"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"

class PerformanceMetric(str, Enum):
    """Performance metrics to track"""
    RESPONSE_TIME = "response_time"
    CACHE_HIT_RATE = "cache_hit_rate"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"

@dataclass
class CacheConfiguration:
    """Cache configuration settings"""
    strategy: CacheStrategy
    max_size: int
    ttl_seconds: int
    compression_enabled: bool
    serialization_format: str
    eviction_policy: str
    memory_threshold: float

@dataclass
class SearchOptimization:
    """Search optimization settings"""
    index_type: str
    batch_size: int
    parallel_workers: int
    timeout_seconds: float
    result_limit: int
    use_fuzzy_matching: bool
    enable_caching: bool

@dataclass
class PerformanceMetrics:
    """Performance metrics data"""
    timestamp: datetime
    response_times: List[float]
    cache_hit_rate: float
    memory_usage_mb: float
    cpu_usage_percent: float
    active_connections: int
    requests_per_second: float
    error_count: int

@dataclass
class OptimizationResult:
    """Optimization result"""
    optimization_id: str
    level: OptimizationLevel
    improvements: Dict[str, Any]
    before_metrics: PerformanceMetrics
    after_metrics: PerformanceMetrics
    recommendations: List[str]
    processing_time: float

# Pydantic models for API
class CacheOptimizationRequest(BaseModel):
    strategy: CacheStrategy = Field(default=CacheStrategy.ADAPTIVE, description="Cache strategy to use")
    max_memory_mb: int = Field(default=512, description="Maximum cache memory in MB")
    ttl_hours: int = Field(default=24, description="Cache TTL in hours")
    enable_compression: bool = Field(default=True, description="Enable cache compression")

class SearchOptimizationRequest(BaseModel):
    optimization_level: OptimizationLevel = Field(default=OptimizationLevel.STANDARD, description="Optimization level")
    max_results: int = Field(default=1000, description="Maximum search results")
    timeout_seconds: float = Field(default=30.0, description="Search timeout")
    enable_parallel: bool = Field(default=True, description="Enable parallel processing")

class PerformanceAnalysisRequest(BaseModel):
    duration_hours: int = Field(default=24, description="Analysis duration in hours")
    metrics: List[PerformanceMetric] = Field(default=[PerformanceMetric.RESPONSE_TIME], description="Metrics to analyze")
    include_recommendations: bool = Field(default=True, description="Include optimization recommendations")

class PerformanceResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class PerformanceOptimizationProcessor:
    """Performance optimization processor for search and caching"""
    
    def __init__(self):
        self.redis_client = None
        self.cache_configs = {}
        self.search_configs = {}
        self.metrics_history = []
        self.optimization_cache = {}
        
        # Initialize default configurations
        self._init_default_configs()
    
    async def initialize(self) -> bool:
        """Initialize performance optimization processor"""
        try:
            # Initialize Redis connection
            if REDIS_AVAILABLE:
                try:
                    redis_url = "redis://localhost:6379"  # Would use env var in production
                    self.redis_client = redis.from_url(redis_url, decode_responses=True)
                    await self.redis_client.ping()
                    logger.info("✅ Redis connected for performance optimization")
                except Exception as e:
                    logger.warning(f"Redis connection failed: {e}")
                    self.redis_client = None
            
            logger.info("✅ Performance optimization processor initialized")
            return True
            
        except Exception as e:
            logger.error(f"Performance optimization processor initialization failed: {e}")
            return False
    
    async def optimize_cache_performance(
        self,
        strategy: CacheStrategy = CacheStrategy.ADAPTIVE,
        max_memory_mb: int = 512,
        ttl_hours: int = 24,
        enable_compression: bool = True
    ) -> OptimizationResult:
        """Optimize cache performance"""
        
        start_time = time.time()
        
        # Collect before metrics
        before_metrics = await self._collect_current_metrics()
        
        # Generate optimization ID
        opt_id = f"cache_opt_{int(time.time())}"
        
        # Apply cache optimizations
        cache_config = CacheConfiguration(
            strategy=strategy,
            max_size=max_memory_mb * 1024 * 1024,  # Convert to bytes
            ttl_seconds=ttl_hours * 3600,  # Convert to seconds
            compression_enabled=enable_compression,
            serialization_format="json",
            eviction_policy=self._get_eviction_policy(strategy),
            memory_threshold=0.8
        )
        
        # Apply configuration
        improvements = await self._apply_cache_optimizations(cache_config)
        
        # Wait for changes to take effect
        await asyncio.sleep(1)
        
        # Collect after metrics
        after_metrics = await self._collect_current_metrics()
        
        # Generate recommendations
        recommendations = await self._generate_cache_recommendations(
            before_metrics, after_metrics, cache_config
        )
        
        processing_time = time.time() - start_time
        
        result = OptimizationResult(
            optimization_id=opt_id,
            level=OptimizationLevel.STANDARD,
            improvements=improvements,
            before_metrics=before_metrics,
            after_metrics=after_metrics,
            recommendations=recommendations,
            processing_time=processing_time
        )
        
        # Cache result
        self.optimization_cache[opt_id] = result
        
        return result
    
    async def optimize_search_performance(
        self,
        optimization_level: OptimizationLevel = OptimizationLevel.STANDARD,
        max_results: int = 1000,
        timeout_seconds: float = 30.0,
        enable_parallel: bool = True
    ) -> OptimizationResult:
        """Optimize search performance"""
        
        start_time = time.time()
        
        # Collect before metrics
        before_metrics = await self._collect_current_metrics()
        
        # Generate optimization ID
        opt_id = f"search_opt_{int(time.time())}"
        
        # Create search optimization config
        search_config = SearchOptimization(
            index_type=self._get_optimal_index_type(optimization_level),
            batch_size=self._get_optimal_batch_size(optimization_level),
            parallel_workers=self._get_optimal_worker_count(enable_parallel),
            timeout_seconds=timeout_seconds,
            result_limit=max_results,
            use_fuzzy_matching=optimization_level in [OptimizationLevel.STANDARD, OptimizationLevel.AGGRESSIVE],
            enable_caching=True
        )
        
        # Apply search optimizations
        improvements = await self._apply_search_optimizations(search_config)
        
        # Wait for changes to take effect
        await asyncio.sleep(1)
        
        # Collect after metrics
        after_metrics = await self._collect_current_metrics()
        
        # Generate recommendations
        recommendations = await self._generate_search_recommendations(
            before_metrics, after_metrics, search_config
        )
        
        processing_time = time.time() - start_time
        
        result = OptimizationResult(
            optimization_id=opt_id,
            level=optimization_level,
            improvements=improvements,
            before_metrics=before_metrics,
            after_metrics=after_metrics,
            recommendations=recommendations,
            processing_time=processing_time
        )
        
        # Cache result
        self.optimization_cache[opt_id] = result
        
        return result
    
    async def analyze_performance(
        self,
        duration_hours: int = 24,
        metrics: List[PerformanceMetric] = None,
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """Analyze system performance over time"""
        
        if metrics is None:
            metrics = [PerformanceMetric.RESPONSE_TIME, PerformanceMetric.CACHE_HIT_RATE]
        
        # Collect historical metrics
        historical_data = await self._collect_historical_metrics(duration_hours)
        
        # Analyze trends
        trends = self._analyze_performance_trends(historical_data, metrics)
        
        # Identify bottlenecks
        bottlenecks = self._identify_bottlenecks(historical_data)
        
        # Generate recommendations
        recommendations = []
        if include_recommendations:
            recommendations = await self._generate_performance_recommendations(
                trends, bottlenecks
            )
        
        return {
            "analysis_period": f"{duration_hours} hours",
            "metrics_analyzed": [m.value for m in metrics],
            "trends": trends,
            "bottlenecks": bottlenecks,
            "recommendations": recommendations,
            "current_performance": asdict(await self._collect_current_metrics())
        }
    
    async def clear_all_caches(self) -> Dict[str, Any]:
        """Clear all system caches"""
        
        start_time = time.time()
        cleared_caches = []
        
        # Clear Redis cache
        if self.redis_client:
            try:
                keys = await self.redis_client.keys("*")
                if keys:
                    await self.redis_client.delete(*keys)
                    cleared_caches.append(f"Redis ({len(keys)} keys)")
            except Exception as e:
                logger.warning(f"Failed to clear Redis cache: {e}")
        
        # Clear optimization cache
        self.optimization_cache.clear()
        cleared_caches.append("Optimization cache")
        
        # Clear metrics history
        self.metrics_history.clear()
        cleared_caches.append("Metrics history")
        
        processing_time = time.time() - start_time
        
        return {
            "cleared_caches": cleared_caches,
            "processing_time": processing_time,
            "timestamp": datetime.now().isoformat()
        }
    
    # Private helper methods
    def _init_default_configs(self):
        """Initialize default configurations"""
        
        self.cache_configs = {
            "default": CacheConfiguration(
                strategy=CacheStrategy.LRU,
                max_size=512 * 1024 * 1024,  # 512MB
                ttl_seconds=24 * 3600,  # 24 hours
                compression_enabled=True,
                serialization_format="json",
                eviction_policy="allkeys-lru",
                memory_threshold=0.8
            )
        }
        
        self.search_configs = {
            "default": SearchOptimization(
                index_type="btree",
                batch_size=100,
                parallel_workers=4,
                timeout_seconds=30.0,
                result_limit=1000,
                use_fuzzy_matching=True,
                enable_caching=True
            )
        }
    
    async def _collect_current_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        
        # Collect system metrics
        memory_usage = 0
        cpu_usage = 0
        
        if PSUTIL_AVAILABLE:
            memory_usage = psutil.virtual_memory().used / (1024 * 1024)  # MB
            cpu_usage = psutil.cpu_percent(interval=1)
        
        # Simulate other metrics (would collect from actual monitoring in production)
        current_time = datetime.now()
        
        return PerformanceMetrics(
            timestamp=current_time,
            response_times=[0.1, 0.2, 0.15, 0.3, 0.12],  # Simulated
            cache_hit_rate=0.75,  # Simulated
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_usage,
            active_connections=10,  # Simulated
            requests_per_second=50.0,  # Simulated
            error_count=0
        )
    
    async def _collect_historical_metrics(self, duration_hours: int) -> List[PerformanceMetrics]:
        """Collect historical performance metrics"""
        
        # In production, would query from monitoring database
        # For now, simulate historical data
        
        historical_data = []
        current_time = datetime.now()
        
        for i in range(duration_hours):
            timestamp = current_time - timedelta(hours=i)
            
            # Simulate varying performance
            base_response_time = 0.2 + (i % 3) * 0.1
            cache_hit_rate = 0.7 + (i % 5) * 0.05
            
            metrics = PerformanceMetrics(
                timestamp=timestamp,
                response_times=[base_response_time] * 5,
                cache_hit_rate=cache_hit_rate,
                memory_usage_mb=400 + (i % 10) * 20,
                cpu_usage_percent=30 + (i % 8) * 5,
                active_connections=8 + (i % 4),
                requests_per_second=40 + (i % 6) * 5,
                error_count=i % 7  # Occasional errors
            )
            
            historical_data.append(metrics)
        
        return historical_data
    
    def _get_eviction_policy(self, strategy: CacheStrategy) -> str:
        """Get Redis eviction policy for cache strategy"""
        
        policy_mapping = {
            CacheStrategy.LRU: "allkeys-lru",
            CacheStrategy.LFU: "allkeys-lfu",
            CacheStrategy.FIFO: "volatile-lru",  # Closest to FIFO
            CacheStrategy.TTL: "volatile-ttl",
            CacheStrategy.ADAPTIVE: "allkeys-lru"  # Default to LRU
        }
        
        return policy_mapping.get(strategy, "allkeys-lru")
    
    def _get_optimal_index_type(self, level: OptimizationLevel) -> str:
        """Get optimal index type for optimization level"""
        
        index_mapping = {
            OptimizationLevel.BASIC: "hash",
            OptimizationLevel.STANDARD: "btree",
            OptimizationLevel.AGGRESSIVE: "gin",  # Generalized Inverted Index
            OptimizationLevel.CUSTOM: "btree"
        }
        
        return index_mapping.get(level, "btree")
    
    def _get_optimal_batch_size(self, level: OptimizationLevel) -> int:
        """Get optimal batch size for optimization level"""
        
        batch_mapping = {
            OptimizationLevel.BASIC: 50,
            OptimizationLevel.STANDARD: 100,
            OptimizationLevel.AGGRESSIVE: 200,
            OptimizationLevel.CUSTOM: 100
        }
        
        return batch_mapping.get(level, 100)
    
    def _get_optimal_worker_count(self, enable_parallel: bool) -> int:
        """Get optimal worker count"""
        
        if not enable_parallel:
            return 1
        
        if PSUTIL_AVAILABLE:
            cpu_count = psutil.cpu_count()
            return min(cpu_count, 8)  # Cap at 8 workers
        
        return 4  # Default
    
    async def _apply_cache_optimizations(self, config: CacheConfiguration) -> Dict[str, Any]:
        """Apply cache optimizations"""
        
        improvements = {}
        
        # Configure Redis if available
        if self.redis_client:
            try:
                # Set memory policy
                await self.redis_client.config_set("maxmemory-policy", config.eviction_policy)
                
                # Set max memory
                max_memory = f"{config.max_size}mb"
                await self.redis_client.config_set("maxmemory", max_memory)
                
                improvements["redis_configured"] = True
                improvements["eviction_policy"] = config.eviction_policy
                improvements["max_memory"] = max_memory
                
            except Exception as e:
                logger.warning(f"Failed to configure Redis: {e}")
                improvements["redis_configured"] = False
        
        # Store configuration
        self.cache_configs["current"] = config
        improvements["cache_strategy"] = config.strategy.value
        improvements["compression_enabled"] = config.compression_enabled
        
        return improvements
    
    async def _apply_search_optimizations(self, config: SearchOptimization) -> Dict[str, Any]:
        """Apply search optimizations"""
        
        improvements = {}
        
        # Store configuration
        self.search_configs["current"] = config
        
        improvements["index_type"] = config.index_type
        improvements["batch_size"] = config.batch_size
        improvements["parallel_workers"] = config.parallel_workers
        improvements["fuzzy_matching"] = config.use_fuzzy_matching
        improvements["caching_enabled"] = config.enable_caching
        
        return improvements
    
    def _analyze_performance_trends(
        self,
        historical_data: List[PerformanceMetrics],
        metrics: List[PerformanceMetric]
    ) -> Dict[str, Any]:
        """Analyze performance trends"""
        
        trends = {}
        
        if not historical_data:
            return trends
        
        for metric in metrics:
            if metric == PerformanceMetric.RESPONSE_TIME:
                response_times = []
                for data in historical_data:
                    avg_response_time = sum(data.response_times) / len(data.response_times)
                    response_times.append(avg_response_time)
                
                trends["response_time"] = {
                    "current": response_times[0] if response_times else 0,
                    "average": sum(response_times) / len(response_times) if response_times else 0,
                    "trend": "improving" if len(response_times) > 1 and response_times[0] < response_times[-1] else "stable"
                }
            
            elif metric == PerformanceMetric.CACHE_HIT_RATE:
                hit_rates = [data.cache_hit_rate for data in historical_data]
                trends["cache_hit_rate"] = {
                    "current": hit_rates[0] if hit_rates else 0,
                    "average": sum(hit_rates) / len(hit_rates) if hit_rates else 0,
                    "trend": "improving" if len(hit_rates) > 1 and hit_rates[0] > hit_rates[-1] else "stable"
                }
            
            elif metric == PerformanceMetric.MEMORY_USAGE:
                memory_usage = [data.memory_usage_mb for data in historical_data]
                trends["memory_usage"] = {
                    "current": memory_usage[0] if memory_usage else 0,
                    "average": sum(memory_usage) / len(memory_usage) if memory_usage else 0,
                    "trend": "increasing" if len(memory_usage) > 1 and memory_usage[0] > memory_usage[-1] else "stable"
                }
        
        return trends
    
    def _identify_bottlenecks(self, historical_data: List[PerformanceMetrics]) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks"""
        
        bottlenecks = []
        
        if not historical_data:
            return bottlenecks
        
        current_metrics = historical_data[0]
        
        # High response time
        avg_response_time = sum(current_metrics.response_times) / len(current_metrics.response_times)
        if avg_response_time > 0.5:  # 500ms threshold
            bottlenecks.append({
                "type": "high_response_time",
                "severity": "high" if avg_response_time > 1.0 else "medium",
                "value": avg_response_time,
                "description": f"Average response time is {avg_response_time:.2f}s"
            })
        
        # Low cache hit rate
        if current_metrics.cache_hit_rate < 0.5:  # 50% threshold
            bottlenecks.append({
                "type": "low_cache_hit_rate",
                "severity": "high" if current_metrics.cache_hit_rate < 0.3 else "medium",
                "value": current_metrics.cache_hit_rate,
                "description": f"Cache hit rate is {current_metrics.cache_hit_rate:.1%}"
            })
        
        # High memory usage
        if current_metrics.memory_usage_mb > 800:  # 800MB threshold
            bottlenecks.append({
                "type": "high_memory_usage",
                "severity": "high" if current_metrics.memory_usage_mb > 1000 else "medium",
                "value": current_metrics.memory_usage_mb,
                "description": f"Memory usage is {current_metrics.memory_usage_mb:.0f}MB"
            })
        
        # High CPU usage
        if current_metrics.cpu_usage_percent > 80:  # 80% threshold
            bottlenecks.append({
                "type": "high_cpu_usage",
                "severity": "high" if current_metrics.cpu_usage_percent > 90 else "medium",
                "value": current_metrics.cpu_usage_percent,
                "description": f"CPU usage is {current_metrics.cpu_usage_percent:.1f}%"
            })
        
        return bottlenecks
    
    async def _generate_cache_recommendations(
        self,
        before_metrics: PerformanceMetrics,
        after_metrics: PerformanceMetrics,
        config: CacheConfiguration
    ) -> List[str]:
        """Generate cache optimization recommendations"""
        
        recommendations = []
        
        # Cache hit rate improvements
        hit_rate_improvement = after_metrics.cache_hit_rate - before_metrics.cache_hit_rate
        if hit_rate_improvement > 0.1:
            recommendations.append(f"Cache hit rate improved by {hit_rate_improvement:.1%}")
        elif after_metrics.cache_hit_rate < 0.7:
            recommendations.append("Consider increasing cache size or TTL for better hit rate")
        
        # Memory usage
        if after_metrics.memory_usage_mb > before_metrics.memory_usage_mb:
            recommendations.append("Monitor memory usage - cache optimizations increased memory consumption")
        
        # Strategy recommendations
        if config.strategy == CacheStrategy.LRU and after_metrics.cache_hit_rate < 0.6:
            recommendations.append("Consider switching to LFU cache strategy for better hit rate")
        
        # Compression recommendations
        if not config.compression_enabled:
            recommendations.append("Enable cache compression to reduce memory usage")
        
        return recommendations
    
    async def _generate_search_recommendations(
        self,
        before_metrics: PerformanceMetrics,
        after_metrics: PerformanceMetrics,
        config: SearchOptimization
    ) -> List[str]:
        """Generate search optimization recommendations"""
        
        recommendations = []
        
        # Response time improvements
        before_avg = sum(before_metrics.response_times) / len(before_metrics.response_times)
        after_avg = sum(after_metrics.response_times) / len(after_metrics.response_times)
        
        if after_avg < before_avg:
            improvement = ((before_avg - after_avg) / before_avg) * 100
            recommendations.append(f"Search response time improved by {improvement:.1f}%")
        
        # Parallel processing
        if not config.parallel_workers > 1:
            recommendations.append("Enable parallel processing for better search performance")
        
        # Batch size optimization
        if config.batch_size < 100:
            recommendations.append("Consider increasing batch size for bulk operations")
        
        # Caching
        if not config.enable_caching:
            recommendations.append("Enable search result caching for frequently accessed data")
        
        return recommendations
    
    async def _generate_performance_recommendations(
        self,
        trends: Dict[str, Any],
        bottlenecks: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate general performance recommendations"""
        
        recommendations = []
        
        # Address bottlenecks
        for bottleneck in bottlenecks:
            if bottleneck["type"] == "high_response_time":
                recommendations.append("Optimize database queries and enable result caching")
            elif bottleneck["type"] == "low_cache_hit_rate":
                recommendations.append("Increase cache size and optimize cache keys")
            elif bottleneck["type"] == "high_memory_usage":
                recommendations.append("Enable memory compression and review data structures")
            elif bottleneck["type"] == "high_cpu_usage":
                recommendations.append("Scale horizontally or optimize CPU-intensive operations")
        
        # Trend-based recommendations
        if trends.get("response_time", {}).get("trend") == "degrading":
            recommendations.append("Response time is degrading - investigate recent changes")
        
        if trends.get("cache_hit_rate", {}).get("average", 0) < 0.6:
            recommendations.append("Overall cache hit rate is low - review caching strategy")
        
        # General recommendations
        if not recommendations:
            recommendations.append("Performance is within acceptable ranges")
            recommendations.append("Consider implementing proactive monitoring alerts")
        
        return recommendations

# Global performance processor instance
_performance_processor: Optional[PerformanceOptimizationProcessor] = None

async def get_performance_processor() -> PerformanceOptimizationProcessor:
    """Get or create the global performance processor"""
    global _performance_processor
    
    if _performance_processor is None:
        _performance_processor = PerformanceOptimizationProcessor()
        if await _performance_processor.initialize():
            logger.info("✅ Performance optimization processor initialized")
        else:
            logger.warning("⚠️ Performance processor initialized with limited functionality")
    
    return _performance_processor

# API endpoints
@router.post("/optimize-cache", response_model=PerformanceResponse)
async def optimize_cache_endpoint(
    request: CacheOptimizationRequest
) -> PerformanceResponse:
    """Optimize cache performance"""
    try:
        start_time = time.time()
        perf_processor = await get_performance_processor()
        
        result = await perf_processor.optimize_cache_performance(
            strategy=request.strategy,
            max_memory_mb=request.max_memory_mb,
            ttl_hours=request.ttl_hours,
            enable_compression=request.enable_compression
        )
        
        processing_time = time.time() - start_time
        
        return PerformanceResponse(
            success=True,
            data=asdict(result),
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Cache optimization failed: {e}")
        return PerformanceResponse(
            success=False,
            error=str(e)
        )

@router.post("/optimize-search", response_model=PerformanceResponse)
async def optimize_search_endpoint(
    request: SearchOptimizationRequest
) -> PerformanceResponse:
    """Optimize search performance"""
    try:
        perf_processor = await get_performance_processor()
        
        result = await perf_processor.optimize_search_performance(
            optimization_level=request.optimization_level,
            max_results=request.max_results,
            timeout_seconds=request.timeout_seconds,
            enable_parallel=request.enable_parallel
        )
        
        return PerformanceResponse(
            success=True,
            data=asdict(result)
        )
        
    except Exception as e:
        logger.error(f"Search optimization failed: {e}")
        return PerformanceResponse(
            success=False,
            error=str(e)
        )

@router.post("/analyze-performance", response_model=PerformanceResponse)
async def analyze_performance_endpoint(
    request: PerformanceAnalysisRequest
) -> PerformanceResponse:
    """Analyze system performance"""
    try:
        perf_processor = await get_performance_processor()
        
        analysis = await perf_processor.analyze_performance(
            duration_hours=request.duration_hours,
            metrics=request.metrics,
            include_recommendations=request.include_recommendations
        )
        
        return PerformanceResponse(
            success=True,
            data=analysis
        )
        
    except Exception as e:
        logger.error(f"Performance analysis failed: {e}")
        return PerformanceResponse(
            success=False,
            error=str(e)
        )

@router.post("/clear-caches", response_model=PerformanceResponse)
async def clear_caches_endpoint() -> PerformanceResponse:
    """Clear all system caches"""
    try:
        perf_processor = await get_performance_processor()
        
        result = await perf_processor.clear_all_caches()
        
        return PerformanceResponse(
            success=True,
            data=result
        )
        
    except Exception as e:
        logger.error(f"Cache clearing failed: {e}")
        return PerformanceResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def performance_health_status() -> Dict[str, Any]:
    """Get performance optimization system health status"""
    try:
        perf_processor = await get_performance_processor()
        current_metrics = await perf_processor._collect_current_metrics()
        
        return {
            "status": "healthy",
            "redis_available": REDIS_AVAILABLE,
            "psutil_available": PSUTIL_AVAILABLE,
            "current_metrics": asdict(current_metrics),
            "optimization_cache_size": len(perf_processor.optimization_cache),
            "supported_cache_strategies": [cs.value for cs in CacheStrategy],
            "optimization_levels": [ol.value for ol in OptimizationLevel]
        }
        
    except Exception as e:
        logger.error(f"Performance health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_performance_processor"]