"""
Enhanced Circuit Breaker Pattern Implementation
Military-grade circuit breaker with advanced features for production resilience

SECURITY CRITICAL: This component prevents cascading failures and API abuse
PERFORMANCE CRITICAL: Must handle 10k+ requests/second with minimal overhead
"""

import time
import asyncio
import logging
from typing import Dict, Callable, Any, Optional, List, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor
import json

try:
    import pybreaker
    HAS_PYBREAKER = True
except ImportError:
    HAS_PYBREAKER = False
    logging.warning("py-breaker not installed, using enhanced internal implementation")

from core.monitoring.observability import trace_operation
from core.monitoring.structured_logging import get_logger
from core.monitoring.metrics_exporter import MetricsExporter

logger = get_logger(__name__)
metrics = MetricsExporter()


class CircuitState(Enum):
    """Circuit breaker states with enhanced granularity"""
    CLOSED = "closed"              # Normal operation
    OPEN = "open"                  # Failing, rejecting calls
    HALF_OPEN = "half_open"        # Testing if service recovered
    FORCED_OPEN = "forced_open"    # Manually opened for maintenance
    THROTTLED = "throttled"        # Allowing limited traffic


@dataclass
class EnhancedCircuitBreakerConfig:
    """Enhanced configuration with production-grade settings"""
    # Basic thresholds
    failure_threshold: int = 5              # Failures before opening
    success_threshold: int = 3              # Successes to close from half-open
    recovery_timeout: int = 60              # Seconds before trying half-open
    timeout: int = 30                       # Request timeout seconds
    
    # Advanced features
    failure_rate_threshold: float = 0.5     # Open if failure rate exceeds this
    min_throughput: int = 10                # Min calls before calculating failure rate
    throttle_percentage: float = 0.1        # Traffic allowed when throttled
    
    # Sliding window configuration
    window_size: int = 100                  # Number of calls to track
    window_duration: int = 60               # Time window in seconds
    
    # Backoff configuration
    exponential_backoff: bool = True        # Use exponential backoff for recovery
    max_recovery_timeout: int = 300         # Max recovery timeout (5 minutes)
    backoff_factor: float = 2.0            # Exponential backoff multiplier
    
    # Monitoring
    emit_metrics: bool = True               # Send metrics to monitoring
    log_level: str = "WARNING"              # Logging level for state changes
    alert_on_open: bool = True              # Alert when circuit opens
    
    # Fallback configuration
    enable_fallback: bool = True            # Use fallback when open
    cache_fallback_results: bool = True     # Cache successful fallback results
    fallback_cache_ttl: int = 300          # Fallback cache TTL in seconds


class CircuitBreakerMetrics:
    """Track detailed metrics for circuit breaker performance"""
    
    def __init__(self, name: str):
        self.name = name
        self.call_history = deque(maxlen=1000)  # Recent call results
        self.state_changes = deque(maxlen=100)  # State change history
        self.response_times = deque(maxlen=1000)  # Response time tracking
        self.error_types = defaultdict(int)      # Error categorization
        self.last_reset = time.time()
        self._lock = threading.Lock()
    
    def record_call(self, success: bool, duration: float, error: Optional[Exception] = None):
        """Record call result with thread safety"""
        with self._lock:
            timestamp = time.time()
            self.call_history.append({
                'timestamp': timestamp,
                'success': success,
                'duration': duration,
                'error_type': type(error).__name__ if error else None
            })
            
            self.response_times.append(duration)
            
            if error:
                self.error_types[type(error).__name__] += 1
    
    def record_state_change(self, old_state: CircuitState, new_state: CircuitState, reason: str):
        """Record state transition"""
        with self._lock:
            self.state_changes.append({
                'timestamp': time.time(),
                'old_state': old_state.value,
                'new_state': new_state.value,
                'reason': reason
            })
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        with self._lock:
            if not self.call_history:
                return {
                    'name': self.name,
                    'total_calls': 0,
                    'success_rate': 0,
                    'avg_response_time': 0,
                    'error_distribution': {},
                    'recent_state_changes': []
                }
            
            recent_calls = list(self.call_history)
            successes = sum(1 for call in recent_calls if call['success'])
            
            return {
                'name': self.name,
                'total_calls': len(recent_calls),
                'success_rate': (successes / len(recent_calls)) * 100,
                'failure_rate': ((len(recent_calls) - successes) / len(recent_calls)) * 100,
                'avg_response_time': sum(self.response_times) / len(self.response_times) if self.response_times else 0,
                'p50_response_time': self._percentile(self.response_times, 50),
                'p95_response_time': self._percentile(self.response_times, 95),
                'p99_response_time': self._percentile(self.response_times, 99),
                'error_distribution': dict(self.error_types),
                'recent_state_changes': list(self.state_changes)[-5:],
                'uptime_seconds': time.time() - self.last_reset
            }
    
    def _percentile(self, data: deque, percentile: float) -> float:
        """Calculate percentile from deque"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * (percentile / 100))
        return sorted_data[min(index, len(sorted_data) - 1)]


class EnhancedCircuitBreaker:
    """
    Production-grade circuit breaker with advanced features:
    - Sliding window failure detection
    - Exponential backoff recovery
    - Request throttling
    - Fallback strategies
    - Comprehensive metrics
    - Thread-safe operation
    """
    
    def __init__(self, name: str, config: Optional[EnhancedCircuitBreakerConfig] = None):
        self.name = name
        self.config = config or EnhancedCircuitBreakerConfig()
        self.logger = get_logger(f"CircuitBreaker.{name}")
        
        # State management
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.consecutive_failures = 0
        self.last_failure_time = None
        self.last_success_time = None
        self.recovery_attempts = 0
        
        # Sliding window for failure rate calculation
        self.call_results = deque(maxlen=self.config.window_size)
        self.window_start_time = time.time()
        
        # Metrics tracking
        self.metrics = CircuitBreakerMetrics(name)
        
        # Thread safety
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix=f"CB-{name}")
        
        # Fallback cache
        self.fallback_cache: Dict[str, Tuple[Any, float]] = {}
        
        # PyBreaker integration if available
        self.pybreaker = None
        if HAS_PYBREAKER and config.emit_metrics:
            self._setup_pybreaker()
        
        logger.info(f"Enhanced circuit breaker '{name}' initialized", extra={
            'config': self.config.__dict__
        })
    
    def _setup_pybreaker(self):
        """Setup py-breaker integration for additional reliability"""
        self.pybreaker = pybreaker.CircuitBreaker(
            fail_max=self.config.failure_threshold,
            reset_timeout=self.config.recovery_timeout,
            exclude=[KeyboardInterrupt, SystemExit],
            name=f"{self.name}_pybreaker"
        )
    
    @trace_operation("circuit_breaker_execute")
    async def execute(self, func: Callable, *args, fallback: Optional[Callable] = None, **kwargs) -> Any:
        """
        Execute async function with circuit breaker protection
        
        Args:
            func: Async function to execute
            fallback: Optional fallback function when circuit is open
            *args, **kwargs: Arguments for the function
            
        Returns:
            Function result or fallback result
            
        Raises:
            CircuitBreakerError: When circuit is open and no fallback provided
        """
        start_time = time.time()
        
        try:
            # Check circuit state
            with self._lock:
                self._update_state()
                
                if self.state == CircuitState.FORCED_OPEN:
                    raise CircuitBreakerError(f"Circuit breaker {self.name} is forced open for maintenance")
                
                if self.state == CircuitState.OPEN:
                    if fallback and self.config.enable_fallback:
                        return await self._execute_fallback(fallback, args, kwargs)
                    raise CircuitBreakerError(f"Circuit breaker {self.name} is open")
                
                if self.state == CircuitState.THROTTLED:
                    # Allow only a percentage of requests through
                    import random
                    if random.random() > self.config.throttle_percentage:
                        if fallback and self.config.enable_fallback:
                            return await self._execute_fallback(fallback, args, kwargs)
                        raise CircuitBreakerError(f"Circuit breaker {self.name} is throttling requests")
            
            # Execute function with timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.config.timeout
            )
            
            # Record success
            duration = time.time() - start_time
            self._record_success(duration)
            
            return result
            
        except asyncio.TimeoutError as e:
            duration = time.time() - start_time
            self._record_failure(duration, e)
            logger.error(f"Circuit breaker {self.name}: Timeout after {self.config.timeout}s")
            raise
        except Exception as e:
            duration = time.time() - start_time
            self._record_failure(duration, e)
            
            # Try fallback if available
            if fallback and self.config.enable_fallback and self.state != CircuitState.CLOSED:
                try:
                    return await self._execute_fallback(fallback, args, kwargs)
                except Exception as fallback_error:
                    logger.error(f"Fallback also failed for {self.name}: {fallback_error}")
            raise
    
    async def _execute_fallback(self, fallback: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute fallback function with caching"""
        # Check cache first
        cache_key = self._get_cache_key(fallback, args, kwargs)
        if self.config.cache_fallback_results and cache_key in self.fallback_cache:
            cached_result, timestamp = self.fallback_cache[cache_key]
            if time.time() - timestamp < self.config.fallback_cache_ttl:
                logger.debug(f"Returning cached fallback result for {self.name}")
                metrics.increment('circuit_breaker.fallback.cache_hit', tags={'breaker': self.name})
                return cached_result
        
        # Execute fallback
        logger.info(f"Executing fallback for {self.name}")
        metrics.increment('circuit_breaker.fallback.executed', tags={'breaker': self.name})
        
        if asyncio.iscoroutinefunction(fallback):
            result = await fallback(*args, **kwargs)
        else:
            result = fallback(*args, **kwargs)
        
        # Cache result
        if self.config.cache_fallback_results:
            self.fallback_cache[cache_key] = (result, time.time())
        
        return result
    
    def _get_cache_key(self, func: Callable, args: tuple, kwargs: dict) -> str:
        """Generate cache key for fallback results"""
        # Simple cache key generation - can be enhanced
        return f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
    
    def _update_state(self):
        """Update circuit breaker state based on current conditions"""
        current_time = time.time()
        
        if self.state == CircuitState.OPEN:
            # Calculate recovery timeout with exponential backoff
            recovery_timeout = self.config.recovery_timeout
            if self.config.exponential_backoff:
                recovery_timeout = min(
                    self.config.recovery_timeout * (self.config.backoff_factor ** self.recovery_attempts),
                    self.config.max_recovery_timeout
                )
            
            # Check if we should try half-open
            if (self.last_failure_time and 
                current_time - self.last_failure_time >= recovery_timeout):
                self._transition_state(CircuitState.HALF_OPEN, "Recovery timeout reached")
                self.success_count = 0
                self.recovery_attempts += 1
        
        elif self.state == CircuitState.HALF_OPEN:
            # Check if we should close completely
            if self.success_count >= self.config.success_threshold:
                self._transition_state(CircuitState.CLOSED, "Success threshold reached")
                self.failure_count = 0
                self.consecutive_failures = 0
                self.recovery_attempts = 0
        
        elif self.state == CircuitState.CLOSED:
            # Check failure rate in sliding window
            if len(self.call_results) >= self.config.min_throughput:
                failure_rate = self._calculate_failure_rate()
                if failure_rate > self.config.failure_rate_threshold:
                    self._transition_state(CircuitState.OPEN, f"Failure rate {failure_rate:.2%} exceeds threshold")
    
    def _calculate_failure_rate(self) -> float:
        """Calculate failure rate in sliding window"""
        if not self.call_results:
            return 0.0
        
        current_time = time.time()
        window_start = current_time - self.config.window_duration
        
        # Filter calls within time window
        recent_calls = [call for call in self.call_results if call['timestamp'] > window_start]
        
        if not recent_calls:
            return 0.0
        
        failures = sum(1 for call in recent_calls if not call['success'])
        return failures / len(recent_calls)
    
    def _record_success(self, duration: float):
        """Record successful call"""
        with self._lock:
            self.success_count += 1
            self.consecutive_failures = 0
            self.last_success_time = time.time()
            
            # Add to sliding window
            self.call_results.append({
                'timestamp': time.time(),
                'success': True,
                'duration': duration
            })
            
            # Record metrics
            self.metrics.record_call(True, duration)
            
            if self.config.emit_metrics:
                metrics.increment('circuit_breaker.call.success', tags={'breaker': self.name})
                metrics.histogram('circuit_breaker.call.duration', duration, tags={'breaker': self.name})
            
            # Reset failure count on successful calls in closed state
            if self.state == CircuitState.CLOSED:
                self.failure_count = max(0, self.failure_count - 1)
    
    def _record_failure(self, duration: float, error: Exception):
        """Record failed call"""
        with self._lock:
            self.failure_count += 1
            self.consecutive_failures += 1
            self.last_failure_time = time.time()
            
            # Add to sliding window
            self.call_results.append({
                'timestamp': time.time(),
                'success': False,
                'duration': duration,
                'error': str(error)
            })
            
            # Record metrics
            self.metrics.record_call(False, duration, error)
            
            if self.config.emit_metrics:
                metrics.increment('circuit_breaker.call.failure', tags={
                    'breaker': self.name,
                    'error_type': type(error).__name__
                })
            
            # Check if we should open the circuit
            if self.state in [CircuitState.CLOSED, CircuitState.HALF_OPEN]:
                if self.consecutive_failures >= self.config.failure_threshold:
                    self._transition_state(CircuitState.OPEN, f"{self.consecutive_failures} consecutive failures")
                    
                    # Alert if configured
                    if self.config.alert_on_open:
                        self._send_alert(f"Circuit breaker {self.name} opened after {self.consecutive_failures} failures")
    
    def _transition_state(self, new_state: CircuitState, reason: str):
        """Transition to new state with logging and metrics"""
        old_state = self.state
        self.state = new_state
        
        # Record state change
        self.metrics.record_state_change(old_state, new_state, reason)
        
        # Log state change
        log_method = getattr(self.logger, self.config.log_level.lower())
        log_method(f"Circuit breaker {self.name} state change: {old_state.value} -> {new_state.value}", extra={
            'reason': reason,
            'failure_count': self.failure_count,
            'success_count': self.success_count
        })
        
        # Emit metrics
        if self.config.emit_metrics:
            metrics.increment('circuit_breaker.state_change', tags={
                'breaker': self.name,
                'old_state': old_state.value,
                'new_state': new_state.value
            })
    
    def _send_alert(self, message: str):
        """Send alert for critical events"""
        logger.error(f"CIRCUIT BREAKER ALERT: {message}", extra={
            'breaker_name': self.name,
            'state': self.state.value,
            'stats': self.get_stats()
        })
        
        # Could integrate with alerting system here
        if self.config.emit_metrics:
            metrics.increment('circuit_breaker.alert', tags={'breaker': self.name})
    
    def force_open(self, reason: str = "Manual intervention"):
        """Manually open the circuit breaker"""
        with self._lock:
            self._transition_state(CircuitState.FORCED_OPEN, reason)
    
    def force_close(self, reason: str = "Manual intervention"):
        """Manually close the circuit breaker"""
        with self._lock:
            self._transition_state(CircuitState.CLOSED, reason)
            self.failure_count = 0
            self.consecutive_failures = 0
            self.recovery_attempts = 0
    
    def reset(self):
        """Reset circuit breaker to initial state"""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.success_count = 0
            self.consecutive_failures = 0
            self.last_failure_time = None
            self.last_success_time = None
            self.recovery_attempts = 0
            self.call_results.clear()
            self.fallback_cache.clear()
            logger.info(f"Circuit breaker {self.name} reset")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive circuit breaker statistics"""
        with self._lock:
            stats = self.metrics.get_statistics()
            stats.update({
                'state': self.state.value,
                'failure_count': self.failure_count,
                'success_count': self.success_count,
                'consecutive_failures': self.consecutive_failures,
                'recovery_attempts': self.recovery_attempts,
                'last_failure_time': self.last_failure_time,
                'last_success_time': self.last_success_time,
                'failure_rate': self._calculate_failure_rate() * 100,
                'cache_size': len(self.fallback_cache)
            })
            return stats
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker prevents execution"""
    pass


class EnhancedCircuitBreakerManager:
    """
    Centralized manager for all circuit breakers with:
    - Global monitoring and metrics
    - Coordinated state management
    - Health reporting
    - Configuration management
    """
    
    def __init__(self):
        self.breakers: Dict[str, EnhancedCircuitBreaker] = {}
        self.global_config = EnhancedCircuitBreakerConfig()
        self.logger = get_logger("CircuitBreakerManager")
        self._lock = threading.Lock()
        
        # Start monitoring thread
        self._monitoring_thread = threading.Thread(
            target=self._monitor_breakers,
            daemon=True,
            name="CircuitBreakerMonitor"
        )
        self._monitoring_thread.start()
    
    def get_breaker(
        self, 
        name: str, 
        config: Optional[EnhancedCircuitBreakerConfig] = None
    ) -> EnhancedCircuitBreaker:
        """Get or create circuit breaker"""
        with self._lock:
            if name not in self.breakers:
                breaker_config = config or self.global_config
                self.breakers[name] = EnhancedCircuitBreaker(name, breaker_config)
                self.logger.info(f"Created enhanced circuit breaker: {name}")
            return self.breakers[name]
    
    async def execute_with_breaker(
        self,
        name: str,
        func: Callable,
        *args,
        fallback: Optional[Callable] = None,
        config: Optional[EnhancedCircuitBreakerConfig] = None,
        **kwargs
    ) -> Any:
        """Execute function with named circuit breaker"""
        breaker = self.get_breaker(name, config)
        return await breaker.execute(func, *args, fallback=fallback, **kwargs)
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all circuit breakers"""
        with self._lock:
            return {name: breaker.get_stats() for name, breaker in self.breakers.items()}
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status of circuit breakers"""
        stats = self.get_all_stats()
        
        open_breakers = [name for name, stat in stats.items() if stat['state'] == 'open']
        degraded_breakers = [name for name, stat in stats.items() if stat['state'] in ['half_open', 'throttled']]
        
        overall_health = 'healthy'
        if len(open_breakers) > len(self.breakers) * 0.5:
            overall_health = 'critical'
        elif open_breakers or len(degraded_breakers) > len(self.breakers) * 0.3:
            overall_health = 'degraded'
        
        return {
            'overall_health': overall_health,
            'total_breakers': len(self.breakers),
            'open_breakers': open_breakers,
            'degraded_breakers': degraded_breakers,
            'stats': stats
        }
    
    def reset_all(self):
        """Reset all circuit breakers"""
        with self._lock:
            for breaker in self.breakers.values():
                breaker.reset()
            self.logger.info("All circuit breakers reset")
    
    def force_open_all(self, reason: str = "Emergency stop"):
        """Force open all circuit breakers (emergency use)"""
        with self._lock:
            for breaker in self.breakers.values():
                breaker.force_open(reason)
            self.logger.warning(f"All circuit breakers forced open: {reason}")
    
    def _monitor_breakers(self):
        """Background monitoring of circuit breakers"""
        while True:
            try:
                time.sleep(30)  # Check every 30 seconds
                
                health = self.get_health_status()
                
                # Log health status
                if health['overall_health'] == 'critical':
                    self.logger.error("Circuit breaker health CRITICAL", extra=health)
                elif health['overall_health'] == 'degraded':
                    self.logger.warning("Circuit breaker health degraded", extra=health)
                
                # Emit metrics
                if metrics:
                    metrics.gauge('circuit_breaker.total', health['total_breakers'])
                    metrics.gauge('circuit_breaker.open_count', len(health['open_breakers']))
                    metrics.gauge('circuit_breaker.degraded_count', len(health['degraded_breakers']))
                
            except Exception as e:
                self.logger.error(f"Error in circuit breaker monitoring: {e}")


# Global enhanced circuit breaker manager
enhanced_circuit_manager = EnhancedCircuitBreakerManager()


# Convenience decorators
def circuit_breaker(
    name: str,
    config: Optional[EnhancedCircuitBreakerConfig] = None,
    fallback: Optional[Callable] = None
):
    """Decorator to apply circuit breaker to a function"""
    def decorator(func: Callable) -> Callable:
        async def async_wrapper(*args, **kwargs):
            return await enhanced_circuit_manager.execute_with_breaker(
                name, func, *args, fallback=fallback, config=config, **kwargs
            )
        
        def sync_wrapper(*args, **kwargs):
            # For sync functions, we need to handle them differently
            breaker = enhanced_circuit_manager.get_breaker(name, config)
            # This is a simplified version - production would need proper sync handling
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(
                breaker.execute(func, *args, fallback=fallback, **kwargs)
            )
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator