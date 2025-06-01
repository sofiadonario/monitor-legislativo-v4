"""Enhanced circuit breaker implementation with comprehensive monitoring and recovery."""

import time
import logging
import threading
from typing import Callable, Any, Dict, Optional, Union
from enum import Enum
from functools import wraps
from datetime import datetime, timedelta
import statistics
from core.utils.metrics_collector import metrics

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""
    pass


class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Union[type, tuple] = Exception,
        success_threshold: int = 3,
        timeout: int = 30,
        monitor_requests: int = 10,
        failure_rate_threshold: float = 0.5
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.monitor_requests = monitor_requests
        self.failure_rate_threshold = failure_rate_threshold


class CircuitBreakerMetrics:
    """Metrics tracking for circuit breaker."""
    
    def __init__(self, name: str):
        self.name = name
        self.total_requests = 0
        self.failed_requests = 0
        self.successful_requests = 0
        self.timeouts = 0
        self.circuit_opened_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.response_times: list = []
        self.recent_failures: list = []
        self._lock = threading.Lock()
    
    def record_success(self, response_time: float):
        """Record successful request."""
        with self._lock:
            self.total_requests += 1
            self.successful_requests += 1
            self.response_times.append(response_time)
            
            # Keep only recent response times (last 100)
            if len(self.response_times) > 100:
                self.response_times = self.response_times[-100:]
    
    def record_failure(self, error_type: str):
        """Record failed request."""
        with self._lock:
            self.total_requests += 1
            self.failed_requests += 1
            self.last_failure_time = datetime.now()
            self.recent_failures.append({
                'time': self.last_failure_time,
                'error_type': error_type
            })
            
            # Keep only recent failures (last 50)
            if len(self.recent_failures) > 50:
                self.recent_failures = self.recent_failures[-50:]
    
    def record_timeout(self):
        """Record timeout."""
        with self._lock:
            self.timeouts += 1
            self.record_failure('timeout')
    
    def record_circuit_opened(self):
        """Record circuit opening."""
        with self._lock:
            self.circuit_opened_count += 1
    
    def get_failure_rate(self, window_minutes: int = 5) -> float:
        """Get failure rate within time window."""
        if self.total_requests == 0:
            return 0.0
        
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        recent_failures = [
            f for f in self.recent_failures 
            if f['time'] > cutoff_time
        ]
        
        # Approximate recent requests (this could be more precise with request tracking)
        recent_requests = max(len(recent_failures) * 2, 1)  # Rough estimation
        
        return len(recent_failures) / recent_requests if recent_requests > 0 else 0.0
    
    def get_average_response_time(self) -> float:
        """Get average response time."""
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        with self._lock:
            return {
                'name': self.name,
                'total_requests': self.total_requests,
                'successful_requests': self.successful_requests,
                'failed_requests': self.failed_requests,
                'failure_rate': self.failed_requests / max(self.total_requests, 1),
                'success_rate': self.successful_requests / max(self.total_requests, 1),
                'timeouts': self.timeouts,
                'circuit_opened_count': self.circuit_opened_count,
                'average_response_time': self.get_average_response_time(),
                'recent_failure_rate': self.get_failure_rate(),
                'last_failure': self.last_failure_time.isoformat() if self.last_failure_time else None
            }


class EnhancedCircuitBreaker:
    """Enhanced circuit breaker with monitoring and adaptive behavior."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0
        self.next_attempt_time = 0
        self.metrics = CircuitBreakerMetrics(name)
        self._lock = threading.Lock()
        
        # Report initial state to metrics
        metrics.set_circuit_breaker_state(self.name, self.state.value)
        
        logger.info(f"Circuit breaker '{name}' initialized in {self.state.value} state")
    
    def _can_attempt_request(self) -> bool:
        """Check if request can be attempted based on current state."""
        current_time = time.time()
        
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            if current_time >= self.next_attempt_time:
                self._transition_to_half_open()
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    def _transition_to_open(self):
        """Transition circuit breaker to OPEN state."""
        with self._lock:
            self.state = CircuitState.OPEN
            self.next_attempt_time = time.time() + self.config.recovery_timeout
            self.metrics.record_circuit_opened()
            
            metrics.set_circuit_breaker_state(self.name, self.state.value)
            
            logger.warning(
                f"Circuit breaker '{self.name}' opened due to {self.failure_count} failures. "
                f"Next attempt in {self.config.recovery_timeout} seconds."
            )
    
    def _transition_to_half_open(self):
        """Transition circuit breaker to HALF_OPEN state."""
        with self._lock:
            self.state = CircuitState.HALF_OPEN
            self.success_count = 0
            
            metrics.set_circuit_breaker_state(self.name, self.state.value)
            
            logger.info(f"Circuit breaker '{self.name}' transitioning to half-open state")
    
    def _transition_to_closed(self):
        """Transition circuit breaker to CLOSED state."""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.success_count = 0
            
            metrics.set_circuit_breaker_state(self.name, self.state.value)
            
            logger.info(f"Circuit breaker '{self.name}' closed - service recovered")
    
    def _record_success(self, response_time: float):
        """Record successful request."""
        with self._lock:
            self.metrics.record_success(response_time)
            
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self._transition_to_closed()
            elif self.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.failure_count = max(0, self.failure_count - 1)
    
    def _record_failure(self, exception: Exception):
        """Record failed request."""
        error_type = type(exception).__name__
        
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            self.metrics.record_failure(error_type)
            
            if self.state == CircuitState.HALF_OPEN:
                # Go back to open state immediately on failure
                self._transition_to_open()
            elif self.state == CircuitState.CLOSED:
                # Check if we should open the circuit
                if self.failure_count >= self.config.failure_threshold:
                    self._transition_to_open()
                elif self.metrics.get_failure_rate() > self.config.failure_rate_threshold:
                    # Also consider failure rate
                    self._transition_to_open()
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        if not self._can_attempt_request():
            self.metrics.record_failure('circuit_open')
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN. "
                f"Next attempt in {self.next_attempt_time - time.time():.1f} seconds."
            )
        
        start_time = time.time()
        
        try:
            # Execute the function with timeout
            result = self._execute_with_timeout(func, *args, **kwargs)
            
            response_time = time.time() - start_time
            self._record_success(response_time)
            
            return result
            
        except Exception as e:
            if isinstance(e, self.config.expected_exception):
                self._record_failure(e)
            
            logger.error(f"Circuit breaker '{self.name}' recorded failure: {e}")
            raise
    
    def _execute_with_timeout(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with timeout protection."""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Function call timed out after {self.config.timeout} seconds")
        
        # Set up timeout (only works on Unix systems)
        try:
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.config.timeout)
            
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Cancel alarm
                return result
            finally:
                signal.signal(signal.SIGALRM, old_handler)
                
        except AttributeError:
            # Windows doesn't support signal.SIGALRM, use simple execution
            return func(*args, **kwargs)
        except TimeoutError:
            self.metrics.record_timeout()
            raise
    
    def get_state(self) -> str:
        """Get current circuit breaker state."""
        return self.state.value
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        base_metrics = self.metrics.get_stats()
        base_metrics.update({
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'next_attempt_time': self.next_attempt_time if self.state == CircuitState.OPEN else None,
            'time_until_next_attempt': max(0, self.next_attempt_time - time.time()) if self.state == CircuitState.OPEN else 0
        })
        return base_metrics
    
    def reset(self):
        """Manually reset circuit breaker to closed state."""
        with self._lock:
            self._transition_to_closed()
            logger.info(f"Circuit breaker '{self.name}' manually reset")
    
    def force_open(self):
        """Manually force circuit breaker to open state."""
        with self._lock:
            self._transition_to_open()
            logger.warning(f"Circuit breaker '{self.name}' manually forced open")


class CircuitBreakerRegistry:
    """Registry to manage multiple circuit breakers."""
    
    def __init__(self):
        self._breakers: Dict[str, EnhancedCircuitBreaker] = {}
        self._lock = threading.Lock()
    
    def get_breaker(self, name: str, config: CircuitBreakerConfig = None) -> EnhancedCircuitBreaker:
        """Get or create circuit breaker by name."""
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = EnhancedCircuitBreaker(name, config)
            return self._breakers[name]
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all circuit breakers."""
        with self._lock:
            return {name: breaker.get_metrics() for name, breaker in self._breakers.items()}
    
    def reset_all(self):
        """Reset all circuit breakers."""
        with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status of all circuit breakers."""
        all_metrics = self.get_all_metrics()
        
        total_breakers = len(all_metrics)
        open_breakers = sum(1 for m in all_metrics.values() if m['state'] == 'open')
        half_open_breakers = sum(1 for m in all_metrics.values() if m['state'] == 'half_open')
        
        overall_health = "healthy"
        if open_breakers > 0:
            overall_health = "degraded" if open_breakers < total_breakers else "unhealthy"
        
        return {
            'overall_health': overall_health,
            'total_breakers': total_breakers,
            'closed_breakers': total_breakers - open_breakers - half_open_breakers,
            'open_breakers': open_breakers,
            'half_open_breakers': half_open_breakers,
            'breaker_details': all_metrics
        }


# Global registry
registry = CircuitBreakerRegistry()


def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    expected_exception: Union[type, tuple] = Exception,
    success_threshold: int = 3,
    timeout: int = 30
):
    """Decorator to apply circuit breaker to a function."""
    def decorator(func: Callable) -> Callable:
        config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception,
            success_threshold=success_threshold,
            timeout=timeout
        )
        
        breaker = registry.get_breaker(name, config)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return breaker.call(func, *args, **kwargs)
        
        # Add breaker reference to function for testing/monitoring
        wrapper._circuit_breaker = breaker
        return wrapper
    
    return decorator


# Convenience functions for common external APIs
def camara_circuit_breaker(func: Callable) -> Callable:
    """Circuit breaker specifically configured for Camara API."""
    return circuit_breaker(
        name="camara_api",
        failure_threshold=3,
        recovery_timeout=30,
        timeout=15
    )(func)


def senado_circuit_breaker(func: Callable) -> Callable:
    """Circuit breaker specifically configured for Senado API."""
    return circuit_breaker(
        name="senado_api",
        failure_threshold=3,
        recovery_timeout=30,
        timeout=15
    )(func)


def planalto_circuit_breaker(func: Callable) -> Callable:
    """Circuit breaker specifically configured for Planalto API."""
    return circuit_breaker(
        name="planalto_api",
        failure_threshold=5,
        recovery_timeout=60,
        timeout=20
    )(func)


def regulatory_circuit_breaker(agency: str):
    """Circuit breaker for regulatory agencies."""
    def decorator(func: Callable) -> Callable:
        return circuit_breaker(
            name=f"{agency}_api",
            failure_threshold=3,
            recovery_timeout=45,
            timeout=20
        )(func)
    return decorator