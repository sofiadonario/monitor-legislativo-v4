"""
Circuit Breaker Pattern Implementation
Prevents cascading failures when APIs are down
"""

import time
import logging
import asyncio
from typing import Dict, Callable, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting calls
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5      # Failures before opening
    recovery_timeout: int = 60      # Seconds before trying half-open
    success_threshold: int = 3      # Successes needed to close from half-open
    timeout: int = 30              # Request timeout seconds


class CircuitBreaker:
    """Circuit breaker for external API calls"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.logger = logging.getLogger(f"CircuitBreaker.{name}")
        
        # State management
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        
        # Metrics
        self.total_calls = 0
        self.total_failures = 0
        self.total_successes = 0
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute async function with circuit breaker protection"""
        self.total_calls += 1
        
        # Check if circuit should be closed
        self._update_state()
        
        if self.state == CircuitState.OPEN:
            self.logger.warning(f"Circuit breaker {self.name} is OPEN - rejecting call")
            raise CircuitBreakerError(f"Circuit breaker {self.name} is open")
        
        try:
            # Execute function with timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.config.timeout
            )
            
            self._record_success()
            return result
            
        except Exception as e:
            self._record_failure()
            raise
    
    def execute_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute sync function with circuit breaker protection"""
        self.total_calls += 1
        
        # Check if circuit should be closed
        self._update_state()
        
        if self.state == CircuitState.OPEN:
            self.logger.warning(f"Circuit breaker {self.name} is OPEN - rejecting call")
            raise CircuitBreakerError(f"Circuit breaker {self.name} is open")
        
        try:
            # Execute function
            result = func(*args, **kwargs)
            
            self._record_success()
            return result
            
        except Exception as e:
            self._record_failure()
            raise
    
    def _update_state(self):
        """Update circuit breaker state based on current conditions"""
        current_time = time.time()
        
        if self.state == CircuitState.OPEN:
            # Check if we should try half-open
            if (self.last_failure_time and 
                current_time - self.last_failure_time >= self.config.recovery_timeout):
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                self.logger.info(f"Circuit breaker {self.name} moving to HALF_OPEN")
        
        elif self.state == CircuitState.HALF_OPEN:
            # Check if we should close completely
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.logger.info(f"Circuit breaker {self.name} moving to CLOSED")
    
    def _record_success(self):
        """Record successful call"""
        self.total_successes += 1
        self.last_success_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on successful calls
            self.failure_count = max(0, self.failure_count - 1)
    
    def _record_failure(self):
        """Record failed call"""
        self.total_failures += 1
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        # Check if we should open the circuit
        if (self.state in [CircuitState.CLOSED, CircuitState.HALF_OPEN] and 
            self.failure_count >= self.config.failure_threshold):
            self.state = CircuitState.OPEN
            self.logger.warning(f"Circuit breaker {self.name} moving to OPEN after {self.failure_count} failures")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics"""
        return {
            "name": self.name,
            "state": self.state.value,
            "total_calls": self.total_calls,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
            "success_rate": (self.total_successes / self.total_calls * 100) if self.total_calls > 0 else 0
        }
    
    def reset(self):
        """Reset circuit breaker to initial state"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        self.logger.info(f"Circuit breaker {self.name} reset")


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open"""
    pass


# Alias for backward compatibility
CircuitBreakerOpenError = CircuitBreakerError


class CircuitBreakerManager:
    """Manage multiple circuit breakers"""
    
    def __init__(self):
        self.breakers: Dict[str, CircuitBreaker] = {}
        self.logger = logging.getLogger("CircuitBreakerManager")
    
    def get_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create circuit breaker"""
        if name not in self.breakers:
            self.breakers[name] = CircuitBreaker(name, config)
            self.logger.info(f"Created circuit breaker: {name}")
        return self.breakers[name]
    
    def call_with_breaker(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        breaker = self.get_breaker(name)
        # Check if function is async
        if asyncio.iscoroutinefunction(func):
            # Return the coroutine for async functions
            return breaker.execute(func, *args, **kwargs)
        else:
            # Execute sync functions directly
            return breaker.execute_sync(func, *args, **kwargs)
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all circuit breakers"""
        return {name: breaker.get_stats() for name, breaker in self.breakers.items()}
    
    def reset_all(self):
        """Reset all circuit breakers"""
        for breaker in self.breakers.values():
            breaker.reset()
    
    async def call_with_breaker(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with named circuit breaker"""
        breaker = self.get_breaker(name)
        return await breaker.execute(func, *args, **kwargs)


# Global circuit breaker manager
circuit_manager = CircuitBreakerManager()