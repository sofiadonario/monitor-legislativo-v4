"""
Retry handler with exponential backoff and circuit breaker
Production-grade error handling for government APIs
"""

import asyncio
import functools
import logging
from datetime import datetime, timedelta
from typing import Callable, Optional, Any, Dict, List
import random

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Circuit breaker pattern for API protection"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open
        self.total_requests = 0
        self.successful_requests = 0
    
    def record_success(self):
        """Record successful call"""
        self.failure_count = 0
        self.state = 'closed'
        self.total_requests += 1
        self.successful_requests += 1
    
    def record_failure(self):
        """Record failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        self.total_requests += 1
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
    
    def can_attempt(self) -> bool:
        """Check if request can be attempted"""
        if self.state == 'closed':
            return True
        
        if self.state == 'open':
            if (datetime.now() - self.last_failure_time).seconds > self.recovery_timeout:
                self.state = 'half-open'
                logger.info("Circuit breaker entering half-open state")
                return True
            return False
        
        return True  # half-open
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics"""
        success_rate = 0
        if self.total_requests > 0:
            success_rate = (self.successful_requests / self.total_requests) * 100
        
        return {
            'state': self.state,
            'failure_count': self.failure_count,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'success_rate': round(success_rate, 2),
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None
        }


class RetryHandler:
    """Advanced retry handler with multiple strategies"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
    
    def get_circuit_breaker(self, service_name: str) -> CircuitBreaker:
        """Get or create circuit breaker for service"""
        if service_name not in self.circuit_breakers:
            self.circuit_breakers[service_name] = CircuitBreaker()
        return self.circuit_breakers[service_name]
    
    async def execute_with_retry(
        self,
        func: Callable,
        service_name: str,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        retryable_exceptions: Optional[List[type]] = None,
        retryable_status_codes: Optional[List[int]] = None
    ) -> Any:
        """
        Execute function with comprehensive retry logic
        
        Args:
            func: Async function to execute
            service_name: Name of the service for circuit breaker
            max_retries: Maximum number of retry attempts
            base_delay: Initial delay between retries
            max_delay: Maximum delay between retries
            exponential_base: Base for exponential backoff
            jitter: Add random jitter to delays
            retryable_exceptions: List of exceptions to retry
            retryable_status_codes: HTTP status codes to retry
        
        Returns:
            Result of function execution
        """
        circuit_breaker = self.get_circuit_breaker(service_name)
        
        if not circuit_breaker.can_attempt():
            raise Exception(f"Circuit breaker is open for {service_name}")
        
        retryable_exceptions = retryable_exceptions or [Exception]
        retryable_status_codes = retryable_status_codes or [429, 500, 502, 503, 504]
        
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                result = await func()
                circuit_breaker.record_success()
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if exception is retryable
                is_retryable = any(isinstance(e, exc_type) for exc_type in retryable_exceptions)
                
                # Check for HTTP status codes
                if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
                    is_retryable = is_retryable or e.response.status_code in retryable_status_codes
                
                if not is_retryable or attempt == max_retries:
                    circuit_breaker.record_failure()
                    logger.error(f"Non-retryable error or max retries reached for {service_name}: {e}")
                    raise
                
                # Calculate delay with exponential backoff
                delay = min(base_delay * (exponential_base ** attempt), max_delay)
                
                # Add jitter
                if jitter:
                    delay = delay * (0.5 + random.random())
                
                logger.warning(
                    f"Retry attempt {attempt + 1}/{max_retries} for {service_name} "
                    f"after {delay:.2f}s delay. Error: {e}"
                )
                
                await asyncio.sleep(delay)
        
        circuit_breaker.record_failure()
        raise last_exception
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all circuit breakers"""
        return {
            service: breaker.get_stats()
            for service, breaker in self.circuit_breakers.items()
        }


# Global retry handler instance
retry_handler = RetryHandler()


def with_retry(
    service_name: str,
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs
):
    """Decorator for adding retry logic to async functions"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **func_kwargs):
            return await retry_handler.execute_with_retry(
                lambda: func(*args, **func_kwargs),
                service_name=service_name,
                max_retries=max_retries,
                base_delay=base_delay,
                **kwargs
            )
        return wrapper
    return decorator


# Specific retry strategies for different scenarios

async def retry_with_backoff(
    func: Callable,
    service_name: str,
    max_retries: int = 5
) -> Any:
    """Retry with exponential backoff for general API calls"""
    return await retry_handler.execute_with_retry(
        func,
        service_name=service_name,
        max_retries=max_retries,
        base_delay=1.0,
        exponential_base=2.0,
        jitter=True
    )


async def retry_rate_limited(
    func: Callable,
    service_name: str,
    max_retries: int = 10
) -> Any:
    """Retry with longer delays for rate-limited APIs"""
    return await retry_handler.execute_with_retry(
        func,
        service_name=service_name,
        max_retries=max_retries,
        base_delay=5.0,
        max_delay=300.0,  # 5 minutes max
        exponential_base=1.5,
        jitter=True,
        retryable_status_codes=[429]
    )


async def retry_government_api(
    func: Callable,
    service_name: str,
    max_retries: int = 7
) -> Any:
    """Specialized retry for Brazilian government APIs"""
    return await retry_handler.execute_with_retry(
        func,
        service_name=service_name,
        max_retries=max_retries,
        base_delay=2.0,
        max_delay=120.0,
        exponential_base=1.8,
        jitter=True,
        retryable_status_codes=[429, 500, 502, 503, 504, 520, 522, 524]
    )


class RetryConfig:
    """Configuration class for different retry strategies"""
    
    LEXML_API = {
        'max_retries': 5,
        'base_delay': 2.0,
        'max_delay': 60.0,
        'exponential_base': 2.0,
        'retryable_status_codes': [429, 500, 502, 503, 504]
    }
    
    CAMARA_API = {
        'max_retries': 3,
        'base_delay': 1.0,
        'max_delay': 30.0,
        'exponential_base': 2.0,
        'retryable_status_codes': [429, 500, 502, 503, 504]
    }
    
    SENADO_API = {
        'max_retries': 4,
        'base_delay': 1.5,
        'max_delay': 45.0,
        'exponential_base': 2.0,
        'retryable_status_codes': [429, 500, 502, 503, 504]
    }
    
    REGULATORY_AGENCIES = {
        'max_retries': 6,
        'base_delay': 3.0,
        'max_delay': 120.0,
        'exponential_base': 1.8,
        'retryable_status_codes': [429, 500, 502, 503, 504, 520, 522, 524]
    }


def get_retry_config(api_name: str) -> Dict[str, Any]:
    """Get retry configuration for specific API"""
    config_map = {
        'lexml': RetryConfig.LEXML_API,
        'camara': RetryConfig.CAMARA_API,
        'senado': RetryConfig.SENADO_API,
        'antt': RetryConfig.REGULATORY_AGENCIES,
        'anac': RetryConfig.REGULATORY_AGENCIES,
        'aneel': RetryConfig.REGULATORY_AGENCIES,
        'anatel': RetryConfig.REGULATORY_AGENCIES,
        'anvisa': RetryConfig.REGULATORY_AGENCIES,
        'ans': RetryConfig.REGULATORY_AGENCIES,
        'ana': RetryConfig.REGULATORY_AGENCIES,
        'ancine': RetryConfig.REGULATORY_AGENCIES,
        'anm': RetryConfig.REGULATORY_AGENCIES,
        'anp': RetryConfig.REGULATORY_AGENCIES,
        'antaq': RetryConfig.REGULATORY_AGENCIES,
        'cade': RetryConfig.REGULATORY_AGENCIES
    }
    
    return config_map.get(api_name, RetryConfig.LEXML_API)


async def execute_with_api_retry(func: Callable, api_name: str) -> Any:
    """Execute function with API-specific retry configuration"""
    config = get_retry_config(api_name)
    
    return await retry_handler.execute_with_retry(
        func,
        service_name=api_name,
        **config
    )


class RetryMetrics:
    """Metrics collection for retry operations"""
    
    def __init__(self):
        self.metrics = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'retries_triggered': 0,
            'circuit_breaker_trips': 0,
            'average_retry_count': 0.0
        }
    
    def record_attempt(self, success: bool, retry_count: int):
        """Record attempt metrics"""
        self.metrics['total_attempts'] += 1
        
        if success:
            self.metrics['successful_attempts'] += 1
        else:
            self.metrics['failed_attempts'] += 1
        
        if retry_count > 0:
            self.metrics['retries_triggered'] += 1
        
        # Update average retry count
        total_retries = self.metrics.get('total_retries', 0) + retry_count
        self.metrics['total_retries'] = total_retries
        
        if self.metrics['total_attempts'] > 0:
            self.metrics['average_retry_count'] = total_retries / self.metrics['total_attempts']
    
    def record_circuit_breaker_trip(self):
        """Record circuit breaker trip"""
        self.metrics['circuit_breaker_trips'] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return self.metrics.copy()
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.metrics = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'retries_triggered': 0,
            'circuit_breaker_trips': 0,
            'average_retry_count': 0.0,
            'total_retries': 0
        }


# Global metrics instance
retry_metrics = RetryMetrics()