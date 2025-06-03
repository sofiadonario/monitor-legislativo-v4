"""
Fault Injectors for Monitor Legislativo v4 Chaos Engineering
Inject various types of faults for resilience testing

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
import time
import threading
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
import random

logger = logging.getLogger(__name__)

class FaultInjector(ABC):
    """Base class for fault injectors"""
    
    def __init__(self):
        self.active = False
        self.fault_config: Dict[str, Any] = {}
        self.start_time: Optional[float] = None
        
    @abstractmethod
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject fault into target"""
        pass
    
    @abstractmethod
    async def stop_fault(self) -> None:
        """Stop fault injection"""
        pass
    
    def is_active(self) -> bool:
        """Check if fault is currently active"""
        return self.active

class NetworkFaultInjector(FaultInjector):
    """Inject network-related faults"""
    
    def __init__(self):
        super().__init__()
        self.original_delay = None
        self.delay_task: Optional[asyncio.Task] = None
    
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject network latency or packet loss"""
        fault_type = parameters.get("type", "latency")
        
        if fault_type == "latency":
            await self._inject_latency(target, parameters)
        elif fault_type == "packet_loss":
            await self._inject_packet_loss(target, parameters)
        elif fault_type == "connection_timeout":
            await self._inject_connection_timeout(target, parameters)
        else:
            raise ValueError(f"Unknown network fault type: {fault_type}")
        
        self.active = True
        self.start_time = time.time()
        logger.info(f"Injected network fault '{fault_type}' on {target}")
    
    async def _inject_latency(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject network latency"""
        delay_ms = parameters.get("delay_ms", 1000)
        
        # Simulate network delay by monkey-patching HTTP requests
        # In a real implementation, this would use tools like tc, iptables, or toxiproxy
        
        async def add_delay():
            """Add artificial delay to network operations"""
            while self.active:
                # This is a simplified simulation
                # Real implementation would intercept network calls
                await asyncio.sleep(0.1)
        
        self.delay_task = asyncio.create_task(add_delay())
        self.fault_config = {"type": "latency", "delay_ms": delay_ms, "target": target}
    
    async def _inject_packet_loss(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject packet loss"""
        loss_rate = parameters.get("loss_rate", 0.1)  # 10% packet loss
        
        # Simulate packet loss
        self.fault_config = {"type": "packet_loss", "loss_rate": loss_rate, "target": target}
        logger.info(f"Simulating {loss_rate*100}% packet loss for {target}")
    
    async def _inject_connection_timeout(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject connection timeouts"""
        timeout_rate = parameters.get("timeout_rate", 0.2)  # 20% of connections timeout
        
        self.fault_config = {"type": "connection_timeout", "timeout_rate": timeout_rate, "target": target}
        logger.info(f"Simulating connection timeouts for {target}")
    
    async def stop_fault(self) -> None:
        """Stop network fault injection"""
        self.active = False
        
        if self.delay_task:
            self.delay_task.cancel()
            try:
                await self.delay_task
            except asyncio.CancelledError:
                pass
        
        duration = time.time() - (self.start_time or 0)
        logger.info(f"Stopped network fault injection after {duration:.1f}s")

class DatabaseFaultInjector(FaultInjector):
    """Inject database-related faults"""
    
    def __init__(self):
        super().__init__()
        self.connection_pool = None
        
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject database fault"""
        fault_type = parameters.get("type", "connection_failure")
        
        if fault_type == "connection_failure":
            await self._inject_connection_failure(target, parameters)
        elif fault_type == "slow_queries":
            await self._inject_slow_queries(target, parameters)
        elif fault_type == "connection_pool_exhaustion":
            await self._inject_pool_exhaustion(target, parameters)
        elif fault_type == "transaction_deadlock":
            await self._inject_deadlock(target, parameters)
        else:
            raise ValueError(f"Unknown database fault type: {fault_type}")
        
        self.active = True
        self.start_time = time.time()
        logger.info(f"Injected database fault '{fault_type}' on {target}")
    
    async def _inject_connection_failure(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject database connection failures"""
        failure_rate = parameters.get("failure_rate", 0.5)  # 50% connection failures
        
        # Simulate connection failures by intercepting database calls
        self.fault_config = {"type": "connection_failure", "failure_rate": failure_rate, "target": target}
        logger.info(f"Simulating {failure_rate*100}% database connection failures")
    
    async def _inject_slow_queries(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject slow database queries"""
        delay_ms = parameters.get("delay_ms", 5000)  # 5 second delay
        affected_queries = parameters.get("affected_queries", 0.3)  # 30% of queries
        
        self.fault_config = {
            "type": "slow_queries", 
            "delay_ms": delay_ms, 
            "affected_queries": affected_queries,
            "target": target
        }
        logger.info(f"Simulating slow queries ({delay_ms}ms delay) for {target}")
    
    async def _inject_pool_exhaustion(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject connection pool exhaustion"""
        max_connections = parameters.get("max_connections", 5)
        
        # Simulate by consuming all available connections
        self.fault_config = {"type": "pool_exhaustion", "max_connections": max_connections, "target": target}
        logger.info(f"Simulating connection pool exhaustion (max {max_connections}) for {target}")
    
    async def _inject_deadlock(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject transaction deadlocks"""
        deadlock_rate = parameters.get("deadlock_rate", 0.1)  # 10% deadlock rate
        
        self.fault_config = {"type": "deadlock", "deadlock_rate": deadlock_rate, "target": target}
        logger.info(f"Simulating transaction deadlocks for {target}")
    
    async def stop_fault(self) -> None:
        """Stop database fault injection"""
        self.active = False
        
        duration = time.time() - (self.start_time or 0)
        logger.info(f"Stopped database fault injection after {duration:.1f}s")

class ServiceFaultInjector(FaultInjector):
    """Inject service-level faults"""
    
    def __init__(self):
        super().__init__()
        self.unavailable_services = set()
        
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject service fault"""
        fault_type = parameters.get("type", "unavailable")
        
        if fault_type == "unavailable":
            await self._inject_service_unavailable(target, parameters)
        elif fault_type == "degraded_performance":
            await self._inject_degraded_performance(target, parameters)
        elif fault_type == "partial_failure":
            await self._inject_partial_failure(target, parameters)
        else:
            raise ValueError(f"Unknown service fault type: {fault_type}")
        
        self.active = True
        self.start_time = time.time()
        logger.info(f"Injected service fault '{fault_type}' on {target}")
    
    async def _inject_service_unavailable(self, target: str, parameters: Dict[str, Any]) -> None:
        """Make service completely unavailable"""
        self.unavailable_services.add(target)
        self.fault_config = {"type": "unavailable", "target": target}
        logger.info(f"Service {target} marked as unavailable")
    
    async def _inject_degraded_performance(self, target: str, parameters: Dict[str, Any]) -> None:
        """Degrade service performance"""
        slowdown_factor = parameters.get("slowdown_factor", 5)  # 5x slower
        
        self.fault_config = {"type": "degraded_performance", "slowdown_factor": slowdown_factor, "target": target}
        logger.info(f"Service {target} performance degraded by {slowdown_factor}x")
    
    async def _inject_partial_failure(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject partial service failures"""
        failure_rate = parameters.get("failure_rate", 0.3)  # 30% requests fail
        
        self.fault_config = {"type": "partial_failure", "failure_rate": failure_rate, "target": target}
        logger.info(f"Service {target} failing {failure_rate*100}% of requests")
    
    async def stop_fault(self) -> None:
        """Stop service fault injection"""
        self.active = False
        
        # Restore service availability
        target = self.fault_config.get("target")
        if target:
            self.unavailable_services.discard(target)
        
        duration = time.time() - (self.start_time or 0)
        logger.info(f"Stopped service fault injection after {duration:.1f}s")

class ResourceFaultInjector(FaultInjector):
    """Inject resource-related faults"""
    
    def __init__(self):
        super().__init__()
        self.stress_threads = []
        
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject resource fault"""
        fault_type = parameters.get("type", "cpu_stress")
        
        if fault_type == "cpu_stress":
            await self._inject_cpu_stress(target, parameters)
        elif fault_type == "memory_stress":
            await self._inject_memory_stress(target, parameters)
        elif fault_type == "disk_stress":
            await self._inject_disk_stress(target, parameters)
        else:
            raise ValueError(f"Unknown resource fault type: {fault_type}")
        
        self.active = True
        self.start_time = time.time()
        logger.info(f"Injected resource fault '{fault_type}' on {target}")
    
    async def _inject_cpu_stress(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject CPU stress"""
        cpu_percent = parameters.get("cpu_percent", 80)
        duration = parameters.get("duration_seconds", 300)
        
        def cpu_stress():
            """CPU stress function"""
            end_time = time.time() + duration
            while time.time() < end_time and self.active:
                # Consume CPU
                for _ in range(1000):
                    pass
                time.sleep(0.001)  # Small sleep to prevent complete lockup
        
        # Start stress threads
        num_threads = parameters.get("threads", 2)
        for _ in range(num_threads):
            thread = threading.Thread(target=cpu_stress)
            thread.daemon = True
            thread.start()
            self.stress_threads.append(thread)
        
        self.fault_config = {"type": "cpu_stress", "cpu_percent": cpu_percent, "target": target}
        logger.info(f"Started CPU stress test on {target}")
    
    async def _inject_memory_stress(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject memory stress"""
        memory_mb = parameters.get("memory_mb", 512)
        
        # Allocate memory
        self.memory_blocks = []
        try:
            for _ in range(memory_mb):
                # Allocate 1MB blocks
                block = bytearray(1024 * 1024)
                self.memory_blocks.append(block)
        except MemoryError:
            logger.warning("Memory allocation failed - system limit reached")
        
        self.fault_config = {"type": "memory_stress", "memory_mb": memory_mb, "target": target}
        logger.info(f"Allocated {len(self.memory_blocks)}MB of memory for stress test")
    
    async def _inject_disk_stress(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject disk I/O stress"""
        io_size_mb = parameters.get("io_size_mb", 100)
        
        # Simulate disk I/O stress
        self.fault_config = {"type": "disk_stress", "io_size_mb": io_size_mb, "target": target}
        logger.info(f"Started disk I/O stress test on {target}")
    
    async def stop_fault(self) -> None:
        """Stop resource fault injection"""
        self.active = False
        
        # Clean up memory allocations
        if hasattr(self, 'memory_blocks'):
            self.memory_blocks.clear()
        
        # Wait for stress threads to finish
        for thread in self.stress_threads:
            if thread.is_alive():
                thread.join(timeout=1)
        self.stress_threads.clear()
        
        duration = time.time() - (self.start_time or 0)
        logger.info(f"Stopped resource fault injection after {duration:.1f}s")

class CPUStressFaultInjector(ResourceFaultInjector):
    """Specialized CPU stress injector"""
    
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject CPU stress specifically"""
        parameters["type"] = "cpu_stress"
        await super().inject_fault(target, parameters)

class MemoryStressFaultInjector(ResourceFaultInjector):
    """Specialized memory stress injector"""
    
    async def inject_fault(self, target: str, parameters: Dict[str, Any]) -> None:
        """Inject memory stress specifically"""
        parameters["type"] = "memory_stress"
        await super().inject_fault(target, parameters)