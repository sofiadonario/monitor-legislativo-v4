"""
Offline API Client for Monitor Legislativo v4 Desktop App
Handles API requests with offline capabilities

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import json
import uuid

from .offline_storage import offline_storage

logger = logging.getLogger(__name__)

class RequestMethod(Enum):
    """HTTP request methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"

class RequestStatus(Enum):
    """Request status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CACHED = "cached"

@dataclass
class OfflineRequest:
    """Represents an API request that can be queued offline"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    method: RequestMethod = RequestMethod.GET
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, str]] = None
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 30
    cache_duration: Optional[int] = None  # seconds
    error_message: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None

class RequestQueue:
    """Manages queued offline requests"""
    
    def __init__(self):
        self.queue: List[OfflineRequest] = []
        self.completed_requests: Dict[str, OfflineRequest] = {}
        self.max_completed_history = 1000
        
    def add_request(self, request: OfflineRequest) -> str:
        """Add request to queue"""
        self.queue.append(request)
        logger.info(f"Added request to queue: {request.method.value} {request.url}")
        return request.id
    
    def get_pending_requests(self) -> List[OfflineRequest]:
        """Get all pending requests"""
        return [req for req in self.queue if req.status == RequestStatus.PENDING]
    
    def complete_request(self, request_id: str, response_data: Dict[str, Any]) -> bool:
        """Mark request as completed"""
        for i, req in enumerate(self.queue):
            if req.id == request_id:
                req.status = RequestStatus.COMPLETED
                req.response_data = response_data
                
                # Move to completed history
                self.completed_requests[request_id] = req
                self.queue.pop(i)
                
                # Limit completed history size
                if len(self.completed_requests) > self.max_completed_history:
                    oldest_id = min(self.completed_requests.keys(), 
                                  key=lambda x: self.completed_requests[x].created_at)
                    del self.completed_requests[oldest_id]
                
                return True
        return False
    
    def fail_request(self, request_id: str, error_message: str) -> bool:
        """Mark request as failed"""
        for req in self.queue:
            if req.id == request_id:
                req.status = RequestStatus.FAILED
                req.error_message = error_message
                req.retry_count += 1
                
                # Reset to pending if retries available
                if req.retry_count <= req.max_retries:
                    req.status = RequestStatus.PENDING
                    
                return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        pending = len([r for r in self.queue if r.status == RequestStatus.PENDING])
        in_progress = len([r for r in self.queue if r.status == RequestStatus.IN_PROGRESS])
        failed = len([r for r in self.queue if r.status == RequestStatus.FAILED])
        
        return {
            "total_queued": len(self.queue),
            "pending": pending,
            "in_progress": in_progress,
            "failed": failed,
            "completed": len(self.completed_requests)
        }

class OfflineAPIClient:
    """API client with offline capabilities"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.request_queue = RequestQueue()
        self.session: Optional[aiohttp.ClientSession] = None
        self.is_online = False
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.processing_queue = False
        self.queue_processor_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self.online_callbacks: List[Callable] = []
        self.offline_callbacks: List[Callable] = []
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def start(self) -> None:
        """Start the API client"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=10)
        )
        
        # Check initial connectivity
        await self.check_connectivity()
        
        # Start queue processor
        await self.start_queue_processor()
        
        logger.info("Offline API client started")
    
    async def close(self) -> None:
        """Close the API client"""
        await self.stop_queue_processor()
        
        if self.session:
            await self.session.close()
            
        logger.info("Offline API client closed")
    
    async def check_connectivity(self) -> bool:
        """Check if we can connect to the API"""
        try:
            if not self.session:
                return False
                
            async with self.session.get(f"{self.base_url}/health", timeout=5) as response:
                was_online = self.is_online
                self.is_online = response.status == 200
                
                # Trigger callbacks if status changed
                if not was_online and self.is_online:
                    await self._trigger_online_callbacks()
                elif was_online and not self.is_online:
                    await self._trigger_offline_callbacks()
                    
                return self.is_online
                
        except Exception as e:
            was_online = self.is_online
            self.is_online = False
            
            if was_online:
                await self._trigger_offline_callbacks()
                
            logger.debug(f"Connectivity check failed: {e}")
            return False
    
    async def get(self, 
                  endpoint: str,
                  params: Optional[Dict[str, str]] = None,
                  cache_duration: Optional[int] = None,
                  offline_fallback: bool = True) -> Dict[str, Any]:
        """GET request with offline support"""
        
        cache_key = self._get_cache_key("GET", endpoint, params)
        
        # Check cache first
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if self._is_cache_valid(cached, cache_duration):
                logger.debug(f"Returning cached response for GET {endpoint}")
                return cached["data"]
        
        # Try online request
        if self.is_online:
            try:
                url = f"{self.base_url}/{endpoint.lstrip('/')}"
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache successful response
                        if cache_duration:
                            self.cache[cache_key] = {
                                "data": data,
                                "timestamp": datetime.now(),
                                "duration": cache_duration
                            }
                        
                        return data
                    else:
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status
                        )
                        
            except Exception as e:
                logger.warning(f"Online GET request failed: {e}")
                self.is_online = False
        
        # Fallback to offline storage
        if offline_fallback:
            return await self._get_from_offline_storage(endpoint, params)
        
        raise Exception("Request failed and no offline fallback available")
    
    async def post(self,
                   endpoint: str,
                   data: Dict[str, Any],
                   queue_if_offline: bool = True) -> Dict[str, Any]:
        """POST request with offline queueing"""
        
        if self.is_online:
            try:
                url = f"{self.base_url}/{endpoint.lstrip('/')}"
                async with self.session.post(url, json=data) as response:
                    if response.status in [200, 201]:
                        return await response.json()
                    else:
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status
                        )
                        
            except Exception as e:
                logger.warning(f"Online POST request failed: {e}")
                self.is_online = False
        
        # Queue for later if offline
        if queue_if_offline:
            request = OfflineRequest(
                method=RequestMethod.POST,
                url=endpoint,
                data=data
            )
            
            request_id = self.request_queue.add_request(request)
            
            # Store in offline storage for immediate use
            await self._store_pending_change(endpoint, data, "create")
            
            return {
                "id": request_id,
                "status": "queued",
                "message": "Request queued for synchronization when online"
            }
        
        raise Exception("Request failed and queueing is disabled")
    
    async def put(self,
                  endpoint: str,
                  data: Dict[str, Any],
                  queue_if_offline: bool = True) -> Dict[str, Any]:
        """PUT request with offline queueing"""
        
        if self.is_online:
            try:
                url = f"{self.base_url}/{endpoint.lstrip('/')}"
                async with self.session.put(url, json=data) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status
                        )
                        
            except Exception as e:
                logger.warning(f"Online PUT request failed: {e}")
                self.is_online = False
        
        # Queue for later if offline
        if queue_if_offline:
            request = OfflineRequest(
                method=RequestMethod.PUT,
                url=endpoint,
                data=data
            )
            
            request_id = self.request_queue.add_request(request)
            
            # Store in offline storage for immediate use
            await self._store_pending_change(endpoint, data, "update")
            
            return {
                "id": request_id,
                "status": "queued",
                "message": "Request queued for synchronization when online"
            }
        
        raise Exception("Request failed and queueing is disabled")
    
    async def delete(self,
                     endpoint: str,
                     queue_if_offline: bool = True) -> Dict[str, Any]:
        """DELETE request with offline queueing"""
        
        if self.is_online:
            try:
                url = f"{self.base_url}/{endpoint.lstrip('/')}"
                async with self.session.delete(url) as response:
                    if response.status in [200, 204]:
                        return {"status": "deleted"}
                    else:
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status
                        )
                        
            except Exception as e:
                logger.warning(f"Online DELETE request failed: {e}")
                self.is_online = False
        
        # Queue for later if offline
        if queue_if_offline:
            request = OfflineRequest(
                method=RequestMethod.DELETE,
                url=endpoint
            )
            
            request_id = self.request_queue.add_request(request)
            
            # Mark as deleted in offline storage
            await self._store_pending_change(endpoint, {}, "delete")
            
            return {
                "id": request_id,
                "status": "queued",
                "message": "Delete queued for synchronization when online"
            }
        
        raise Exception("Request failed and queueing is disabled")
    
    async def start_queue_processor(self) -> None:
        """Start processing queued requests"""
        if self.queue_processor_task and not self.queue_processor_task.done():
            return
            
        self.processing_queue = True
        self.queue_processor_task = asyncio.create_task(self._process_queue())
        logger.info("Started request queue processor")
    
    async def stop_queue_processor(self) -> None:
        """Stop processing queued requests"""
        self.processing_queue = False
        if self.queue_processor_task:
            self.queue_processor_task.cancel()
            try:
                await self.queue_processor_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped request queue processor")
    
    async def _process_queue(self) -> None:
        """Process queued requests when online"""
        while self.processing_queue:
            try:
                # Check connectivity
                await self.check_connectivity()
                
                if self.is_online:
                    pending_requests = self.request_queue.get_pending_requests()
                    
                    for request in pending_requests[:5]:  # Process 5 at a time
                        await self._process_single_request(request)
                
                # Wait before next iteration
                await asyncio.sleep(10)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in queue processor: {e}")
                await asyncio.sleep(30)  # Wait longer after error
    
    async def _process_single_request(self, request: OfflineRequest) -> None:
        """Process a single queued request"""
        try:
            request.status = RequestStatus.IN_PROGRESS
            
            url = f"{self.base_url}/{request.url.lstrip('/')}"
            
            if request.method == RequestMethod.GET:
                async with self.session.get(url, params=request.params) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.request_queue.complete_request(request.id, data)
                    else:
                        raise Exception(f"HTTP {response.status}")
                        
            elif request.method == RequestMethod.POST:
                async with self.session.post(url, json=request.data) as response:
                    if response.status in [200, 201]:
                        data = await response.json()
                        self.request_queue.complete_request(request.id, data)
                    else:
                        raise Exception(f"HTTP {response.status}")
                        
            elif request.method == RequestMethod.PUT:
                async with self.session.put(url, json=request.data) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.request_queue.complete_request(request.id, data)
                    else:
                        raise Exception(f"HTTP {response.status}")
                        
            elif request.method == RequestMethod.DELETE:
                async with self.session.delete(url) as response:
                    if response.status in [200, 204]:
                        self.request_queue.complete_request(request.id, {"status": "deleted"})
                    else:
                        raise Exception(f"HTTP {response.status}")
            
            logger.info(f"Successfully processed queued request: {request.method.value} {request.url}")
            
        except Exception as e:
            error_msg = str(e)
            self.request_queue.fail_request(request.id, error_msg)
            logger.error(f"Failed to process request {request.id}: {error_msg}")
    
    def _get_cache_key(self, method: str, endpoint: str, params: Optional[Dict] = None) -> str:
        """Generate cache key for request"""
        import hashlib
        
        key_data = f"{method}:{endpoint}"
        if params:
            key_data += f":{json.dumps(params, sort_keys=True)}"
            
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_cache_valid(self, cached: Dict[str, Any], cache_duration: Optional[int]) -> bool:
        """Check if cached data is still valid"""
        if not cache_duration:
            cache_duration = cached.get("duration", 300)  # Default 5 minutes
            
        age_seconds = (datetime.now() - cached["timestamp"]).total_seconds()
        return age_seconds < cache_duration
    
    async def _get_from_offline_storage(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Get data from offline storage"""
        # This is a simplified implementation
        # In practice, you'd map endpoints to storage tables/queries
        
        if "propositions" in endpoint:
            search_query = params.get("q") if params else None
            propositions = await offline_storage.get_propositions(limit=100, search_query=search_query)
            return {"propositions": propositions}
        
        # Return empty result for unknown endpoints
        return {"data": [], "message": "Offline data not available"}
    
    async def _store_pending_change(self, endpoint: str, data: Dict[str, Any], operation: str) -> None:
        """Store pending change in offline storage"""
        # This is a simplified implementation
        # Map endpoints to appropriate storage operations
        
        if "propositions" in endpoint and operation in ["create", "update"]:
            if "id" in data:
                if operation == "create":
                    await offline_storage.store_proposition(data)
                else:  # update
                    await offline_storage.update_proposition(str(data["id"]), data)
    
    async def _trigger_online_callbacks(self) -> None:
        """Trigger callbacks when going online"""
        for callback in self.online_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                logger.error(f"Error in online callback: {e}")
    
    async def _trigger_offline_callbacks(self) -> None:
        """Trigger callbacks when going offline"""
        for callback in self.offline_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                logger.error(f"Error in offline callback: {e}")
    
    def add_online_callback(self, callback: Callable) -> None:
        """Add callback for when API goes online"""
        self.online_callbacks.append(callback)
    
    def add_offline_callback(self, callback: Callable) -> None:
        """Add callback for when API goes offline"""
        self.offline_callbacks.append(callback)
    
    def get_status(self) -> Dict[str, Any]:
        """Get API client status"""
        return {
            "is_online": self.is_online,
            "processing_queue": self.processing_queue,
            "queue_stats": self.request_queue.get_stats(),
            "cache_entries": len(self.cache),
            "base_url": self.base_url
        }

# Global offline API client
offline_api_client = OfflineAPIClient()