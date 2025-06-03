"""
Background Sync Service for Monitor Legislativo v4 Desktop App
Handles automatic synchronization in the background

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
import platform
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import json

from .sync_manager import sync_manager, SyncDirection
from .offline_api import offline_api_client

logger = logging.getLogger(__name__)

class NetworkStatus(Enum):
    """Network connectivity status"""
    ONLINE = "online"
    OFFLINE = "offline"
    LIMITED = "limited"  # Poor connection
    UNKNOWN = "unknown"

class SyncTrigger(Enum):
    """What triggered a sync"""
    SCHEDULED = "scheduled"
    NETWORK_CONNECTED = "network_connected"
    MANUAL = "manual"
    APP_START = "app_start"
    DATA_CHANGED = "data_changed"

@dataclass
class SyncSchedule:
    """Sync scheduling configuration"""
    interval_minutes: int = 15
    retry_interval_minutes: int = 5
    max_retries: int = 3
    sync_on_startup: bool = True
    sync_on_network_connect: bool = True
    sync_on_data_change: bool = False
    peak_hours_start: int = 9  # 9 AM
    peak_hours_end: int = 17   # 5 PM
    reduce_frequency_during_peak: bool = True

class NetworkDetector:
    """Detects network connectivity changes"""
    
    def __init__(self):
        self.current_status = NetworkStatus.UNKNOWN
        self.last_check = datetime.now()
        self.check_interval = 30  # seconds
        self.callbacks: List[Callable] = []
        self._detector_task: Optional[asyncio.Task] = None
        
    async def start(self) -> None:
        """Start network detection"""
        self._detector_task = asyncio.create_task(self._detection_loop())
        logger.info("Network detector started")
    
    async def stop(self) -> None:
        """Stop network detection"""
        if self._detector_task:
            self._detector_task.cancel()
            try:
                await self._detector_task
            except asyncio.CancelledError:
                pass
        logger.info("Network detector stopped")
    
    async def _detection_loop(self) -> None:
        """Main detection loop"""
        while True:
            try:
                old_status = self.current_status
                new_status = await self._check_connectivity()
                
                if old_status != new_status:
                    logger.info(f"Network status changed: {old_status.value} -> {new_status.value}")
                    self.current_status = new_status
                    await self._notify_callbacks(old_status, new_status)
                
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in network detection: {e}")
                await asyncio.sleep(60)
    
    async def _check_connectivity(self) -> NetworkStatus:
        """Check current network connectivity"""
        try:
            # Use the offline API client's connectivity check
            is_online = await offline_api_client.check_connectivity()
            
            if is_online:
                # Could add more sophisticated checks here
                # (e.g., measure latency, bandwidth)
                return NetworkStatus.ONLINE
            else:
                return NetworkStatus.OFFLINE
                
        except Exception as e:
            logger.debug(f"Connectivity check failed: {e}")
            return NetworkStatus.OFFLINE
    
    def add_callback(self, callback: Callable) -> None:
        """Add callback for network status changes"""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable) -> None:
        """Remove network status callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    async def _notify_callbacks(self, old_status: NetworkStatus, new_status: NetworkStatus) -> None:
        """Notify callbacks of status change"""
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(old_status, new_status)
                else:
                    callback(old_status, new_status)
            except Exception as e:
                logger.error(f"Error in network callback: {e}")
    
    def get_status(self) -> NetworkStatus:
        """Get current network status"""
        return self.current_status

class SyncScheduler:
    """Manages sync scheduling"""
    
    def __init__(self, schedule: SyncSchedule = None):
        self.schedule = schedule or SyncSchedule()
        self.last_sync: Optional[datetime] = None
        self.next_sync: Optional[datetime] = None
        self.retry_count = 0
        self.is_running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        
    async def start(self) -> None:
        """Start the scheduler"""
        if self._scheduler_task and not self._scheduler_task.done():
            return
            
        self.is_running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        self._calculate_next_sync()
        logger.info("Sync scheduler started")
    
    async def stop(self) -> None:
        """Stop the scheduler"""
        self.is_running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("Sync scheduler stopped")
    
    async def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.is_running:
            try:
                now = datetime.now()
                
                if self.next_sync and now >= self.next_sync:
                    await self._trigger_sync(SyncTrigger.SCHEDULED)
                
                # Sleep for 1 minute
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync scheduler: {e}")
                await asyncio.sleep(60)
    
    async def _trigger_sync(self, trigger: SyncTrigger) -> None:
        """Trigger a sync operation"""
        try:
            logger.info(f"Triggering sync: {trigger.value}")
            
            # Perform sync
            result = await sync_manager.sync_all()
            
            if result["status"] == "completed" and not result["errors"]:
                # Sync successful
                self.last_sync = datetime.now()
                self.retry_count = 0
                self._calculate_next_sync()
                logger.info("Scheduled sync completed successfully")
            else:
                # Sync failed
                self.retry_count += 1
                if self.retry_count <= self.schedule.max_retries:
                    # Schedule retry
                    retry_delay = self.schedule.retry_interval_minutes
                    self.next_sync = datetime.now() + timedelta(minutes=retry_delay)
                    logger.warning(f"Sync failed, retrying in {retry_delay} minutes (attempt {self.retry_count})")
                else:
                    # Max retries reached
                    self.retry_count = 0
                    self._calculate_next_sync()
                    logger.error("Sync failed after max retries, scheduling next regular sync")
                    
        except Exception as e:
            logger.error(f"Error during triggered sync: {e}")
            self.retry_count += 1
            if self.retry_count <= self.schedule.max_retries:
                retry_delay = self.schedule.retry_interval_minutes
                self.next_sync = datetime.now() + timedelta(minutes=retry_delay)
    
    def _calculate_next_sync(self) -> None:
        """Calculate next sync time"""
        now = datetime.now()
        interval = self.schedule.interval_minutes
        
        # Adjust interval during peak hours if configured
        if self.schedule.reduce_frequency_during_peak and self._is_peak_hours(now):
            interval *= 2  # Double the interval during peak hours
        
        self.next_sync = now + timedelta(minutes=interval)
        logger.debug(f"Next sync scheduled for: {self.next_sync}")
    
    def _is_peak_hours(self, dt: datetime) -> bool:
        """Check if current time is during peak hours"""
        hour = dt.hour
        return self.schedule.peak_hours_start <= hour < self.schedule.peak_hours_end
    
    def force_next_sync(self) -> None:
        """Force next sync to happen immediately"""
        self.next_sync = datetime.now()
        logger.info("Next sync forced to run immediately")
    
    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        return {
            "is_running": self.is_running,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "next_sync": self.next_sync.isoformat() if self.next_sync else None,
            "retry_count": self.retry_count,
            "schedule": {
                "interval_minutes": self.schedule.interval_minutes,
                "retry_interval_minutes": self.schedule.retry_interval_minutes,
                "max_retries": self.schedule.max_retries
            }
        }

class BackgroundSyncService:
    """Main background sync service"""
    
    def __init__(self):
        self.network_detector = NetworkDetector()
        self.scheduler = SyncScheduler()
        self.is_running = False
        
        # Configuration
        self.config = {
            "auto_sync_enabled": True,
            "sync_on_network_change": True,
            "sync_on_app_start": True,
            "battery_optimization": True
        }
        
        # Statistics
        self.stats = {
            "total_syncs": 0,
            "successful_syncs": 0,
            "failed_syncs": 0,
            "network_triggered_syncs": 0,
            "scheduled_syncs": 0,
            "manual_syncs": 0,
            "last_sync_duration": 0,
            "average_sync_duration": 0
        }
        
        # Setup callbacks
        self.network_detector.add_callback(self._on_network_change)
    
    async def start(self) -> None:
        """Start the background sync service"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start components
        await self.network_detector.start()
        
        if self.config["auto_sync_enabled"]:
            await self.scheduler.start()
        
        # Initial sync on startup if configured
        if self.config["sync_on_app_start"]:
            asyncio.create_task(self._initial_sync())
        
        logger.info("Background sync service started")
    
    async def stop(self) -> None:
        """Stop the background sync service"""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Stop components
        await self.network_detector.stop()
        await self.scheduler.stop()
        
        logger.info("Background sync service stopped")
    
    async def _initial_sync(self) -> None:
        """Perform initial sync on startup"""
        try:
            # Wait a bit for app to initialize
            await asyncio.sleep(5)
            
            logger.info("Performing initial sync on startup")
            start_time = datetime.now()
            
            result = await sync_manager.sync_all()
            
            duration = (datetime.now() - start_time).total_seconds()
            self._update_stats("startup", duration, result["status"] == "completed")
            
        except Exception as e:
            logger.error(f"Error in initial sync: {e}")
    
    async def _on_network_change(self, old_status: NetworkStatus, new_status: NetworkStatus) -> None:
        """Handle network status changes"""
        if not self.config["sync_on_network_change"]:
            return
        
        # Trigger sync when going online
        if old_status == NetworkStatus.OFFLINE and new_status == NetworkStatus.ONLINE:
            logger.info("Network connected, triggering sync")
            asyncio.create_task(self._network_triggered_sync())
    
    async def _network_triggered_sync(self) -> None:
        """Perform sync triggered by network reconnection"""
        try:
            start_time = datetime.now()
            
            result = await sync_manager.sync_all()
            
            duration = (datetime.now() - start_time).total_seconds()
            self._update_stats("network", duration, result["status"] == "completed")
            
            self.stats["network_triggered_syncs"] += 1
            
        except Exception as e:
            logger.error(f"Error in network-triggered sync: {e}")
    
    async def manual_sync(self) -> Dict[str, Any]:
        """Manually trigger sync"""
        try:
            logger.info("Manual sync triggered")
            start_time = datetime.now()
            
            result = await sync_manager.sync_all()
            
            duration = (datetime.now() - start_time).total_seconds()
            self._update_stats("manual", duration, result["status"] == "completed")
            
            self.stats["manual_syncs"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Error in manual sync: {e}")
            return {
                "status": "failed",
                "error": str(e)
            }
    
    def _update_stats(self, sync_type: str, duration: float, success: bool) -> None:
        """Update sync statistics"""
        self.stats["total_syncs"] += 1
        self.stats["last_sync_duration"] = duration
        
        if success:
            self.stats["successful_syncs"] += 1
        else:
            self.stats["failed_syncs"] += 1
        
        # Update average duration
        total_duration = (self.stats["average_sync_duration"] * (self.stats["total_syncs"] - 1)) + duration
        self.stats["average_sync_duration"] = total_duration / self.stats["total_syncs"]
        
        if sync_type == "scheduled":
            self.stats["scheduled_syncs"] += 1
    
    def enable_auto_sync(self) -> None:
        """Enable automatic synchronization"""
        self.config["auto_sync_enabled"] = True
        if self.is_running:
            asyncio.create_task(self.scheduler.start())
        logger.info("Auto-sync enabled")
    
    def disable_auto_sync(self) -> None:
        """Disable automatic synchronization"""
        self.config["auto_sync_enabled"] = False
        if self.is_running:
            asyncio.create_task(self.scheduler.stop())
        logger.info("Auto-sync disabled")
    
    def update_config(self, config_updates: Dict[str, Any]) -> None:
        """Update service configuration"""
        self.config.update(config_updates)
        logger.info(f"Background sync config updated: {config_updates}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive service status"""
        return {
            "service": {
                "is_running": self.is_running,
                "config": self.config
            },
            "network": {
                "status": self.network_detector.get_status().value,
                "last_check": self.network_detector.last_check.isoformat()
            },
            "scheduler": self.scheduler.get_status(),
            "sync_manager": sync_manager.get_sync_status(),
            "stats": self.stats
        }
    
    def get_sync_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent sync history"""
        # This would typically come from a persistent log
        # For now, return basic info
        return [{
            "timestamp": datetime.now().isoformat(),
            "type": "placeholder",
            "status": "completed",
            "duration": 1.5
        }]

# Global background sync service
background_sync_service = BackgroundSyncService()

# Convenience functions
async def start_background_sync() -> None:
    """Start background sync service"""
    await background_sync_service.start()

async def stop_background_sync() -> None:
    """Stop background sync service"""
    await background_sync_service.stop()

async def manual_sync() -> Dict[str, Any]:
    """Trigger manual sync"""
    return await background_sync_service.manual_sync()

def get_sync_status() -> Dict[str, Any]:
    """Get current sync status"""
    return background_sync_service.get_status()