"""
Sync Manager for Monitor Legislativo v4 Desktop App
Handles data synchronization between offline and online systems

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import json
import hashlib

from .offline_storage import OfflineStorage, OfflineRecord, offline_storage
from .conflict_resolver import ConflictResolver, ConflictType, conflict_resolver

logger = logging.getLogger(__name__)

class SyncStatus(Enum):
    """Synchronization status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CONFLICT = "conflict"

class SyncDirection(Enum):
    """Synchronization direction"""
    UPLOAD = "upload"      # Local to remote
    DOWNLOAD = "download"  # Remote to local
    BIDIRECTIONAL = "bidirectional"

@dataclass
class SyncOperation:
    """Represents a sync operation"""
    id: str
    operation_type: str  # create, update, delete
    table: str
    record_id: str
    direction: SyncDirection
    status: SyncStatus
    local_data: Optional[Dict[str, Any]] = None
    remote_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass 
class ConflictResolution:
    """Represents how to resolve a conflict"""
    strategy: str  # "local_wins", "remote_wins", "merge", "manual"
    merged_data: Optional[Dict[str, Any]] = None
    manual_resolution: Optional[Dict[str, Any]] = None

class SyncManager:
    """Manages data synchronization between local and remote"""
    
    def __init__(self, storage: OfflineStorage = None):
        self.storage = storage or offline_storage
        self.conflict_resolver = conflict_resolver
        self.sync_operations: Dict[str, SyncOperation] = {}
        self.sync_callbacks: List[Callable] = []
        self.auto_sync_enabled = True
        self.sync_interval_minutes = 5
        self._sync_task: Optional[asyncio.Task] = None
        self._is_syncing = False
        
        # Sync statistics
        self.stats = {
            "total_syncs": 0,
            "successful_syncs": 0,
            "failed_syncs": 0,
            "conflicts_resolved": 0,
            "last_sync": None,
            "sync_duration_seconds": 0
        }
    
    async def start_auto_sync(self) -> None:
        """Start automatic synchronization"""
        if self._sync_task and not self._sync_task.done():
            return
            
        self.auto_sync_enabled = True
        self._sync_task = asyncio.create_task(self._auto_sync_loop())
        logger.info("Auto-sync started")
    
    async def stop_auto_sync(self) -> None:
        """Stop automatic synchronization"""
        self.auto_sync_enabled = False
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        logger.info("Auto-sync stopped")
    
    async def _auto_sync_loop(self) -> None:
        """Auto-sync loop"""
        while self.auto_sync_enabled:
            try:
                if not self._is_syncing:
                    await self.sync_all()
                
                # Wait for next sync interval
                await asyncio.sleep(self.sync_interval_minutes * 60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto-sync loop: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def sync_all(self, direction: SyncDirection = SyncDirection.BIDIRECTIONAL) -> Dict[str, Any]:
        """Synchronize all data"""
        if self._is_syncing:
            return {"status": "already_syncing"}
            
        self._is_syncing = True
        start_time = datetime.now()
        
        try:
            results = {
                "status": "completed",
                "operations": [],
                "conflicts": [],
                "errors": []
            }
            
            # Get unsynced records
            unsynced_records = await self.storage.database.get_unsynced_records()
            
            # Process upload operations (local changes to remote)
            if direction in [SyncDirection.UPLOAD, SyncDirection.BIDIRECTIONAL]:
                upload_results = await self._sync_uploads(unsynced_records)
                results["operations"].extend(upload_results["operations"])
                results["conflicts"].extend(upload_results["conflicts"])
                results["errors"].extend(upload_results["errors"])
            
            # Process download operations (remote changes to local)
            if direction in [SyncDirection.DOWNLOAD, SyncDirection.BIDIRECTIONAL]:
                download_results = await self._sync_downloads()
                results["operations"].extend(download_results["operations"])
                results["conflicts"].extend(download_results["conflicts"])
                results["errors"].extend(download_results["errors"])
            
            # Update sync metadata
            await self.storage.database.set_metadata("last_sync_time", datetime.now().isoformat())
            
            # Update statistics
            self.stats["total_syncs"] += 1
            if not results["errors"]:
                self.stats["successful_syncs"] += 1
            else:
                self.stats["failed_syncs"] += 1
            
            self.stats["conflicts_resolved"] += len([c for c in results["conflicts"] if c.get("resolved")])
            self.stats["last_sync"] = datetime.now().isoformat()
            self.stats["sync_duration_seconds"] = (datetime.now() - start_time).total_seconds()
            
            # Notify callbacks
            await self._notify_sync_complete(results)
            
            logger.info(f"Sync completed: {len(results['operations'])} operations, "
                       f"{len(results['conflicts'])} conflicts, {len(results['errors'])} errors")
            
            return results
            
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            self.stats["failed_syncs"] += 1
            return {
                "status": "failed",
                "error": str(e),
                "operations": [],
                "conflicts": [],
                "errors": [str(e)]
            }
        finally:
            self._is_syncing = False
    
    async def _sync_uploads(self, unsynced_records: List[OfflineRecord]) -> Dict[str, Any]:
        """Sync local changes to remote"""
        results = {
            "operations": [],
            "conflicts": [],
            "errors": []
        }
        
        for record in unsynced_records:
            try:
                # Simulate API call to sync record
                sync_op = SyncOperation(
                    id=f"upload_{record.id}",
                    operation_type="update" if not record.is_deleted else "delete",
                    table=record.table,
                    record_id=record.id,
                    direction=SyncDirection.UPLOAD,
                    status=SyncStatus.IN_PROGRESS,
                    local_data=record.data
                )
                
                # Simulate remote API call
                success = await self._simulate_remote_sync(sync_op)
                
                if success:
                    sync_op.status = SyncStatus.COMPLETED
                    
                    # Mark record as synced
                    await self.storage.database.mark_synced(
                        record.id, 
                        record.table, 
                        record.sync_version + 1
                    )
                    
                    results["operations"].append({
                        "type": sync_op.operation_type,
                        "table": sync_op.table,
                        "record_id": sync_op.record_id,
                        "status": "success"
                    })
                    
                else:
                    sync_op.status = SyncStatus.FAILED
                    sync_op.error_message = "Remote sync failed"
                    
                    results["errors"].append({
                        "type": sync_op.operation_type,
                        "table": sync_op.table,
                        "record_id": sync_op.record_id,
                        "error": sync_op.error_message
                    })
                
                self.sync_operations[sync_op.id] = sync_op
                
            except Exception as e:
                logger.error(f"Error syncing upload for record {record.id}: {e}")
                results["errors"].append({
                    "type": "upload",
                    "table": record.table,
                    "record_id": record.id,
                    "error": str(e)
                })
        
        return results
    
    async def _sync_downloads(self) -> Dict[str, Any]:
        """Sync remote changes to local"""
        results = {
            "operations": [],
            "conflicts": [],
            "errors": []
        }
        
        try:
            # Simulate getting remote changes
            remote_changes = await self._get_remote_changes()
            
            for change in remote_changes:
                try:
                    # Check for conflicts
                    conflict = await self._detect_conflict(change)
                    
                    if conflict:
                        # Handle conflict
                        resolution = await self.conflict_resolver.resolve_conflict(conflict)
                        
                        if resolution:
                            # Apply resolution
                            await self._apply_conflict_resolution(change, resolution)
                            
                            results["conflicts"].append({
                                "type": conflict.conflict_type.value,
                                "table": change["table"],
                                "record_id": change["id"],
                                "resolution": resolution.strategy,
                                "resolved": True
                            })
                        else:
                            # Manual resolution required
                            results["conflicts"].append({
                                "type": conflict.conflict_type.value,
                                "table": change["table"],
                                "record_id": change["id"],
                                "resolved": False,
                                "requires_manual_resolution": True
                            })
                            continue
                    
                    # Apply change
                    await self._apply_remote_change(change)
                    
                    results["operations"].append({
                        "type": change["operation"],
                        "table": change["table"],
                        "record_id": change["id"],
                        "status": "success"
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing remote change: {e}")
                    results["errors"].append({
                        "type": "download",
                        "table": change.get("table", "unknown"),
                        "record_id": change.get("id", "unknown"),
                        "error": str(e)
                    })
            
        except Exception as e:
            logger.error(f"Error syncing downloads: {e}")
            results["errors"].append({
                "type": "download",
                "error": str(e)
            })
        
        return results
    
    async def _simulate_remote_sync(self, sync_op: SyncOperation) -> bool:
        """Simulate remote API sync (replace with actual API calls)"""
        # Simulate network delay
        await asyncio.sleep(0.1)
        
        # Simulate success rate of 95%
        import random
        return random.random() < 0.95
    
    async def _get_remote_changes(self) -> List[Dict[str, Any]]:
        """Get changes from remote server (simulate)"""
        # Simulate getting remote changes
        # In production, this would call the actual API
        
        # Get last sync time
        last_sync = await self.storage.database.get_metadata("last_sync_time")
        last_sync_time = datetime.fromisoformat(last_sync) if last_sync else datetime.now() - timedelta(days=1)
        
        # Simulate some remote changes
        simulated_changes = [
            {
                "id": "prop_123",
                "table": "propositions",
                "operation": "update",
                "data": {
                    "id": "prop_123",
                    "title": "Updated proposition title",
                    "status": "approved",
                    "updated_at": datetime.now().isoformat()
                },
                "server_version": 2,
                "timestamp": datetime.now().isoformat()
            }
        ]
        
        return simulated_changes
    
    async def _detect_conflict(self, remote_change: Dict[str, Any]) -> Optional[Any]:
        """Detect if remote change conflicts with local data"""
        record_id = remote_change["id"]
        table = remote_change["table"]
        
        # Get local record
        local_record = await self.storage.database.get_record(record_id, table)
        
        if not local_record:
            return None  # No conflict if record doesn't exist locally
        
        # Check if local record has unsynced changes
        if local_record.local_changes:
            # We have a conflict - both local and remote have changes
            from .conflict_resolver import ConflictData
            
            return ConflictData(
                record_id=record_id,
                table=table,
                conflict_type=ConflictType.UPDATE_UPDATE,
                local_data=local_record.data,
                remote_data=remote_change["data"],
                local_timestamp=local_record.updated_at,
                remote_timestamp=datetime.fromisoformat(remote_change["timestamp"])
            )
        
        return None
    
    async def _apply_conflict_resolution(self, 
                                       remote_change: Dict[str, Any], 
                                       resolution: ConflictResolution) -> None:
        """Apply conflict resolution"""
        record_id = remote_change["id"]
        table = remote_change["table"]
        
        if resolution.strategy == "local_wins":
            # Keep local data, mark as synced
            await self.storage.database.mark_synced(record_id, table, remote_change["server_version"])
            
        elif resolution.strategy == "remote_wins":
            # Use remote data
            await self._apply_remote_change(remote_change)
            
        elif resolution.strategy == "merge":
            # Use merged data
            if resolution.merged_data:
                # Update local record with merged data
                local_record = await self.storage.database.get_record(record_id, table)
                if local_record:
                    local_record.data = resolution.merged_data
                    local_record.sync_version = remote_change["server_version"]
                    local_record.local_changes = False
                    local_record.synced_at = datetime.now()
                    
                    await self.storage.database.insert_record(local_record)
    
    async def _apply_remote_change(self, change: Dict[str, Any]) -> None:
        """Apply remote change to local storage"""
        record_id = change["id"]
        table = change["table"]
        operation = change["operation"]
        
        if operation == "create" or operation == "update":
            # Create/update record
            record = OfflineRecord(
                id=record_id,
                table=table,
                data=change["data"],
                created_at=datetime.now(),
                updated_at=datetime.fromisoformat(change["timestamp"]),
                synced_at=datetime.now(),
                sync_version=change["server_version"],
                local_changes=False
            )
            
            await self.storage.database.insert_record(record)
            
        elif operation == "delete":
            # Delete record
            await self.storage.database.delete_record(record_id, table, soft_delete=False)
    
    async def force_sync_record(self, record_id: str, table: str) -> bool:
        """Force sync of specific record"""
        try:
            record = await self.storage.database.get_record(record_id, table)
            if not record:
                return False
            
            sync_op = SyncOperation(
                id=f"force_sync_{record_id}",
                operation_type="update",
                table=table,
                record_id=record_id,
                direction=SyncDirection.UPLOAD,
                status=SyncStatus.IN_PROGRESS,
                local_data=record.data
            )
            
            success = await self._simulate_remote_sync(sync_op)
            
            if success:
                await self.storage.database.mark_synced(record_id, table, record.sync_version + 1)
                sync_op.status = SyncStatus.COMPLETED
            else:
                sync_op.status = SyncStatus.FAILED
            
            self.sync_operations[sync_op.id] = sync_op
            return success
            
        except Exception as e:
            logger.error(f"Error force syncing record {record_id}: {e}")
            return False
    
    async def reset_sync_state(self) -> bool:
        """Reset synchronization state (use with caution)"""
        try:
            # Mark all records as unsynced
            # This would require database operations to reset sync flags
            
            # Clear sync metadata
            await self.storage.database.set_metadata("last_sync_time", None)
            
            # Clear sync operations
            self.sync_operations.clear()
            
            # Reset statistics
            self.stats = {
                "total_syncs": 0,
                "successful_syncs": 0,
                "failed_syncs": 0,
                "conflicts_resolved": 0,
                "last_sync": None,
                "sync_duration_seconds": 0
            }
            
            logger.warning("Sync state reset")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting sync state: {e}")
            return False
    
    def add_sync_callback(self, callback: Callable) -> None:
        """Add callback for sync completion"""
        self.sync_callbacks.append(callback)
    
    def remove_sync_callback(self, callback: Callable) -> None:
        """Remove sync callback"""
        if callback in self.sync_callbacks:
            self.sync_callbacks.remove(callback)
    
    async def _notify_sync_complete(self, results: Dict[str, Any]) -> None:
        """Notify callbacks of sync completion"""
        for callback in self.sync_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(results)
                else:
                    callback(results)
            except Exception as e:
                logger.error(f"Error in sync callback: {e}")
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status"""
        return {
            "is_syncing": self._is_syncing,
            "auto_sync_enabled": self.auto_sync_enabled,
            "sync_interval_minutes": self.sync_interval_minutes,
            "stats": self.stats,
            "pending_operations": len([op for op in self.sync_operations.values() 
                                     if op.status == SyncStatus.PENDING]),
            "failed_operations": len([op for op in self.sync_operations.values() 
                                    if op.status == SyncStatus.FAILED])
        }

# Global sync manager instance
sync_manager = SyncManager()