"""
Tenant Storage Management for Monitor Legislativo v4
Handles file storage isolation per tenant

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import os
import logging
from typing import Optional, BinaryIO, List, Dict, Any
from datetime import datetime
import aiofiles
import shutil
from pathlib import Path

from .tenant_model import Tenant
from .tenant_manager import get_current_tenant

logger = logging.getLogger(__name__)

class TenantStorage:
    """File storage operations with tenant isolation"""
    
    def __init__(self, tenant: Tenant, base_path: str = "data"):
        self.tenant = tenant
        self.base_path = base_path
        self.tenant_path = os.path.join(base_path, tenant.get_storage_path())
        
        # Ensure tenant directory exists
        self._ensure_directories()
    
    def _ensure_directories(self) -> None:
        """Ensure tenant directories exist"""
        directories = [
            self.tenant_path,
            os.path.join(self.tenant_path, "uploads"),
            os.path.join(self.tenant_path, "exports"),
            os.path.join(self.tenant_path, "temp"),
            os.path.join(self.tenant_path, "documents")
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def _make_path(self, relative_path: str) -> str:
        """Make absolute path from relative tenant path"""
        # Sanitize path to prevent directory traversal
        safe_path = os.path.normpath(relative_path)
        if safe_path.startswith('..'):
            raise ValueError("Invalid path: directory traversal not allowed")
            
        return os.path.join(self.tenant_path, safe_path)
    
    async def save_file(self, 
                       file_path: str, 
                       content: bytes,
                       metadata: Optional[Dict[str, Any]] = None) -> str:
        """Save file to tenant storage"""
        # Check storage limits
        if not await self._check_storage_limit(len(content)):
            raise Exception(f"Storage limit exceeded for tenant {self.tenant.id}")
        
        # Make full path
        full_path = self._make_path(file_path)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        # Save file
        async with aiofiles.open(full_path, 'wb') as f:
            await f.write(content)
        
        # Save metadata if provided
        if metadata:
            metadata_path = f"{full_path}.metadata.json"
            metadata['created_at'] = datetime.now().isoformat()
            metadata['size_bytes'] = len(content)
            
            async with aiofiles.open(metadata_path, 'w') as f:
                await f.write(json.dumps(metadata, indent=2))
        
        # Update usage
        await self._update_storage_usage(len(content))
        
        logger.info(f"Saved file {file_path} for tenant {self.tenant.id}")
        return file_path
    
    async def read_file(self, file_path: str) -> bytes:
        """Read file from tenant storage"""
        full_path = self._make_path(file_path)
        
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        async with aiofiles.open(full_path, 'rb') as f:
            content = await f.read()
            
        return content
    
    async def delete_file(self, file_path: str) -> bool:
        """Delete file from tenant storage"""
        full_path = self._make_path(file_path)
        
        if not os.path.exists(full_path):
            return False
        
        # Get file size for usage update
        file_size = os.path.getsize(full_path)
        
        # Delete file
        os.remove(full_path)
        
        # Delete metadata if exists
        metadata_path = f"{full_path}.metadata.json"
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
        
        # Update usage
        await self._update_storage_usage(-file_size)
        
        logger.info(f"Deleted file {file_path} for tenant {self.tenant.id}")
        return True
    
    async def list_files(self, 
                        directory: str = "",
                        pattern: Optional[str] = None) -> List[Dict[str, Any]]:
        """List files in tenant storage"""
        full_path = self._make_path(directory)
        
        if not os.path.exists(full_path):
            return []
        
        files = []
        
        for root, dirs, filenames in os.walk(full_path):
            for filename in filenames:
                # Skip metadata files
                if filename.endswith('.metadata.json'):
                    continue
                    
                # Apply pattern filter if provided
                if pattern and not self._match_pattern(filename, pattern):
                    continue
                
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, self.tenant_path)
                
                # Get file info
                stat = os.stat(file_path)
                
                file_info = {
                    "path": relative_path,
                    "name": filename,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
                
                # Load metadata if exists
                metadata_path = f"{file_path}.metadata.json"
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        file_info.update(metadata)
                
                files.append(file_info)
        
        return sorted(files, key=lambda f: f['modified_at'], reverse=True)
    
    async def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics for tenant"""
        total_size = 0
        file_count = 0
        
        for root, dirs, files in os.walk(self.tenant_path):
            for file in files:
                file_path = os.path.join(root, file)
                total_size += os.path.getsize(file_path)
                file_count += 1
        
        return {
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "total_size_gb": total_size / (1024 * 1024 * 1024),
            "file_count": file_count,
            "limit_gb": self.tenant.limits.storage_gb,
            "usage_percentage": (total_size / (self.tenant.limits.storage_gb * 1024 * 1024 * 1024)) * 100
        }
    
    async def create_export(self, 
                          export_type: str,
                          data: Any,
                          filename: Optional[str] = None) -> str:
        """Create an export file"""
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{export_type}_{timestamp}.json"
        
        # Save to exports directory
        export_path = os.path.join("exports", filename)
        
        # Convert data to bytes
        if isinstance(data, str):
            content = data.encode('utf-8')
        elif isinstance(data, bytes):
            content = data
        else:
            content = json.dumps(data, indent=2, default=str).encode('utf-8')
        
        # Save file
        await self.save_file(export_path, content, {
            "export_type": export_type,
            "created_by": "system"
        })
        
        # Update export count
        from .tenant_manager import tenant_manager
        await tenant_manager.update_usage(
            self.tenant.id,
            "exports_this_month",
            1
        )
        
        return export_path
    
    async def cleanup_temp_files(self, older_than_hours: int = 24) -> int:
        """Clean up temporary files older than specified hours"""
        temp_path = self._make_path("temp")
        deleted_count = 0
        
        if not os.path.exists(temp_path):
            return 0
        
        cutoff_time = datetime.now().timestamp() - (older_than_hours * 3600)
        
        for filename in os.listdir(temp_path):
            file_path = os.path.join(temp_path, filename)
            
            if os.path.isfile(file_path):
                if os.path.getmtime(file_path) < cutoff_time:
                    os.remove(file_path)
                    deleted_count += 1
        
        logger.info(f"Cleaned up {deleted_count} temp files for tenant {self.tenant.id}")
        return deleted_count
    
    async def _check_storage_limit(self, additional_bytes: int) -> bool:
        """Check if adding bytes would exceed storage limit"""
        stats = await self.get_storage_stats()
        
        new_total_gb = (stats['total_size_bytes'] + additional_bytes) / (1024 * 1024 * 1024)
        
        return new_total_gb <= self.tenant.limits.storage_gb
    
    async def _update_storage_usage(self, bytes_delta: int) -> None:
        """Update storage usage for tenant"""
        from .tenant_manager import tenant_manager
        
        current_stats = await self.get_storage_stats()
        
        await tenant_manager.update_usage(
            self.tenant.id,
            "storage_gb",
            current_stats['total_size_gb']
        )
    
    def _match_pattern(self, filename: str, pattern: str) -> bool:
        """Simple pattern matching"""
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)

class TenantStorageManager:
    """Manages storage instances for multiple tenants"""
    
    def __init__(self, base_path: str = "data"):
        self.base_path = base_path
        self.storages: Dict[str, TenantStorage] = {}
        
    def get_storage(self, tenant: Tenant) -> TenantStorage:
        """Get storage instance for tenant"""
        if tenant.id not in self.storages:
            self.storages[tenant.id] = TenantStorage(tenant, self.base_path)
            
        return self.storages[tenant.id]
    
    async def cleanup_all_tenants(self) -> Dict[str, int]:
        """Run cleanup for all tenants"""
        results = {}
        
        for tenant_id, storage in self.storages.items():
            try:
                count = await storage.cleanup_temp_files()
                results[tenant_id] = count
            except Exception as e:
                logger.error(f"Error cleaning up tenant {tenant_id}: {e}")
                results[tenant_id] = -1
                
        return results

# Global storage manager
tenant_storage_manager = TenantStorageManager()

# Helper functions
def get_tenant_storage(tenant: Optional[Tenant] = None) -> TenantStorage:
    """Get storage for tenant"""
    if not tenant:
        tenant = get_current_tenant()
        
    if not tenant:
        raise ValueError("No tenant context available")
        
    return tenant_storage_manager.get_storage(tenant)

def get_tenant_file_path(relative_path: str, tenant: Optional[Tenant] = None) -> str:
    """Get absolute file path for tenant"""
    storage = get_tenant_storage(tenant)
    return storage._make_path(relative_path)

# Import json at the top level
import json