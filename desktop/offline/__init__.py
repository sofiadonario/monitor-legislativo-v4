"""
Offline-First Capabilities for Monitor Legislativo v4 Desktop App
Enables seamless operation without internet connectivity

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .offline_storage import (
    OfflineStorage,
    OfflineDatabase,
    OfflineFileManager,
    offline_storage
)

from .sync_manager import (
    SyncManager,
    SyncOperation,
    SyncStatus,
    ConflictResolution,
    sync_manager
)

from .offline_cache import (
    OfflineCache,
    CacheEntry,
    CacheStrategy as OfflineCacheStrategy,
    offline_cache
)

from .conflict_resolver import (
    ConflictResolver,
    ConflictType,
    ConflictData,
    AutoResolutionStrategy,
    conflict_resolver
)

from .offline_api import (
    OfflineAPIClient,
    OfflineRequest,
    RequestQueue,
    offline_api_client
)

from .background_sync import (
    BackgroundSyncService,
    SyncScheduler,
    NetworkDetector,
    background_sync_service
)

__all__ = [
    # Storage
    "OfflineStorage",
    "OfflineDatabase", 
    "OfflineFileManager",
    "offline_storage",
    
    # Sync management
    "SyncManager",
    "SyncOperation",
    "SyncStatus",
    "ConflictResolution",
    "sync_manager",
    
    # Cache
    "OfflineCache",
    "CacheEntry",
    "OfflineCacheStrategy",
    "offline_cache",
    
    # Conflict resolution
    "ConflictResolver",
    "ConflictType",
    "ConflictData",
    "AutoResolutionStrategy",
    "conflict_resolver",
    
    # API client
    "OfflineAPIClient",
    "OfflineRequest",
    "RequestQueue",
    "offline_api_client",
    
    # Background sync
    "BackgroundSyncService",
    "SyncScheduler",
    "NetworkDetector",
    "background_sync_service"
]