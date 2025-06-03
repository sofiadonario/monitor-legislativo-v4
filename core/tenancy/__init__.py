"""
Multi-Tenant Support for Monitor Legislativo v4
Provides tenant isolation and management

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .tenant_model import (
    Tenant,
    TenantConfig,
    TenantStatus,
    TenantFeatures,
    TenantLimits,
    TenantIsolationLevel
)

from .tenant_manager import (
    TenantManager,
    TenantContext,
    get_current_tenant,
    set_current_tenant,
    clear_current_tenant,
    tenant_manager
)

from .tenant_middleware import (
    TenantMiddleware,
    TenantContextMiddleware,
    require_tenant,
    get_tenant_from_request
)

from .tenant_database import (
    TenantDatabase,
    TenantConnectionPool,
    get_tenant_db,
    execute_in_tenant_context
)

from .tenant_cache import (
    TenantCache,
    TenantCacheManager,
    get_tenant_cache,
    invalidate_tenant_cache
)

from .tenant_storage import (
    TenantStorage,
    TenantStorageManager,
    get_tenant_storage,
    get_tenant_file_path
)

__all__ = [
    # Tenant models
    "Tenant",
    "TenantConfig",
    "TenantStatus",
    "TenantFeatures",
    "TenantLimits",
    "TenantIsolationLevel",
    
    # Tenant management
    "TenantManager",
    "TenantContext",
    "get_current_tenant",
    "set_current_tenant",
    "clear_current_tenant",
    "tenant_manager",
    
    # Middleware
    "TenantMiddleware",
    "TenantContextMiddleware",
    "require_tenant",
    "get_tenant_from_request",
    
    # Database
    "TenantDatabase",
    "TenantConnectionPool",
    "get_tenant_db",
    "execute_in_tenant_context",
    
    # Cache
    "TenantCache",
    "TenantCacheManager",
    "get_tenant_cache",
    "invalidate_tenant_cache",
    
    # Storage
    "TenantStorage",
    "TenantStorageManager",
    "get_tenant_storage",
    "get_tenant_file_path"
]