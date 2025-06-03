"""
Tenant Manager for Monitor Legislativo v4
Manages tenant lifecycle and context

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import asyncio
from contextvars import ContextVar
import json
import os

from .tenant_model import Tenant, TenantStatus, TenantFeatures, TenantLimits, TenantConfig
from ..database.models import get_db_session
from ..cache.cache_strategy import CacheStrategy
from ..utils.secure_executor import SecureExecutor

logger = logging.getLogger(__name__)

# Context variable for current tenant
_current_tenant: ContextVar[Optional[Tenant]] = ContextVar('current_tenant', default=None)

class TenantContext:
    """Context manager for tenant operations"""
    
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self._token = None
        
    def __enter__(self):
        self._token = _current_tenant.set(self.tenant)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        _current_tenant.reset(self._token)

class TenantManager:
    """Manages tenants and their lifecycle"""
    
    def __init__(self):
        self.tenants_cache: Dict[str, Tenant] = {}
        self.cache_strategy = CacheStrategy()
        self.secure_executor = SecureExecutor()
        self._load_lock = asyncio.Lock()
        
    async def create_tenant(self,
                          name: str,
                          slug: str,
                          admin_email: str,
                          plan: str = "basic",
                          **kwargs) -> Tenant:
        """Create a new tenant"""
        try:
            # Validate slug is unique
            existing = await self.get_tenant_by_slug(slug)
            if existing:
                raise ValueError(f"Tenant with slug '{slug}' already exists")
                
            # Create tenant object
            tenant = Tenant(
                id=f"tenant_{slug}_{datetime.now().timestamp()}",
                name=name,
                slug=slug,
                admin_email=admin_email,
                plan=plan,
                status=TenantStatus.TRIAL,
                trial_ends_at=datetime.now() + timedelta(days=30),
                **kwargs
            )
            
            # Set plan-specific features and limits
            self._apply_plan_settings(tenant, plan)
            
            # Initialize tenant infrastructure
            await self._initialize_tenant_infrastructure(tenant)
            
            # Save to database
            await self._save_tenant(tenant)
            
            # Cache tenant
            self.tenants_cache[tenant.id] = tenant
            
            logger.info(f"Created tenant: {tenant.id} ({tenant.name})")
            return tenant
            
        except Exception as e:
            logger.error(f"Error creating tenant: {e}")
            raise
    
    async def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        # Check cache first
        if tenant_id in self.tenants_cache:
            return self.tenants_cache[tenant_id]
            
        # Load from database
        tenant = await self._load_tenant(tenant_id)
        if tenant:
            self.tenants_cache[tenant_id] = tenant
            
        return tenant
    
    async def get_tenant_by_slug(self, slug: str) -> Optional[Tenant]:
        """Get tenant by slug"""
        # Check cache
        for tenant in self.tenants_cache.values():
            if tenant.slug == slug:
                return tenant
                
        # Load from database
        tenant = await self._load_tenant_by_slug(slug)
        if tenant:
            self.tenants_cache[tenant.id] = tenant
            
        return tenant
    
    async def update_tenant(self, tenant_id: str, updates: Dict[str, Any]) -> Optional[Tenant]:
        """Update tenant settings"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return None
            
        # Apply updates
        for key, value in updates.items():
            if hasattr(tenant, key):
                setattr(tenant, key, value)
                
        tenant.updated_at = datetime.now()
        
        # Save to database
        await self._save_tenant(tenant)
        
        # Update cache
        self.tenants_cache[tenant_id] = tenant
        
        logger.info(f"Updated tenant: {tenant_id}")
        return tenant
    
    async def suspend_tenant(self, tenant_id: str, reason: str = "") -> bool:
        """Suspend a tenant"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False
            
        tenant.status = TenantStatus.SUSPENDED
        tenant.updated_at = datetime.now()
        
        # Add suspension reason to metadata
        tenant.config.metadata["suspension_reason"] = reason
        tenant.config.metadata["suspended_at"] = datetime.now().isoformat()
        
        await self._save_tenant(tenant)
        
        # Clear tenant cache to force reload
        await self._clear_tenant_cache(tenant)
        
        logger.warning(f"Suspended tenant: {tenant_id} - Reason: {reason}")
        return True
    
    async def activate_tenant(self, tenant_id: str) -> bool:
        """Activate a suspended tenant"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False
            
        tenant.status = TenantStatus.ACTIVE
        tenant.updated_at = datetime.now()
        
        # Remove suspension metadata
        tenant.config.metadata.pop("suspension_reason", None)
        tenant.config.metadata.pop("suspended_at", None)
        
        await self._save_tenant(tenant)
        
        logger.info(f"Activated tenant: {tenant_id}")
        return True
    
    async def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant (soft delete)"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False
            
        # Mark as deleted
        tenant.status = TenantStatus.EXPIRED
        tenant.config.metadata["deleted_at"] = datetime.now().isoformat()
        
        await self._save_tenant(tenant)
        
        # Remove from cache
        self.tenants_cache.pop(tenant_id, None)
        
        logger.warning(f"Deleted tenant: {tenant_id}")
        return True
    
    async def update_usage(self, tenant_id: str, usage_type: str, value: Any) -> None:
        """Update tenant usage statistics"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return
            
        # Update usage data
        if usage_type not in tenant.usage_data:
            tenant.usage_data[usage_type] = 0
            
        if isinstance(value, (int, float)):
            tenant.usage_data[usage_type] += value
        else:
            tenant.usage_data[usage_type] = value
            
        # Update last active timestamp
        tenant.last_active_at = datetime.now()
        
        # Check limits
        if not tenant.limits.is_within_limits(tenant.usage_data):
            logger.warning(f"Tenant {tenant_id} exceeding limits")
            # Could trigger alerts or automatic suspension
            
        # Save periodically (not every update for performance)
        if datetime.now().minute % 5 == 0:
            await self._save_tenant(tenant)
    
    async def list_tenants(self, 
                          status: Optional[TenantStatus] = None,
                          plan: Optional[str] = None) -> List[Tenant]:
        """List all tenants with optional filtering"""
        tenants = []
        
        # Load all tenants if needed
        await self._ensure_tenants_loaded()
        
        for tenant in self.tenants_cache.values():
            if status and tenant.status != status:
                continue
            if plan and tenant.plan != plan:
                continue
            tenants.append(tenant)
            
        return sorted(tenants, key=lambda t: t.created_at, reverse=True)
    
    def _apply_plan_settings(self, tenant: Tenant, plan: str) -> None:
        """Apply plan-specific features and limits"""
        plans = {
            "basic": {
                "features": TenantFeatures(
                    max_users=5,
                    max_searches_per_day=500,
                    max_alerts=10,
                    max_exports_per_month=20,
                    enable_ai_analysis=False,
                    enable_custom_branding=False,
                    enable_sso=False,
                    enable_webhook_integration=False
                ),
                "limits": TenantLimits(
                    storage_gb=5.0,
                    bandwidth_gb_per_month=50.0,
                    api_calls_per_minute=30,
                    concurrent_connections=50
                )
            },
            "professional": {
                "features": TenantFeatures(
                    max_users=20,
                    max_searches_per_day=2000,
                    max_alerts=50,
                    max_exports_per_month=100,
                    enable_ai_analysis=True,
                    enable_custom_branding=True,
                    enable_sso=False,
                    enable_webhook_integration=True
                ),
                "limits": TenantLimits(
                    storage_gb=25.0,
                    bandwidth_gb_per_month=250.0,
                    api_calls_per_minute=100,
                    concurrent_connections=200
                )
            },
            "enterprise": {
                "features": TenantFeatures(
                    max_users=1000,
                    max_searches_per_day=10000,
                    max_alerts=500,
                    max_exports_per_month=1000,
                    enable_ai_analysis=True,
                    enable_custom_branding=True,
                    enable_sso=True,
                    enable_webhook_integration=True,
                    enable_slack_integration=True
                ),
                "limits": TenantLimits(
                    storage_gb=100.0,
                    bandwidth_gb_per_month=1000.0,
                    api_calls_per_minute=500,
                    concurrent_connections=1000,
                    max_db_connections=50,
                    max_db_size_gb=50.0
                )
            }
        }
        
        if plan in plans:
            tenant.features = plans[plan]["features"]
            tenant.limits = plans[plan]["limits"]
    
    async def _initialize_tenant_infrastructure(self, tenant: Tenant) -> None:
        """Initialize infrastructure for new tenant"""
        # Create database schema if needed
        if tenant.isolation_level.value in ["schema", "database"]:
            await self._create_tenant_database(tenant)
            
        # Create storage directories
        storage_path = tenant.get_storage_path()
        os.makedirs(f"data/{storage_path}", exist_ok=True)
        os.makedirs(f"data/{storage_path}/exports", exist_ok=True)
        os.makedirs(f"data/{storage_path}/uploads", exist_ok=True)
        
        # Initialize cache namespace
        cache_prefix = tenant.get_cache_prefix()
        await self.cache_strategy.set(f"{cache_prefix}initialized", True, ttl=86400)
    
    async def _create_tenant_database(self, tenant: Tenant) -> None:
        """Create database/schema for tenant"""
        # This would create actual database or schema
        # For now, just log the action
        logger.info(f"Would create database/schema for tenant {tenant.id}")
    
    async def _save_tenant(self, tenant: Tenant) -> None:
        """Save tenant to database"""
        # In production, this would save to actual database
        # For now, save to JSON file
        tenants_file = "data/tenants.json"
        
        async with self._load_lock:
            # Load existing tenants
            tenants_data = {}
            if os.path.exists(tenants_file):
                with open(tenants_file, 'r') as f:
                    tenants_data = json.load(f)
                    
            # Update tenant data
            tenants_data[tenant.id] = tenant.to_dict()
            
            # Save back
            os.makedirs("data", exist_ok=True)
            with open(tenants_file, 'w') as f:
                json.dump(tenants_data, f, indent=2)
    
    async def _load_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Load tenant from database"""
        tenants_file = "data/tenants.json"
        
        if not os.path.exists(tenants_file):
            return None
            
        async with self._load_lock:
            with open(tenants_file, 'r') as f:
                tenants_data = json.load(f)
                
        if tenant_id not in tenants_data:
            return None
            
        return self._tenant_from_dict(tenants_data[tenant_id])
    
    async def _load_tenant_by_slug(self, slug: str) -> Optional[Tenant]:
        """Load tenant by slug from database"""
        tenants_file = "data/tenants.json"
        
        if not os.path.exists(tenants_file):
            return None
            
        async with self._load_lock:
            with open(tenants_file, 'r') as f:
                tenants_data = json.load(f)
                
        for tenant_data in tenants_data.values():
            if tenant_data.get("slug") == slug:
                return self._tenant_from_dict(tenant_data)
                
        return None
    
    def _tenant_from_dict(self, data: Dict[str, Any]) -> Tenant:
        """Create tenant object from dictionary"""
        # Parse dates
        for date_field in ["created_at", "updated_at", "trial_ends_at", 
                          "subscription_ends_at", "last_active_at"]:
            if data.get(date_field):
                data[date_field] = datetime.fromisoformat(data[date_field])
                
        # Parse enums
        data["status"] = TenantStatus(data["status"])
        
        # Create feature and limit objects
        features_data = data.pop("features", {})
        limits_data = data.pop("limits", {})
        config_data = data.pop("config", {})
        
        tenant = Tenant(**data)
        
        # Set features
        for key, value in features_data.items():
            if hasattr(tenant.features, key):
                setattr(tenant.features, key, value)
                
        # Set limits
        for key, value in limits_data.items():
            if hasattr(tenant.limits, key):
                setattr(tenant.limits, key, value)
                
        # Set config
        if "branding" in config_data:
            for key, value in config_data["branding"].items():
                if hasattr(tenant.config, key):
                    setattr(tenant.config, key, value)
                    
        return tenant
    
    async def _ensure_tenants_loaded(self) -> None:
        """Ensure all tenants are loaded into cache"""
        if self.tenants_cache:
            return
            
        tenants_file = "data/tenants.json"
        if not os.path.exists(tenants_file):
            return
            
        async with self._load_lock:
            with open(tenants_file, 'r') as f:
                tenants_data = json.load(f)
                
        for tenant_id, tenant_data in tenants_data.items():
            if tenant_id not in self.tenants_cache:
                self.tenants_cache[tenant_id] = self._tenant_from_dict(tenant_data)
    
    async def _clear_tenant_cache(self, tenant: Tenant) -> None:
        """Clear all cache entries for a tenant"""
        cache_prefix = tenant.get_cache_prefix()
        await self.cache_strategy.invalidate(f"{cache_prefix}*")

# Global tenant manager instance
tenant_manager = TenantManager()

# Helper functions
def get_current_tenant() -> Optional[Tenant]:
    """Get current tenant from context"""
    return _current_tenant.get()

def set_current_tenant(tenant: Tenant) -> None:
    """Set current tenant in context"""
    _current_tenant.set(tenant)

def clear_current_tenant() -> None:
    """Clear current tenant from context"""
    _current_tenant.set(None)