"""
Tenant Management Routes for Monitor Legislativo v4
API endpoints for tenant administration

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel

from core.tenancy import (
    tenant_manager,
    Tenant,
    TenantStatus,
    TenantFeatures,
    TenantLimits,
    TenantConfig,
    get_current_tenant,
    require_tenant
)
from core.auth.decorators import require_auth, require_admin
from core.tenancy.tenant_cache import get_tenant_cache
from core.tenancy.tenant_storage import get_tenant_storage

router = APIRouter(tags=["tenants"])

class CreateTenantRequest(BaseModel):
    """Request model for creating tenant"""
    name: str
    slug: str
    admin_email: str
    admin_name: str
    organization: Optional[str] = None
    plan: str = "basic"

class UpdateTenantRequest(BaseModel):
    """Request model for updating tenant"""
    name: Optional[str] = None
    admin_email: Optional[str] = None
    admin_name: Optional[str] = None
    organization: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None

class TenantConfigUpdate(BaseModel):
    """Request model for updating tenant configuration"""
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    logo_url: Optional[str] = None
    default_language: Optional[str] = None
    timezone: Optional[str] = None
    notification_email: Optional[str] = None
    webhook_url: Optional[str] = None

@router.post("/tenants", status_code=status.HTTP_201_CREATED)
async def create_tenant(
    request: CreateTenantRequest,
    _admin = Depends(require_admin)
):
    """
    Create a new tenant (requires admin)
    """
    try:
        tenant = await tenant_manager.create_tenant(
            name=request.name,
            slug=request.slug,
            admin_email=request.admin_email,
            admin_name=request.admin_name,
            organization=request.organization,
            plan=request.plan
        )
        
        return {
            "message": "Tenant created successfully",
            "tenant": tenant.to_dict()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating tenant: {str(e)}")

@router.get("/tenants")
async def list_tenants(
    status_filter: Optional[str] = Query(None, alias="status"),
    plan: Optional[str] = None,
    _admin = Depends(require_admin)
):
    """
    List all tenants with optional filtering (requires admin)
    """
    try:
        # Parse status filter
        status_enum = None
        if status_filter:
            try:
                status_enum = TenantStatus(status_filter)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")
        
        tenants = await tenant_manager.list_tenants(status=status_enum, plan=plan)
        
        return {
            "tenants": [tenant.to_dict() for tenant in tenants],
            "count": len(tenants)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tenants/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    _admin = Depends(require_admin)
):
    """
    Get tenant details (requires admin)
    """
    tenant = await tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    return tenant.to_dict()

@router.put("/tenants/{tenant_id}")
async def update_tenant(
    tenant_id: str,
    request: UpdateTenantRequest,
    _admin = Depends(require_admin)
):
    """
    Update tenant details (requires admin)
    """
    try:
        # Prepare updates
        updates = {}
        for field, value in request.dict(exclude_unset=True).items():
            if field == "status" and value:
                try:
                    updates[field] = TenantStatus(value)
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"Invalid status: {value}")
            else:
                updates[field] = value
        
        tenant = await tenant_manager.update_tenant(tenant_id, updates)
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
            
        return {
            "message": "Tenant updated successfully",
            "tenant": tenant.to_dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/tenants/{tenant_id}/suspend")
async def suspend_tenant(
    tenant_id: str,
    reason: str = "Administrative action",
    _admin = Depends(require_admin)
):
    """
    Suspend a tenant (requires admin)
    """
    success = await tenant_manager.suspend_tenant(tenant_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    return {"message": "Tenant suspended successfully"}

@router.post("/tenants/{tenant_id}/activate")
async def activate_tenant(
    tenant_id: str,
    _admin = Depends(require_admin)
):
    """
    Activate a suspended tenant (requires admin)
    """
    success = await tenant_manager.activate_tenant(tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    return {"message": "Tenant activated successfully"}

@router.delete("/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    _admin = Depends(require_admin)
):
    """
    Delete a tenant (requires admin)
    """
    success = await tenant_manager.delete_tenant(tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    return {"message": "Tenant deleted successfully"}

@router.get("/tenant/current")
async def get_current_tenant_info(_auth = Depends(require_auth)):
    """
    Get current tenant information (requires authentication)
    """
    tenant = get_current_tenant()
    if not tenant:
        raise HTTPException(status_code=400, detail="No tenant context")
        
    return tenant.to_dict()

@router.put("/tenant/config")
async def update_tenant_config(
    request: TenantConfigUpdate,
    _auth = Depends(require_auth)
):
    """
    Update current tenant configuration (requires authentication)
    """
    tenant = get_current_tenant()
    if not tenant:
        raise HTTPException(status_code=400, detail="No tenant context")
    
    try:
        # Update configuration
        config_updates = request.dict(exclude_unset=True)
        
        for field, value in config_updates.items():
            if hasattr(tenant.config, field):
                setattr(tenant.config, field, value)
        
        # Save updates
        await tenant_manager.update_tenant(tenant.id, {"config": tenant.config})
        
        return {
            "message": "Configuration updated successfully",
            "config": tenant.config.to_dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tenant/usage")
async def get_tenant_usage(_auth = Depends(require_auth)):
    """
    Get current tenant usage statistics (requires authentication)
    """
    tenant = get_current_tenant()
    if not tenant:
        raise HTTPException(status_code=400, detail="No tenant context")
    
    try:
        # Get storage stats
        storage = get_tenant_storage(tenant)
        storage_stats = await storage.get_storage_stats()
        
        # Get cache stats
        cache = await get_tenant_cache(tenant)
        cache_stats = await cache.get_stats()
        
        return {
            "tenant_id": tenant.id,
            "usage": tenant.usage_data,
            "limits": {
                "storage_gb": tenant.limits.storage_gb,
                "bandwidth_gb_per_month": tenant.limits.bandwidth_gb_per_month,
                "api_calls_per_minute": tenant.limits.api_calls_per_minute,
                "concurrent_connections": tenant.limits.concurrent_connections
            },
            "storage": storage_stats,
            "cache": cache_stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tenant/features")
async def get_tenant_features(_auth = Depends(require_auth)):
    """
    Get current tenant features (requires authentication)
    """
    tenant = get_current_tenant()
    if not tenant:
        raise HTTPException(status_code=400, detail="No tenant context")
        
    return {
        "tenant_id": tenant.id,
        "plan": tenant.plan,
        "features": tenant.features.to_dict()
    }

@router.post("/tenant/cache/clear")
async def clear_tenant_cache(_auth = Depends(require_auth)):
    """
    Clear current tenant cache (requires authentication)
    """
    tenant = get_current_tenant()
    if not tenant:
        raise HTTPException(status_code=400, detail="No tenant context")
    
    try:
        cache = await get_tenant_cache(tenant)
        count = await cache.invalidate_pattern("*")
        
        return {
            "message": "Cache cleared successfully",
            "entries_cleared": count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/tenant/storage/cleanup")
async def cleanup_tenant_storage(_auth = Depends(require_auth)):
    """
    Clean up temporary files for current tenant (requires authentication)
    """
    tenant = get_current_tenant()
    if not tenant:
        raise HTTPException(status_code=400, detail="No tenant context")
    
    try:
        storage = get_tenant_storage(tenant)
        count = await storage.cleanup_temp_files()
        
        return {
            "message": "Storage cleanup completed",
            "files_deleted": count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/admin/tenants/stats")
async def get_tenants_stats(_admin = Depends(require_admin)):
    """
    Get statistics for all tenants (requires admin)
    """
    try:
        tenants = await tenant_manager.list_tenants()
        
        stats = {
            "total_tenants": len(tenants),
            "active_tenants": len([t for t in tenants if t.status == TenantStatus.ACTIVE]),
            "trial_tenants": len([t for t in tenants if t.status == TenantStatus.TRIAL]),
            "suspended_tenants": len([t for t in tenants if t.status == TenantStatus.SUSPENDED]),
            "plans": {},
            "total_usage": {
                "storage_gb": 0,
                "api_requests": 0,
                "searches": 0
            }
        }
        
        # Count by plan
        for tenant in tenants:
            plan = tenant.plan
            if plan not in stats["plans"]:
                stats["plans"][plan] = 0
            stats["plans"][plan] += 1
            
            # Aggregate usage
            usage = tenant.usage_data
            stats["total_usage"]["storage_gb"] += usage.get("storage_gb", 0)
            stats["total_usage"]["api_requests"] += usage.get("api_requests", 0)
            stats["total_usage"]["searches"] += usage.get("search_performed_count", 0)
        
        return stats
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))