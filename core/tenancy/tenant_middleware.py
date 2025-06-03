"""
Tenant Middleware for Monitor Legislativo v4
Handles tenant resolution and context

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Optional, Callable
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import re

from .tenant_manager import tenant_manager, set_current_tenant, clear_current_tenant, get_current_tenant
from .tenant_model import Tenant

logger = logging.getLogger(__name__)

class TenantMiddleware:
    """Middleware to resolve tenant from request"""
    
    def __init__(self, app, tenant_header: str = "X-Tenant-ID"):
        self.app = app
        self.tenant_header = tenant_header
        # Patterns for tenant resolution
        self.subdomain_pattern = re.compile(r"^([a-z0-9-]+)\..*")
        self.path_pattern = re.compile(r"^/tenant/([a-z0-9-]+)/.*")
        
    async def __call__(self, request: Request, call_next):
        try:
            # Try to resolve tenant
            tenant = await self._resolve_tenant(request)
            
            if tenant:
                # Validate tenant is active
                if not tenant.is_active():
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Tenant is not active"}
                    )
                
                # Set tenant in context
                set_current_tenant(tenant)
                
                # Update tenant usage
                await tenant_manager.update_usage(
                    tenant.id,
                    "api_requests",
                    1
                )
                
                # Add tenant info to request state
                request.state.tenant = tenant
                
            # Process request
            response = await call_next(request)
            
            # Add tenant header to response
            if tenant:
                response.headers["X-Tenant-ID"] = tenant.id
                
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Tenant middleware error: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"}
            )
        finally:
            # Clear tenant context
            clear_current_tenant()
    
    async def _resolve_tenant(self, request: Request) -> Optional[Tenant]:
        """Resolve tenant from request"""
        # 1. Try header-based resolution
        tenant_id = request.headers.get(self.tenant_header)
        if tenant_id:
            tenant = await tenant_manager.get_tenant(tenant_id)
            if tenant:
                logger.debug(f"Resolved tenant from header: {tenant.id}")
                return tenant
        
        # 2. Try subdomain-based resolution
        host = request.headers.get("host", "")
        match = self.subdomain_pattern.match(host)
        if match:
            subdomain = match.group(1)
            if subdomain not in ["www", "api", "app"]:  # Exclude system subdomains
                tenant = await tenant_manager.get_tenant_by_slug(subdomain)
                if tenant:
                    logger.debug(f"Resolved tenant from subdomain: {tenant.id}")
                    return tenant
        
        # 3. Try path-based resolution
        match = self.path_pattern.match(request.url.path)
        if match:
            tenant_slug = match.group(1)
            tenant = await tenant_manager.get_tenant_by_slug(tenant_slug)
            if tenant:
                logger.debug(f"Resolved tenant from path: {tenant.id}")
                return tenant
        
        # 4. Try JWT token resolution (if authenticated)
        if hasattr(request.state, "user") and request.state.user:
            tenant_id = getattr(request.state.user, "tenant_id", None)
            if tenant_id:
                tenant = await tenant_manager.get_tenant(tenant_id)
                if tenant:
                    logger.debug(f"Resolved tenant from JWT: {tenant.id}")
                    return tenant
        
        # 5. Default tenant for public endpoints
        if self._is_public_endpoint(request.url.path):
            return None
            
        logger.debug("No tenant resolved from request")
        return None
    
    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public (no tenant required)"""
        public_paths = [
            "/health",
            "/metrics",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/auth/login",
            "/auth/register"
        ]
        
        return any(path.startswith(p) for p in public_paths)

class TenantContextMiddleware:
    """Simpler middleware that just ensures tenant context is set"""
    
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, request: Request, call_next):
        # Get tenant from request state (set by TenantMiddleware)
        tenant = getattr(request.state, "tenant", None)
        
        if tenant:
            set_current_tenant(tenant)
            
        try:
            response = await call_next(request)
            return response
        finally:
            clear_current_tenant()

def require_tenant(func: Callable) -> Callable:
    """Decorator to require tenant context"""
    async def wrapper(*args, **kwargs):
        tenant = get_current_tenant()
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tenant context required"
            )
        return await func(*args, **kwargs)
    
    # Preserve function metadata
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    
    return wrapper

def require_tenant_feature(feature: str) -> Callable:
    """Decorator to require specific tenant feature"""
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            tenant = get_current_tenant()
            if not tenant:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Tenant context required"
                )
                
            if not tenant.has_feature(feature):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Feature '{feature}' not available in your plan"
                )
                
            return await func(*args, **kwargs)
        
        # Preserve function metadata
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        
        return wrapper
    
    return decorator

async def get_tenant_from_request(request: Request) -> Optional[Tenant]:
    """Get tenant from request (utility function)"""
    return getattr(request.state, "tenant", None)