"""
Tenant Model for Monitor Legislativo v4
Defines tenant structure and configuration

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
import json

class TenantStatus(Enum):
    """Tenant status options"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"
    PENDING = "pending"

class TenantIsolationLevel(Enum):
    """Level of isolation between tenants"""
    SHARED = "shared"  # Shared database with row-level security
    SCHEMA = "schema"  # Separate schema per tenant
    DATABASE = "database"  # Separate database per tenant

@dataclass
class TenantFeatures:
    """Features enabled for a tenant"""
    max_users: int = 10
    max_searches_per_day: int = 1000
    max_alerts: int = 50
    max_exports_per_month: int = 100
    
    # Feature flags
    enable_api_access: bool = True
    enable_websocket: bool = True
    enable_advanced_search: bool = True
    enable_ai_analysis: bool = False
    enable_plugins: bool = True
    enable_custom_branding: bool = False
    enable_sso: bool = False
    enable_data_export: bool = True
    
    # Integration features
    enable_email_notifications: bool = True
    enable_webhook_integration: bool = False
    enable_slack_integration: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "max_users": self.max_users,
            "max_searches_per_day": self.max_searches_per_day,
            "max_alerts": self.max_alerts,
            "max_exports_per_month": self.max_exports_per_month,
            "features": {
                "api_access": self.enable_api_access,
                "websocket": self.enable_websocket,
                "advanced_search": self.enable_advanced_search,
                "ai_analysis": self.enable_ai_analysis,
                "plugins": self.enable_plugins,
                "custom_branding": self.enable_custom_branding,
                "sso": self.enable_sso,
                "data_export": self.enable_data_export,
                "email_notifications": self.enable_email_notifications,
                "webhook_integration": self.enable_webhook_integration,
                "slack_integration": self.enable_slack_integration
            }
        }

@dataclass
class TenantLimits:
    """Resource limits for a tenant"""
    storage_gb: float = 10.0
    bandwidth_gb_per_month: float = 100.0
    api_calls_per_minute: int = 60
    concurrent_connections: int = 100
    
    # Database limits
    max_db_connections: int = 10
    max_db_size_gb: float = 5.0
    
    # Processing limits
    max_background_jobs: int = 5
    max_export_size_mb: int = 100
    
    def is_within_limits(self, usage: Dict[str, Any]) -> bool:
        """Check if usage is within limits"""
        if usage.get("storage_gb", 0) > self.storage_gb:
            return False
        if usage.get("bandwidth_gb", 0) > self.bandwidth_gb_per_month:
            return False
        if usage.get("api_calls_per_minute", 0) > self.api_calls_per_minute:
            return False
        return True

@dataclass
class TenantConfig:
    """Tenant-specific configuration"""
    # Branding
    logo_url: Optional[str] = None
    primary_color: str = "#1976D2"
    secondary_color: str = "#FF4081"
    custom_css: Optional[str] = None
    
    # Localization
    default_language: str = "pt-BR"
    timezone: str = "America/Sao_Paulo"
    date_format: str = "%d/%m/%Y"
    
    # Security
    password_policy: Dict[str, Any] = field(default_factory=lambda: {
        "min_length": 8,
        "require_uppercase": True,
        "require_numbers": True,
        "require_special": True,
        "max_age_days": 90
    })
    
    session_timeout_minutes: int = 30
    ip_whitelist: List[str] = field(default_factory=list)
    
    # Notifications
    notification_email: Optional[str] = None
    webhook_url: Optional[str] = None
    slack_webhook: Optional[str] = None
    
    # Custom fields
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "branding": {
                "logo_url": self.logo_url,
                "primary_color": self.primary_color,
                "secondary_color": self.secondary_color,
                "custom_css": self.custom_css
            },
            "localization": {
                "default_language": self.default_language,
                "timezone": self.timezone,
                "date_format": self.date_format
            },
            "security": {
                "password_policy": self.password_policy,
                "session_timeout_minutes": self.session_timeout_minutes,
                "ip_whitelist": self.ip_whitelist
            },
            "notifications": {
                "email": self.notification_email,
                "webhook_url": self.webhook_url,
                "slack_webhook": self.slack_webhook
            },
            "metadata": self.metadata
        }

@dataclass
class Tenant:
    """Tenant model"""
    id: str
    name: str
    slug: str  # URL-safe identifier
    status: TenantStatus = TenantStatus.ACTIVE
    
    # Contact information
    admin_email: str = ""
    admin_name: str = ""
    organization: Optional[str] = None
    
    # Subscription
    plan: str = "basic"
    trial_ends_at: Optional[datetime] = None
    subscription_ends_at: Optional[datetime] = None
    
    # Configuration
    isolation_level: TenantIsolationLevel = TenantIsolationLevel.SHARED
    features: TenantFeatures = field(default_factory=TenantFeatures)
    limits: TenantLimits = field(default_factory=TenantLimits)
    config: TenantConfig = field(default_factory=TenantConfig)
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_active_at: Optional[datetime] = None
    
    # Usage tracking
    usage_data: Dict[str, Any] = field(default_factory=dict)
    
    def is_active(self) -> bool:
        """Check if tenant is active"""
        if self.status != TenantStatus.ACTIVE:
            return False
            
        # Check trial expiration
        if self.status == TenantStatus.TRIAL and self.trial_ends_at:
            if datetime.now() > self.trial_ends_at:
                return False
                
        # Check subscription expiration
        if self.subscription_ends_at:
            if datetime.now() > self.subscription_ends_at:
                return False
                
        return True
    
    def has_feature(self, feature: str) -> bool:
        """Check if tenant has a specific feature"""
        return getattr(self.features, f"enable_{feature}", False)
    
    def get_database_name(self) -> str:
        """Get database name for tenant"""
        if self.isolation_level == TenantIsolationLevel.DATABASE:
            return f"legislativo_{self.slug}"
        return "legislativo_main"
    
    def get_schema_name(self) -> str:
        """Get schema name for tenant"""
        if self.isolation_level == TenantIsolationLevel.SCHEMA:
            return f"tenant_{self.slug}"
        return "public"
    
    def get_cache_prefix(self) -> str:
        """Get cache key prefix for tenant"""
        return f"tenant:{self.id}:"
    
    def get_storage_path(self) -> str:
        """Get storage path for tenant"""
        return f"tenants/{self.slug}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status.value,
            "admin_email": self.admin_email,
            "admin_name": self.admin_name,
            "organization": self.organization,
            "plan": self.plan,
            "trial_ends_at": self.trial_ends_at.isoformat() if self.trial_ends_at else None,
            "subscription_ends_at": self.subscription_ends_at.isoformat() if self.subscription_ends_at else None,
            "isolation_level": self.isolation_level.value,
            "features": self.features.to_dict(),
            "limits": {
                "storage_gb": self.limits.storage_gb,
                "bandwidth_gb_per_month": self.limits.bandwidth_gb_per_month,
                "api_calls_per_minute": self.limits.api_calls_per_minute,
                "concurrent_connections": self.limits.concurrent_connections
            },
            "config": self.config.to_dict(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_active_at": self.last_active_at.isoformat() if self.last_active_at else None,
            "usage_data": self.usage_data
        }
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), default=str)