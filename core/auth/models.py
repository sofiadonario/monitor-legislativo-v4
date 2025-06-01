"""
Authentication and Authorization Models
"""

from enum import Enum
from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Table, Integer
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from core.models.models import Base

# Association tables for many-to-many relationships
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)

class UserRole(str, Enum):
    """User role enumeration"""
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    VIEWER = "viewer"

class User(Base):
    """User model with authentication"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile
    full_name = Column(String(100))
    department = Column(String(50))
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = Column(DateTime)
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    
    # Relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    
    def set_password(self, password: str):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Check if password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission"""
        for role in self.roles:
            if any(perm.name == permission_name for perm in role.permissions):
                return True
        return False
    
    def get_permissions(self) -> List[str]:
        """Get all user permissions"""
        permissions = set()
        for role in self.roles:
            for permission in role.permissions:
                permissions.add(permission.name)
        return list(permissions)
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False
    
    def to_dict(self):
        """Convert to dictionary for JWT claims"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'department': self.department,
            'roles': [role.name for role in self.roles],
            'permissions': self.get_permissions(),
            'is_active': self.is_active,
            'is_verified': self.is_verified
        }

class Role(Base):
    """Role model for RBAC"""
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(200))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')
    permissions = relationship('Permission', secondary=role_permissions, back_populates='roles')
    
    def __repr__(self):
        return f"<Role {self.name}>"

class Permission(Base):
    """Permission model for fine-grained access control"""
    __tablename__ = 'permissions'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(50), nullable=False)  # e.g., 'document', 'user', 'export'
    action = Column(String(50), nullable=False)    # e.g., 'read', 'write', 'delete'
    description = Column(String(200))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    roles = relationship('Role', secondary=role_permissions, back_populates='permissions')
    
    def __repr__(self):
        return f"<Permission {self.name}>"

# Default permissions structure
DEFAULT_PERMISSIONS = {
    # Document permissions
    'document:read': {'resource': 'document', 'action': 'read', 'description': 'View documents'},
    'document:write': {'resource': 'document', 'action': 'write', 'description': 'Create/edit documents'},
    'document:delete': {'resource': 'document', 'action': 'delete', 'description': 'Delete documents'},
    'document:export': {'resource': 'document', 'action': 'export', 'description': 'Export documents'},
    
    # User permissions
    'user:read': {'resource': 'user', 'action': 'read', 'description': 'View users'},
    'user:write': {'resource': 'user', 'action': 'write', 'description': 'Create/edit users'},
    'user:delete': {'resource': 'user', 'action': 'delete', 'description': 'Delete users'},
    
    # Alert permissions
    'alert:read': {'resource': 'alert', 'action': 'read', 'description': 'View alerts'},
    'alert:write': {'resource': 'alert', 'action': 'write', 'description': 'Create/edit alerts'},
    'alert:delete': {'resource': 'alert', 'action': 'delete', 'description': 'Delete alerts'},
    
    # Export permissions
    'export:create': {'resource': 'export', 'action': 'create', 'description': 'Create exports'},
    'export:read': {'resource': 'export', 'action': 'read', 'description': 'View exports'},
    
    # Admin permissions
    'admin:access': {'resource': 'admin', 'action': 'access', 'description': 'Access admin panel'},
    'admin:metrics': {'resource': 'admin', 'action': 'metrics', 'description': 'View system metrics'},
    'admin:config': {'resource': 'admin', 'action': 'config', 'description': 'Modify system config'},
}

# Default role-permission mappings
DEFAULT_ROLE_PERMISSIONS = {
    'admin': list(DEFAULT_PERMISSIONS.keys()),  # All permissions
    'manager': [
        'document:read', 'document:write', 'document:export',
        'user:read',
        'alert:read', 'alert:write',
        'export:create', 'export:read',
        'admin:metrics'
    ],
    'user': [
        'document:read', 'document:export',
        'alert:read', 'alert:write',
        'export:create', 'export:read'
    ],
    'viewer': [
        'document:read',
        'alert:read',
        'export:read'
    ]
}