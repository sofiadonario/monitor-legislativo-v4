"""
Authentication and Authorization module for Monitor Legislativo
"""

from .jwt_manager import JWTManager, create_access_token, verify_token
from .models import User, Role, Permission
from .decorators import require_auth, require_role, require_permission

__all__ = [
    'JWTManager',
    'create_access_token',
    'verify_token',
    'User',
    'Role',
    'Permission',
    'require_auth',
    'require_role',
    'require_permission'
]