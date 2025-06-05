"""
FastAPI Authentication Dependencies and Security
Designed for scientific research data integrity - no mock authentication allowed
"""

import logging
from typing import Optional, List, Annotated
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .jwt_manager import jwt_manager
from .models import User
from core.models.models import get_session

logger = logging.getLogger(__name__)

# Security scheme for API documentation
bearer_scheme = HTTPBearer(
    scheme_name="Bearer Token",
    description="JWT Bearer token for authentication"
)


class AuthenticationError(HTTPException):
    """Custom authentication error with proper logging."""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=status_code, detail=detail)
        logger.warning(f"Authentication error: {detail}")


class AuthorizationError(HTTPException):
    """Custom authorization error with proper logging."""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(status_code=status_code, detail=detail)
        logger.warning(f"Authorization error: {detail}")


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]
) -> User:
    """
    Get current authenticated user from JWT token.
    
    This function NEVER returns mock users - only real authenticated users
    for scientific research integrity.
    
    Args:
        credentials: JWT bearer token credentials
        
    Returns:
        Authenticated User object
        
    Raises:
        AuthenticationError: If token is invalid or user not found
    """
    if not credentials or not credentials.credentials:
        raise AuthenticationError("Authentication token required")
    
    token = credentials.credentials
    
    # Verify JWT token (includes blacklist check)
    is_valid, payload = jwt_manager.verify_token(token)
    
    if not is_valid:
        raise AuthenticationError("Invalid or expired token")
    
    user_id = payload.get('sub')
    if not user_id:
        raise AuthenticationError("Token missing user identifier")
    
    # Get user from database (REAL user only - no mocks)
    session = get_session()
    try:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            logger.error(f"User {user_id} not found in database")
            raise AuthenticationError("User account not found")
        
        if not user.is_active:
            logger.warning(f"Inactive user {user_id} attempted access")
            raise AuthenticationError("Account is inactive")
        
        if user.is_locked():
            logger.warning(f"Locked user {user_id} attempted access")
            raise AuthenticationError("Account is temporarily locked")
        
        # Update last activity for security monitoring
        user.update_last_activity()
        session.commit()
        
        logger.debug(f"User {user_id} authenticated successfully")
        return user
        
    except Exception as e:
        session.rollback()
        if isinstance(e, (AuthenticationError, AuthorizationError)):
            raise
        logger.error(f"Database error during authentication: {e}")
        raise AuthenticationError("Authentication service error")
    finally:
        session.close()


async def get_optional_user(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Optional[User]:
    """
    Get current user if authenticated, None otherwise.
    Used for endpoints that work with or without authentication.
    
    Args:
        authorization: Authorization header
        
    Returns:
        User object if authenticated, None otherwise
    """
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    try:
        token = authorization.replace("Bearer ", "")
        is_valid, payload = jwt_manager.verify_token(token)
        
        if not is_valid:
            return None
        
        user_id = payload.get('sub')
        if not user_id:
            return None
        
        session = get_session()
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if user and user.is_active and not user.is_locked():
                return user
            return None
        finally:
            session.close()
            
    except Exception as e:
        logger.debug(f"Optional authentication failed: {e}")
        return None


def require_roles(allowed_roles: List[str]):
    """
    Dependency factory for role-based access control.
    
    Args:
        allowed_roles: List of roles that can access the endpoint
        
    Returns:
        Dependency function that checks user roles
    """
    async def check_roles(current_user: User = Depends(get_current_user)) -> User:
        """Check if current user has any of the required roles."""
        if not any(current_user.has_role(role) for role in allowed_roles):
            user_roles = [role.name for role in current_user.roles]
            logger.warning(
                f"User {current_user.id} with roles {user_roles} "
                f"attempted to access endpoint requiring {allowed_roles}"
            )
            raise AuthorizationError(
                f"Access denied. Required roles: {', '.join(allowed_roles)}"
            )
        
        return current_user
    
    return check_roles


def require_permissions(required_permissions: List[str]):
    """
    Dependency factory for permission-based access control.
    
    Args:
        required_permissions: List of permissions required
        
    Returns:
        Dependency function that checks user permissions
    """
    async def check_permissions(current_user: User = Depends(get_current_user)) -> User:
        """Check if current user has all required permissions."""
        missing_permissions = [
            perm for perm in required_permissions 
            if not current_user.has_permission(perm)
        ]
        
        if missing_permissions:
            logger.warning(
                f"User {current_user.id} missing permissions: {missing_permissions}"
            )
            raise AuthorizationError(
                f"Access denied. Missing permissions: {', '.join(missing_permissions)}"
            )
        
        return current_user
    
    return check_permissions


def require_admin() -> User:
    """Dependency that requires admin role."""
    return Depends(require_roles(["admin"]))


def require_researcher() -> User:
    """Dependency that requires researcher role (for scientific data access)."""
    return Depends(require_roles(["researcher", "admin"]))


def require_api_access() -> User:
    """Dependency that requires API access permission."""
    return Depends(require_permissions(["api_access"]))


def require_cache_management() -> User:
    """Dependency that requires cache management permission."""
    return Depends(require_permissions(["cache_management", "admin"]))


def log_admin_action(action: str, resource: str = None):
    """
    Decorator to log administrative actions for audit trail.
    Critical for scientific research compliance.
    
    Args:
        action: Description of the action performed
        resource: Resource being acted upon
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs (injected by dependency)
            current_user = None
            for arg in args:
                if isinstance(arg, User):
                    current_user = arg
                    break
            
            if not current_user:
                for value in kwargs.values():
                    if isinstance(value, User):
                        current_user = value
                        break
            
            if current_user:
                logger.info(
                    f"ADMIN ACTION: {action} on {resource or 'system'} "
                    f"by user {current_user.id} ({current_user.email})"
                )
            else:
                logger.warning(f"ADMIN ACTION: {action} by unknown user")
            
            # Execute the function
            result = await func(*args, **kwargs)
            
            # Log completion
            if current_user:
                logger.info(f"ADMIN ACTION COMPLETED: {action} by user {current_user.id}")
            
            return result
        
        return wrapper
    return decorator


# Rate limiting dependency (to be implemented with Redis)
async def rate_limit_check(
    current_user: Optional[User] = Depends(get_optional_user)
) -> None:
    """
    Check rate limits for the current user or IP.
    
    Args:
        current_user: Current authenticated user (optional)
    """
    # TODO: Implement Redis-based rate limiting
    # For now, just log the check
    identifier = current_user.id if current_user else "anonymous"
    logger.debug(f"Rate limit check for: {identifier}")
    
    # In production, this would check Redis for rate limit violations
    # and raise HTTPException(429) if limits exceeded


# Security headers dependency
async def add_security_headers() -> dict:
    """Add security headers to responses."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY", 
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }