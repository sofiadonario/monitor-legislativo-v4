"""
Authentication and Authorization Decorators
"""

import logging
from functools import wraps
from typing import List, Union, Callable
from flask import request, jsonify, g

from .jwt_manager import jwt_manager
from .models import User
from core.models.models import get_session

logger = logging.getLogger(__name__)

def require_auth(f: Callable) -> Callable:
    """Decorator to require valid JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from header
        token = jwt_manager.get_token_from_headers()
        
        if not token:
            logger.warning("No authorization token provided")
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please provide a valid authentication token'
            }), 401
        
        # Verify token
        is_valid, payload = jwt_manager.verify_token(token)
        
        if not is_valid:
            logger.warning("Invalid token provided")
            return jsonify({
                'error': 'Invalid token',
                'message': 'The provided token is invalid or expired'
            }), 401
        
        # Get user from database
        user_id = payload.get('sub')
        session = get_session()
        
        try:
            user = session.query(User).filter_by(id=user_id).first()
            
            if not user:
                logger.warning(f"User {user_id} not found in database")
                return jsonify({
                    'error': 'User not found',
                    'message': 'The authenticated user no longer exists'
                }), 401
            
            if not user.is_active:
                logger.warning(f"Inactive user {user_id} attempted access")
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'Your account has been deactivated'
                }), 403
            
            if user.is_locked():
                logger.warning(f"Locked user {user_id} attempted access")
                return jsonify({
                    'error': 'Account locked',
                    'message': 'Your account is temporarily locked'
                }), 403
            
            # Store user in request context
            g.current_user = user
            g.jwt_payload = payload
            
            return f(*args, **kwargs)
            
        finally:
            session.close()
    
    return decorated_function

def require_role(roles: Union[str, List[str]]) -> Callable:
    """Decorator to require specific role(s)"""
    if isinstance(roles, str):
        roles = [roles]
    
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = g.current_user
            
            # Check if user has any of the required roles
            if not any(user.has_role(role) for role in roles):
                logger.warning(f"User {user.id} lacks required roles: {roles}")
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'This action requires one of the following roles: {", ".join(roles)}'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator

def require_permission(permissions: Union[str, List[str]]) -> Callable:
    """Decorator to require specific permission(s)"""
    if isinstance(permissions, str):
        permissions = [permissions]
    
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = g.current_user
            
            # Check if user has all required permissions
            missing_permissions = [p for p in permissions if not user.has_permission(p)]
            
            if missing_permissions:
                logger.warning(f"User {user.id} lacks permissions: {missing_permissions}")
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'This action requires the following permissions: {", ".join(missing_permissions)}'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator

def optional_auth(f: Callable) -> Callable:
    """Decorator for endpoints that work with or without authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Try to get token
        token = jwt_manager.get_token_from_headers()
        
        if token:
            # Verify token but don't fail if invalid
            is_valid, payload = jwt_manager.verify_token(token)
            
            if is_valid:
                user_id = payload.get('sub')
                session = get_session()
                
                try:
                    user = session.query(User).filter_by(id=user_id).first()
                    if user and user.is_active and not user.is_locked():
                        g.current_user = user
                        g.jwt_payload = payload
                    else:
                        g.current_user = None
                        g.jwt_payload = None
                finally:
                    session.close()
            else:
                g.current_user = None
                g.jwt_payload = None
        else:
            g.current_user = None
            g.jwt_payload = None
        
        return f(*args, **kwargs)
    
    return decorated_function

def rate_limit(max_requests: int = 100, window: int = 60) -> Callable:
    """Decorator to implement rate limiting per user"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get user identifier (IP or user ID)
            if hasattr(g, 'current_user') and g.current_user:
                identifier = f"user:{g.current_user.id}"
            else:
                identifier = f"ip:{request.remote_addr}"
            
            # TODO: Implement actual rate limiting with Redis
            # For now, just pass through
            logger.debug(f"Rate limit check for {identifier}: {max_requests} per {window}s")
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator

def log_activity(action: str, resource: str = None) -> Callable:
    """Decorator to log user activities"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Log before execution
            user_id = g.current_user.id if hasattr(g, 'current_user') and g.current_user else 'anonymous'
            
            logger.info(f"Activity: {action} on {resource or 'unknown'} by user {user_id}")
            
            # Execute function
            result = f(*args, **kwargs)
            
            # Log result
            if hasattr(result, 'status_code'):
                logger.info(f"Activity result: {action} completed with status {result.status_code}")
            
            return result
        
        return decorated_function
    
    return decorator