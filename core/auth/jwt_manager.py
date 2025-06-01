"""
JWT Authentication Manager
Handles token creation, validation, and management
"""

import os
import jwt
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
from functools import wraps
from flask import request, jsonify, current_app

logger = logging.getLogger(__name__)

class JWTManager:
    """Manages JWT authentication tokens"""
    
    def __init__(self, app=None):
        self.app = app
        self.algorithm = 'HS256'
        self.access_token_expires = timedelta(hours=24)
        self.refresh_token_expires = timedelta(days=30)
        self.secret_key = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize JWT manager with Flask app"""
        self.app = app
        
        # Load configuration
        self.secret_key = app.config.get('JWT_SECRET_KEY') or os.environ.get('JWT_SECRET_KEY')
        if not self.secret_key:
            raise ValueError("JWT_SECRET_KEY must be set in config or environment")
        
        # Token expiration settings
        access_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES')
        if access_expires:
            self.access_token_expires = timedelta(seconds=access_expires)
        
        refresh_expires = app.config.get('JWT_REFRESH_TOKEN_EXPIRES')
        if refresh_expires:
            self.refresh_token_expires = timedelta(seconds=refresh_expires)
        
        # Algorithm
        self.algorithm = app.config.get('JWT_ALGORITHM', 'HS256')
        
        logger.info("JWT Manager initialized")
    
    def create_access_token(self, identity: str, additional_claims: Dict[str, Any] = None) -> str:
        """Create an access token"""
        now = datetime.now(timezone.utc)
        payload = {
            'sub': identity,  # Subject (user ID)
            'iat': now,  # Issued at
            'exp': now + self.access_token_expires,  # Expiration
            'type': 'access',
            'fresh': True  # Indicates if token was just created
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.debug(f"Access token created for user: {identity}")
        
        return token
    
    def create_refresh_token(self, identity: str) -> str:
        """Create a refresh token"""
        now = datetime.now(timezone.utc)
        payload = {
            'sub': identity,
            'iat': now,
            'exp': now + self.refresh_token_expires,
            'type': 'refresh'
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.debug(f"Refresh token created for user: {identity}")
        
        return token
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate a token"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={'verify_exp': True}
            )
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise ValueError("Token has expired")
            
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise ValueError("Invalid token")
    
    def verify_token(self, token: str, token_type: str = 'access') -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verify a token and return (is_valid, payload)"""
        try:
            payload = self.decode_token(token)
            
            # Check token type
            if payload.get('type') != token_type:
                logger.warning(f"Invalid token type: expected {token_type}, got {payload.get('type')}")
                return False, None
            
            return True, payload
            
        except ValueError:
            return False, None
    
    def get_token_from_headers(self) -> Optional[str]:
        """Extract token from request headers"""
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header:
            return None
        
        # Bearer token format
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            logger.warning(f"Invalid authorization header format: {auth_header}")
            return None
        
        return parts[1]
    
    def get_current_user_id(self) -> Optional[str]:
        """Get current user ID from token"""
        token = self.get_token_from_headers()
        if not token:
            return None
        
        is_valid, payload = self.verify_token(token)
        if not is_valid:
            return None
        
        return payload.get('sub')
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Create new access token from refresh token"""
        is_valid, payload = self.verify_token(refresh_token, token_type='refresh')
        
        if not is_valid:
            logger.warning("Invalid refresh token")
            return None
        
        # Create new access token
        user_id = payload.get('sub')
        new_token = self.create_access_token(user_id)
        
        logger.info(f"Access token refreshed for user: {user_id}")
        return new_token
    
    def revoke_token(self, token: str):
        """Revoke a token (add to blacklist)"""
        # In production, implement token blacklist with Redis
        # For now, log the revocation
        try:
            payload = self.decode_token(token)
            user_id = payload.get('sub')
            exp = payload.get('exp')
            
            logger.info(f"Token revoked for user {user_id}, expires at {exp}")
            
            # TODO: Add to Redis blacklist
            # redis_client.setex(f"blacklist:{token}", exp - time.time(), "1")
            
        except ValueError:
            logger.warning("Attempted to revoke invalid token")

# Global JWT manager instance
jwt_manager = JWTManager()

def create_access_token(identity: str, **kwargs) -> str:
    """Create an access token for the given identity"""
    return jwt_manager.create_access_token(identity, kwargs)

def create_refresh_token(identity: str) -> str:
    """Create a refresh token for the given identity"""
    return jwt_manager.create_refresh_token(identity)

def verify_token(token: str, token_type: str = 'access') -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify a token and return (is_valid, payload)"""
    return jwt_manager.verify_token(token, token_type)

def get_current_user_id() -> Optional[str]:
    """Get the current user ID from request context"""
    return jwt_manager.get_current_user_id()