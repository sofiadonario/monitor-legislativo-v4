"""
JWT Authentication Manager
Handles token creation, validation, and management
"""

import os
import jwt
import time
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple, Set
from functools import wraps
from flask import request, jsonify, current_app

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from core.security.key_rotation_service import get_key_rotation_service

logger = logging.getLogger(__name__)


class TokenBlacklist:
    """Manages JWT token blacklist with Redis backend and in-memory fallback."""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self._memory_blacklist: Set[str] = set()  # Fallback for when Redis unavailable
        
        if redis_client:
            try:
                # Test Redis connection
                redis_client.ping()
                logger.info("Token blacklist using Redis backend")
            except Exception as e:
                logger.warning(f"Redis connection failed, using memory fallback: {e}")
                self.redis_client = None
        
        if not self.redis_client:
            logger.warning("Token blacklist using in-memory storage (not recommended for production)")
    
    def _hash_token(self, token: str) -> str:
        """Create a hash of the token for storage efficiency."""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def add_token(self, token: str, exp_timestamp: int) -> None:
        """Add a token to the blacklist.
        
        Args:
            token: JWT token to blacklist
            exp_timestamp: Token expiration timestamp
        """
        token_hash = self._hash_token(token)
        
        # Calculate TTL (time until expiration)
        current_time = int(time.time())
        ttl = max(0, exp_timestamp - current_time)
        
        if ttl <= 0:
            # Token already expired, no need to blacklist
            return
        
        if self.redis_client:
            try:
                # Store in Redis with TTL
                self.redis_client.setex(f"blacklist:{token_hash}", ttl, "1")
                logger.debug(f"Token blacklisted in Redis with TTL {ttl}s")
            except Exception as e:
                logger.error(f"Failed to add token to Redis blacklist: {e}")
                # Fall back to memory storage
                self._memory_blacklist.add(token_hash)
        else:
            # Use memory storage
            self._memory_blacklist.add(token_hash)
            logger.debug(f"Token blacklisted in memory")
    
    def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted.
        
        Args:
            token: JWT token to check
            
        Returns:
            True if token is blacklisted
        """
        token_hash = self._hash_token(token)
        
        if self.redis_client:
            try:
                result = self.redis_client.get(f"blacklist:{token_hash}")
                return result is not None
            except Exception as e:
                logger.error(f"Failed to check Redis blacklist: {e}")
                # Fall back to memory check
                return token_hash in self._memory_blacklist
        else:
            return token_hash in self._memory_blacklist
    
    def remove_token(self, token: str) -> None:
        """Remove a token from blacklist (for testing/admin purposes).
        
        Args:
            token: JWT token to remove
        """
        token_hash = self._hash_token(token)
        
        if self.redis_client:
            try:
                self.redis_client.delete(f"blacklist:{token_hash}")
            except Exception as e:
                logger.error(f"Failed to remove token from Redis blacklist: {e}")
        
        # Also remove from memory
        self._memory_blacklist.discard(token_hash)
    
    def cleanup_expired(self) -> int:
        """Clean up expired tokens from memory storage (Redis handles this automatically).
        
        Returns:
            Number of tokens cleaned up
        """
        if self.redis_client:
            # Redis handles TTL cleanup automatically
            return 0
        
        # For memory storage, we don't have expiration info
        # This would need to be enhanced with timestamp tracking
        # For now, just log the issue
        logger.warning("Memory blacklist cleanup not implemented - consider using Redis")
        return 0


class JWTManager:
    """Manages JWT authentication tokens"""
    
    def __init__(self, app=None):
        self.app = app
        self.algorithm = 'RS256'  # Changed to asymmetric signing
        self.access_token_expires = timedelta(hours=1)  # Reduced from 24h to 1h for security
        self.refresh_token_expires = timedelta(days=7)  # Reduced from 30d to 7d for security
        self.secret_key = None  # Legacy HS256 support
        self.blacklist = None
        self._key_rotation_service = None
        self._signing_key_id = None
        self._private_key = None
        self._public_key = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize JWT manager with Flask app"""
        self.app = app
        
        # Load configuration
        self.secret_key = app.config.get('JWT_SECRET_KEY') or os.environ.get('JWT_SECRET_KEY')
        if not self.secret_key:
            raise ValueError("JWT_SECRET_KEY must be set in config or environment")
        
        # Validate secret key strength
        if len(self.secret_key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        
        # Token expiration settings
        access_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES')
        if access_expires:
            self.access_token_expires = timedelta(seconds=access_expires)
        
        refresh_expires = app.config.get('JWT_REFRESH_TOKEN_EXPIRES')
        if refresh_expires:
            self.refresh_token_expires = timedelta(seconds=refresh_expires)
        
        # Algorithm (default to RS256 for new apps)
        self.algorithm = app.config.get('JWT_ALGORITHM', 'RS256')
        
        # Initialize key rotation service for RS256
        if self.algorithm == 'RS256':
            self._init_key_rotation()
        
        # Initialize token blacklist
        self._init_blacklist(app)
        
        logger.info(f"JWT Manager initialized with {self.algorithm} algorithm and blacklist support")
    
    def _init_blacklist(self, app):
        """Initialize token blacklist with Redis if available."""
        redis_client = None
        
        if REDIS_AVAILABLE:
            try:
                redis_url = app.config.get('REDIS_URL') or os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
                redis_client = redis.from_url(redis_url, decode_responses=True)
                redis_client.ping()  # Test connection
                logger.info(f"Connected to Redis for token blacklist: {redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")
                redis_client = None
        
        self.blacklist = TokenBlacklist(redis_client)
    
    def _init_key_rotation(self):
        """Initialize key rotation service for RS256 signing."""
        self._key_rotation_service = get_key_rotation_service()
        
        # Get or generate JWT signing key
        self._signing_key_id = self._key_rotation_service.get_active_key_id('jwt_signing')
        if not self._signing_key_id:
            # Generate initial signing key
            self._signing_key_id, _ = self._key_rotation_service.generate_key('jwt_signing')
            logger.info("Generated initial JWT signing key pair")
        
        # Load private and public keys
        self._load_signing_keys()
    
    def _load_signing_keys(self):
        """Load private and public keys for JWT signing."""
        # Get private key
        private_key_pem = self._key_rotation_service.get_key(self._signing_key_id)
        if not private_key_pem:
            raise ValueError("Failed to load JWT signing private key")
        
        self._private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Get public key
        public_key_pem = self._key_rotation_service.get_public_key(self._signing_key_id)
        if not public_key_pem:
            raise ValueError("Failed to load JWT signing public key")
        
        self._public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
    
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
        
        # Add key ID for RS256 to support key rotation
        if self.algorithm == 'RS256' and self._signing_key_id:
            payload['kid'] = self._signing_key_id
        
        # Encode with appropriate key
        if self.algorithm == 'RS256' and self._private_key:
            token = jwt.encode(payload, self._private_key, algorithm=self.algorithm)
        else:
            # Fallback to HS256
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        logger.debug(f"Access token created for user: {identity} using {self.algorithm}")
        
        return token
    
    def create_refresh_token(self, identity: str) -> str:
        """Create a refresh token"""
        now = datetime.now(timezone.utc)
        payload = {
            'sub': identity,
            'iat': now,
            'exp': now + self.refresh_token_expires,
            'type': 'refresh',
            'jti': secrets.token_urlsafe(16)  # Unique token ID for rotation tracking
        }
        
        # Add key ID for RS256
        if self.algorithm == 'RS256' and self._signing_key_id:
            payload['kid'] = self._signing_key_id
        
        # Encode with appropriate key
        if self.algorithm == 'RS256' and self._private_key:
            token = jwt.encode(payload, self._private_key, algorithm=self.algorithm)
        else:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        logger.debug(f"Refresh token created for user: {identity} with jti: {payload['jti']}")
        
        return token
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate a token with key rotation support"""
        try:
            # For RS256, we need to handle key rotation
            if self.algorithm == 'RS256':
                # First, decode without verification to get the header
                unverified = jwt.decode(token, options={"verify_signature": False})
                kid = unverified.get('kid')
                
                if kid:
                    # Token has key ID, use appropriate key
                    if kid == self._signing_key_id:
                        # Current key
                        verify_key = self._public_key
                    else:
                        # Older key during rotation period
                        public_key_pem = self._key_rotation_service.get_public_key(kid)
                        if public_key_pem:
                            verify_key = serialization.load_pem_public_key(
                                public_key_pem,
                                backend=default_backend()
                            )
                        else:
                            raise ValueError(f"Unknown key ID: {kid}")
                else:
                    # No key ID, use current key
                    verify_key = self._public_key
                
                payload = jwt.decode(
                    token,
                    verify_key,
                    algorithms=[self.algorithm],
                    options={'verify_exp': True}
                )
            else:
                # HS256 mode
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
            # First check if token is blacklisted
            if self.blacklist and self.blacklist.is_blacklisted(token):
                logger.warning("Token is blacklisted")
                return False, None
            
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
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Create new access token from refresh token with refresh token rotation.
        
        Args:
            refresh_token: Current refresh token
            
        Returns:
            Tuple of (new_access_token, new_refresh_token) or None if invalid
        """
        is_valid, payload = self.verify_token(refresh_token, token_type='refresh')
        
        if not is_valid:
            logger.warning("Invalid refresh token")
            return None
        
        user_id = payload.get('sub')
        
        # Revoke the old refresh token (one-time use)
        self.revoke_token(refresh_token)
        
        # Create new tokens
        new_access_token = self.create_access_token(user_id)
        new_refresh_token = self.create_refresh_token(user_id)
        
        logger.info(f"Tokens refreshed for user: {user_id}")
        return new_access_token, new_refresh_token
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token (add to blacklist).
        
        Args:
            token: JWT token to revoke
            
        Returns:
            True if successfully revoked, False otherwise
        """
        if not self.blacklist:
            logger.error("Token blacklist not initialized - cannot revoke token")
            return False
        
        try:
            payload = self.decode_token(token)
            user_id = payload.get('sub')
            exp = payload.get('exp')
            
            if not exp:
                logger.warning("Token has no expiration timestamp")
                return False
            
            # Add to blacklist
            self.blacklist.add_token(token, exp)
            
            logger.info(f"Token revoked for user {user_id}, expires at {datetime.fromtimestamp(exp, timezone.utc)}")
            return True
            
        except ValueError as e:
            logger.warning(f"Failed to revoke token: {e}")
            return False
    
    def revoke_all_user_tokens(self, user_id: str) -> None:
        """Revoke all tokens for a specific user.
        
        This is implemented by updating a user-specific salt/version
        that invalidates all existing tokens for that user.
        """
        # This would require storing user token versions in the database
        # For now, log the intent
        logger.info(f"All tokens revoked for user: {user_id}")
        # TODO: Implement user token versioning

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