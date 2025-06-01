"""
Authentication API Routes
"""

import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from pydantic import BaseModel, EmailStr, validator
from typing import Optional

from core.auth import create_access_token, create_refresh_token, jwt_manager
from core.auth.models import User, Role, UserRole
from core.auth.decorators import require_auth, rate_limit
from core.models.models import get_session

logger = logging.getLogger(__name__)

# Create blueprint
auth_router = Blueprint('auth', __name__, url_prefix='/api/auth')

# Pydantic models for request validation
class LoginRequest(BaseModel):
    """Login request model"""
    email: EmailStr
    password: str
    
    @validator('password')
    def password_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Password cannot be empty')
        return v

class RegisterRequest(BaseModel):
    """Registration request model"""
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    department: Optional[str] = None
    
    @validator('username')
    def username_valid(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.lower()
    
    @validator('password')
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        return v

class RefreshRequest(BaseModel):
    """Token refresh request model"""
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    """Change password request model"""
    current_password: str
    new_password: str
    
    @validator('new_password')
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

# Routes
@auth_router.route('/login', methods=['POST'])
@rate_limit(max_requests=5, window=60)  # 5 login attempts per minute
def login():
    """Authenticate user and return tokens"""
    try:
        # Validate request
        data = LoginRequest(**request.get_json())
        
        session = get_session()
        
        try:
            # Find user by email
            user = session.query(User).filter_by(email=data.email.lower()).first()
            
            if not user:
                logger.warning(f"Login attempt for non-existent email: {data.email}")
                return jsonify({
                    'error': 'Invalid credentials',
                    'message': 'Email or password is incorrect'
                }), 401
            
            # Check if account is locked
            if user.is_locked():
                logger.warning(f"Login attempt for locked account: {user.id}")
                return jsonify({
                    'error': 'Account locked',
                    'message': 'Your account is temporarily locked due to multiple failed login attempts'
                }), 403
            
            # Verify password
            if not user.check_password(data.password):
                # Increment failed attempts
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(hours=1)
                    logger.warning(f"Account locked due to failed attempts: {user.id}")
                
                session.commit()
                
                return jsonify({
                    'error': 'Invalid credentials',
                    'message': 'Email or password is incorrect'
                }), 401
            
            # Check if account is active
            if not user.is_active:
                logger.warning(f"Login attempt for inactive account: {user.id}")
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'Your account has been deactivated'
                }), 403
            
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.last_login_at = datetime.utcnow()
            session.commit()
            
            # Create tokens
            user_data = user.to_dict()
            access_token = create_access_token(
                str(user.id),
                roles=user_data['roles'],
                permissions=user_data['permissions']
            )
            refresh_token = create_refresh_token(str(user.id))
            
            logger.info(f"Successful login for user: {user.id}")
            
            return jsonify({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.full_name,
                    'roles': user_data['roles'],
                    'permissions': user_data['permissions']
                }
            }), 200
            
        finally:
            session.close()
            
    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred during login'
        }), 500

@auth_router.route('/register', methods=['POST'])
@rate_limit(max_requests=3, window=300)  # 3 registrations per 5 minutes
def register():
    """Register a new user"""
    try:
        # Validate request
        data = RegisterRequest(**request.get_json())
        
        session = get_session()
        
        try:
            # Check if username or email already exists
            existing_user = session.query(User).filter(
                (User.username == data.username) | 
                (User.email == data.email.lower())
            ).first()
            
            if existing_user:
                if existing_user.username == data.username:
                    return jsonify({
                        'error': 'Username taken',
                        'message': 'This username is already in use'
                    }), 409
                else:
                    return jsonify({
                        'error': 'Email taken',
                        'message': 'This email is already registered'
                    }), 409
            
            # Create new user
            new_user = User(
                username=data.username,
                email=data.email.lower(),
                full_name=data.full_name,
                department=data.department
            )
            new_user.set_password(data.password)
            
            # Assign default role
            default_role = session.query(Role).filter_by(name=UserRole.USER.value).first()
            if default_role:
                new_user.roles.append(default_role)
            
            session.add(new_user)
            session.commit()
            
            logger.info(f"New user registered: {new_user.id}")
            
            # Create tokens for immediate login
            user_data = new_user.to_dict()
            access_token = create_access_token(
                str(new_user.id),
                roles=user_data['roles'],
                permissions=user_data['permissions']
            )
            refresh_token = create_refresh_token(str(new_user.id))
            
            return jsonify({
                'message': 'Registration successful',
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': {
                    'id': new_user.id,
                    'username': new_user.username,
                    'email': new_user.email,
                    'full_name': new_user.full_name,
                    'roles': user_data['roles']
                }
            }), 201
            
        finally:
            session.close()
            
    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred during registration'
        }), 500

@auth_router.route('/refresh', methods=['POST'])
def refresh():
    """Refresh access token using refresh token"""
    try:
        # Validate request
        data = RefreshRequest(**request.get_json())
        
        # Refresh the token
        new_access_token = jwt_manager.refresh_access_token(data.refresh_token)
        
        if not new_access_token:
            return jsonify({
                'error': 'Invalid refresh token',
                'message': 'The refresh token is invalid or expired'
            }), 401
        
        return jsonify({
            'access_token': new_access_token
        }), 200
        
    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred during token refresh'
        }), 500

@auth_router.route('/logout', methods=['POST'])
@require_auth
def logout():
    """Logout user and invalidate tokens"""
    try:
        # Get current token
        token = jwt_manager.get_token_from_headers()
        
        # Revoke the token
        jwt_manager.revoke_token(token)
        
        logger.info(f"User logged out: {g.current_user.id}")
        
        return jsonify({
            'message': 'Logout successful'
        }), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred during logout'
        }), 500

@auth_router.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user information"""
    try:
        user = g.current_user
        user_data = user.to_dict()
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'department': user.department,
                'roles': user_data['roles'],
                'permissions': user_data['permissions'],
                'is_verified': user.is_verified,
                'created_at': user.created_at.isoformat(),
                'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get current user error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred while fetching user information'
        }), 500

@auth_router.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    """Change user password"""
    try:
        # Validate request
        data = ChangePasswordRequest(**request.get_json())
        
        user = g.current_user
        
        # Verify current password
        if not user.check_password(data.current_password):
            return jsonify({
                'error': 'Invalid password',
                'message': 'Current password is incorrect'
            }), 401
        
        # Update password
        session = get_session()
        try:
            user.set_password(data.new_password)
            session.merge(user)
            session.commit()
            
            logger.info(f"Password changed for user: {user.id}")
            
            return jsonify({
                'message': 'Password changed successfully'
            }), 200
            
        finally:
            session.close()
            
    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred while changing password'
        }), 500

# Import g from Flask
from flask import g