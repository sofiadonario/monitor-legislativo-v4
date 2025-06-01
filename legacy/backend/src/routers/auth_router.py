"""Authentication router for SSO between FastAPI and R Shiny."""
import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Response, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Cookie configuration
COOKIE_NAME = "monitor-jwt"
COOKIE_SECURE = os.getenv("ENVIRONMENT", "development") == "production"
COOKIE_SAMESITE = "none" if COOKIE_SECURE else "lax"


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserInfo(BaseModel):
    user_id: str
    username: str
    roles: list[str] = []
    permissions: list[str] = []


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserInfo:
    """Get current user from JWT token."""
    payload = verify_token(credentials.credentials)
    
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    return UserInfo(
        user_id=user_id,
        username=payload.get("username", ""),
        roles=payload.get("roles", []),
        permissions=payload.get("permissions", [])
    )


def authenticate_user(username: str, password: str) -> Optional[UserInfo]:
    """
    Authenticate user credentials.
    
    This is a placeholder implementation. In production, you should:
    1. Hash passwords using bcrypt or similar
    2. Store user data in a database
    3. Implement proper role-based access control
    """
    # Demo users - replace with real authentication
    demo_users = {
        "admin": {
            "password": "admin123",  # In production: use hashed passwords
            "roles": ["admin", "user"],
            "permissions": ["read", "write", "admin"]
        },
        "user": {
            "password": "user123",
            "roles": ["user"],
            "permissions": ["read"]
        }
    }
    
    if username in demo_users and demo_users[username]["password"] == password:
        return UserInfo(
            user_id=username,
            username=username,
            roles=demo_users[username]["roles"],
            permissions=demo_users[username]["permissions"]
        )
    return None


@router.post("/login", response_model=TokenResponse)
async def login(login_data: LoginRequest, response: Response):
    """
    Authenticate user and set JWT cookie.
    
    Returns JWT tokens and sets HttpOnly cookie for browser access.
    """
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Create tokens
    token_data = {
        "sub": user.user_id,
        "username": user.username,
        "roles": user.roles,
        "permissions": user.permissions
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token({"sub": user.user_id})
    
    # Set HttpOnly cookie for browser access
    response.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        max_age=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE
    )
    
    # Also set refresh token cookie
    response.set_cookie(
        key=f"{COOKIE_NAME}-refresh",
        value=refresh_token,
        max_age=JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE
    )
    
    logger.info(f"User {user.username} logged in successfully")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout")
async def logout(response: Response):
    """Logout user by clearing JWT cookies."""
    response.delete_cookie(key=COOKIE_NAME, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
    response.delete_cookie(key=f"{COOKIE_NAME}-refresh", secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
    return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request, response: Response):
    """Refresh access token using refresh token from cookie."""
    refresh_token = request.cookies.get(f"{COOKIE_NAME}-refresh")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found"
        )
    
    try:
        payload = verify_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user_id = payload.get("sub")
        # In production, fetch user data from database
        user = UserInfo(user_id=user_id, username=user_id, roles=["user"], permissions=["read"])
        
        # Create new access token
        token_data = {
            "sub": user.user_id,
            "username": user.username,
            "roles": user.roles,
            "permissions": user.permissions
        }
        
        new_access_token = create_access_token(token_data)
        
        # Update cookie
        response.set_cookie(
            key=COOKIE_NAME,
            value=new_access_token,
            max_age=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE
        )
        
        return TokenResponse(
            access_token=new_access_token,
            expires_in=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not refresh token"
        )


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(current_user: UserInfo = Depends(get_current_user)):
    """Get current user information."""
    return current_user


@router.get("/verify")
async def verify_token_endpoint(current_user: UserInfo = Depends(get_current_user)):
    """Verify token validity (for R Shiny integration)."""
    return {
        "valid": True,
        "user": current_user.dict(),
        "timestamp": datetime.utcnow().isoformat()
    }