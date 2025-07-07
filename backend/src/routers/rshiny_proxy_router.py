from fastapi import APIRouter, Response, HTTPException, Request, Depends
from fastapi.responses import StreamingResponse
import httpx
import os
import jwt
from typing import Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

RSHINY_URL = os.getenv("RSHINY_URL", "https://rshiny-production-1f4b.up.railway.app")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
COOKIE_NAME = "monitor-jwt"


def extract_jwt_from_request(request: Request) -> Optional[str]:
    """Extract JWT token from request (cookie or Authorization header)."""
    # Try cookie first
    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token
    
    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    
    return None


def get_user_from_token(token: str) -> Optional[dict]:
    """Decode JWT token and extract user information."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "roles": payload.get("roles", []),
            "permissions": payload.get("permissions", [])
        }
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token has expired")
        return None
    except jwt.JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        return None

@router.get("/rshiny/health", tags=["RShiny"])
async def rshiny_health():
    """Proxy health endpoint to avoid CORS."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{RSHINY_URL}/")
        status = 200 if resp.status_code == 200 else 503
        return Response(
            content="OK" if status == 200 else "DOWN",
            status_code=status,
            media_type="text/plain",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.api_route("/rshiny/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], tags=["RShiny"])
async def proxy_to_rshiny(request: Request, path: str):
    """
    Proxy all requests to R Shiny app with JWT authentication headers.
    
    This endpoint:
    1. Extracts JWT token from request
    2. Validates and decodes the token
    3. Forwards request to R Shiny with user info in headers
    4. Returns R Shiny response
    """
    # Extract JWT token
    token = extract_jwt_from_request(request)
    user_info = None
    
    if token:
        user_info = get_user_from_token(token)
    
    # Prepare headers for R Shiny
    proxy_headers = {}
    
    # Copy original headers (excluding host)
    for key, value in request.headers.items():
        if key.lower() not in ["host", "content-length"]:
            proxy_headers[key] = value
    
    # Add authentication headers for R Shiny
    if user_info:
        proxy_headers["X-User-Id"] = user_info["user_id"]
        proxy_headers["X-Username"] = user_info["username"]
        proxy_headers["X-User-Roles"] = ",".join(user_info["roles"])
        proxy_headers["X-User-Permissions"] = ",".join(user_info["permissions"])
        
        # Also send as Authorization Bearer for standard auth
        if token:
            proxy_headers["Authorization"] = f"Bearer {token}"
    else:
        # No authentication - R Shiny can handle as anonymous user
        proxy_headers["X-User-Id"] = "anonymous"
        proxy_headers["X-Username"] = "anonymous"
        proxy_headers["X-User-Roles"] = "guest"
        proxy_headers["X-User-Permissions"] = "read"
    
    # Build target URL
    target_url = f"{RSHINY_URL}/{path}"
    if request.query_params:
        target_url += f"?{request.query_params}"
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get request body if present
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Make request to R Shiny
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=proxy_headers,
                content=body
            )
            
            # Handle streaming responses (like server-sent events)
            if "text/event-stream" in response.headers.get("content-type", ""):
                return StreamingResponse(
                    response.aiter_bytes(),
                    media_type=response.headers.get("content-type"),
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Return regular response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers={
                    **dict(response.headers),
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
                media_type=response.headers.get("content-type")
            )
            
    except httpx.ConnectError:
        logger.error(f"Failed to connect to R Shiny at {RSHINY_URL}")
        raise HTTPException(
            status_code=503, 
            detail="R Shiny service unavailable"
        )
    except httpx.TimeoutException:
        logger.error(f"Timeout connecting to R Shiny at {RSHINY_URL}")
        raise HTTPException(
            status_code=504, 
            detail="R Shiny service timeout"
        )
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Internal proxy error"
        ) 