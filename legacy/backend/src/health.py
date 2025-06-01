"""Health check endpoints for monitoring service readiness."""
import asyncio
import os
from datetime import datetime
from typing import Dict, Any, Optional
import logging
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

logger = logging.getLogger(__name__)


async def check_postgres(session: Optional[AsyncSession]) -> Dict[str, Any]:
    """Check PostgreSQL connectivity and health."""
    if not session:
        return {
            "status": "unavailable",
            "message": "No database session available"
        }
    
    try:
        start = datetime.utcnow()
        result = await session.execute(text("SELECT 1"))
        await session.commit()
        latency_ms = (datetime.utcnow() - start).total_seconds() * 1000
        
        return {
            "status": "healthy",
            "latency_ms": round(latency_ms, 2)
        }
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }


async def check_redis(redis_url: Optional[str]) -> Dict[str, Any]:
    """Check Redis connectivity and health."""
    if not redis_url:
        return {
            "status": "not_configured",
            "message": "REDIS_URL not set"
        }
    
    client = None
    try:
        start = datetime.utcnow()
        client = redis.from_url(redis_url, decode_responses=True)
        await client.ping()
        latency_ms = (datetime.utcnow() - start).total_seconds() * 1000
        
        return {
            "status": "healthy",
            "latency_ms": round(latency_ms, 2)
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }
    finally:
        if client:
            await client.close()


async def check_readiness(
    db_session: Optional[AsyncSession] = None,
    check_db: bool = True,
    check_redis_conn: bool = True
) -> Dict[str, Any]:
    """
    Comprehensive readiness check for the service.
    
    Returns 200 if all critical services are healthy.
    Returns 503 if any critical service is unhealthy.
    """
    checks = {}
    all_healthy = True
    
    # Always include basic service info
    checks["service"] = {
        "name": "monitor-legislativo-api",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Check PostgreSQL if requested
    if check_db:
        postgres_check = await check_postgres(db_session)
        checks["postgres"] = postgres_check
        if postgres_check["status"] != "healthy":
            all_healthy = False
    
    # Check Redis if requested
    if check_redis_conn:
        redis_url = os.getenv("REDIS_URL")
        redis_check = await check_redis(redis_url)
        checks["redis"] = redis_check
        # Redis is optional, so don't fail readiness if not configured
        if redis_check["status"] == "unhealthy":
            all_healthy = False
    
    # Overall status
    overall_status = "ready" if all_healthy else "not_ready"
    
    response = {
        "status": overall_status,
        "checks": checks
    }
    
    if not all_healthy:
        raise HTTPException(status_code=503, detail=response)
    
    return response