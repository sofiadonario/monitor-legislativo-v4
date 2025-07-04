from fastapi import APIRouter, Response, HTTPException
import httpx, os

router = APIRouter()

RSHINY_URL = os.getenv("RSHINY_URL", "https://rshiny-production-1f4b.up.railway.app")

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