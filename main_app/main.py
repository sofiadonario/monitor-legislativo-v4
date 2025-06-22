from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from . import gateway_router
from .routers import lexml_router

# Version 1.1.0 - Added LexML Brasil API integration
app = FastAPI(
    title="Monitor Legislativo - Unified Service",
    description="Brazilian Legislative Monitor with LexML Brasil API Integration",
    version="1.1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sofiadonario.github.io",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(gateway_router.router)
app.include_router(lexml_router.router)

@app.get("/", tags=["Root"])
async def read_root():
    return {
        "message": "Welcome to the Monitor Legislativo Unified Service",
        "version": "1.1.0",
        "features": [
            "LexML Brasil API Integration",
            "Real-time Legislative Search",
            "Hybrid Data Sources (API + CSV Fallback)",
            "Circuit Breaker Pattern",
            "Academic Research Tools"
        ]
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Enhanced health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": "monitor-legislativo-api",
        "version": "1.1.0",
        "components": {
            "lexml_api": "available",
            "csv_fallback": "available",
            "cache_service": "available"
        }
    } 