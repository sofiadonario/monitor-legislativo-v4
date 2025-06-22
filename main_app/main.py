from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from . import gateway_router

# Version 1.0.1 - Fixed Pydantic v2 compatibility (regex -> pattern)
app = FastAPI(title="Monitor Legislativo - Unified Service")

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

@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Monitor Legislativo Unified Service"}

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": "monitor-legislativo-api",
        "version": "1.0.1"
    }

# We will add the other routers here. 