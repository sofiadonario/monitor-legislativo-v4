"""
Minimal FastAPI app for Railway deployment testing
Monitor Legislativo v4 - Ultra-Budget Academic Deployment
"""

import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Create minimal FastAPI app
app = FastAPI(
    title="Monitor Legislativo v4 API",
    description="Brazilian Legislative Monitoring System",
    version="4.0.0"
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Monitor Legislativo v4 API",
        "version": "4.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Railway"""
    return {
        "status": "healthy",
        "version": "4.0.0",
        "port": os.getenv("PORT", "8000"),
        "environment": "production"
    }

@app.get("/api/docs")
async def docs_redirect():
    """Redirect to docs"""
    return {"message": "API documentation available at /docs"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)