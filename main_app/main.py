from fastapi import FastAPI
from . import gateway_router

# Version 1.0.1 - Fixed Pydantic v2 compatibility (regex -> pattern)
app = FastAPI(title="Monitor Legislativo - Unified Service")

app.include_router(gateway_router.router)

@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Monitor Legislativo Unified Service"}

# We will add the other routers here. 