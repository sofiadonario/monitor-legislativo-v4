from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
from typing import Dict, Any

router = APIRouter(prefix="/analytics", tags=["Analytics"])

@router.get("/summary", response_model=Dict[str, Any])
async def get_summary() -> Dict[str, Any]:
    """Return high-level analytics about the dataset.
    In a real implementation this would query the database. For now we return static placeholders so that the
    contract is available for the R Shiny dashboard or any other consumer."""
    # TODO: wire this up to database models once migration is complete
    summary = {
        "documents_total": 123456,
        "latest_document": datetime.utcnow().isoformat() + "Z",
        "analytics_generated": 98765,
        "cache_entries": 4321,
    }
    return summary

@router.get("/health", response_model=Dict[str, str])
async def analytics_health() -> Dict[str, str]:
    """Simple health-check so the container orchestrator can verify this router is reachable."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"} 