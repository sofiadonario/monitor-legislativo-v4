#!/usr/bin/env python3
'''
LexML Advanced Analytics API
FastAPI endpoints for accessing analysis results
'''

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import json
import os
from datetime import datetime

app = FastAPI(
    title="LexML Advanced Analytics API",
    description="API for accessing LexML regulatory analysis results",
    version="1.0.0"
)

class DocumentRequest(BaseModel):
    title: str
    description: str
    document_type: Optional[str] = None
    authority: Optional[str] = None
    year: Optional[int] = None

class AnalysisResponse(BaseModel):
    timestamp: str
    results: Dict[str, Any]
    status: str

@app.get("/")
async def root():
    return {"message": "LexML Advanced Analytics API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/analysis/summary")
async def get_analysis_summary():
    '''Get comprehensive analysis summary'''
    try:
        # Find latest analysis file
        analysis_files = [f for f in os.listdir('.') if f.startswith('lexml_comprehensive_analysis_')]
        if not analysis_files:
            raise HTTPException(status_code=404, detail="No analysis files found")
        
        latest_file = sorted(analysis_files)[-1]
        
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return AnalysisResponse(
            timestamp=data.get('analysis_timestamp', datetime.now().isoformat()),
            results=data.get('analysis_results', {}),
            status="success"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analysis/temporal")
async def get_temporal_analysis():
    '''Get temporal analysis results'''
    try:
        analysis_files = [f for f in os.listdir('.') if f.startswith('lexml_comprehensive_analysis_')]
        if not analysis_files:
            raise HTTPException(status_code=404, detail="No analysis files found")
        
        latest_file = sorted(analysis_files)[-1]
        
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        temporal_data = data.get('analysis_results', {}).get('temporal', {})
        
        return {
            "temporal_analysis": temporal_data,
            "timestamp": data.get('analysis_timestamp', datetime.now().isoformat())
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analysis/network")
async def get_network_analysis():
    '''Get network analysis results'''
    try:
        analysis_files = [f for f in os.listdir('.') if f.startswith('lexml_comprehensive_analysis_')]
        if not analysis_files:
            raise HTTPException(status_code=404, detail="No analysis files found")
        
        latest_file = sorted(analysis_files)[-1]
        
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        network_data = data.get('analysis_results', {}).get('network', {})
        
        return {
            "network_analysis": network_data,
            "timestamp": data.get('analysis_timestamp', datetime.now().isoformat())
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analysis/semantic")
async def get_semantic_analysis():
    '''Get semantic analysis results'''
    try:
        analysis_files = [f for f in os.listdir('.') if f.startswith('lexml_comprehensive_analysis_')]
        if not analysis_files:
            raise HTTPException(status_code=404, detail="No analysis files found")
        
        latest_file = sorted(analysis_files)[-1]
        
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        semantic_data = data.get('analysis_results', {}).get('semantic', {})
        
        return {
            "semantic_analysis": semantic_data,
            "timestamp": data.get('analysis_timestamp', datetime.now().isoformat())
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analysis/geospatial")
async def get_geospatial_analysis():
    '''Get geospatial analysis results'''
    try:
        analysis_files = [f for f in os.listdir('.') if f.startswith('lexml_comprehensive_analysis_')]
        if not analysis_files:
            raise HTTPException(status_code=404, detail="No analysis files found")
        
        latest_file = sorted(analysis_files)[-1]
        
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        geospatial_data = data.get('analysis_results', {}).get('geospatial', {})
        
        return {
            "geospatial_analysis": geospatial_data,
            "timestamp": data.get('analysis_timestamp', datetime.now().isoformat())
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/document")
async def predict_document(request: DocumentRequest):
    '''Predict document classification and impact'''
    try:
        # This would integrate with the ML pipeline
        # For now, return a mock response
        
        mock_prediction = {
            "document_type": {
                "predicted_class": "legislacao",
                "confidence": 0.87
            },
            "impact_level": {
                "predicted_class": "Alto",
                "confidence": 0.73
            },
            "transport_mode": {
                "predicted_class": "rodoviario",
                "confidence": 0.82
            },
            "authority": {
                "predicted_class": "ANTT",
                "confidence": 0.91
            }
        }
        
        return {
            "predictions": mock_prediction,
            "input": request.dict(),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/forecast/regulatory")
async def get_regulatory_forecast():
    '''Get regulatory production forecast'''
    try:
        # Mock forecast data
        forecast_data = {
            "forecast_horizon": 24,
            "base_scenario": {
                "total_documents": [350, 365, 380, 395, 410, 425],
                "months": ["2025-01", "2025-02", "2025-03", "2025-04", "2025-05", "2025-06"]
            },
            "confidence_intervals": {
                "upper_80": [420, 438, 456, 474, 492, 510],
                "lower_80": [280, 292, 304, 316, 328, 340]
            },
            "key_insights": [
                "Steady growth expected in regulatory production",
                "Peak activity anticipated in Q4",
                "Technology regulations showing highest growth"
            ]
        }
        
        return {
            "forecast": forecast_data,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
