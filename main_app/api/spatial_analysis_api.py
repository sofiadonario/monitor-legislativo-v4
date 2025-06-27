"""
Spatial Analysis API Router
FastAPI endpoints for advanced spatial document analysis
"""
from fastapi import APIRouter, HTTPException, Query, Body
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import asyncio
import logging

from core.services.spatial_analysis import SpatialAnalysisService, GeoLocation, SpatialCluster, DocumentSpatialAnalysis
from core.models.legislative_data import LegislativeDocument

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/spatial", tags=["Spatial Analysis"])

# Global service instance
spatial_service: Optional[SpatialAnalysisService] = None

async def get_spatial_service() -> SpatialAnalysisService:
    """Get or create spatial analysis service instance."""
    global spatial_service
    if spatial_service is None:
        spatial_service = SpatialAnalysisService()
    return spatial_service

# Pydantic models for API
class GeoLocationResponse(BaseModel):
    latitude: float
    longitude: float
    municipality: str
    state: str
    state_code: str
    region: str
    ibge_code: str
    population: Optional[int] = None
    area_km2: Optional[float] = None
    confidence: float

class SpatialAnalysisResponse(BaseModel):
    document_id: str
    extracted_locations: List[GeoLocationResponse]
    primary_location: Optional[GeoLocationResponse]
    jurisdiction_level: str
    coverage_area: List[str]
    spatial_keywords: List[str]
    geographic_scope: str
    related_locations: List[GeoLocationResponse]
    confidence_score: float

class SpatialClusterResponse(BaseModel):
    cluster_id: str
    centroid: GeoLocationResponse
    documents: List[str]
    radius_km: float
    document_count: int
    themes: List[str]
    temporal_span: List[str]
    regulatory_density: float
    cluster_strength: float

class DocumentInput(BaseModel):
    id: str
    title: str
    summary: str
    data_evento: Optional[str] = None
    tipo_documento: Optional[str] = None
    fonte: Optional[str] = None

class ReverseGeocodeRequest(BaseModel):
    latitude: float
    longitude: float

@router.post("/analyze-document", response_model=SpatialAnalysisResponse)
async def analyze_document_spatial_context(document: DocumentInput):
    """Analyze spatial context of a legislative document."""
    try:
        service = await get_spatial_service()
        
        # Convert input to LegislativeDocument
        legislative_doc = LegislativeDocument(
            id=document.id,
            title=document.title,
            summary=document.summary,
            data_evento=document.data_evento or "",
            tipo_documento=document.tipo_documento or "",
            fonte=document.fonte or ""
        )
        
        # Perform spatial analysis
        analysis = await service.analyze_document_spatial_context(legislative_doc)
        
        # Convert to response format
        def convert_location(loc: GeoLocation) -> GeoLocationResponse:
            return GeoLocationResponse(
                latitude=loc.latitude,
                longitude=loc.longitude,
                municipality=loc.municipality,
                state=loc.state,
                state_code=loc.state_code,
                region=loc.region,
                ibge_code=loc.ibge_code,
                population=loc.population,
                area_km2=loc.area_km2,
                confidence=loc.confidence
            )
        
        return SpatialAnalysisResponse(
            document_id=analysis.document_id,
            extracted_locations=[convert_location(loc) for loc in analysis.extracted_locations],
            primary_location=convert_location(analysis.primary_location) if analysis.primary_location else None,
            jurisdiction_level=analysis.jurisdiction_level,
            coverage_area=analysis.coverage_area,
            spatial_keywords=analysis.spatial_keywords,
            geographic_scope=analysis.geographic_scope,
            related_locations=[convert_location(loc) for loc in analysis.related_locations],
            confidence_score=analysis.confidence_score
        )
        
    except Exception as e:
        logger.error(f"Error analyzing document spatial context: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Spatial analysis failed: {str(e)}")

@router.post("/find-clusters", response_model=List[SpatialClusterResponse])
async def find_spatial_clusters(
    documents: List[DocumentInput],
    max_distance_km: float = Query(100.0, description="Maximum distance in kilometers for clustering")
):
    """Find spatial clusters of documents based on geographic proximity."""
    try:
        service = await get_spatial_service()
        
        # Convert inputs to LegislativeDocument
        legislative_docs = [
            LegislativeDocument(
                id=doc.id,
                title=doc.title,
                summary=doc.summary,
                data_evento=doc.data_evento or "",
                tipo_documento=doc.tipo_documento or "",
                fonte=doc.fonte or ""
            )
            for doc in documents
        ]
        
        # Find clusters
        clusters = await service.find_spatial_clusters(legislative_docs, max_distance_km)
        
        # Convert to response format
        def convert_cluster(cluster: SpatialCluster) -> SpatialClusterResponse:
            return SpatialClusterResponse(
                cluster_id=cluster.cluster_id,
                centroid=GeoLocationResponse(
                    latitude=cluster.centroid.latitude,
                    longitude=cluster.centroid.longitude,
                    municipality=cluster.centroid.municipality,
                    state=cluster.centroid.state,
                    state_code=cluster.centroid.state_code,
                    region=cluster.centroid.region,
                    ibge_code=cluster.centroid.ibge_code,
                    population=cluster.centroid.population,
                    area_km2=cluster.centroid.area_km2,
                    confidence=cluster.centroid.confidence
                ),
                documents=cluster.documents,
                radius_km=cluster.radius_km,
                document_count=cluster.document_count,
                themes=cluster.themes,
                temporal_span=list(cluster.temporal_span),
                regulatory_density=cluster.regulatory_density,
                cluster_strength=cluster.cluster_strength
            )
        
        return [convert_cluster(cluster) for cluster in clusters]
        
    except Exception as e:
        logger.error(f"Error finding spatial clusters: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Spatial clustering failed: {str(e)}")

@router.post("/reverse-geocode", response_model=Optional[GeoLocationResponse])
async def reverse_geocode_location(request: ReverseGeocodeRequest):
    """Reverse geocode coordinates to get Brazilian location information."""
    try:
        service = await get_spatial_service()
        
        location = await service.reverse_geocode_location(request.latitude, request.longitude)
        
        if location:
            return GeoLocationResponse(
                latitude=location.latitude,
                longitude=location.longitude,
                municipality=location.municipality,
                state=location.state,
                state_code=location.state_code,
                region=location.region,
                ibge_code=location.ibge_code,
                population=location.population,
                area_km2=location.area_km2,
                confidence=location.confidence
            )
        else:
            return None
            
    except Exception as e:
        logger.error(f"Error reverse geocoding: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Reverse geocoding failed: {str(e)}")

@router.post("/analyze-relationships")
async def analyze_spatial_relationships(documents: List[DocumentInput]):
    """Analyze spatial relationships between documents."""
    try:
        service = await get_spatial_service()
        
        # Convert inputs to LegislativeDocument
        legislative_docs = [
            LegislativeDocument(
                id=doc.id,
                title=doc.title,
                summary=doc.summary,
                data_evento=doc.data_evento or "",
                tipo_documento=doc.tipo_documento or "",
                fonte=doc.fonte or ""
            )
            for doc in documents
        ]
        
        # Analyze relationships
        relationships = await service.analyze_spatial_relationships(legislative_docs)
        
        # Convert to response format
        response_relationships = []
        for rel in relationships:
            response_relationships.append({
                "document1_id": rel.document1_id,
                "document2_id": rel.document2_id,
                "relationship_type": rel.relationship_type,
                "distance_km": rel.distance_km,
                "shared_locations": rel.shared_locations,
                "correlation_strength": rel.correlation_strength,
                "temporal_overlap": rel.temporal_overlap
            })
        
        return {
            "total_relationships": len(response_relationships),
            "relationships": response_relationships
        }
        
    except Exception as e:
        logger.error(f"Error analyzing spatial relationships: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Spatial relationship analysis failed: {str(e)}")

@router.get("/brazilian-geography")
async def get_brazilian_geography_data():
    """Get Brazilian geography reference data."""
    try:
        service = await get_spatial_service()
        
        return {
            "states": service.brazilian_states,
            "major_municipalities": service.major_municipalities,
            "regional_boundaries": service.regional_boundaries,
            "total_states": len(service.brazilian_states),
            "total_major_cities": len(service.major_municipalities),
            "regions": list(service.regional_boundaries.keys())
        }
        
    except Exception as e:
        logger.error(f"Error getting Brazilian geography data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get geography data: {str(e)}")

@router.get("/health")
async def get_spatial_service_health():
    """Get spatial analysis service health status."""
    try:
        service = await get_spatial_service()
        
        return {
            "status": "healthy",
            "service": "spatial_analysis",
            "components": {
                "geographic_data": "loaded",
                "pattern_recognition": "initialized",
                "clustering_algorithm": "ready",
                "reverse_geocoding": "available"
            },
            "data_coverage": {
                "brazilian_states": len(service.brazilian_states),
                "major_cities": len(service.major_municipalities),
                "geographic_keywords": sum(len(keywords) for keywords in service.geographic_keywords.values()),
                "jurisdiction_patterns": sum(len(patterns) for patterns in service.jurisdiction_patterns.values())
            }
        }
        
    except Exception as e:
        logger.error(f"Spatial service health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "service": "spatial_analysis",
            "error": str(e)
        }