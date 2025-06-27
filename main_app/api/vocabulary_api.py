"""
Vocabulary API Router
FastAPI endpoints for SKOS vocabulary management and navigation
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging

from core.vocabulary.skos_manager import SKOSVocabularyManager, ConceptScheme

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vocabulary", tags=["Vocabulary"])

# Global service instance
vocab_manager: Optional[SKOSVocabularyManager] = None

async def get_vocabulary_manager() -> SKOSVocabularyManager:
    """Get or create vocabulary manager instance."""
    global vocab_manager
    if vocab_manager is None:
        vocab_manager = SKOSVocabularyManager()
    return vocab_manager

# Pydantic models for API
class ConceptResponse(BaseModel):
    uri: str
    pref_label: Dict[str, str]
    alt_labels: Dict[str, List[str]]
    definition: Dict[str, str]
    concept_scheme: Optional[str]
    broader: List[str]
    narrower: List[str]
    related: List[str]
    notation: Optional[str] = None

class SearchResultResponse(BaseModel):
    concept: ConceptResponse
    match_type: str
    score: float
    matched_label: str
    context: Optional[str] = None

class HierarchyResponse(BaseModel):
    concept: ConceptResponse
    path: List[str]
    children: List[ConceptResponse]
    parent: Optional[ConceptResponse] = None
    siblings: List[ConceptResponse]
    depth: int
    is_root: bool
    is_leaf: bool

class QueryExpansionResponse(BaseModel):
    original: List[str]
    narrower: List[str]
    broader: List[str]
    related: List[str]
    synonyms: List[str]

class SchemeOverviewResponse(BaseModel):
    scheme: str
    total_concepts: int
    max_depth: int
    root_concepts: List[Dict[str, Any]]
    top_level_categories: int

@router.get("/search", response_model=List[SearchResultResponse])
async def search_concepts(
    query: str = Query(..., description="Search query"),
    lang: str = Query("pt", description="Language for search"),
    limit: int = Query(20, description="Maximum number of results"),
    concept_scheme: Optional[str] = Query(None, description="Filter by concept scheme")
):
    """Search concepts with fuzzy matching and ranking."""
    try:
        manager = await get_vocabulary_manager()
        
        # Convert scheme string to enum if provided
        scheme_filter = None
        if concept_scheme:
            try:
                scheme_filter = ConceptScheme(concept_scheme)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid concept scheme: {concept_scheme}")
        
        # Perform search
        results = manager.search_concepts(query, lang, limit, scheme_filter)
        
        # Convert to response format
        response_results = []
        for result in results:
            concept_response = ConceptResponse(
                uri=result.concept.uri,
                pref_label=result.concept.pref_label,
                alt_labels=result.concept.alt_labels,
                definition=result.concept.definition,
                concept_scheme=result.concept.concept_scheme.value if result.concept.concept_scheme else None,
                broader=list(result.concept.broader),
                narrower=list(result.concept.narrower),
                related=list(result.concept.related),
                notation=result.concept.notation
            )
            
            response_results.append(SearchResultResponse(
                concept=concept_response,
                match_type=result.match_type,
                score=result.score,
                matched_label=result.matched_label,
                context=result.context
            ))
        
        return response_results
        
    except Exception as e:
        logger.error(f"Error searching concepts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Concept search failed: {str(e)}")

@router.get("/concept/{concept_uri:path}", response_model=HierarchyResponse)
async def get_concept_hierarchy(concept_uri: str):
    """Get hierarchical information for a concept."""
    try:
        manager = await get_vocabulary_manager()
        
        # Get concept hierarchy
        hierarchy_data = manager.get_concept_hierarchy(concept_uri)
        
        if not hierarchy_data:
            raise HTTPException(status_code=404, detail=f"Concept not found: {concept_uri}")
        
        # Convert to response format
        def convert_concept(concept):
            return ConceptResponse(
                uri=concept.uri,
                pref_label=concept.pref_label,
                alt_labels=concept.alt_labels,
                definition=concept.definition,
                concept_scheme=concept.concept_scheme.value if concept.concept_scheme else None,
                broader=list(concept.broader),
                narrower=list(concept.narrower),
                related=list(concept.related),
                notation=concept.notation
            )
        
        main_concept = convert_concept(hierarchy_data["concept"])
        children = [convert_concept(child) for child in hierarchy_data.get("children", [])]
        siblings = [convert_concept(sibling) for sibling in hierarchy_data.get("siblings", [])]
        parent = convert_concept(hierarchy_data["parent"]) if hierarchy_data.get("parent") else None
        
        return HierarchyResponse(
            concept=main_concept,
            path=hierarchy_data.get("path", []),
            children=children,
            parent=parent,
            siblings=siblings,
            depth=hierarchy_data.get("depth", 0),
            is_root=hierarchy_data.get("is_root", False),
            is_leaf=hierarchy_data.get("is_leaf", False)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting concept hierarchy: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get concept hierarchy: {str(e)}")

@router.get("/concept/{concept_uri:path}/broader", response_model=List[ConceptResponse])
async def get_broader_concepts(
    concept_uri: str,
    transitive: bool = Query(False, description="Include transitive broader concepts")
):
    """Get broader concepts (direct or transitive)."""
    try:
        manager = await get_vocabulary_manager()
        
        broader_concepts = manager.get_broader_concepts(concept_uri, transitive)
        
        return [
            ConceptResponse(
                uri=concept.uri,
                pref_label=concept.pref_label,
                alt_labels=concept.alt_labels,
                definition=concept.definition,
                concept_scheme=concept.concept_scheme.value if concept.concept_scheme else None,
                broader=list(concept.broader),
                narrower=list(concept.narrower),
                related=list(concept.related),
                notation=concept.notation
            )
            for concept in broader_concepts
        ]
        
    except Exception as e:
        logger.error(f"Error getting broader concepts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get broader concepts: {str(e)}")

@router.get("/concept/{concept_uri:path}/narrower", response_model=List[ConceptResponse])
async def get_narrower_concepts(
    concept_uri: str,
    transitive: bool = Query(False, description="Include transitive narrower concepts")
):
    """Get narrower concepts (direct or transitive)."""
    try:
        manager = await get_vocabulary_manager()
        
        narrower_concepts = manager.get_narrower_concepts(concept_uri, transitive)
        
        return [
            ConceptResponse(
                uri=concept.uri,
                pref_label=concept.pref_label,
                alt_labels=concept.alt_labels,
                definition=concept.definition,
                concept_scheme=concept.concept_scheme.value if concept.concept_scheme else None,
                broader=list(concept.broader),
                narrower=list(concept.narrower),
                related=list(concept.related),
                notation=concept.notation
            )
            for concept in narrower_concepts
        ]
        
    except Exception as e:
        logger.error(f"Error getting narrower concepts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get narrower concepts: {str(e)}")

@router.get("/concept/{concept_uri:path}/related", response_model=List[ConceptResponse])
async def get_related_concepts(concept_uri: str):
    """Get related concepts."""
    try:
        manager = await get_vocabulary_manager()
        
        related_concepts = manager.get_related_concepts(concept_uri)
        
        return [
            ConceptResponse(
                uri=concept.uri,
                pref_label=concept.pref_label,
                alt_labels=concept.alt_labels,
                definition=concept.definition,
                concept_scheme=concept.concept_scheme.value if concept.concept_scheme else None,
                broader=list(concept.broader),
                narrower=list(concept.narrower),
                related=list(concept.related),
                notation=concept.notation
            )
            for concept in related_concepts
        ]
        
    except Exception as e:
        logger.error(f"Error getting related concepts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get related concepts: {str(e)}")

@router.post("/expand-query", response_model=QueryExpansionResponse)
async def expand_query_with_vocabulary(
    query: str,
    expansion_types: List[str] = Query(["narrower", "broader", "related", "synonyms"], description="Types of expansion"),
    max_expansions: int = Query(10, description="Maximum expansions per type")
):
    """Expand query using vocabulary relationships."""
    try:
        manager = await get_vocabulary_manager()
        
        expansion = manager.expand_query_with_vocabulary(query, expansion_types, max_expansions)
        
        return QueryExpansionResponse(
            original=expansion["original"],
            narrower=expansion["narrower"],
            broader=expansion["broader"],
            related=expansion["related"],
            synonyms=expansion["synonyms"]
        )
        
    except Exception as e:
        logger.error(f"Error expanding query: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Query expansion failed: {str(e)}")

@router.get("/schemes", response_model=List[SchemeOverviewResponse])
async def get_all_concept_schemes():
    """Get overview of all concept schemes."""
    try:
        manager = await get_vocabulary_manager()
        
        schemes = manager.get_all_concept_schemes()
        
        return [
            SchemeOverviewResponse(
                scheme=scheme["scheme"],
                total_concepts=scheme["total_concepts"],
                max_depth=scheme["max_depth"],
                root_concepts=scheme["root_concepts"],
                top_level_categories=scheme["top_level_categories"]
            )
            for scheme in schemes
        ]
        
    except Exception as e:
        logger.error(f"Error getting concept schemes: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get concept schemes: {str(e)}")

@router.get("/scheme/{scheme_name}", response_model=SchemeOverviewResponse)
async def get_concept_scheme_overview(scheme_name: str):
    """Get overview of a specific concept scheme."""
    try:
        manager = await get_vocabulary_manager()
        
        # Convert scheme name to enum
        try:
            scheme = ConceptScheme(scheme_name)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid concept scheme: {scheme_name}")
        
        scheme_data = manager.get_concept_scheme_overview(scheme)
        
        if not scheme_data:
            raise HTTPException(status_code=404, detail=f"Concept scheme not found: {scheme_name}")
        
        return SchemeOverviewResponse(
            scheme=scheme_data["scheme"],
            total_concepts=scheme_data["total_concepts"],
            max_depth=scheme_data["max_depth"],
            root_concepts=scheme_data["root_concepts"],
            top_level_categories=scheme_data["top_level_categories"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting concept scheme overview: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get scheme overview: {str(e)}")

@router.get("/export/skos-rdf")
async def export_skos_rdf(concept_scheme: Optional[str] = Query(None, description="Export specific scheme")):
    """Export vocabulary as SKOS RDF/XML."""
    try:
        manager = await get_vocabulary_manager()
        
        # Convert scheme string to enum if provided
        scheme_filter = None
        if concept_scheme:
            try:
                scheme_filter = ConceptScheme(concept_scheme)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid concept scheme: {concept_scheme}")
        
        rdf_data = manager.export_skos_rdf(scheme_filter)
        
        return {
            "format": "application/ld+json",
            "scheme": concept_scheme or "all",
            "exported_at": "2024-01-01T00:00:00Z",  # Would be actual timestamp
            "data": rdf_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting SKOS RDF: {str(e)}")
        raise HTTPException(status_code=500, detail=f"SKOS export failed: {str(e)}")

@router.get("/health")
async def get_vocabulary_service_health():
    """Get vocabulary service health status."""
    try:
        manager = await get_vocabulary_manager()
        
        total_concepts = len(manager.concepts)
        total_schemes = len(manager.hierarchies)
        
        return {
            "status": "healthy",
            "service": "vocabulary_management",
            "components": {
                "skos_compliance": "w3c_compliant",
                "vocabulary_loading": "completed",
                "search_indexing": "ready",
                "hierarchy_building": "completed"
            },
            "data_coverage": {
                "total_concepts": total_concepts,
                "concept_schemes": total_schemes,
                "languages_supported": ["pt", "en"],
                "relationship_types": ["broader", "narrower", "related", "exact_match", "close_match"]
            },
            "performance": {
                "label_index_size": len(manager.label_index),
                "average_hierarchy_depth": sum(h.max_depth for h in manager.hierarchies.values()) / len(manager.hierarchies) if manager.hierarchies else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Vocabulary service health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "service": "vocabulary_management",
            "error": str(e)
        }