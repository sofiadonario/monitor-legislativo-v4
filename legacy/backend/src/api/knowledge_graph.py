"""
Knowledge Graph API - Legislative Knowledge Graph Generator
Entity extraction and relationship mapping for Brazilian legislative documents
Based on ai-knowledge-graph patterns with NetworkX integration
"""

import asyncio
import json
import logging
import time
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import hashlib

# NetworkX for graph operations
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    logging.warning("NetworkX not available - knowledge graph functionality limited")

logger = logging.getLogger(__name__)

# Router for knowledge graph API
router = APIRouter(prefix="/api/v1/knowledge-graph", tags=["Knowledge Graph"])

class EntityType(str, Enum):
    """Types of entities that can be extracted from documents"""
    PERSON = "person"
    ORGANIZATION = "organization"
    LOCATION = "location"
    LAW = "law"
    REGULATION = "regulation"
    CONCEPT = "concept"
    DATE = "date"
    MONETARY = "monetary"
    TRANSPORT_MODE = "transport_mode"
    AGENCY = "agency"

class RelationshipType(str, Enum):
    """Types of relationships between entities"""
    CITES = "cites"
    MENTIONS = "mentions"
    RELATES_TO = "relates_to"
    MODIFIES = "modifies"
    IMPLEMENTS = "implements"
    SUPERSEDES = "supersedes"
    INFLUENCES = "influences"
    GOVERNS = "governs"
    LOCATED_IN = "located_in"
    REGULATED_BY = "regulated_by"

class GraphMetricType(str, Enum):
    """Types of graph analysis metrics"""
    CENTRALITY = "centrality"
    CLUSTERING = "clustering"
    CONNECTIVITY = "connectivity"
    INFLUENCE = "influence"

@dataclass
class Entity:
    """Represents an entity extracted from documents"""
    id: str
    name: str
    type: EntityType
    mentions: int
    confidence: float
    context: List[str]
    properties: Dict[str, Any]
    document_ids: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type.value,
            'mentions': self.mentions,
            'confidence': self.confidence,
            'context': self.context,
            'properties': self.properties,
            'document_ids': self.document_ids
        }

@dataclass
class Relationship:
    """Represents a relationship between entities"""
    id: str
    source_entity_id: str
    target_entity_id: str
    type: RelationshipType
    confidence: float
    context: str
    document_id: str
    properties: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source_entity_id': self.source_entity_id,
            'target_entity_id': self.target_entity_id,
            'type': self.type.value,
            'confidence': self.confidence,
            'context': self.context,
            'document_id': self.document_id,
            'properties': self.properties
        }

@dataclass
class GraphCluster:
    """Represents a cluster of related entities"""
    id: str
    name: str
    entities: List[str]
    coherence_score: float
    topics: List[str]
    summary: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'entities': self.entities,
            'coherence_score': self.coherence_score,
            'topics': self.topics,
            'summary': self.summary
        }

@dataclass
class GraphInsight:
    """Represents an insight discovered in the knowledge graph"""
    id: str
    type: str
    description: str
    entities: List[str]
    relationships: List[str]
    significance: float
    evidence: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'description': self.description,
            'entities': self.entities,
            'relationships': self.relationships,
            'significance': self.significance,
            'evidence': self.evidence
        }

# Pydantic models for API
class DocumentInput(BaseModel):
    id: str = Field(..., description="Document identifier")
    title: str = Field(..., description="Document title")
    content: str = Field(..., description="Document content")
    date: Optional[str] = Field(None, description="Document date")
    source: Optional[str] = Field(None, description="Document source")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Additional metadata")

class EntityExtractionRequest(BaseModel):
    documents: List[DocumentInput] = Field(..., description="Documents to extract entities from")
    entity_types: List[EntityType] = Field(default=[], description="Specific entity types to extract")
    min_confidence: float = Field(default=0.5, description="Minimum confidence threshold")
    extract_relationships: bool = Field(default=True, description="Whether to extract relationships")

class GraphAnalysisRequest(BaseModel):
    entities: List[str] = Field(default=[], description="Specific entities to analyze")
    analysis_types: List[GraphMetricType] = Field(default=[], description="Types of analysis to perform")
    include_clusters: bool = Field(default=True, description="Include cluster analysis")
    include_insights: bool = Field(default=True, description="Include insight generation")

class GraphVisualizationRequest(BaseModel):
    entities: List[str] = Field(default=[], description="Entities to include in visualization")
    max_nodes: int = Field(default=100, description="Maximum number of nodes")
    layout: str = Field(default="spring", description="Graph layout algorithm")
    include_labels: bool = Field(default=True, description="Include node labels")

class KnowledgeGraphResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None
    stats: Optional[Dict[str, Any]] = None

class LegislativeKnowledgeGraph:
    """Main knowledge graph system for Brazilian legislative documents"""
    
    def __init__(self):
        self.graph = nx.MultiDiGraph() if NETWORKX_AVAILABLE else None
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        self.clusters: Dict[str, GraphCluster] = {}
        self.insights: List[GraphInsight] = []
        
        # Brazilian legislative patterns
        self.law_patterns = [
            r'Lei\s+(?:Federal\s+)?n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
            r'Decreto\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
            r'Medida\s+Provisória\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
            r'Resolução\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
            r'Portaria\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)'
        ]
        
        self.organization_patterns = [
            r'\b(?:ANTT|ANTAQ|ANAC|DNIT|IBAMA|CONAMA)\b',
            r'Ministério\s+(?:dos?\s+)?(?:Transportes?|Meio\s+Ambiente|Infraestrutura)',
            r'Secretaria\s+(?:de\s+)?(?:Transportes?|Mobilidade|Trânsito)',
            r'Prefeitura\s+(?:Municipal\s+)?de\s+\w+',
            r'Governo\s+(?:Federal|Estadual|do\s+Estado\s+de\s+\w+)'
        ]
        
        self.location_patterns = [
            r'\b(?:São\s+Paulo|Rio\s+de\s+Janeiro|Brasília|Belo\s+Horizonte|Salvador|Fortaleza|Recife|Porto\s+Alegre|Curitiba|Goiânia)\b',
            r'Estado\s+de\s+\w+',
            r'Município\s+de\s+\w+',
            r'Região\s+(?:Metropolitana\s+de\s+)?\w+'
        ]
        
        self.transport_patterns = [
            r'\b(?:rodoviário|ferroviário|aeroviário|aquaviário|metropolitano|urbano)\b',
            r'\b(?:ônibus|metrô|trem|avião|navio|bicicleta|motocicleta)\b',
            r'\b(?:rodovia|ferrovia|aeroporto|porto|terminal|estação)\b'
        ]
    
    async def extract_entities(self, documents: List[DocumentInput]) -> List[Entity]:
        """Extract entities from legislative documents"""
        start_time = time.time()
        entities_found = {}
        
        for doc in documents:
            # Extract different types of entities
            law_entities = self._extract_law_entities(doc)
            org_entities = self._extract_organization_entities(doc)
            location_entities = self._extract_location_entities(doc)
            transport_entities = self._extract_transport_entities(doc)
            
            # Merge all entities
            all_entities = law_entities + org_entities + location_entities + transport_entities
            
            for entity in all_entities:
                entity_key = f"{entity.type.value}:{entity.name.lower()}"
                
                if entity_key in entities_found:
                    # Merge with existing entity
                    existing = entities_found[entity_key]
                    existing.mentions += entity.mentions
                    existing.context.extend(entity.context)
                    existing.document_ids.extend(entity.document_ids)
                    existing.confidence = max(existing.confidence, entity.confidence)
                else:
                    entities_found[entity_key] = entity
        
        # Store entities
        for entity in entities_found.values():
            self.entities[entity.id] = entity
            if self.graph:
                self.graph.add_node(entity.id, **entity.to_dict())
        
        processing_time = time.time() - start_time
        logger.info(f"Extracted {len(entities_found)} entities in {processing_time:.2f}s")
        
        return list(entities_found.values())
    
    async def extract_relationships(self, documents: List[DocumentInput]) -> List[Relationship]:
        """Extract relationships between entities"""
        start_time = time.time()
        relationships_found = []
        
        for doc in documents:
            # Extract various relationship types
            citation_rels = self._extract_citation_relationships(doc)
            modification_rels = self._extract_modification_relationships(doc)
            location_rels = self._extract_location_relationships(doc)
            regulatory_rels = self._extract_regulatory_relationships(doc)
            
            all_rels = citation_rels + modification_rels + location_rels + regulatory_rels
            relationships_found.extend(all_rels)
        
        # Store relationships
        for rel in relationships_found:
            self.relationships[rel.id] = rel
            if self.graph and rel.source_entity_id in self.entities and rel.target_entity_id in self.entities:
                self.graph.add_edge(
                    rel.source_entity_id,
                    rel.target_entity_id,
                    key=rel.id,
                    **rel.to_dict()
                )
        
        processing_time = time.time() - start_time
        logger.info(f"Extracted {len(relationships_found)} relationships in {processing_time:.2f}s")
        
        return relationships_found
    
    async def analyze_graph(self, analysis_types: List[GraphMetricType] = None) -> Dict[str, Any]:
        """Perform various graph analysis operations"""
        if not self.graph or not NETWORKX_AVAILABLE:
            return {"error": "Graph not available or NetworkX not installed"}
        
        start_time = time.time()
        analysis_results = {}
        
        if not analysis_types:
            analysis_types = list(GraphMetricType)
        
        try:
            # Basic graph metrics
            analysis_results['basic_metrics'] = {
                'nodes': self.graph.number_of_nodes(),
                'edges': self.graph.number_of_edges(),
                'density': nx.density(self.graph),
                'is_connected': nx.is_weakly_connected(self.graph)
            }
            
            if GraphMetricType.CENTRALITY in analysis_types:
                analysis_results['centrality'] = await self._analyze_centrality()
            
            if GraphMetricType.CLUSTERING in analysis_types:
                analysis_results['clustering'] = await self._analyze_clustering()
            
            if GraphMetricType.CONNECTIVITY in analysis_types:
                analysis_results['connectivity'] = await self._analyze_connectivity()
            
            if GraphMetricType.INFLUENCE in analysis_types:
                analysis_results['influence'] = await self._analyze_influence()
            
            processing_time = time.time() - start_time
            analysis_results['processing_time'] = processing_time
            
            logger.info(f"Graph analysis completed in {processing_time:.2f}s")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Graph analysis failed: {e}")
            return {"error": str(e)}
    
    async def discover_insights(self) -> List[GraphInsight]:
        """Discover insights from the knowledge graph"""
        insights = []
        
        # Hub identification
        hub_insights = await self._identify_hubs()
        insights.extend(hub_insights)
        
        # Bridge detection
        bridge_insights = await self._detect_bridges()
        insights.extend(bridge_insights)
        
        # Community discovery
        community_insights = await self._discover_communities()
        insights.extend(community_insights)
        
        # Influence pathway analysis
        influence_insights = await self._analyze_influence_pathways()
        insights.extend(influence_insights)
        
        self.insights = insights
        return insights
    
    async def generate_clusters(self) -> List[GraphCluster]:
        """Generate clusters of related entities"""
        if not self.graph or not NETWORKX_AVAILABLE:
            return []
        
        clusters = []
        
        try:
            # Use community detection algorithm
            undirected_graph = self.graph.to_undirected()
            communities = nx.community.greedy_modularity_communities(undirected_graph)
            
            for i, community in enumerate(communities):
                if len(community) >= 3:  # Only include meaningful clusters
                    cluster_entities = list(community)
                    topics = self._extract_cluster_topics(cluster_entities)
                    
                    cluster = GraphCluster(
                        id=f"cluster_{i}",
                        name=f"Cluster {i+1}: {', '.join(topics[:2])}",
                        entities=cluster_entities,
                        coherence_score=self._calculate_cluster_coherence(cluster_entities),
                        topics=topics,
                        summary=self._generate_cluster_summary(cluster_entities, topics)
                    )
                    
                    clusters.append(cluster)
                    self.clusters[cluster.id] = cluster
            
            logger.info(f"Generated {len(clusters)} clusters")
            return clusters
            
        except Exception as e:
            logger.error(f"Cluster generation failed: {e}")
            return []
    
    def get_graph_data(self, max_nodes: int = 100) -> Dict[str, Any]:
        """Get graph data for visualization"""
        if not self.graph:
            return {"nodes": [], "edges": []}
        
        # Limit nodes if graph is too large
        nodes = list(self.graph.nodes(data=True))[:max_nodes]
        node_ids = [node[0] for node in nodes]
        
        # Get edges between selected nodes
        edges = []
        for edge in self.graph.edges(data=True):
            if edge[0] in node_ids and edge[1] in node_ids:
                edges.append({
                    'source': edge[0],
                    'target': edge[1],
                    'data': edge[2]
                })
        
        return {
            'nodes': [{'id': node[0], 'data': node[1]} for node in nodes],
            'edges': edges,
            'stats': {
                'total_nodes': self.graph.number_of_nodes(),
                'total_edges': self.graph.number_of_edges(),
                'displayed_nodes': len(nodes),
                'displayed_edges': len(edges)
            }
        }
    
    # Private helper methods for entity extraction
    def _extract_law_entities(self, doc: DocumentInput) -> List[Entity]:
        """Extract law and regulation entities"""
        entities = []
        
        for pattern in self.law_patterns:
            matches = re.finditer(pattern, doc.content, re.IGNORECASE)
            for match in matches:
                entity_name = match.group(0)
                entity_id = f"law_{hashlib.md5(entity_name.encode()).hexdigest()[:8]}"
                
                entity = Entity(
                    id=entity_id,
                    name=entity_name,
                    type=EntityType.LAW,
                    mentions=1,
                    confidence=0.9,
                    context=[match.group(0)],
                    properties={"number": match.group(1) if match.groups() else None},
                    document_ids=[doc.id]
                )
                entities.append(entity)
        
        return entities
    
    def _extract_organization_entities(self, doc: DocumentInput) -> List[Entity]:
        """Extract organization entities"""
        entities = []
        
        for pattern in self.organization_patterns:
            matches = re.finditer(pattern, doc.content, re.IGNORECASE)
            for match in matches:
                entity_name = match.group(0)
                entity_id = f"org_{hashlib.md5(entity_name.encode()).hexdigest()[:8]}"
                
                entity = Entity(
                    id=entity_id,
                    name=entity_name,
                    type=EntityType.ORGANIZATION,
                    mentions=1,
                    confidence=0.85,
                    context=[match.group(0)],
                    properties={"category": "government_agency"},
                    document_ids=[doc.id]
                )
                entities.append(entity)
        
        return entities
    
    def _extract_location_entities(self, doc: DocumentInput) -> List[Entity]:
        """Extract location entities"""
        entities = []
        
        for pattern in self.location_patterns:
            matches = re.finditer(pattern, doc.content, re.IGNORECASE)
            for match in matches:
                entity_name = match.group(0)
                entity_id = f"loc_{hashlib.md5(entity_name.encode()).hexdigest()[:8]}"
                
                entity = Entity(
                    id=entity_id,
                    name=entity_name,
                    type=EntityType.LOCATION,
                    mentions=1,
                    confidence=0.8,
                    context=[match.group(0)],
                    properties={"country": "Brasil"},
                    document_ids=[doc.id]
                )
                entities.append(entity)
        
        return entities
    
    def _extract_transport_entities(self, doc: DocumentInput) -> List[Entity]:
        """Extract transport-related entities"""
        entities = []
        
        for pattern in self.transport_patterns:
            matches = re.finditer(pattern, doc.content, re.IGNORECASE)
            for match in matches:
                entity_name = match.group(0)
                entity_id = f"transport_{hashlib.md5(entity_name.encode()).hexdigest()[:8]}"
                
                entity = Entity(
                    id=entity_id,
                    name=entity_name,
                    type=EntityType.TRANSPORT_MODE,
                    mentions=1,
                    confidence=0.75,
                    context=[match.group(0)],
                    properties={"domain": "transport"},
                    document_ids=[doc.id]
                )
                entities.append(entity)
        
        return entities
    
    # Private helper methods for relationship extraction
    def _extract_citation_relationships(self, doc: DocumentInput) -> List[Relationship]:
        """Extract citation relationships between laws"""
        relationships = []
        # Implementation would analyze citation patterns
        return relationships
    
    def _extract_modification_relationships(self, doc: DocumentInput) -> List[Relationship]:
        """Extract modification relationships"""
        relationships = []
        # Implementation would analyze modification patterns
        return relationships
    
    def _extract_location_relationships(self, doc: DocumentInput) -> List[Relationship]:
        """Extract location-based relationships"""
        relationships = []
        # Implementation would analyze geographic relationships
        return relationships
    
    def _extract_regulatory_relationships(self, doc: DocumentInput) -> List[Relationship]:
        """Extract regulatory relationships"""
        relationships = []
        # Implementation would analyze regulatory patterns
        return relationships
    
    # Private helper methods for graph analysis
    async def _analyze_centrality(self) -> Dict[str, Any]:
        """Analyze node centrality metrics"""
        if not self.graph:
            return {}
        
        try:
            centrality_metrics = {
                'degree_centrality': nx.degree_centrality(self.graph),
                'betweenness_centrality': nx.betweenness_centrality(self.graph),
                'closeness_centrality': nx.closeness_centrality(self.graph),
                'eigenvector_centrality': nx.eigenvector_centrality(self.graph, max_iter=1000)
            }
            
            # Find top central nodes
            top_nodes = {}
            for metric, values in centrality_metrics.items():
                top_nodes[metric] = sorted(values.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'metrics': centrality_metrics,
                'top_nodes': top_nodes
            }
        except Exception as e:
            logger.warning(f"Centrality analysis failed: {e}")
            return {"error": str(e)}
    
    async def _analyze_clustering(self) -> Dict[str, Any]:
        """Analyze graph clustering"""
        if not self.graph:
            return {}
        
        try:
            undirected = self.graph.to_undirected()
            clustering_metrics = {
                'average_clustering': nx.average_clustering(undirected),
                'transitivity': nx.transitivity(undirected),
                'clustering_coefficient': nx.clustering(undirected)
            }
            
            return clustering_metrics
        except Exception as e:
            logger.warning(f"Clustering analysis failed: {e}")
            return {"error": str(e)}
    
    async def _analyze_connectivity(self) -> Dict[str, Any]:
        """Analyze graph connectivity"""
        if not self.graph:
            return {}
        
        try:
            connectivity_metrics = {
                'weakly_connected': nx.is_weakly_connected(self.graph),
                'strongly_connected': nx.is_strongly_connected(self.graph),
                'number_weakly_connected_components': nx.number_weakly_connected_components(self.graph),
                'number_strongly_connected_components': nx.number_strongly_connected_components(self.graph)
            }
            
            return connectivity_metrics
        except Exception as e:
            logger.warning(f"Connectivity analysis failed: {e}")
            return {"error": str(e)}
    
    async def _analyze_influence(self) -> Dict[str, Any]:
        """Analyze influence patterns"""
        # Implementation would analyze influence propagation
        return {"influence_paths": [], "key_influencers": []}
    
    # Private helper methods for insight discovery
    async def _identify_hubs(self) -> List[GraphInsight]:
        """Identify hub nodes in the graph"""
        insights = []
        # Implementation would identify high-degree nodes
        return insights
    
    async def _detect_bridges(self) -> List[GraphInsight]:
        """Detect bridge nodes that connect communities"""
        insights = []
        # Implementation would identify bridge nodes
        return insights
    
    async def _discover_communities(self) -> List[GraphInsight]:
        """Discover communities in the graph"""
        insights = []
        # Implementation would analyze community structure
        return insights
    
    async def _analyze_influence_pathways(self) -> List[GraphInsight]:
        """Analyze influence pathways"""
        insights = []
        # Implementation would trace influence paths
        return insights
    
    # Private helper methods for clustering
    def _extract_cluster_topics(self, entities: List[str]) -> List[str]:
        """Extract topics from cluster entities"""
        topics = []
        for entity_id in entities:
            if entity_id in self.entities:
                entity = self.entities[entity_id]
                if entity.type == EntityType.CONCEPT:
                    topics.append(entity.name)
        return topics[:5]
    
    def _calculate_cluster_coherence(self, entities: List[str]) -> float:
        """Calculate coherence score for a cluster"""
        return 0.8  # Simplified implementation
    
    def _generate_cluster_summary(self, entities: List[str], topics: List[str]) -> str:
        """Generate summary for a cluster"""
        return f"Cluster com {len(entities)} entidades relacionadas a {', '.join(topics[:3])}"

# Global knowledge graph instance
_knowledge_graph: Optional[LegislativeKnowledgeGraph] = None

async def get_knowledge_graph() -> LegislativeKnowledgeGraph:
    """Get or create the global knowledge graph instance"""
    global _knowledge_graph
    
    if _knowledge_graph is None:
        _knowledge_graph = LegislativeKnowledgeGraph()
        logger.info("✅ Legislative knowledge graph initialized")
    
    return _knowledge_graph

# API endpoints
@router.post("/extract-entities", response_model=KnowledgeGraphResponse)
async def extract_entities_endpoint(request: EntityExtractionRequest) -> KnowledgeGraphResponse:
    """Extract entities from legislative documents"""
    try:
        start_time = time.time()
        kg = await get_knowledge_graph()
        
        entities = await kg.extract_entities(request.documents)
        
        # Extract relationships if requested
        relationships = []
        if request.extract_relationships:
            relationships = await kg.extract_relationships(request.documents)
        
        processing_time = time.time() - start_time
        
        return KnowledgeGraphResponse(
            success=True,
            data={
                "entities": [entity.to_dict() for entity in entities],
                "relationships": [rel.to_dict() for rel in relationships],
                "total_entities": len(entities),
                "total_relationships": len(relationships)
            },
            processing_time=processing_time,
            stats={
                "documents_processed": len(request.documents),
                "entities_per_document": len(entities) / len(request.documents) if request.documents else 0
            }
        )
        
    except Exception as e:
        logger.error(f"Entity extraction failed: {e}")
        return KnowledgeGraphResponse(
            success=False,
            error=str(e)
        )

@router.post("/analyze-graph", response_model=KnowledgeGraphResponse)
async def analyze_graph_endpoint(request: GraphAnalysisRequest) -> KnowledgeGraphResponse:
    """Perform graph analysis operations"""
    try:
        start_time = time.time()
        kg = await get_knowledge_graph()
        
        analysis_results = await kg.analyze_graph(request.analysis_types)
        
        clusters = []
        if request.include_clusters:
            clusters = await kg.generate_clusters()
        
        insights = []
        if request.include_insights:
            insights = await kg.discover_insights()
        
        processing_time = time.time() - start_time
        
        return KnowledgeGraphResponse(
            success=True,
            data={
                "analysis": analysis_results,
                "clusters": [cluster.to_dict() for cluster in clusters],
                "insights": [insight.to_dict() for insight in insights]
            },
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Graph analysis failed: {e}")
        return KnowledgeGraphResponse(
            success=False,
            error=str(e)
        )

@router.get("/visualization-data", response_model=KnowledgeGraphResponse)
async def get_visualization_data(max_nodes: int = 100) -> KnowledgeGraphResponse:
    """Get graph data for visualization"""
    try:
        kg = await get_knowledge_graph()
        graph_data = kg.get_graph_data(max_nodes)
        
        return KnowledgeGraphResponse(
            success=True,
            data=graph_data
        )
        
    except Exception as e:
        logger.error(f"Visualization data retrieval failed: {e}")
        return KnowledgeGraphResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def knowledge_graph_health() -> Dict[str, Any]:
    """Get knowledge graph health status"""
    try:
        kg = await get_knowledge_graph()
        
        return {
            "status": "healthy",
            "networkx_available": NETWORKX_AVAILABLE,
            "entities_count": len(kg.entities),
            "relationships_count": len(kg.relationships),
            "clusters_count": len(kg.clusters),
            "insights_count": len(kg.insights),
            "graph_nodes": kg.graph.number_of_nodes() if kg.graph else 0,
            "graph_edges": kg.graph.number_of_edges() if kg.graph else 0
        }
        
    except Exception as e:
        logger.error(f"Knowledge graph health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and getter
__all__ = ["router", "get_knowledge_graph"]