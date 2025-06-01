"""
Interactive Visualization API - Network visualization for document relationships
Provides interactive graph visualizations for Brazilian legislative document networks
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

# Graph visualization libraries
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    logging.warning("NetworkX not available - graph analysis will be limited")

# Import knowledge graph for integration
try:
    from .knowledge_graph import get_knowledge_graph_processor, LegislativeEntity, EntityRelationship
    KNOWLEDGE_GRAPH_AVAILABLE = True
except ImportError:
    KNOWLEDGE_GRAPH_AVAILABLE = False
    logging.warning("Knowledge graph not available - visualization will be limited")

logger = logging.getLogger(__name__)

# Router for interactive visualization API
router = APIRouter(prefix="/api/v1/interactive-visualization", tags=["Interactive Visualization"])

class VisualizationType(str, Enum):
    """Types of network visualizations"""
    FORCE_DIRECTED = "force_directed"
    HIERARCHICAL = "hierarchical"
    CIRCULAR = "circular"
    TIMELINE = "timeline"
    GEOGRAPHIC = "geographic"
    CLUSTERED = "clustered"

class NodeType(str, Enum):
    """Types of nodes in the visualization"""
    DOCUMENT = "document"
    ENTITY = "entity"
    CONCEPT = "concept"
    PERSON = "person"
    ORGANIZATION = "organization"
    LOCATION = "location"
    LAW = "law"
    REGULATION = "regulation"

class EdgeType(str, Enum):
    """Types of edges in the visualization"""
    REFERENCES = "references"
    SIMILAR_TO = "similar_to"
    CONTAINS = "contains"
    RELATED_TO = "related_to"
    CITES = "cites"
    AMENDS = "amends"
    SUPERSEDES = "supersedes"

@dataclass
class VisualizationNode:
    """Node in the visualization graph"""
    id: str
    label: str
    node_type: NodeType
    size: float
    color: str
    metadata: Dict[str, Any]
    position: Optional[Tuple[float, float]] = None
    cluster_id: Optional[str] = None

@dataclass
class VisualizationEdge:
    """Edge in the visualization graph"""
    source: str
    target: str
    edge_type: EdgeType
    weight: float
    color: str
    label: Optional[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class VisualizationLayout:
    """Layout configuration for visualization"""
    type: VisualizationType
    width: int
    height: int
    node_spacing: float
    edge_spacing: float
    cluster_separation: float
    animation_duration: float

@dataclass
class InteractiveVisualization:
    """Complete interactive visualization"""
    visualization_id: str
    title: str
    description: str
    nodes: List[VisualizationNode]
    edges: List[VisualizationEdge]
    layout: VisualizationLayout
    statistics: Dict[str, Any]
    filters: Dict[str, Any]
    export_formats: List[str]
    processing_time: float

# Pydantic models for API
class NetworkVisualizationRequest(BaseModel):
    document_ids: List[str] = Field(..., description="List of document IDs to visualize")
    visualization_type: VisualizationType = Field(default=VisualizationType.FORCE_DIRECTED, description="Type of visualization layout")
    include_entities: bool = Field(default=True, description="Include entity nodes")
    include_relationships: bool = Field(default=True, description="Include relationship edges")
    max_nodes: int = Field(default=100, description="Maximum number of nodes")
    similarity_threshold: float = Field(default=0.5, description="Minimum similarity for edges")

class EntityNetworkRequest(BaseModel):
    entity_types: List[str] = Field(..., description="Types of entities to visualize")
    document_filter: Optional[str] = Field(default=None, description="Filter documents by content")
    time_range: Optional[Tuple[str, str]] = Field(default=None, description="Date range filter")
    geographic_filter: Optional[str] = Field(default=None, description="Geographic region filter")

class VisualizationExportRequest(BaseModel):
    visualization_id: str = Field(..., description="ID of visualization to export")
    export_format: str = Field(..., description="Export format (json, svg, png, pdf)")
    width: Optional[int] = Field(default=1200, description="Export width")
    height: Optional[int] = Field(default=800, description="Export height")

class VisualizationResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class InteractiveVisualizationProcessor:
    """Interactive visualization processor for legislative document networks"""
    
    def __init__(self):
        self.knowledge_graph_processor = None
        self.visualization_cache = {}
        self.color_schemes = self._init_color_schemes()
        self.layout_algorithms = self._init_layout_algorithms()
    
    async def initialize(self) -> bool:
        """Initialize visualization processor"""
        try:
            # Initialize knowledge graph integration
            if KNOWLEDGE_GRAPH_AVAILABLE:
                from .knowledge_graph import get_knowledge_graph_processor
                self.knowledge_graph_processor = await get_knowledge_graph_processor()
            
            logger.info("✅ Interactive visualization processor initialized")
            return True
            
        except Exception as e:
            logger.error(f"Visualization processor initialization failed: {e}")
            return False
    
    async def create_network_visualization(
        self,
        document_ids: List[str],
        visualization_type: VisualizationType = VisualizationType.FORCE_DIRECTED,
        include_entities: bool = True,
        include_relationships: bool = True,
        max_nodes: int = 100,
        similarity_threshold: float = 0.5
    ) -> InteractiveVisualization:
        """Create interactive network visualization for documents"""
        
        start_time = time.time()
        
        # Generate unique visualization ID
        viz_id = f"viz_{int(time.time())}_{len(document_ids)}"
        
        # Extract nodes and edges from knowledge graph
        nodes, edges = await self._extract_network_data(
            document_ids,
            include_entities,
            include_relationships,
            max_nodes,
            similarity_threshold
        )
        
        # Apply layout algorithm
        layout = self._create_layout(visualization_type, len(nodes), len(edges))
        positioned_nodes = await self._apply_layout(nodes, edges, layout)
        
        # Generate visualization statistics
        statistics = self._calculate_visualization_statistics(positioned_nodes, edges)
        
        # Create filter configuration
        filters = self._create_filter_configuration(positioned_nodes, edges)
        
        processing_time = time.time() - start_time
        
        visualization = InteractiveVisualization(
            visualization_id=viz_id,
            title=f"Legislative Document Network ({len(document_ids)} documents)",
            description=f"Interactive {visualization_type.value} visualization of legislative document relationships",
            nodes=positioned_nodes,
            edges=edges,
            layout=layout,
            statistics=statistics,
            filters=filters,
            export_formats=["json", "svg", "png", "pdf", "graphml"],
            processing_time=processing_time
        )
        
        # Cache visualization
        self.visualization_cache[viz_id] = visualization
        
        return visualization
    
    async def create_entity_network(
        self,
        entity_types: List[str],
        document_filter: Optional[str] = None,
        time_range: Optional[Tuple[str, str]] = None,
        geographic_filter: Optional[str] = None
    ) -> InteractiveVisualization:
        """Create entity-focused network visualization"""
        
        start_time = time.time()
        
        # Generate unique visualization ID
        viz_id = f"entity_viz_{int(time.time())}"
        
        # Extract entity network data
        nodes, edges = await self._extract_entity_network_data(
            entity_types,
            document_filter,
            time_range,
            geographic_filter
        )
        
        # Use clustered layout for entity networks
        layout = self._create_layout(VisualizationType.CLUSTERED, len(nodes), len(edges))
        positioned_nodes = await self._apply_layout(nodes, edges, layout)
        
        # Generate statistics
        statistics = self._calculate_visualization_statistics(positioned_nodes, edges)
        
        # Create filters
        filters = self._create_filter_configuration(positioned_nodes, edges)
        
        processing_time = time.time() - start_time
        
        visualization = InteractiveVisualization(
            visualization_id=viz_id,
            title=f"Entity Network ({', '.join(entity_types)})",
            description=f"Interactive visualization of {', '.join(entity_types)} entities and relationships",
            nodes=positioned_nodes,
            edges=edges,
            layout=layout,
            statistics=statistics,
            filters=filters,
            export_formats=["json", "svg", "png", "pdf", "graphml"],
            processing_time=processing_time
        )
        
        # Cache visualization
        self.visualization_cache[viz_id] = visualization
        
        return visualization
    
    async def export_visualization(
        self,
        visualization_id: str,
        export_format: str,
        width: int = 1200,
        height: int = 800
    ) -> Dict[str, Any]:
        """Export visualization in specified format"""
        
        visualization = self.visualization_cache.get(visualization_id)
        if not visualization:
            raise ValueError(f"Visualization {visualization_id} not found")
        
        if export_format == "json":
            return await self._export_json(visualization)
        elif export_format == "svg":
            return await self._export_svg(visualization, width, height)
        elif export_format == "png":
            return await self._export_png(visualization, width, height)
        elif export_format == "pdf":
            return await self._export_pdf(visualization, width, height)
        elif export_format == "graphml":
            return await self._export_graphml(visualization)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
    
    # Private helper methods
    def _init_color_schemes(self) -> Dict[str, Dict[str, str]]:
        """Initialize color schemes for different node and edge types"""
        
        return {
            "node_colors": {
                NodeType.DOCUMENT.value: "#4A90E2",  # Blue
                NodeType.ENTITY.value: "#7ED321",    # Green
                NodeType.CONCEPT.value: "#F5A623",   # Orange
                NodeType.PERSON.value: "#D0021B",    # Red
                NodeType.ORGANIZATION.value: "#9013FE", # Purple
                NodeType.LOCATION.value: "#50E3C2",  # Teal
                NodeType.LAW.value: "#B8E986",       # Light Green
                NodeType.REGULATION.value: "#4A4A4A" # Gray
            },
            "edge_colors": {
                EdgeType.REFERENCES.value: "#000000",   # Black
                EdgeType.SIMILAR_TO.value: "#666666",   # Gray
                EdgeType.CONTAINS.value: "#0066CC",     # Blue
                EdgeType.RELATED_TO.value: "#FF6600",   # Orange
                EdgeType.CITES.value: "#009900",        # Green
                EdgeType.AMENDS.value: "#CC0000",       # Red
                EdgeType.SUPERSEDES.value: "#9900CC"    # Purple
            }
        }
    
    def _init_layout_algorithms(self) -> Dict[str, Dict[str, Any]]:
        """Initialize layout algorithm configurations"""
        
        return {
            VisualizationType.FORCE_DIRECTED.value: {
                "algorithm": "spring",
                "k": 1.0,
                "iterations": 50,
                "repulsion": 1000
            },
            VisualizationType.HIERARCHICAL.value: {
                "algorithm": "hierarchical",
                "direction": "top-bottom",
                "level_separation": 100
            },
            VisualizationType.CIRCULAR.value: {
                "algorithm": "circular",
                "radius": 300
            },
            VisualizationType.CLUSTERED.value: {
                "algorithm": "clustered",
                "cluster_separation": 200
            }
        }
    
    async def _extract_network_data(
        self,
        document_ids: List[str],
        include_entities: bool,
        include_relationships: bool,
        max_nodes: int,
        similarity_threshold: float
    ) -> Tuple[List[VisualizationNode], List[VisualizationEdge]]:
        """Extract nodes and edges for network visualization"""
        
        nodes = []
        edges = []
        
        # Create document nodes
        for i, doc_id in enumerate(document_ids[:max_nodes//2]):  # Limit document nodes
            node = VisualizationNode(
                id=f"doc_{doc_id}",
                label=f"Document {doc_id}",
                node_type=NodeType.DOCUMENT,
                size=20.0,
                color=self.color_schemes["node_colors"][NodeType.DOCUMENT.value],
                metadata={
                    "document_id": doc_id,
                    "type": "legislative_document"
                }
            )
            nodes.append(node)
        
        # Extract entities if requested
        if include_entities and self.knowledge_graph_processor:
            entity_nodes, entity_edges = await self._extract_entity_nodes_and_edges(
                document_ids, max_nodes - len(nodes)
            )
            nodes.extend(entity_nodes)
            edges.extend(entity_edges)
        
        # Create document similarity edges if requested
        if include_relationships:
            similarity_edges = await self._create_similarity_edges(
                document_ids, similarity_threshold
            )
            edges.extend(similarity_edges)
        
        return nodes, edges
    
    async def _extract_entity_network_data(
        self,
        entity_types: List[str],
        document_filter: Optional[str],
        time_range: Optional[Tuple[str, str]],
        geographic_filter: Optional[str]
    ) -> Tuple[List[VisualizationNode], List[VisualizationEdge]]:
        """Extract entity network data with filters"""
        
        nodes = []
        edges = []
        
        # Simulate entity extraction (in production, would use knowledge graph)
        entities_data = [
            {"id": "antt", "label": "ANTT", "type": "organization"},
            {"id": "dnit", "label": "DNIT", "type": "organization"},
            {"id": "br101", "label": "BR-101", "type": "regulation"},
            {"id": "sao_paulo", "label": "São Paulo", "type": "location"},
            {"id": "transporte_rodoviario", "label": "Transporte Rodoviário", "type": "concept"}
        ]
        
        for entity in entities_data:
            if entity["type"] in entity_types:
                node = VisualizationNode(
                    id=entity["id"],
                    label=entity["label"],
                    node_type=NodeType(entity["type"]),
                    size=15.0,
                    color=self.color_schemes["node_colors"].get(entity["type"], "#666666"),
                    metadata=entity
                )
                nodes.append(node)
        
        # Create entity relationships
        relationships = [
            ("antt", "br101", EdgeType.RELATED_TO, 0.8),
            ("dnit", "br101", EdgeType.RELATED_TO, 0.9),
            ("sao_paulo", "br101", EdgeType.CONTAINS, 0.7),
            ("transporte_rodoviario", "br101", EdgeType.RELATED_TO, 0.9)
        ]
        
        for source, target, edge_type, weight in relationships:
            if any(n.id == source for n in nodes) and any(n.id == target for n in nodes):
                edge = VisualizationEdge(
                    source=source,
                    target=target,
                    edge_type=edge_type,
                    weight=weight,
                    color=self.color_schemes["edge_colors"][edge_type.value],
                    label=edge_type.value.replace("_", " ").title(),
                    metadata={"relationship_type": edge_type.value}
                )
                edges.append(edge)
        
        return nodes, edges
    
    async def _extract_entity_nodes_and_edges(
        self,
        document_ids: List[str],
        max_entities: int
    ) -> Tuple[List[VisualizationNode], List[VisualizationEdge]]:
        """Extract entity nodes and edges from knowledge graph"""
        
        nodes = []
        edges = []
        
        # Simulate entity extraction (would use actual knowledge graph in production)
        sample_entities = [
            {"id": "lei_12587", "label": "Lei 12.587/2012", "type": "law"},
            {"id": "mobilidade_urbana", "label": "Mobilidade Urbana", "type": "concept"},
            {"id": "ministério_transportes", "label": "Ministério dos Transportes", "type": "organization"}
        ]
        
        for entity in sample_entities[:max_entities]:
            node = VisualizationNode(
                id=entity["id"],
                label=entity["label"],
                node_type=NodeType(entity["type"]),
                size=12.0,
                color=self.color_schemes["node_colors"][entity["type"]],
                metadata=entity
            )
            nodes.append(node)
        
        return nodes, edges
    
    async def _create_similarity_edges(
        self,
        document_ids: List[str],
        threshold: float
    ) -> List[VisualizationEdge]:
        """Create edges based on document similarity"""
        
        edges = []
        
        # Simulate document similarity calculation
        for i, doc1 in enumerate(document_ids):
            for doc2 in document_ids[i+1:]:
                # Simulate similarity score
                similarity = 0.6  # Would calculate actual similarity in production
                
                if similarity >= threshold:
                    edge = VisualizationEdge(
                        source=f"doc_{doc1}",
                        target=f"doc_{doc2}",
                        edge_type=EdgeType.SIMILAR_TO,
                        weight=similarity,
                        color=self.color_schemes["edge_colors"][EdgeType.SIMILAR_TO.value],
                        label=f"Similarity: {similarity:.2f}",
                        metadata={"similarity_score": similarity}
                    )
                    edges.append(edge)
        
        return edges
    
    def _create_layout(
        self,
        visualization_type: VisualizationType,
        num_nodes: int,
        num_edges: int
    ) -> VisualizationLayout:
        """Create layout configuration"""
        
        # Calculate optimal dimensions based on node count
        width = max(800, min(1600, num_nodes * 20))
        height = max(600, min(1200, num_nodes * 15))
        
        return VisualizationLayout(
            type=visualization_type,
            width=width,
            height=height,
            node_spacing=50.0,
            edge_spacing=10.0,
            cluster_separation=100.0,
            animation_duration=1000.0
        )
    
    async def _apply_layout(
        self,
        nodes: List[VisualizationNode],
        edges: List[VisualizationEdge],
        layout: VisualizationLayout
    ) -> List[VisualizationNode]:
        """Apply layout algorithm to position nodes"""
        
        if not NETWORKX_AVAILABLE:
            # Fallback to simple grid layout
            return self._apply_grid_layout(nodes, layout)
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add nodes
        for node in nodes:
            G.add_node(node.id, **asdict(node))
        
        # Add edges
        for edge in edges:
            G.add_edge(edge.source, edge.target, weight=edge.weight)
        
        # Apply layout algorithm
        if layout.type == VisualizationType.FORCE_DIRECTED:
            pos = nx.spring_layout(G, k=1.0, iterations=50)
        elif layout.type == VisualizationType.CIRCULAR:
            pos = nx.circular_layout(G)
        elif layout.type == VisualizationType.HIERARCHICAL:
            pos = nx.nx_agraph.graphviz_layout(G, prog='dot') if hasattr(nx, 'nx_agraph') else nx.spring_layout(G)
        else:
            pos = nx.spring_layout(G)
        
        # Scale positions to layout dimensions
        positioned_nodes = []
        for node in nodes:
            if node.id in pos:
                x, y = pos[node.id]
                # Scale to layout dimensions
                scaled_x = (x + 1) * layout.width / 2
                scaled_y = (y + 1) * layout.height / 2
                node.position = (scaled_x, scaled_y)
            else:
                # Fallback position
                node.position = (layout.width / 2, layout.height / 2)
            
            positioned_nodes.append(node)
        
        return positioned_nodes
    
    def _apply_grid_layout(
        self,
        nodes: List[VisualizationNode],
        layout: VisualizationLayout
    ) -> List[VisualizationNode]:
        """Apply simple grid layout as fallback"""
        
        import math
        
        grid_size = math.ceil(math.sqrt(len(nodes)))
        cell_width = layout.width / grid_size
        cell_height = layout.height / grid_size
        
        positioned_nodes = []
        for i, node in enumerate(nodes):
            row = i // grid_size
            col = i % grid_size
            
            x = col * cell_width + cell_width / 2
            y = row * cell_height + cell_height / 2
            
            node.position = (x, y)
            positioned_nodes.append(node)
        
        return positioned_nodes
    
    def _calculate_visualization_statistics(
        self,
        nodes: List[VisualizationNode],
        edges: List[VisualizationEdge]
    ) -> Dict[str, Any]:
        """Calculate visualization statistics"""
        
        # Count nodes by type
        node_counts = {}
        for node in nodes:
            node_type = node.node_type.value
            node_counts[node_type] = node_counts.get(node_type, 0) + 1
        
        # Count edges by type
        edge_counts = {}
        for edge in edges:
            edge_type = edge.edge_type.value
            edge_counts[edge_type] = edge_counts.get(edge_type, 0) + 1
        
        # Calculate network metrics
        density = len(edges) / (len(nodes) * (len(nodes) - 1) / 2) if len(nodes) > 1 else 0
        
        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_counts": node_counts,
            "edge_counts": edge_counts,
            "network_density": density,
            "average_degree": (2 * len(edges)) / len(nodes) if len(nodes) > 0 else 0
        }
    
    def _create_filter_configuration(
        self,
        nodes: List[VisualizationNode],
        edges: List[VisualizationEdge]
    ) -> Dict[str, Any]:
        """Create filter configuration for interactive features"""
        
        return {
            "node_types": list(set(node.node_type.value for node in nodes)),
            "edge_types": list(set(edge.edge_type.value for edge in edges)),
            "size_range": [min(node.size for node in nodes), max(node.size for node in nodes)] if nodes else [0, 0],
            "weight_range": [min(edge.weight for edge in edges), max(edge.weight for edge in edges)] if edges else [0, 0]
        }
    
    async def _export_json(self, visualization: InteractiveVisualization) -> Dict[str, Any]:
        """Export visualization as JSON"""
        
        return {
            "format": "json",
            "data": asdict(visualization),
            "export_timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    async def _export_svg(self, visualization: InteractiveVisualization, width: int, height: int) -> Dict[str, Any]:
        """Export visualization as SVG"""
        
        # Generate SVG representation
        svg_content = f"""
        <svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
            <title>{visualization.title}</title>
            <!-- Nodes -->
            {self._generate_svg_nodes(visualization.nodes)}
            <!-- Edges -->
            {self._generate_svg_edges(visualization.edges)}
        </svg>
        """
        
        return {
            "format": "svg",
            "content": svg_content,
            "export_timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    async def _export_png(self, visualization: InteractiveVisualization, width: int, height: int) -> Dict[str, Any]:
        """Export visualization as PNG (placeholder)"""
        
        return {
            "format": "png",
            "message": "PNG export requires additional image processing libraries",
            "svg_available": True,
            "export_timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    async def _export_pdf(self, visualization: InteractiveVisualization, width: int, height: int) -> Dict[str, Any]:
        """Export visualization as PDF (placeholder)"""
        
        return {
            "format": "pdf",
            "message": "PDF export requires additional libraries (reportlab, weasyprint)",
            "svg_available": True,
            "export_timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    async def _export_graphml(self, visualization: InteractiveVisualization) -> Dict[str, Any]:
        """Export visualization as GraphML"""
        
        if not NETWORKX_AVAILABLE:
            return {
                "format": "graphml",
                "error": "NetworkX not available for GraphML export"
            }
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add nodes with attributes
        for node in visualization.nodes:
            G.add_node(node.id, 
                      label=node.label,
                      node_type=node.node_type.value,
                      size=node.size,
                      color=node.color)
        
        # Add edges with attributes
        for edge in visualization.edges:
            G.add_edge(edge.source, edge.target,
                      edge_type=edge.edge_type.value,
                      weight=edge.weight,
                      color=edge.color,
                      label=edge.label or "")
        
        # Generate GraphML content
        try:
            import io
            graphml_content = io.StringIO()
            nx.write_graphml(G, graphml_content)
            content = graphml_content.getvalue()
            graphml_content.close()
            
            return {
                "format": "graphml",
                "content": content,
                "export_timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            return {
                "format": "graphml",
                "error": f"GraphML export failed: {e}"
            }
    
    def _generate_svg_nodes(self, nodes: List[VisualizationNode]) -> str:
        """Generate SVG representation of nodes"""
        
        svg_nodes = []
        for node in nodes:
            if node.position:
                x, y = node.position
                svg_nodes.append(f"""
                <circle cx="{x}" cy="{y}" r="{node.size/2}" 
                        fill="{node.color}" stroke="#000" stroke-width="1">
                    <title>{node.label}</title>
                </circle>
                <text x="{x}" y="{y+node.size+10}" 
                      text-anchor="middle" font-size="10" font-family="Arial">
                    {node.label[:20]}{'...' if len(node.label) > 20 else ''}
                </text>
                """)
        
        return "\n".join(svg_nodes)
    
    def _generate_svg_edges(self, edges: List[VisualizationEdge]) -> str:
        """Generate SVG representation of edges"""
        
        # For now, return placeholder as we need node positions to draw edges
        return "<!-- Edges would be drawn here with actual node positions -->"

# Global visualization processor instance
_visualization_processor: Optional[InteractiveVisualizationProcessor] = None

async def get_visualization_processor() -> InteractiveVisualizationProcessor:
    """Get or create the global visualization processor"""
    global _visualization_processor
    
    if _visualization_processor is None:
        _visualization_processor = InteractiveVisualizationProcessor()
        if await _visualization_processor.initialize():
            logger.info("✅ Interactive visualization processor initialized")
        else:
            logger.warning("⚠️ Visualization processor initialized with limited functionality")
    
    return _visualization_processor

# API endpoints
@router.post("/create-network", response_model=VisualizationResponse)
async def create_network_visualization_endpoint(
    request: NetworkVisualizationRequest
) -> VisualizationResponse:
    """Create interactive network visualization for documents"""
    try:
        start_time = time.time()
        viz_processor = await get_visualization_processor()
        
        visualization = await viz_processor.create_network_visualization(
            document_ids=request.document_ids,
            visualization_type=request.visualization_type,
            include_entities=request.include_entities,
            include_relationships=request.include_relationships,
            max_nodes=request.max_nodes,
            similarity_threshold=request.similarity_threshold
        )
        
        processing_time = time.time() - start_time
        
        return VisualizationResponse(
            success=True,
            data=asdict(visualization),
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Network visualization creation failed: {e}")
        return VisualizationResponse(
            success=False,
            error=str(e)
        )

@router.post("/create-entity-network", response_model=VisualizationResponse)
async def create_entity_network_endpoint(
    request: EntityNetworkRequest
) -> VisualizationResponse:
    """Create entity-focused network visualization"""
    try:
        viz_processor = await get_visualization_processor()
        
        visualization = await viz_processor.create_entity_network(
            entity_types=request.entity_types,
            document_filter=request.document_filter,
            time_range=request.time_range,
            geographic_filter=request.geographic_filter
        )
        
        return VisualizationResponse(
            success=True,
            data=asdict(visualization)
        )
        
    except Exception as e:
        logger.error(f"Entity network creation failed: {e}")
        return VisualizationResponse(
            success=False,
            error=str(e)
        )

@router.post("/export", response_model=VisualizationResponse)
async def export_visualization_endpoint(
    request: VisualizationExportRequest
) -> VisualizationResponse:
    """Export visualization in specified format"""
    try:
        viz_processor = await get_visualization_processor()
        
        export_data = await viz_processor.export_visualization(
            visualization_id=request.visualization_id,
            export_format=request.export_format,
            width=request.width,
            height=request.height
        )
        
        return VisualizationResponse(
            success=True,
            data=export_data
        )
        
    except Exception as e:
        logger.error(f"Visualization export failed: {e}")
        return VisualizationResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def visualization_health_status() -> Dict[str, Any]:
    """Get visualization system health status"""
    try:
        viz_processor = await get_visualization_processor()
        
        return {
            "status": "healthy",
            "cached_visualizations": len(viz_processor.visualization_cache),
            "networkx_available": NETWORKX_AVAILABLE,
            "knowledge_graph_available": KNOWLEDGE_GRAPH_AVAILABLE,
            "supported_formats": ["json", "svg", "png", "pdf", "graphml"],
            "supported_layouts": ["force_directed", "hierarchical", "circular", "clustered"]
        }
        
    except Exception as e:
        logger.error(f"Visualization health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_visualization_processor"]