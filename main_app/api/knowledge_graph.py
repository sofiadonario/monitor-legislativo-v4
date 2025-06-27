"""Knowledge graph API endpoints."""
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
import asyncio

from core.config.config import Config
from core.utils.logger import Logger
from core.ai.knowledge_graph import KnowledgeGraphBuilder
from core.ai.entity_extractor import EntityExtractor
from core.services.lexml_official_client import LexMLOfficialClient
from core.models.legislative_data import LegislativeDocument

logger = Logger()
router = APIRouter(prefix="/api/v1/knowledge-graph", tags=["knowledge-graph"])

# Global instances
config = Config()
graph_builder = KnowledgeGraphBuilder()
entity_extractor = EntityExtractor()
lexml_client = LexMLOfficialClient()


@router.post("/build")
async def build_knowledge_graph(
    query: str = Query(..., description="Search query to build graph from"),
    max_documents: int = Query(50, description="Maximum number of documents to process"),
    sources: Optional[str] = Query("lexml", description="Data sources to use")
):
    """Build knowledge graph from search results."""
    try:
        logger.info(f"Building knowledge graph for query: {query}")
        
        # Search for documents
        if sources == "lexml":
            search_results = await lexml_client.search_documents(
                query=query,
                maximum_records=max_documents
            )
            documents = search_results.documents
        else:
            # Fallback to other sources if needed
            raise HTTPException(status_code=400, detail="Only LexML source supported currently")
        
        if not documents:
            raise HTTPException(status_code=404, detail="No documents found for query")
        
        # Build knowledge graph
        graph = await graph_builder.build_graph(documents)
        
        # Export graph data for visualization
        graph_data = graph_builder.export_graph_data()
        
        return JSONResponse(content={
            "success": True,
            "message": f"Knowledge graph built successfully from {len(documents)} documents",
            "data": graph_data,
            "query": query,
            "document_count": len(documents)
        })
        
    except Exception as e:
        logger.error(f"Failed to build knowledge graph: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to build knowledge graph: {str(e)}")


@router.get("/statistics")
async def get_graph_statistics():
    """Get knowledge graph statistics."""
    try:
        stats = graph_builder.get_graph_statistics()
        
        return JSONResponse(content={
            "success": True,
            "data": stats
        })
        
    except Exception as e:
        logger.error(f"Failed to get graph statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@router.get("/export")
async def export_graph_data():
    """Export current knowledge graph data."""
    try:
        graph_data = graph_builder.export_graph_data()
        
        return JSONResponse(content={
            "success": True,
            "data": graph_data
        })
        
    except Exception as e:
        logger.error(f"Failed to export graph data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to export graph: {str(e)}")


@router.post("/entities/extract")
async def extract_entities_from_documents(
    query: str = Query(..., description="Search query"),
    max_documents: int = Query(10, description="Maximum number of documents to process")
):
    """Extract entities from documents."""
    try:
        logger.info(f"Extracting entities from documents for query: {query}")
        
        # Search for documents
        search_results = await lexml_client.search_documents(
            query=query,
            maximum_records=max_documents
        )
        documents = search_results.documents
        
        if not documents:
            raise HTTPException(status_code=404, detail="No documents found for query")
        
        # Extract entities from all documents
        all_entities = []
        for document in documents:
            entities = await entity_extractor.extract_entities(document)
            all_entities.extend(entities)
        
        # Get entity summary
        entity_summary = entity_extractor.get_entity_summary(all_entities)
        
        # Convert entities to dict format
        entities_data = []
        for entity in all_entities:
            entities_data.append({
                "name": entity.name,
                "type": entity.type.value,
                "confidence": entity.confidence,
                "context": entity.context,
                "positions": entity.positions,
                "metadata": entity.metadata
            })
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "entities": entities_data,
                "summary": entity_summary,
                "document_count": len(documents)
            },
            "query": query
        })
        
    except Exception as e:
        logger.error(f"Failed to extract entities: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to extract entities: {str(e)}")


@router.get("/nodes/{node_id}")
async def get_node_details(node_id: str):
    """Get detailed information about a specific node."""
    try:
        if not graph_builder.graph.has_node(node_id):
            raise HTTPException(status_code=404, detail="Node not found")
        
        node_data = graph_builder.graph.nodes[node_id]
        
        # Get connected nodes
        neighbors = []
        for neighbor in graph_builder.graph.neighbors(node_id):
            edge_data = graph_builder.graph.edges[node_id, neighbor]
            neighbor_data = graph_builder.graph.nodes[neighbor]
            
            neighbors.append({
                "id": neighbor,
                "name": neighbor_data.get("name", neighbor),
                "type": neighbor_data.get("type", "unknown"),
                "relationship": edge_data.get("relationship_type", "unknown"),
                "weight": edge_data.get("weight", 1),
                "confidence": edge_data.get("confidence", 0.5)
            })
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "node": {
                    "id": node_id,
                    "name": node_data.get("name", node_id),
                    "type": node_data.get("type", "unknown"),
                    "properties": node_data,
                    "neighbor_count": len(neighbors),
                    "neighbors": neighbors
                }
            }
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get node details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get node details: {str(e)}")


@router.get("/search/nodes")
async def search_nodes(
    q: str = Query(..., description="Search query"),
    node_type: Optional[str] = Query(None, description="Filter by node type"),
    limit: int = Query(20, description="Maximum number of results")
):
    """Search for nodes in the knowledge graph."""
    try:
        matching_nodes = []
        
        for node_id, node_data in graph_builder.graph.nodes(data=True):
            name = node_data.get("name", node_id).lower()
            
            # Filter by type if specified
            if node_type and node_data.get("type") != node_type:
                continue
            
            # Search in name
            if q.lower() in name:
                matching_nodes.append({
                    "id": node_id,
                    "name": node_data.get("name", node_id),
                    "type": node_data.get("type", "unknown"),
                    "centrality": node_data.get("centrality_score", 0),
                    "document_count": node_data.get("document_count", 0),
                    "relevance_score": 1.0 if q.lower() == name else 0.8
                })
        
        # Sort by relevance and centrality
        matching_nodes.sort(key=lambda x: (x["relevance_score"], x["centrality"]), reverse=True)
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "nodes": matching_nodes[:limit],
                "total": len(matching_nodes),
                "query": q
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to search nodes: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to search nodes: {str(e)}")


@router.get("/path/{source_id}/{target_id}")
async def find_shortest_path(source_id: str, target_id: str):
    """Find shortest path between two nodes."""
    try:
        import networkx as nx
        
        if not graph_builder.graph.has_node(source_id):
            raise HTTPException(status_code=404, detail="Source node not found")
        
        if not graph_builder.graph.has_node(target_id):
            raise HTTPException(status_code=404, detail="Target node not found")
        
        try:
            path = nx.shortest_path(graph_builder.graph, source_id, target_id)
            path_length = len(path) - 1
            
            # Get path details
            path_details = []
            for i in range(len(path)):
                node_id = path[i]
                node_data = graph_builder.graph.nodes[node_id]
                
                path_node = {
                    "id": node_id,
                    "name": node_data.get("name", node_id),
                    "type": node_data.get("type", "unknown"),
                    "step": i
                }
                
                # Add edge information if not the last node
                if i < len(path) - 1:
                    next_node = path[i + 1]
                    edge_data = graph_builder.graph.edges[node_id, next_node]
                    path_node["edge_to_next"] = {
                        "relationship": edge_data.get("relationship_type", "unknown"),
                        "weight": edge_data.get("weight", 1),
                        "confidence": edge_data.get("confidence", 0.5)
                    }
                
                path_details.append(path_node)
            
            return JSONResponse(content={
                "success": True,
                "data": {
                    "path": path_details,
                    "length": path_length,
                    "source": source_id,
                    "target": target_id
                }
            })
            
        except nx.NetworkXNoPath:
            raise HTTPException(status_code=404, detail="No path found between nodes")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to find path: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to find path: {str(e)}")


@router.get("/subgraph")
async def get_subgraph(
    center_node: str = Query(..., description="Center node for subgraph"),
    radius: int = Query(2, description="Radius (number of hops)"),
    max_nodes: int = Query(50, description="Maximum number of nodes to include")
):
    """Get a subgraph around a center node."""
    try:
        import networkx as nx
        
        if not graph_builder.graph.has_node(center_node):
            raise HTTPException(status_code=404, detail="Center node not found")
        
        # Get nodes within radius
        subgraph_nodes = set([center_node])
        current_nodes = set([center_node])
        
        for _ in range(radius):
            next_nodes = set()
            for node in current_nodes:
                neighbors = set(graph_builder.graph.neighbors(node))
                next_nodes.update(neighbors)
            
            subgraph_nodes.update(next_nodes)
            current_nodes = next_nodes
            
            # Limit total nodes
            if len(subgraph_nodes) > max_nodes:
                break
        
        # Create subgraph
        subgraph = graph_builder.graph.subgraph(list(subgraph_nodes)[:max_nodes])
        
        # Convert to export format
        nodes = []
        edges = []
        
        for node_id, data in subgraph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "name": data.get("name", node_id),
                "type": data.get("type", "unknown"),
                "centrality": data.get("centrality_score", 0),
                "is_center": node_id == center_node,
                "metadata": {k: v for k, v in data.items() if k not in ["name", "type"]}
            })
        
        for source, target, data in subgraph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "relationship": data.get("relationship_type", "unknown"),
                "weight": data.get("weight", 1),
                "confidence": data.get("confidence", 0.5)
            })
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "nodes": nodes,
                "edges": edges,
                "center_node": center_node,
                "radius": radius,
                "total_nodes": len(nodes),
                "total_edges": len(edges)
            }
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get subgraph: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get subgraph: {str(e)}")