"""Knowledge graph generation and management for legislative documents."""
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import json
import networkx as nx
from datetime import datetime
import asyncio

from core.config.config import Config
from core.utils.logger import Logger
from core.models.legislative_data import LegislativeDocument
from core.ai.entity_extractor import Entity, EntityType, EntityExtractor

logger = Logger()


class RelationshipType(Enum):
    """Types of relationships between entities."""
    REFERENCES = "references"
    REGULATES = "regulates"
    AMENDS = "amends"
    REPEALS = "repeals"
    MENTIONS = "mentions"
    APPLIES_TO = "applies_to"
    ISSUED_BY = "issued_by"
    CONCERNS = "concerns"
    CO_OCCURS = "co_occurs"
    TEMPORAL = "temporal"


@dataclass
class Relationship:
    """Represents a relationship between two entities."""
    source_entity: str
    target_entity: str
    relationship_type: RelationshipType
    confidence: float
    evidence: str
    metadata: Dict[str, Any]


@dataclass
class GraphNode:
    """Represents a node in the knowledge graph."""
    id: str
    name: str
    type: str
    properties: Dict[str, Any]
    document_count: int
    centrality_score: float


@dataclass
class GraphEdge:
    """Represents an edge in the knowledge graph."""
    source: str
    target: str
    relationship_type: str
    weight: float
    evidence_count: int
    properties: Dict[str, Any]


class KnowledgeGraphBuilder:
    """Build knowledge graphs from legislative documents."""
    
    def __init__(self):
        self.config = Config()
        self.entity_extractor = EntityExtractor()
        self.graph = nx.Graph()
        self._load_relationship_patterns()
    
    def _load_relationship_patterns(self):
        """Load patterns for relationship extraction."""
        self.relationship_patterns = {
            RelationshipType.REFERENCES: [
                r'(?:conforme|segundo|de acordo com|nos termos de)',
                r'(?:art\.|artigo)\s*\d+',
                r'(?:inciso|parágrafo|alínea)'
            ],
            RelationshipType.REGULATES: [
                r'(?:regulamenta|estabelece|define|dispõe sobre)',
                r'(?:normas para|critérios para|diretrizes para)'
            ],
            RelationshipType.AMENDS: [
                r'(?:altera|modifica|acrescenta|inclui)',
                r'(?:nova redação|revoga|substitui)'
            ],
            RelationshipType.REPEALS: [
                r'(?:revoga|ab-roga|derroga)',
                r'(?:sem efeito|não se aplica)'
            ],
            RelationshipType.ISSUED_BY: [
                r'(?:expedido por|publicado por|emitido por)',
                r'(?:portaria|resolução|decreto).+(?:ministério|secretaria)'
            ]
        }
    
    async def build_graph(self, documents: List[LegislativeDocument]) -> nx.Graph:
        """Build knowledge graph from a collection of documents."""
        try:
            logger.info(f"Building knowledge graph from {len(documents)} documents")
            
            # Reset graph
            self.graph = nx.Graph()
            
            # Extract entities from all documents
            all_entities = []
            document_entities = {}
            
            for document in documents:
                entities = await self.entity_extractor.extract_entities(document)
                all_entities.extend(entities)
                document_entities[document.id] = entities
            
            # Add nodes to graph
            self._add_nodes_to_graph(all_entities)
            
            # Extract relationships
            relationships = await self._extract_relationships(documents, document_entities)
            
            # Add edges to graph
            self._add_edges_to_graph(relationships)
            
            # Calculate centrality metrics
            self._calculate_centrality_metrics()
            
            logger.info(f"Knowledge graph built with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges")
            return self.graph
            
        except Exception as e:
            logger.error(f"Failed to build knowledge graph: {str(e)}")
            raise
    
    def _add_nodes_to_graph(self, entities: List[Entity]):
        """Add entity nodes to the graph."""
        entity_counts = {}
        
        # Count entity occurrences
        for entity in entities:
            key = (entity.name, entity.type.value)
            if key not in entity_counts:
                entity_counts[key] = {
                    'entity': entity,
                    'count': 0,
                    'documents': set()
                }
            
            entity_counts[key]['count'] += len(entity.positions)
            entity_counts[key]['documents'].add(entity.metadata.get('document_id'))
        
        # Add nodes
        for (name, entity_type), data in entity_counts.items():
            entity = data['entity']
            node_id = f"{entity_type}:{name}"
            
            self.graph.add_node(
                node_id,
                name=name,
                type=entity_type,
                occurrence_count=data['count'],
                document_count=len(data['documents']),
                confidence=entity.confidence,
                metadata=entity.metadata
            )
    
    async def _extract_relationships(self, documents: List[LegislativeDocument], 
                                   document_entities: Dict[str, List[Entity]]) -> List[Relationship]:
        """Extract relationships between entities."""
        relationships = []
        
        for document in documents:
            entities = document_entities.get(document.id, [])
            
            # Extract document-level relationships
            doc_relationships = await self._extract_document_relationships(document, entities)
            relationships.extend(doc_relationships)
            
            # Extract co-occurrence relationships
            cooccurrence_relationships = self._extract_cooccurrence_relationships(entities, document)
            relationships.extend(cooccurrence_relationships)
        
        return relationships
    
    async def _extract_document_relationships(self, document: LegislativeDocument, 
                                           entities: List[Entity]) -> List[Relationship]:
        """Extract relationships from a single document."""
        relationships = []
        text = self._get_document_text(document)
        
        # Extract explicit relationships using patterns
        for i, entity1 in enumerate(entities):
            for j, entity2 in enumerate(entities[i+1:], i+1):
                relationship = self._find_relationship_between_entities(
                    entity1, entity2, text, document
                )
                if relationship:
                    relationships.append(relationship)
        
        return relationships
    
    def _find_relationship_between_entities(self, entity1: Entity, entity2: Entity, 
                                          text: str, document: LegislativeDocument) -> Optional[Relationship]:
        """Find relationship between two entities in text."""
        # Check if entities are close to each other in text
        min_distance = float('inf')
        best_evidence = ""
        
        for pos1 in entity1.positions:
            for pos2 in entity2.positions:
                distance = abs(pos1 - pos2)
                if distance < min_distance:
                    min_distance = distance
                    # Get evidence text
                    start = min(pos1, pos2) - 50
                    end = max(pos1, pos2) + len(max(entity1.name, entity2.name, key=len)) + 50
                    best_evidence = text[max(0, start):min(len(text), end)]
        
        # If entities are too far apart, no relationship
        if min_distance > 500:  # 500 characters max distance
            return None
        
        # Determine relationship type based on patterns and entity types
        relationship_type = self._determine_relationship_type(entity1, entity2, best_evidence)
        
        if relationship_type:
            return Relationship(
                source_entity=f"{entity1.type.value}:{entity1.name}",
                target_entity=f"{entity2.type.value}:{entity2.name}",
                relationship_type=relationship_type,
                confidence=min(entity1.confidence, entity2.confidence) * 0.8,
                evidence=best_evidence,
                metadata={
                    'document_id': document.id,
                    'distance': min_distance
                }
            )
        
        return None
    
    def _determine_relationship_type(self, entity1: Entity, entity2: Entity, 
                                   evidence: str) -> Optional[RelationshipType]:
        """Determine the type of relationship between entities."""
        evidence_lower = evidence.lower()
        
        # Check for explicit relationship patterns
        for rel_type, patterns in self.relationship_patterns.items():
            for pattern in patterns:
                if pattern in evidence_lower:
                    return rel_type
        
        # Infer relationships based on entity types
        type1, type2 = entity1.type, entity2.type
        
        # Legal reference relationships
        if type1 == EntityType.LEGAL_REFERENCE or type2 == EntityType.LEGAL_REFERENCE:
            if 'altera' in evidence_lower or 'modifica' in evidence_lower:
                return RelationshipType.AMENDS
            elif 'revoga' in evidence_lower:
                return RelationshipType.REPEALS
            else:
                return RelationshipType.REFERENCES
        
        # Organization relationships
        if type1 == EntityType.ORGANIZATION or type2 == EntityType.ORGANIZATION:
            if 'competência' in evidence_lower or 'responsável' in evidence_lower:
                return RelationshipType.REGULATES
            else:
                return RelationshipType.ISSUED_BY
        
        # Geographic relationships
        if type1 == EntityType.GEOGRAPHIC_LOCATION or type2 == EntityType.GEOGRAPHIC_LOCATION:
            return RelationshipType.APPLIES_TO
        
        # Default to co-occurrence
        return RelationshipType.CO_OCCURS
    
    def _extract_cooccurrence_relationships(self, entities: List[Entity], 
                                          document: LegislativeDocument) -> List[Relationship]:
        """Extract co-occurrence relationships between entities."""
        relationships = []
        
        # Create co-occurrence relationships for entities in same document
        for i, entity1 in enumerate(entities):
            for entity2 in entities[i+1:]:
                # Skip if entities are of same type and name (duplicates)
                if entity1.type == entity2.type and entity1.name == entity2.name:
                    continue
                
                relationship = Relationship(
                    source_entity=f"{entity1.type.value}:{entity1.name}",
                    target_entity=f"{entity2.type.value}:{entity2.name}",
                    relationship_type=RelationshipType.CO_OCCURS,
                    confidence=0.5,  # Lower confidence for co-occurrence
                    evidence=f"Co-occur in document {document.id}",
                    metadata={
                        'document_id': document.id,
                        'document_type': document.document_type
                    }
                )
                relationships.append(relationship)
        
        return relationships
    
    def _add_edges_to_graph(self, relationships: List[Relationship]):
        """Add relationship edges to the graph."""
        edge_weights = {}
        
        # Aggregate relationships by source-target pair
        for relationship in relationships:
            edge_key = (relationship.source_entity, relationship.target_entity)
            
            if edge_key not in edge_weights:
                edge_weights[edge_key] = {
                    'weight': 0,
                    'relationship_types': [],
                    'evidence_count': 0,
                    'documents': set(),
                    'avg_confidence': 0,
                    'confidences': []
                }
            
            edge_data = edge_weights[edge_key]
            edge_data['weight'] += 1
            edge_data['relationship_types'].append(relationship.relationship_type.value)
            edge_data['evidence_count'] += 1
            edge_data['documents'].add(relationship.metadata.get('document_id'))
            edge_data['confidences'].append(relationship.confidence)
        
        # Add edges to graph
        for (source, target), data in edge_weights.items():
            # Calculate average confidence
            data['avg_confidence'] = sum(data['confidences']) / len(data['confidences'])
            
            # Get most common relationship type
            most_common_rel = max(set(data['relationship_types']), 
                                key=data['relationship_types'].count)
            
            self.graph.add_edge(
                source,
                target,
                weight=data['weight'],
                relationship_type=most_common_rel,
                evidence_count=data['evidence_count'],
                document_count=len(data['documents']),
                confidence=data['avg_confidence'],
                documents=list(data['documents'])
            )
    
    def _calculate_centrality_metrics(self):
        """Calculate centrality metrics for nodes."""
        if self.graph.number_of_nodes() == 0:
            return
        
        # Calculate different centrality measures
        degree_centrality = nx.degree_centrality(self.graph)
        betweenness_centrality = nx.betweenness_centrality(self.graph)
        closeness_centrality = nx.closeness_centrality(self.graph)
        
        # Add centrality scores to nodes
        for node_id in self.graph.nodes():
            self.graph.nodes[node_id]['degree_centrality'] = degree_centrality.get(node_id, 0)
            self.graph.nodes[node_id]['betweenness_centrality'] = betweenness_centrality.get(node_id, 0)
            self.graph.nodes[node_id]['closeness_centrality'] = closeness_centrality.get(node_id, 0)
            
            # Combined centrality score
            combined_score = (
                degree_centrality.get(node_id, 0) * 0.4 +
                betweenness_centrality.get(node_id, 0) * 0.3 +
                closeness_centrality.get(node_id, 0) * 0.3
            )
            self.graph.nodes[node_id]['centrality_score'] = combined_score
    
    def _get_document_text(self, document: LegislativeDocument) -> str:
        """Get text content from document."""
        text_parts = []
        
        if document.title:
            text_parts.append(document.title)
        if document.summary:
            text_parts.append(document.summary)
        if hasattr(document, 'content') and document.content:
            text_parts.append(document.content)
        if hasattr(document, 'full_text') and document.full_text:
            text_parts.append(document.full_text)
            
        return ' '.join(text_parts)
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the knowledge graph."""
        if self.graph.number_of_nodes() == 0:
            return {
                'nodes': 0,
                'edges': 0,
                'density': 0,
                'connected_components': 0
            }
        
        stats = {
            'nodes': self.graph.number_of_nodes(),
            'edges': self.graph.number_of_edges(),
            'density': nx.density(self.graph),
            'connected_components': nx.number_connected_components(self.graph),
            'average_clustering': nx.average_clustering(self.graph),
            'node_types': {},
            'relationship_types': {},
            'top_central_nodes': []
        }
        
        # Count node types
        for node_id, data in self.graph.nodes(data=True):
            node_type = data.get('type', 'unknown')
            stats['node_types'][node_type] = stats['node_types'].get(node_type, 0) + 1
        
        # Count relationship types
        for source, target, data in self.graph.edges(data=True):
            rel_type = data.get('relationship_type', 'unknown')
            stats['relationship_types'][rel_type] = stats['relationship_types'].get(rel_type, 0) + 1
        
        # Top central nodes
        nodes_with_centrality = [
            (node_id, data.get('centrality_score', 0), data.get('name', node_id))
            for node_id, data in self.graph.nodes(data=True)
        ]
        nodes_with_centrality.sort(key=lambda x: x[1], reverse=True)
        
        stats['top_central_nodes'] = [
            {'id': node_id, 'name': name, 'centrality': score}
            for node_id, score, name in nodes_with_centrality[:10]
        ]
        
        return stats
    
    def export_graph_data(self) -> Dict[str, Any]:
        """Export graph data for visualization."""
        nodes = []
        edges = []
        
        # Export nodes
        for node_id, data in self.graph.nodes(data=True):
            nodes.append({
                'id': node_id,
                'name': data.get('name', node_id),
                'type': data.get('type', 'unknown'),
                'size': data.get('document_count', 1) * 5,  # Scale for visualization
                'centrality': data.get('centrality_score', 0),
                'metadata': {k: v for k, v in data.items() if k not in ['name', 'type']}
            })
        
        # Export edges
        for source, target, data in self.graph.edges(data=True):
            edges.append({
                'source': source,
                'target': target,
                'weight': data.get('weight', 1),
                'type': data.get('relationship_type', 'unknown'),
                'confidence': data.get('confidence', 0.5),
                'metadata': {k: v for k, v in data.items() if k not in ['weight', 'relationship_type', 'confidence']}
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'statistics': self.get_graph_statistics()
        }