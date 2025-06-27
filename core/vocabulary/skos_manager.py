"""
Enhanced SKOS Vocabulary Manager
W3C SKOS-compliant vocabulary management with hierarchical navigation
Based on lexml-vocabulary patterns for Brazilian legislative terms
"""
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import re
from collections import defaultdict, deque
import asyncio

from core.config.config import Config
from core.utils.logger import Logger

logger = Logger()


class SKOSRelationType(Enum):
    """SKOS relationship types according to W3C standard."""
    BROADER = "broader"           # skos:broader
    NARROWER = "narrower"         # skos:narrower
    RELATED = "related"           # skos:related
    EXACT_MATCH = "exactMatch"    # skos:exactMatch
    CLOSE_MATCH = "closeMatch"    # skos:closeMatch
    BROAD_MATCH = "broadMatch"    # skos:broadMatch
    NARROW_MATCH = "narrowMatch"  # skos:narrowMatch


class ConceptScheme(Enum):
    """SKOS concept schemes for Brazilian legislative vocabulary."""
    TRANSPORT = "transport"
    LEGAL_FRAMEWORK = "legal_framework"
    GOVERNMENT_ENTITIES = "government_entities"
    GEOGRAPHIC_AREAS = "geographic_areas"
    POLICY_AREAS = "policy_areas"
    DOCUMENT_TYPES = "document_types"


@dataclass
class SKOSConcept:
    """SKOS Concept with W3C compliance."""
    uri: str
    pref_label: Dict[str, str]  # Language -> Label
    alt_labels: Dict[str, List[str]] = field(default_factory=dict)
    hidden_labels: Dict[str, List[str]] = field(default_factory=dict)
    definition: Dict[str, str] = field(default_factory=dict)
    scope_note: Dict[str, str] = field(default_factory=dict)
    example: Dict[str, str] = field(default_factory=dict)
    notation: Optional[str] = None
    concept_scheme: Optional[ConceptScheme] = None
    broader: Set[str] = field(default_factory=set)
    narrower: Set[str] = field(default_factory=set)
    related: Set[str] = field(default_factory=set)
    exact_match: Set[str] = field(default_factory=set)
    close_match: Set[str] = field(default_factory=set)
    created: Optional[str] = None
    modified: Optional[str] = None
    
    def get_label(self, lang: str = "pt") -> str:
        """Get preferred label in specified language."""
        return self.pref_label.get(lang, self.pref_label.get("pt", self.uri))
    
    def get_all_labels(self, lang: str = "pt") -> List[str]:
        """Get all labels (preferred + alternative) for a language."""
        labels = [self.get_label(lang)]
        labels.extend(self.alt_labels.get(lang, []))
        return list(set(labels))  # Remove duplicates


@dataclass
class VocabularyHierarchy:
    """Represents a vocabulary hierarchy with navigation capabilities."""
    root_concepts: List[str]
    concept_tree: Dict[str, List[str]]  # concept_uri -> children
    concept_paths: Dict[str, List[str]]  # concept_uri -> path from root
    max_depth: int
    concept_count: int


@dataclass
class SearchResult:
    """Vocabulary search result."""
    concept: SKOSConcept
    match_type: str  # "exact", "prefix", "fuzzy", "related"
    score: float
    matched_label: str
    context: Optional[str] = None


class SKOSVocabularyManager:
    """Enhanced vocabulary manager with SKOS W3C compliance and hierarchical navigation."""
    
    def __init__(self):
        self.config = Config()
        self.concepts: Dict[str, SKOSConcept] = {}
        self.label_index: Dict[str, Set[str]] = defaultdict(set)  # label -> concept URIs
        self.hierarchies: Dict[ConceptScheme, VocabularyHierarchy] = {}
        self._load_brazilian_transport_vocabulary()
        self._build_hierarchies()
        
    def _load_brazilian_transport_vocabulary(self):
        """Load Brazilian transport and legislative vocabulary with SKOS structure."""
        
        # Transport Modal Types
        transport_modal = [
            {
                "uri": "http://vocab.lexml.gov.br/transport/modal",
                "pref_label": {"pt": "Modal de Transporte", "en": "Transport Mode"},
                "definition": {"pt": "Categorias de modalidades de transporte"},
                "concept_scheme": ConceptScheme.TRANSPORT,
                "narrower": [
                    "http://vocab.lexml.gov.br/transport/modal/rodoviario",
                    "http://vocab.lexml.gov.br/transport/modal/ferroviario",
                    "http://vocab.lexml.gov.br/transport/modal/aquaviario",
                    "http://vocab.lexml.gov.br/transport/modal/aereo"
                ]
            },
            {
                "uri": "http://vocab.lexml.gov.br/transport/modal/rodoviario",
                "pref_label": {"pt": "Transporte Rodoviário", "en": "Road Transport"},
                "alt_labels": {"pt": ["Modal Rodoviário", "Transporte por Estradas"]},
                "definition": {"pt": "Transporte realizado através de rodovias e estradas"},
                "concept_scheme": ConceptScheme.TRANSPORT,
                "broader": {"http://vocab.lexml.gov.br/transport/modal"},
                "narrower": [
                    "http://vocab.lexml.gov.br/transport/modal/rodoviario/cargas",
                    "http://vocab.lexml.gov.br/transport/modal/rodoviario/passageiros"
                ],
                "related": {
                    "http://vocab.lexml.gov.br/infrastructure/rodovias",
                    "http://vocab.lexml.gov.br/entities/antt"
                }
            },
            {
                "uri": "http://vocab.lexml.gov.br/transport/modal/ferroviario",
                "pref_label": {"pt": "Transporte Ferroviário", "en": "Railway Transport"},
                "alt_labels": {"pt": ["Modal Ferroviário", "Transporte por Trens"]},
                "definition": {"pt": "Transporte realizado através de ferrovias"},
                "concept_scheme": ConceptScheme.TRANSPORT,
                "broader": {"http://vocab.lexml.gov.br/transport/modal"},
                "narrower": [
                    "http://vocab.lexml.gov.br/transport/modal/ferroviario/cargas",
                    "http://vocab.lexml.gov.br/transport/modal/ferroviario/passageiros",
                    "http://vocab.lexml.gov.br/transport/modal/ferroviario/metro"
                ]
            },
            {
                "uri": "http://vocab.lexml.gov.br/transport/modal/aquaviario",
                "pref_label": {"pt": "Transporte Aquaviário", "en": "Water Transport"},
                "alt_labels": {"pt": ["Modal Aquaviário", "Transporte Marítimo", "Transporte Fluvial"]},
                "definition": {"pt": "Transporte realizado através de vias aquáticas"},
                "concept_scheme": ConceptScheme.TRANSPORT,
                "broader": {"http://vocab.lexml.gov.br/transport/modal"},
                "narrower": [
                    "http://vocab.lexml.gov.br/transport/modal/aquaviario/maritimo",
                    "http://vocab.lexml.gov.br/transport/modal/aquaviario/fluvial",
                    "http://vocab.lexml.gov.br/transport/modal/aquaviario/lacustre"
                ]
            },
            {
                "uri": "http://vocab.lexml.gov.br/transport/modal/aereo",
                "pref_label": {"pt": "Transporte Aéreo", "en": "Air Transport"},
                "alt_labels": {"pt": ["Modal Aéreo", "Aviação"]},
                "definition": {"pt": "Transporte realizado através de aeronaves"},
                "concept_scheme": ConceptScheme.TRANSPORT,
                "broader": {"http://vocab.lexml.gov.br/transport/modal"},
                "narrower": [
                    "http://vocab.lexml.gov.br/transport/modal/aereo/comercial",
                    "http://vocab.lexml.gov.br/transport/modal/aereo/geral"
                ]
            }
        ]
        
        # Government Entities
        government_entities = [
            {
                "uri": "http://vocab.lexml.gov.br/entities/regulatory_agencies",
                "pref_label": {"pt": "Agências Reguladoras", "en": "Regulatory Agencies"},
                "definition": {"pt": "Agências reguladoras do governo brasileiro"},
                "concept_scheme": ConceptScheme.GOVERNMENT_ENTITIES,
                "narrower": [
                    "http://vocab.lexml.gov.br/entities/antt",
                    "http://vocab.lexml.gov.br/entities/antaq",
                    "http://vocab.lexml.gov.br/entities/anac",
                    "http://vocab.lexml.gov.br/entities/aneel"
                ]
            },
            {
                "uri": "http://vocab.lexml.gov.br/entities/antt",
                "pref_label": {"pt": "ANTT", "en": "ANTT"},
                "alt_labels": {"pt": ["Agência Nacional de Transportes Terrestres"]},
                "definition": {"pt": "Agência Nacional de Transportes Terrestres"},
                "concept_scheme": ConceptScheme.GOVERNMENT_ENTITIES,
                "broader": {"http://vocab.lexml.gov.br/entities/regulatory_agencies"},
                "related": {
                    "http://vocab.lexml.gov.br/transport/modal/rodoviario",
                    "http://vocab.lexml.gov.br/transport/modal/ferroviario"
                }
            },
            {
                "uri": "http://vocab.lexml.gov.br/entities/antaq",
                "pref_label": {"pt": "ANTAQ", "en": "ANTAQ"},
                "alt_labels": {"pt": ["Agência Nacional de Transportes Aquaviários"]},
                "definition": {"pt": "Agência Nacional de Transportes Aquaviários"},
                "concept_scheme": ConceptScheme.GOVERNMENT_ENTITIES,
                "broader": {"http://vocab.lexml.gov.br/entities/regulatory_agencies"},
                "related": {"http://vocab.lexml.gov.br/transport/modal/aquaviario"}
            },
            {
                "uri": "http://vocab.lexml.gov.br/entities/anac",
                "pref_label": {"pt": "ANAC", "en": "ANAC"},
                "alt_labels": {"pt": ["Agência Nacional de Aviação Civil"]},
                "definition": {"pt": "Agência Nacional de Aviação Civil"},
                "concept_scheme": ConceptScheme.GOVERNMENT_ENTITIES,
                "broader": {"http://vocab.lexml.gov.br/entities/regulatory_agencies"},
                "related": {"http://vocab.lexml.gov.br/transport/modal/aereo"}
            }
        ]
        
        # Legal Framework
        legal_framework = [
            {
                "uri": "http://vocab.lexml.gov.br/legal/document_types",
                "pref_label": {"pt": "Tipos de Documentos Legais", "en": "Legal Document Types"},
                "definition": {"pt": "Categorias de documentos do ordenamento jurídico brasileiro"},
                "concept_scheme": ConceptScheme.DOCUMENT_TYPES,
                "narrower": [
                    "http://vocab.lexml.gov.br/legal/lei",
                    "http://vocab.lexml.gov.br/legal/decreto",
                    "http://vocab.lexml.gov.br/legal/portaria",
                    "http://vocab.lexml.gov.br/legal/resolucao"
                ]
            },
            {
                "uri": "http://vocab.lexml.gov.br/legal/lei",
                "pref_label": {"pt": "Lei", "en": "Law"},
                "alt_labels": {"pt": ["Lei Federal", "Legislação"]},
                "definition": {"pt": "Norma jurídica de caráter geral e abstrato"},
                "concept_scheme": ConceptScheme.DOCUMENT_TYPES,
                "broader": {"http://vocab.lexml.gov.br/legal/document_types"},
                "narrower": [
                    "http://vocab.lexml.gov.br/legal/lei/complementar",
                    "http://vocab.lexml.gov.br/legal/lei/ordinaria"
                ]
            },
            {
                "uri": "http://vocab.lexml.gov.br/legal/decreto",
                "pref_label": {"pt": "Decreto", "en": "Decree"},
                "alt_labels": {"pt": ["Decreto Executivo"]},
                "definition": {"pt": "Ato administrativo do Poder Executivo"},
                "concept_scheme": ConceptScheme.DOCUMENT_TYPES,
                "broader": {"http://vocab.lexml.gov.br/legal/document_types"}
            }
        ]
        
        # Load all concepts
        all_concepts = transport_modal + government_entities + legal_framework
        
        for concept_data in all_concepts:
            concept = SKOSConcept(
                uri=concept_data["uri"],
                pref_label=concept_data["pref_label"],
                alt_labels=concept_data.get("alt_labels", {}),
                definition=concept_data.get("definition", {}),
                concept_scheme=concept_data.get("concept_scheme"),
                broader=set(concept_data.get("broader", [])) if isinstance(concept_data.get("broader"), list) else {concept_data.get("broader")} if concept_data.get("broader") else set(),
                narrower=set(concept_data.get("narrower", [])),
                related=set(concept_data.get("related", []))
            )
            
            self.concepts[concept.uri] = concept
            
            # Build label index
            for lang, label in concept.pref_label.items():
                self.label_index[label.lower()].add(concept.uri)
            
            for lang, labels in concept.alt_labels.items():
                for label in labels:
                    self.label_index[label.lower()].add(concept.uri)
    
    def _build_hierarchies(self):
        """Build hierarchical structures for each concept scheme."""
        for scheme in ConceptScheme:
            scheme_concepts = {uri: concept for uri, concept in self.concepts.items() 
                             if concept.concept_scheme == scheme}
            
            if not scheme_concepts:
                continue
                
            # Find root concepts (those with no broader concepts within the scheme)
            root_concepts = []
            concept_tree = defaultdict(list)
            concept_paths = {}
            
            for uri, concept in scheme_concepts.items():
                # Check if this concept has broader concepts in the same scheme
                has_broader_in_scheme = any(
                    broader_uri in scheme_concepts 
                    for broader_uri in concept.broader
                )
                
                if not has_broader_in_scheme:
                    root_concepts.append(uri)
                
                # Build concept tree
                for narrower_uri in concept.narrower:
                    if narrower_uri in scheme_concepts:
                        concept_tree[uri].append(narrower_uri)
            
            # Calculate paths and max depth
            max_depth = 0
            for root_uri in root_concepts:
                self._calculate_paths(root_uri, concept_tree, concept_paths, [], max_depth)
            
            self.hierarchies[scheme] = VocabularyHierarchy(
                root_concepts=root_concepts,
                concept_tree=dict(concept_tree),
                concept_paths=concept_paths,
                max_depth=max_depth,
                concept_count=len(scheme_concepts)
            )
    
    def _calculate_paths(self, concept_uri: str, concept_tree: Dict[str, List[str]], 
                        concept_paths: Dict[str, List[str]], current_path: List[str], max_depth: int) -> int:
        """Calculate paths from root to each concept."""
        new_path = current_path + [concept_uri]
        concept_paths[concept_uri] = new_path
        current_depth = len(new_path)
        
        max_child_depth = current_depth
        for child_uri in concept_tree.get(concept_uri, []):
            child_depth = self._calculate_paths(child_uri, concept_tree, concept_paths, new_path, max_depth)
            max_child_depth = max(max_child_depth, child_depth)
        
        return max_child_depth
    
    def search_concepts(self, query: str, lang: str = "pt", limit: int = 20, 
                       concept_scheme: Optional[ConceptScheme] = None) -> List[SearchResult]:
        """Search concepts with fuzzy matching and ranking."""
        query_lower = query.lower().strip()
        results = []
        
        if not query_lower:
            return results
        
        # Filter concepts by scheme if specified
        search_concepts = self.concepts
        if concept_scheme:
            search_concepts = {uri: concept for uri, concept in self.concepts.items() 
                             if concept.concept_scheme == concept_scheme}
        
        for uri, concept in search_concepts.items():
            concept_results = self._match_concept(concept, query_lower, lang)
            results.extend(concept_results)
        
        # Sort by score (descending) and limit results
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:limit]
    
    def _match_concept(self, concept: SKOSConcept, query_lower: str, lang: str) -> List[SearchResult]:
        """Match a concept against a query with different match types."""
        results = []
        
        # Get all labels for the concept in the specified language
        all_labels = concept.get_all_labels(lang)
        
        for label in all_labels:
            label_lower = label.lower()
            
            # Exact match
            if label_lower == query_lower:
                results.append(SearchResult(
                    concept=concept,
                    match_type="exact",
                    score=1.0,
                    matched_label=label
                ))
            
            # Prefix match
            elif label_lower.startswith(query_lower) or query_lower.startswith(label_lower):
                score = min(len(query_lower), len(label_lower)) / max(len(query_lower), len(label_lower))
                results.append(SearchResult(
                    concept=concept,
                    match_type="prefix",
                    score=score * 0.9,
                    matched_label=label
                ))
            
            # Contains match
            elif query_lower in label_lower or label_lower in query_lower:
                score = min(len(query_lower), len(label_lower)) / max(len(query_lower), len(label_lower))
                results.append(SearchResult(
                    concept=concept,
                    match_type="contains",
                    score=score * 0.7,
                    matched_label=label
                ))
            
            # Word match (any word in query matches any word in label)
            else:
                query_words = set(query_lower.split())
                label_words = set(label_lower.split())
                common_words = query_words.intersection(label_words)
                
                if common_words:
                    score = len(common_words) / max(len(query_words), len(label_words))
                    results.append(SearchResult(
                        concept=concept,
                        match_type="word",
                        score=score * 0.5,
                        matched_label=label
                    ))
        
        return results
    
    def get_concept_hierarchy(self, concept_uri: str) -> Dict[str, Any]:
        """Get hierarchical information for a concept."""
        if concept_uri not in self.concepts:
            return {}
        
        concept = self.concepts[concept_uri]
        scheme = concept.concept_scheme
        
        if not scheme or scheme not in self.hierarchies:
            return {"concept": concept}
        
        hierarchy = self.hierarchies[scheme]
        
        return {
            "concept": concept,
            "path": hierarchy.concept_paths.get(concept_uri, []),
            "children": [self.concepts[child_uri] for child_uri in hierarchy.concept_tree.get(concept_uri, [])],
            "parent": self._get_parent_concept(concept_uri, hierarchy),
            "siblings": self._get_sibling_concepts(concept_uri, hierarchy),
            "depth": len(hierarchy.concept_paths.get(concept_uri, [])),
            "is_root": concept_uri in hierarchy.root_concepts,
            "is_leaf": len(hierarchy.concept_tree.get(concept_uri, [])) == 0
        }
    
    def _get_parent_concept(self, concept_uri: str, hierarchy: VocabularyHierarchy) -> Optional[SKOSConcept]:
        """Get parent concept in hierarchy."""
        path = hierarchy.concept_paths.get(concept_uri, [])
        if len(path) > 1:
            parent_uri = path[-2]
            return self.concepts.get(parent_uri)
        return None
    
    def _get_sibling_concepts(self, concept_uri: str, hierarchy: VocabularyHierarchy) -> List[SKOSConcept]:
        """Get sibling concepts in hierarchy."""
        parent = self._get_parent_concept(concept_uri, hierarchy)
        if parent:
            sibling_uris = hierarchy.concept_tree.get(parent.uri, [])
            return [self.concepts[uri] for uri in sibling_uris if uri != concept_uri]
        else:
            # Root level siblings
            return [self.concepts[uri] for uri in hierarchy.root_concepts if uri != concept_uri]
    
    def get_broader_concepts(self, concept_uri: str, transitive: bool = False) -> List[SKOSConcept]:
        """Get broader concepts (direct or transitive)."""
        if concept_uri not in self.concepts:
            return []
        
        concept = self.concepts[concept_uri]
        broader_concepts = []
        
        if not transitive:
            # Direct broader concepts only
            for broader_uri in concept.broader:
                if broader_uri in self.concepts:
                    broader_concepts.append(self.concepts[broader_uri])
        else:
            # Transitive closure of broader concepts
            visited = set()
            queue = deque(concept.broader)
            
            while queue:
                broader_uri = queue.popleft()
                if broader_uri in visited or broader_uri not in self.concepts:
                    continue
                
                visited.add(broader_uri)
                broader_concept = self.concepts[broader_uri]
                broader_concepts.append(broader_concept)
                
                # Add broader concepts of this concept to queue
                queue.extend(broader_concept.broader)
        
        return broader_concepts
    
    def get_narrower_concepts(self, concept_uri: str, transitive: bool = False) -> List[SKOSConcept]:
        """Get narrower concepts (direct or transitive)."""
        if concept_uri not in self.concepts:
            return []
        
        concept = self.concepts[concept_uri]
        narrower_concepts = []
        
        if not transitive:
            # Direct narrower concepts only
            for narrower_uri in concept.narrower:
                if narrower_uri in self.concepts:
                    narrower_concepts.append(self.concepts[narrower_uri])
        else:
            # Transitive closure of narrower concepts
            visited = set()
            queue = deque(concept.narrower)
            
            while queue:
                narrower_uri = queue.popleft()
                if narrower_uri in visited or narrower_uri not in self.concepts:
                    continue
                
                visited.add(narrower_uri)
                narrower_concept = self.concepts[narrower_uri]
                narrower_concepts.append(narrower_concept)
                
                # Add narrower concepts of this concept to queue
                queue.extend(narrower_concept.narrower)
        
        return narrower_concepts
    
    def get_related_concepts(self, concept_uri: str) -> List[SKOSConcept]:
        """Get related concepts."""
        if concept_uri not in self.concepts:
            return []
        
        concept = self.concepts[concept_uri]
        related_concepts = []
        
        for related_uri in concept.related:
            if related_uri in self.concepts:
                related_concepts.append(self.concepts[related_uri])
        
        return related_concepts
    
    def expand_query_with_vocabulary(self, query: str, expansion_types: List[str] = None, 
                                   max_expansions: int = 10) -> Dict[str, List[str]]:
        """Expand query using vocabulary relationships."""
        if expansion_types is None:
            expansion_types = ["narrower", "broader", "related", "synonyms"]
        
        query_lower = query.lower()
        expansions = {
            "narrower": [],
            "broader": [],
            "related": [],
            "synonyms": [],
            "original": [query]
        }
        
        # Find concepts matching the query
        search_results = self.search_concepts(query, limit=5)
        
        for result in search_results:
            concept = result.concept
            
            if "narrower" in expansion_types:
                narrower_concepts = self.get_narrower_concepts(concept.uri)
                for narrower in narrower_concepts[:3]:  # Limit to avoid explosion
                    label = narrower.get_label()
                    if label not in expansions["narrower"]:
                        expansions["narrower"].append(label)
            
            if "broader" in expansion_types:
                broader_concepts = self.get_broader_concepts(concept.uri)
                for broader in broader_concepts[:3]:
                    label = broader.get_label()
                    if label not in expansions["broader"]:
                        expansions["broader"].append(label)
            
            if "related" in expansion_types:
                related_concepts = self.get_related_concepts(concept.uri)
                for related in related_concepts[:3]:
                    label = related.get_label()
                    if label not in expansions["related"]:
                        expansions["related"].append(label)
            
            if "synonyms" in expansion_types:
                # Add alternative labels as synonyms
                alt_labels = concept.alt_labels.get("pt", [])
                for alt_label in alt_labels:
                    if alt_label not in expansions["synonyms"] and alt_label.lower() != query_lower:
                        expansions["synonyms"].append(alt_label)
        
        # Limit total expansions
        for key in expansions:
            if key != "original":
                expansions[key] = expansions[key][:max_expansions]
        
        return expansions
    
    def get_concept_scheme_overview(self, scheme: ConceptScheme) -> Dict[str, Any]:
        """Get overview of a concept scheme."""
        if scheme not in self.hierarchies:
            return {}
        
        hierarchy = self.hierarchies[scheme]
        
        return {
            "scheme": scheme.value,
            "total_concepts": hierarchy.concept_count,
            "max_depth": hierarchy.max_depth,
            "root_concepts": [
                {
                    "uri": uri,
                    "label": self.concepts[uri].get_label(),
                    "children_count": len(hierarchy.concept_tree.get(uri, []))
                }
                for uri in hierarchy.root_concepts
            ],
            "top_level_categories": len(hierarchy.root_concepts)
        }
    
    def get_all_concept_schemes(self) -> List[Dict[str, Any]]:
        """Get overview of all concept schemes."""
        return [self.get_concept_scheme_overview(scheme) for scheme in ConceptScheme]
    
    def export_skos_rdf(self, concept_scheme: Optional[ConceptScheme] = None) -> str:
        """Export vocabulary as SKOS RDF/XML (simplified)."""
        # This would generate proper RDF/XML in a production system
        # For now, return a simplified structure
        
        concepts_to_export = self.concepts
        if concept_scheme:
            concepts_to_export = {
                uri: concept for uri, concept in self.concepts.items() 
                if concept.concept_scheme == concept_scheme
            }
        
        rdf_data = {
            "@context": {
                "skos": "http://www.w3.org/2004/02/skos/core#",
                "dc": "http://purl.org/dc/terms/",
                "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
            },
            "@graph": []
        }
        
        for uri, concept in concepts_to_export.items():
            concept_data = {
                "@id": uri,
                "@type": "skos:Concept",
                "skos:prefLabel": [
                    {"@value": label, "@language": lang}
                    for lang, label in concept.pref_label.items()
                ]
            }
            
            if concept.alt_labels:
                concept_data["skos:altLabel"] = []
                for lang, labels in concept.alt_labels.items():
                    for label in labels:
                        concept_data["skos:altLabel"].append({"@value": label, "@language": lang})
            
            if concept.definition:
                concept_data["skos:definition"] = [
                    {"@value": definition, "@language": lang}
                    for lang, definition in concept.definition.items()
                ]
            
            if concept.broader:
                concept_data["skos:broader"] = [{"@id": uri} for uri in concept.broader]
            
            if concept.narrower:
                concept_data["skos:narrower"] = [{"@id": uri} for uri in concept.narrower]
            
            if concept.related:
                concept_data["skos:related"] = [{"@id": uri} for uri in concept.related]
            
            rdf_data["@graph"].append(concept_data)
        
        return json.dumps(rdf_data, indent=2, ensure_ascii=False)