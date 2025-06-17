"""
FRBROO Document Model for Academic Legislative Research
======================================================

Implements the FRBROO (FRBR Object Oriented) model for legislative documents
following the LexML Brasil specification and academic research requirements.

The FRBROO model provides four levels of abstraction:
1. F1 Work - The abstract legal concept
2. F2 Expression - The linguistic realization
3. F3 Manifestation - The specific format
4. F5 Item - The digital/physical exemplar

This implementation includes:
- Full FRBROO hierarchy with temporal control
- SKOS vocabulary integration
- Academic metadata for research
- LexML URN support
- Event tracking for legislative changes

Author: Academic Legislative Monitor Development Team
Created: June 2025
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Set
from enum import Enum
import hashlib
import json
from pathlib import Path

# Import existing models for compatibility
from .models import PropositionType, PropositionStatus, DataSource, Author, Proposition


class FRBROOLevel(Enum):
    """FRBROO abstraction levels for documents."""
    WORK = "F1_Work"
    EXPRESSION = "F2_Expression"
    MANIFESTATION = "F3_Manifestation_Product_Type"
    ITEM = "F5_Item"


class LegislativeEventType(Enum):
    """Types of legislative events following LexML specification."""
    ASSINATURA = "assinatura"
    PUBLICACAO = "publicacao"
    ALTERACAO = "alteracao"
    RETIFICACAO = "retificacao"
    REPUBLICACAO = "republicacao"
    ANULACAO = "anulacao"
    JULGAMENTO = "julgamento"
    INICIATIVA = "iniciativa"
    DERRUBADA_VETO_PARCIAL = "derrubada.veto.parcial"
    DERRUBADA_VETO_TOTAL = "derrubada.veto.total"
    DECLARACAO_INCONSTITUCIONALIDADE = "declaracao.inconstitucionalidade"
    PROMULGACAO = "promulgacao"
    SANÇÃO = "sancao"
    VETO = "veto"


class TemporalControl(Enum):
    """Temporal control types for document versions."""
    VERSION = "version"  # Different versions of the same document
    VISION = "vision"    # Same document at different points in time


@dataclass
class ControlledVocabularyTag:
    """SKOS controlled vocabulary tag for academic classification."""
    uri: str
    label: str
    vocabulary: str
    concept_type: str  # broader, narrower, related
    confidence: float = 1.0  # Confidence score for automatic tagging
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'uri': self.uri,
            'label': self.label,
            'vocabulary': self.vocabulary,
            'concept_type': self.concept_type,
            'confidence': self.confidence
        }


@dataclass
class LegislativeEvent:
    """Event in the legislative lifecycle."""
    event_type: LegislativeEventType
    date: datetime
    description: str
    authority: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_type': self.event_type.value,
            'date': self.date.isoformat(),
            'description': self.description,
            'authority': self.authority,
            'metadata': self.metadata
        }


@dataclass
class LexMLIdentifier:
    """LexML URN components for unique identification."""
    jurisdiction: str = "br"  # Brazil
    authority: str = ""       # e.g., "federal", "congresso.nacional"
    document_type: str = ""   # e.g., "lei", "decreto"
    date: str = ""           # YYYY-MM-DD format
    number: str = ""         # Document number
    version: Optional[str] = None
    fragment: Optional[str] = None
    
    @property
    def urn(self) -> str:
        """Generate LexML URN."""
        base_urn = f"urn:lex:{self.jurisdiction}:{self.authority}:{self.document_type}:{self.date};{self.number}"
        if self.version:
            base_urn += f"@{self.version}"
        if self.fragment:
            base_urn += f"#{self.fragment}"
        return base_urn
    
    @classmethod
    def from_urn(cls, urn: str) -> 'LexMLIdentifier':
        """Parse LexML URN into components."""
        # Simplified parser - in production use full LexML URN parser
        parts = urn.replace("urn:lex:", "").split(":")
        if len(parts) >= 4:
            jurisdiction = parts[0]
            authority = parts[1]
            document_type = parts[2]
            
            # Parse date and number
            date_number = parts[3].split("@")[0]
            date_part, number_part = date_number.split(";") if ";" in date_number else (date_number, "")
            
            # Parse version
            version = None
            if "@" in parts[3]:
                version = parts[3].split("@")[1].split("#")[0]
            
            # Parse fragment
            fragment = None
            if "#" in parts[3]:
                fragment = parts[3].split("#")[1]
            
            return cls(
                jurisdiction=jurisdiction,
                authority=authority,
                document_type=document_type,
                date=date_part,
                number=number_part,
                version=version,
                fragment=fragment
            )
        return cls()


@dataclass
class F1Work:
    """
    F1 Work - The abstract legal concept.
    
    Represents the abstract idea of a legislative work, independent of any
    specific linguistic expression or physical manifestation.
    """
    work_id: str
    title: str
    jurisdiction: str
    authority: str
    document_type: PropositionType
    creation_date: datetime
    subject_areas: List[str] = field(default_factory=list)
    controlled_vocabulary_tags: List[ControlledVocabularyTag] = field(default_factory=list)
    related_works: List[str] = field(default_factory=list)  # URNs of related works
    supersedes: Optional[str] = None  # URN of superseded work
    superseded_by: Optional[str] = None  # URN of superseding work
    
    def add_vocabulary_tag(self, tag: ControlledVocabularyTag):
        """Add a controlled vocabulary tag."""
        self.controlled_vocabulary_tags.append(tag)
    
    def get_tags_by_vocabulary(self, vocabulary: str) -> List[ControlledVocabularyTag]:
        """Get all tags from a specific vocabulary."""
        return [tag for tag in self.controlled_vocabulary_tags if tag.vocabulary == vocabulary]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'level': FRBROOLevel.WORK.value,
            'work_id': self.work_id,
            'title': self.title,
            'jurisdiction': self.jurisdiction,
            'authority': self.authority,
            'document_type': self.document_type.value,
            'creation_date': self.creation_date.isoformat(),
            'subject_areas': self.subject_areas,
            'controlled_vocabulary_tags': [tag.to_dict() for tag in self.controlled_vocabulary_tags],
            'related_works': self.related_works,
            'supersedes': self.supersedes,
            'superseded_by': self.superseded_by
        }


@dataclass
class F2Expression:
    """
    F2 Expression - The linguistic realization.
    
    Represents a specific linguistic expression of the work in a particular
    language and at a specific point in time.
    """
    expression_id: str
    work: F1Work
    language: str  # ISO 639-1 code
    expression_date: datetime
    version: str
    temporal_control: TemporalControl
    text_content: str
    authors: List[Author] = field(default_factory=list)
    legislative_events: List[LegislativeEvent] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)  # URNs of cited documents
    
    def add_event(self, event: LegislativeEvent):
        """Add a legislative event."""
        self.legislative_events.append(event)
        # Sort events by date
        self.legislative_events.sort(key=lambda e: e.date)
    
    def get_events_by_type(self, event_type: LegislativeEventType) -> List[LegislativeEvent]:
        """Get all events of a specific type."""
        return [event for event in self.legislative_events if event.event_type == event_type]
    
    @property
    def is_current_version(self) -> bool:
        """Check if this is the current version."""
        # Current if no anulacao or newer version exists
        anulacao_events = self.get_events_by_type(LegislativeEventType.ANULACAO)
        return len(anulacao_events) == 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'level': FRBROOLevel.EXPRESSION.value,
            'expression_id': self.expression_id,
            'work_id': self.work.work_id,
            'language': self.language,
            'expression_date': self.expression_date.isoformat(),
            'version': self.version,
            'temporal_control': self.temporal_control.value,
            'text_preview': self.text_content[:500] + '...' if len(self.text_content) > 500 else self.text_content,
            'authors': [author.name for author in self.authors],
            'legislative_events': [event.to_dict() for event in self.legislative_events],
            'keywords': self.keywords,
            'citations': self.citations,
            'is_current': self.is_current_version
        }


@dataclass
class F3Manifestation:
    """
    F3 Manifestation - The specific format.
    
    Represents a specific format or publication of the expression,
    such as PDF, HTML, XML, or printed format.
    """
    manifestation_id: str
    expression: F2Expression
    format_type: str  # PDF, HTML, XML, DOCX, etc.
    publication_date: datetime
    publisher: str
    publication_place: str
    official_gazette_info: Optional[Dict[str, Any]] = None
    digital_signature: Optional[str] = None
    file_size: Optional[int] = None  # bytes
    page_count: Optional[int] = None
    isbn_issn: Optional[str] = None
    doi: Optional[str] = None
    
    @property
    def is_official(self) -> bool:
        """Check if this is an official publication."""
        return self.official_gazette_info is not None
    
    def generate_academic_citation(self, standard: str = "ABNT") -> str:
        """Generate academic citation for this manifestation."""
        # Basic ABNT citation format
        authors = ", ".join([author.name.upper() for author in self.expression.authors[:3]])
        if len(self.expression.authors) > 3:
            authors += " et al."
        
        title = self.expression.work.title
        doc_type = self.expression.work.document_type.value
        
        if standard == "ABNT":
            citation = f"{authors}. {title}. {doc_type}. "
            citation += f"{self.publication_place}: {self.publisher}, "
            citation += f"{self.publication_date.strftime('%d de %B de %Y')}."
            
            if self.doi:
                citation += f" DOI: {self.doi}"
        
        return citation
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'level': FRBROOLevel.MANIFESTATION.value,
            'manifestation_id': self.manifestation_id,
            'expression_id': self.expression.expression_id,
            'format_type': self.format_type,
            'publication_date': self.publication_date.isoformat(),
            'publisher': self.publisher,
            'publication_place': self.publication_place,
            'is_official': self.is_official,
            'official_gazette_info': self.official_gazette_info,
            'digital_signature': self.digital_signature,
            'file_size': self.file_size,
            'page_count': self.page_count,
            'isbn_issn': self.isbn_issn,
            'doi': self.doi
        }


@dataclass
class F5Item:
    """
    F5 Item - The digital/physical exemplar.
    
    Represents a specific copy or instance of the manifestation,
    such as a downloaded PDF file or a specific URL.
    """
    item_id: str
    manifestation: F3Manifestation
    location: str  # URL, file path, or physical location
    access_date: datetime
    checksum: Optional[str] = None  # SHA-256 hash
    preservation_status: Optional[str] = None
    access_restrictions: Optional[str] = None
    local_storage_path: Optional[Path] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_checksum(self, content: bytes) -> str:
        """Calculate SHA-256 checksum of content."""
        self.checksum = hashlib.sha256(content).hexdigest()
        return self.checksum
    
    @property
    def is_accessible(self) -> bool:
        """Check if the item is currently accessible."""
        # Simple check - could be extended with actual URL validation
        return self.location.startswith(('http://', 'https://')) or (
            self.local_storage_path and self.local_storage_path.exists()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'level': FRBROOLevel.ITEM.value,
            'item_id': self.item_id,
            'manifestation_id': self.manifestation.manifestation_id,
            'location': self.location,
            'access_date': self.access_date.isoformat(),
            'checksum': self.checksum,
            'preservation_status': self.preservation_status,
            'access_restrictions': self.access_restrictions,
            'local_storage_path': str(self.local_storage_path) if self.local_storage_path else None,
            'is_accessible': self.is_accessible,
            'metadata': self.metadata
        }


@dataclass
class FRBROODocument:
    """
    Complete FRBROO document with all levels.
    
    This class manages the relationships between all FRBROO levels
    and provides methods for academic research and analysis.
    """
    lexml_identifier: LexMLIdentifier
    work: F1Work
    expressions: List[F2Expression] = field(default_factory=list)
    manifestations: List[F3Manifestation] = field(default_factory=list)
    items: List[F5Item] = field(default_factory=list)
    
    @classmethod
    def from_proposition(cls, proposition: Proposition, 
                        vocabulary_tags: List[ControlledVocabularyTag] = None) -> 'FRBROODocument':
        """Create FRBROO document from existing Proposition model."""
        # Create LexML identifier
        lexml_id = LexMLIdentifier(
            jurisdiction="br",
            authority=proposition.source.value.lower().replace(" ", "."),
            document_type=proposition.type.name.lower(),
            date=proposition.publication_date.strftime("%Y-%m-%d"),
            number=proposition.number
        )
        
        # Create Work
        work = F1Work(
            work_id=lexml_id.urn,
            title=proposition.title,
            jurisdiction="Brasil",
            authority=proposition.source.value,
            document_type=proposition.type,
            creation_date=proposition.publication_date,
            subject_areas=proposition.keywords,
            controlled_vocabulary_tags=vocabulary_tags or []
        )
        
        # Create Expression
        expression = F2Expression(
            expression_id=f"{lexml_id.urn}:expression:1",
            work=work,
            language="pt-BR",
            expression_date=proposition.publication_date,
            version="1.0",
            temporal_control=TemporalControl.VERSION,
            text_content=proposition.summary,
            authors=proposition.authors,
            keywords=proposition.keywords
        )
        
        # Add publication event
        pub_event = LegislativeEvent(
            event_type=LegislativeEventType.PUBLICACAO,
            date=proposition.publication_date,
            description=f"Publicação de {proposition.formatted_number}",
            authority=proposition.source.value
        )
        expression.add_event(pub_event)
        
        # Create Manifestation (if URL available)
        manifestations = []
        items = []
        
        if proposition.url:
            manifestation = F3Manifestation(
                manifestation_id=f"{lexml_id.urn}:manifestation:html",
                expression=expression,
                format_type="HTML",
                publication_date=proposition.publication_date,
                publisher=proposition.source.value,
                publication_place="Brasília, DF"
            )
            manifestations.append(manifestation)
            
            # Create Item
            item = F5Item(
                item_id=f"{lexml_id.urn}:item:1",
                manifestation=manifestation,
                location=proposition.url,
                access_date=datetime.now()
            )
            items.append(item)
        
        return cls(
            lexml_identifier=lexml_id,
            work=work,
            expressions=[expression],
            manifestations=manifestations,
            items=items
        )
    
    def get_current_expression(self) -> Optional[F2Expression]:
        """Get the current/latest expression."""
        current_expressions = [exp for exp in self.expressions if exp.is_current_version]
        if current_expressions:
            # Return the most recent
            return sorted(current_expressions, key=lambda e: e.expression_date, reverse=True)[0]
        return None
    
    def get_expressions_by_date(self, start_date: datetime, end_date: datetime) -> List[F2Expression]:
        """Get expressions within a date range."""
        return [
            exp for exp in self.expressions
            if start_date <= exp.expression_date <= end_date
        ]
    
    def get_official_manifestations(self) -> List[F3Manifestation]:
        """Get only official manifestations."""
        return [man for man in self.manifestations if man.is_official]
    
    def get_accessible_items(self) -> List[F5Item]:
        """Get items that are currently accessible."""
        return [item for item in self.items if item.is_accessible]
    
    def add_vocabulary_tag(self, tag: ControlledVocabularyTag):
        """Add controlled vocabulary tag to the work."""
        self.work.add_vocabulary_tag(tag)
    
    def get_complete_history(self) -> List[LegislativeEvent]:
        """Get complete legislative history across all expressions."""
        all_events = []
        for expression in self.expressions:
            all_events.extend(expression.legislative_events)
        
        # Sort by date
        all_events.sort(key=lambda e: e.date)
        return all_events
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'lexml_urn': self.lexml_identifier.urn,
            'work': self.work.to_dict(),
            'expressions': [exp.to_dict() for exp in self.expressions],
            'manifestations': [man.to_dict() for man in self.manifestations],
            'items': [item.to_dict() for item in self.items],
            'metadata': {
                'total_expressions': len(self.expressions),
                'total_manifestations': len(self.manifestations),
                'total_items': len(self.items),
                'has_current_version': self.get_current_expression() is not None,
                'vocabularies_used': list(set(
                    tag.vocabulary for tag in self.work.controlled_vocabulary_tags
                ))
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)
    
    def generate_citation(self, standard: str = "ABNT", 
                         expression_id: Optional[str] = None) -> str:
        """Generate academic citation for the document."""
        # Get specific expression or current
        if expression_id:
            expression = next((exp for exp in self.expressions if exp.expression_id == expression_id), None)
        else:
            expression = self.get_current_expression()
        
        if not expression:
            return ""
        
        # Get first official manifestation for this expression
        official_manifestations = [
            man for man in self.manifestations 
            if man.expression == expression and man.is_official
        ]
        
        if official_manifestations:
            return official_manifestations[0].generate_academic_citation(standard)
        
        # Fallback to basic citation
        return f"{self.work.title}. {self.work.document_type.value}. {expression.expression_date.year}."