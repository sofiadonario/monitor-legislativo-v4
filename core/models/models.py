"""
Data models for Monitor Legislativo
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class PropositionType(Enum):
    """Types of legislative propositions"""
    PL = "Projeto de Lei"
    PLP = "Projeto de Lei Complementar"
    PEC = "Proposta de Emenda à Constituição"
    MPV = "Medida Provisória"
    PLV = "Projeto de Lei de Conversão"
    PDL = "Projeto de Decreto Legislativo"
    PRC = "Projeto de Resolução"
    REQ = "Requerimento"
    RIC = "Requerimento de Informação"
    INC = "Indicação"
    DECRETO = "Decreto"
    PORTARIA = "Portaria"
    RESOLUCAO = "Resolução"
    INSTRUCAO_NORMATIVA = "Instrução Normativa"
    CIRCULAR = "Circular"
    CONSULTA_PUBLICA = "Consulta Pública"
    OTHER = "Outro"


class PropositionStatus(Enum):
    """Status of legislative propositions"""
    ACTIVE = "Em tramitação"
    APPROVED = "Aprovada"
    REJECTED = "Rejeitada"
    ARCHIVED = "Arquivada"
    WITHDRAWN = "Retirada"
    PUBLISHED = "Publicada"
    UNKNOWN = "Desconhecido"


class DataSource(Enum):
    """Data sources for propositions"""
    LEXML = "LexML Brasil - Sistema de Informação Legislativa"
    CAMARA = "Câmara dos Deputados"
    SENADO = "Senado Federal"
    PLANALTO = "Diário Oficial da União"
    # Regulatory agencies
    ANEEL = "ANEEL"
    ANATEL = "ANATEL"
    ANVISA = "ANVISA"
    ANS = "ANS"
    ANA = "ANA"
    ANCINE = "ANCINE"
    ANTT = "ANTT"
    ANTAQ = "ANTAQ"
    ANAC = "ANAC"
    ANP = "ANP"
    ANM = "ANM"


@dataclass
class Author:
    """Author of a proposition"""
    name: str
    type: str = "Unknown"  # Deputado, Senador, Órgão, etc.
    party: Optional[str] = None
    state: Optional[str] = None
    id: Optional[str] = None


@dataclass
class Proposition:
    """A legislative proposition or regulatory document"""
    # Basic info
    id: str
    type: PropositionType
    number: str
    year: int
    title: str
    summary: str
    
    # Metadata
    source: DataSource
    status: PropositionStatus
    url: str
    publication_date: datetime
    last_update: Optional[datetime] = None
    
    # Authors
    authors: List[Author] = field(default_factory=list)
    
    # Additional data
    keywords: List[str] = field(default_factory=list)
    full_text_url: Optional[str] = None
    attachments: List[Dict[str, str]] = field(default_factory=list)
    extra_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # Ensure datetime objects
        if isinstance(self.publication_date, str):
            self.publication_date = datetime.fromisoformat(self.publication_date)
        if self.last_update and isinstance(self.last_update, str):
            self.last_update = datetime.fromisoformat(self.last_update)
    
    @property
    def formatted_number(self) -> str:
        """Get formatted proposition number"""
        return f"{self.type.value} {self.number}/{self.year}"
    
    @property
    def author_names(self) -> str:
        """Get comma-separated list of author names"""
        return ", ".join(author.name for author in self.authors)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "type": self.type.value,
            "number": self.number,
            "year": self.year,
            "title": self.title,
            "summary": self.summary,
            "source": self.source.value,
            "status": self.status.value,
            "url": self.url,
            "publication_date": self.publication_date.isoformat(),
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "authors": [
                {
                    "name": author.name,
                    "type": author.type,
                    "party": author.party,
                    "state": author.state,
                    "id": author.id
                }
                for author in self.authors
            ],
            "keywords": self.keywords,
            "full_text_url": self.full_text_url,
            "attachments": self.attachments,
            "extra_data": self.extra_data
        }


@dataclass
class SearchFilters:
    """Filters for searching propositions"""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    types: List[PropositionType] = field(default_factory=list)
    sources: List[DataSource] = field(default_factory=list)
    status: Optional[PropositionStatus] = None
    author: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API calls"""
        filters = {}
        
        if self.start_date:
            filters["start_date"] = self.start_date.strftime("%Y-%m-%d")
        if self.end_date:
            filters["end_date"] = self.end_date.strftime("%Y-%m-%d")
        if self.types:
            filters["types"] = [t.name for t in self.types]
        if self.sources:
            filters["sources"] = [s.name for s in self.sources]
        if self.status:
            filters["status"] = self.status.name
        if self.author:
            filters["author"] = self.author
        if self.keywords:
            filters["keywords"] = self.keywords
        
        return filters


@dataclass
class SearchResult:
    """Result of a search operation"""
    query: str
    filters: SearchFilters
    propositions: List[Proposition]
    total_count: int
    page: int = 1
    page_size: int = 25
    search_time: float = 0.0  # Search duration in seconds
    source: Optional[DataSource] = None
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None  # Additional metadata for enhanced search
    
    @property
    def total_pages(self) -> int:
        """Calculate total number of pages"""
        if self.page_size == 0:
            return 1
        return (self.total_count + self.page_size - 1) // self.page_size
    
    @property
    def has_next_page(self) -> bool:
        """Check if there's a next page"""
        return self.page < self.total_pages
    
    @property
    def has_previous_page(self) -> bool:
        """Check if there's a previous page"""
        return self.page > 1


@dataclass
class APIStatus:
    """Status of an API service"""
    name: str
    source: DataSource
    is_healthy: bool
    last_check: datetime
    response_time: Optional[float] = None  # in seconds
    error_message: Optional[str] = None
    
    @property
    def status_text(self) -> str:
        """Get human-readable status"""
        return "Operacional" if self.is_healthy else "Indisponível"