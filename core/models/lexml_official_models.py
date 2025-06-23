"""
Official LexML Brasil Data Models
=================================

Data models based on official LexML Brasil specifications and schemas.
Integrates with existing Monitor Legislativo data structures while
maintaining compatibility with LexML standards.

Reference: LexML Brasil oai_lexml schema and Kit Provedor de Dados v3.4.3
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from enum import Enum

from .models import Proposition, SearchResult, DataSource

class DocumentType(Enum):
    """Official LexML document types"""
    LEI = "lei"
    DECRETO = "decreto"
    PORTARIA = "portaria"
    RESOLUCAO = "resolucao"
    MEDIDA_PROVISORIA = "medida_provisoria"
    PROJETO_LEI = "projeto_lei"
    INSTRUCAO_NORMATIVA = "instrucao_normativa"
    ACORDAO = "acordao"
    OUTROS = "outros"

class Autoridade(Enum):
    """Official LexML authorities"""
    FEDERAL = "br"
    CONGRESSO_NACIONAL = "br:congresso.nacional"
    CAMARA_DEPUTADOS = "br:camara.deputados"
    SENADO_FEDERAL = "br:senado.federal"
    PRESIDENCIA = "br:presidencia.republica"
    MINISTERIO = "br:ministerio"
    ANTT = "br:ministerio.transportes:agencia.nacional.transportes.terrestres"
    ANTAQ = "br:ministerio.transportes:agencia.nacional.transportes.aquaviarios"
    ANAC = "br:ministerio.aeronautica:agencia.nacional.aviacao.civil"
    CONTRAN = "br:ministerio.transportes:conselho.nacional.transito"
    DNIT = "br:ministerio.transportes:departamento.nacional.infraestrutura.transportes"

class Evento(Enum):
    """Official LexML events"""
    PUBLICACAO = "publicacao"
    ASSINATURA = "assinatura"
    ALTERACAO = "alteracao"
    RETIFICACAO = "retificacao"
    REPUBLICACAO = "republicacao"
    ANULACAO = "anulacao"
    JULGAMENTO = "julgamento"
    INICIATIVA = "iniciativa"
    DERRUBADA_VETO_PARCIAL = "derrubada.veto.parcial"
    DERRUBADA_VETO_TOTAL = "derrubada.veto.total"
    DECLARACAO_INCONSTITUCIONALIDADE = "declaracao.inconstitucionalidade"

@dataclass
class LexMLMetadata:
    """Extended metadata for LexML documents"""
    urn: str
    autoridade: str
    evento: str
    localidade: str
    data_evento: str
    tipo_documento: str
    vocabulario_expandido: List[str] = field(default_factory=list)
    termos_relacionados: List[str] = field(default_factory=list)
    citacao_academica: Optional[str] = None
    nivel_relevancia: float = 0.0
    fonte_original: str = "LexML Brasil"

@dataclass
class LexMLDocument:
    """
    Official LexML document structure
    Maps to both LexML oai_lexml schema and Monitor Legislativo Proposition
    """
    urn: str
    title: str
    autoridade: str
    evento: str
    localidade: str
    data_evento: str
    tipo_documento: str
    texto_integral_url: Optional[str] = None
    resumo: Optional[str] = None
    palavras_chave: List[str] = field(default_factory=list)
    metadata: Optional[LexMLMetadata] = None
    
    def to_proposition(self) -> Proposition:
        """Convert LexML document to Monitor Legislativo Proposition"""
        
        # Map document type
        doc_type_mapping = {
            DocumentType.LEI.value: 'LEI',
            DocumentType.DECRETO.value: 'DECRETO',
            DocumentType.PORTARIA.value: 'PORTARIA',
            DocumentType.RESOLUCAO.value: 'RESOLUCAO',
            DocumentType.MEDIDA_PROVISORIA.value: 'MPV',
            DocumentType.PROJETO_LEI.value: 'PL',
            DocumentType.INSTRUCAO_NORMATIVA.value: 'INSTRUCAO_NORMATIVA',
            DocumentType.ACORDAO.value: 'ACORDAO',
            DocumentType.OUTROS.value: 'OUTROS'
        }
        
        mapped_type = doc_type_mapping.get(self.tipo_documento, 'OUTROS')
        
        # Parse date
        try:
            if self.data_evento:
                # Handle various date formats
                for date_format in ['%Y-%m-%d', '%d/%m/%Y', '%Y']:
                    try:
                        parsed_date = datetime.strptime(self.data_evento, date_format)
                        break
                    except ValueError:
                        continue
                else:
                    parsed_date = datetime.now()
            else:
                parsed_date = datetime.now()
        except:
            parsed_date = datetime.now()
        
        # Extract authors from autoridade
        authors = []
        if self.autoridade and self.autoridade != 'Não informado':
            # Convert URN-style autoridade to readable name
            autoridade_mapping = {
                'br': 'Brasil',
                'br:congresso.nacional': 'Congresso Nacional',
                'br:camara.deputados': 'Câmara dos Deputados',
                'br:senado.federal': 'Senado Federal',
                'br:presidencia.republica': 'Presidência da República'
            }
            
            author_name = autoridade_mapping.get(self.autoridade, self.autoridade)
            authors.append(author_name)
        
        # Build metadata
        prop_metadata = {
            'lexml_urn': self.urn,
            'lexml_autoridade': self.autoridade,
            'lexml_evento': self.evento,
            'lexml_localidade': self.localidade,
            'lexml_enhanced': True,
            'official_lexml': True
        }
        
        if self.metadata:
            prop_metadata.update({
                'vocabulario_expandido': self.metadata.vocabulario_expandido,
                'termos_relacionados': self.metadata.termos_relacionados,
                'citacao_academica': self.metadata.citacao_academica,
                'nivel_relevancia': self.metadata.nivel_relevancia
            })
        
        # Generate URL (prefer texto_integral_url, fallback to LexML viewer)
        url = self.texto_integral_url or f"https://www.lexml.gov.br/urn/{self.urn}"
        
        return Proposition(
            id=self.urn,
            title=self.title,
            summary=self.resumo or f'Documento {mapped_type} relacionado a transporte',
            type=mapped_type,
            publication_date=parsed_date.isoformat(),
            keywords=self.palavras_chave,
            authors=authors,
            url=url,
            status='PUBLISHED',  # LexML documents are published
            source='LEXML_BRASIL',
            metadata=prop_metadata
        )

@dataclass
class LexMLSearchRequest:
    """LexML search request structure"""
    query: str
    terms: List[str] = field(default_factory=list)
    autoridade: Optional[str] = None
    evento: Optional[str] = None
    tipo_documento: Optional[str] = None
    localidade: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    max_records: int = 50
    start_record: int = 1
    use_vocabulary_expansion: bool = True
    
    def to_cql_query(self) -> str:
        """Convert to CQL (Contextual Query Language) format"""
        query_parts = []
        
        # Add search terms
        if self.terms:
            term_queries = []
            for term in self.terms:
                term_clean = term.strip().replace('"', '\\"')
                term_queries.append(f'(titulo="{term_clean}" OR textoIntegral="{term_clean}")')
            
            if term_queries:
                query_parts.append(f"({' OR '.join(term_queries)})")
        elif self.query and self.query != '*':
            # Use general query
            query_clean = self.query.strip().replace('"', '\\"')
            query_parts.append(f'(titulo="{query_clean}" OR textoIntegral="{query_clean}")')
        
        # Add filters
        if self.autoridade:
            query_parts.append(f'autoridade="{self.autoridade}"')
        
        if self.evento:
            query_parts.append(f'evento="{self.evento}"')
        
        if self.tipo_documento:
            query_parts.append(f'tipoDocumento="{self.tipo_documento}"')
        
        if self.localidade:
            query_parts.append(f'localidade="{self.localidade}"')
        
        if self.date_from and self.date_to:
            query_parts.append(f'data>="{self.date_from}" AND data<="{self.date_to}"')
        elif self.date_from:
            query_parts.append(f'data>="{self.date_from}"')
        elif self.date_to:
            query_parts.append(f'data<="{self.date_to}"')
        
        # Combine with AND
        if query_parts:
            return ' AND '.join(query_parts)
        else:
            return '*'  # Match all if no specific criteria

@dataclass
class LexMLSearchResponse:
    """LexML search response structure"""
    documents: List[LexMLDocument]
    total_count: int
    query: str
    next_record_position: Optional[int] = None
    response_time_ms: int = 0
    source: str = "LexML Brasil"
    vocabulary_expanded: bool = False
    expanded_terms: List[str] = field(default_factory=list)
    
    def to_search_result(self, original_query: str, filters: Dict[str, Any] = None) -> SearchResult:
        """Convert to Monitor Legislativo SearchResult"""
        
        # Convert all documents to propositions
        propositions = [doc.to_proposition() for doc in self.documents]
        
        # Build metadata
        metadata = {
            'lexml_official': True,
            'total_documents': self.total_count,
            'response_time_ms': self.response_time_ms,
            'vocabulary_expanded': self.vocabulary_expanded,
            'next_record_position': self.next_record_position
        }
        
        if self.vocabulary_expanded:
            metadata['vocabulary_expansion'] = {
                'original_query': original_query,
                'expanded_terms': self.expanded_terms,
                'expansion_count': len(self.expanded_terms)
            }
        
        return SearchResult(
            query=original_query,
            filters=filters or {},
            propositions=propositions,
            total_count=self.total_count,
            source=DataSource.LEXML,
            metadata=metadata
        )

class CQLQueryBuilder:
    """Helper class for building CQL queries"""
    
    @staticmethod
    def build_transport_query(terms: List[str], filters: Dict[str, Any] = None) -> str:
        """Build CQL query optimized for transport legislation"""
        
        # Enhanced transport terms
        transport_terms = []
        for term in terms:
            transport_terms.append(term)
            
            # Add transport-specific expansions
            expansions = CQLQueryBuilder._get_transport_expansions(term)
            transport_terms.extend(expansions)
        
        # Remove duplicates
        transport_terms = list(set(transport_terms))
        
        # Build query parts
        query_parts = []
        
        # Add search terms
        if transport_terms:
            term_queries = []
            for term in transport_terms[:10]:  # Limit to prevent overlong queries
                term_clean = term.strip().replace('"', '\\"')
                term_queries.append(f'(titulo="{term_clean}" OR textoIntegral="{term_clean}")')
            
            query_parts.append(f"({' OR '.join(term_queries)})")
        
        # Add transport-specific authorities if not specified
        if filters and not filters.get('autoridade'):
            transport_authorities = [
                'br:ministerio.transportes',
                'br:ministerio.transportes:agencia.nacional.transportes.terrestres',
                'br:ministerio.transportes:agencia.nacional.transportes.aquaviarios',
                'br:ministerio.aeronautica:agencia.nacional.aviacao.civil'
            ]
            
            auth_query = ' OR '.join([f'autoridade="{auth}"' for auth in transport_authorities])
            query_parts.append(f'({auth_query})')
        
        # Add other filters
        if filters:
            if filters.get('autoridade'):
                query_parts.append(f'autoridade="{filters["autoridade"]}"')
            
            if filters.get('evento'):
                query_parts.append(f'evento="{filters["evento"]}"')
            
            if filters.get('date_from') and filters.get('date_to'):
                query_parts.append(f'data>="{filters["date_from"]}" AND data<="{filters["date_to"]}"')
        
        return ' AND '.join(query_parts) if query_parts else '*'
    
    @staticmethod
    def _get_transport_expansions(term: str) -> List[str]:
        """Get transport-specific term expansions"""
        term_lower = term.lower()
        expansions = []
        
        expansion_map = {
            'transporte': ['logística', 'mobilidade', 'modal', 'frete', 'carga'],
            'carga': ['mercadoria', 'commodity', 'produto', 'mercancía'],
            'rodoviário': ['BR-', 'rodovia', 'estrada', 'auto-estrada'],
            'caminhão': ['veículo comercial', 'veículo pesado', 'truck'],
            'sustentável': ['verde', 'limpo', 'ecológico', 'renovável'],
            'combustível': ['energia', 'diesel', 'biodiesel', 'etanol', 'gás natural'],
            'licenciamento': ['licença', 'autorização', 'permissão', 'habilitação']
        }
        
        for key, values in expansion_map.items():
            if key in term_lower:
                expansions.extend(values)
        
        return expansions

# Circuit Breaker for LexML API
@dataclass
class CircuitBreakerState:
    """Circuit breaker state for LexML API"""
    is_open: bool = False
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    timeout_duration: int = 300  # 5 minutes

@dataclass
class APIHealthStatus:
    """Health status for LexML API"""
    is_healthy: bool
    last_check: datetime
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    circuit_breaker_state: Optional[CircuitBreakerState] = None