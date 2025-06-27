"""Entity extraction service for legislative documents."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import re
import json
from datetime import datetime

from core.config.config import Config
from core.utils.logger import Logger
from core.models.legislative_data import LegislativeDocument

logger = Logger()


class EntityType(Enum):
    """Types of entities that can be extracted."""
    ORGANIZATION = "organization"
    LEGAL_CONCEPT = "legal_concept"
    GEOGRAPHIC_LOCATION = "geographic_location"
    PERSON = "person"
    DATE = "date"
    MONETARY_VALUE = "monetary_value"
    LEGAL_REFERENCE = "legal_reference"


@dataclass
class Entity:
    """Represents an extracted entity."""
    name: str
    type: EntityType
    confidence: float
    context: str
    positions: List[int]
    metadata: Dict[str, Any]


class EntityExtractor:
    """Extract entities from Brazilian legislative documents."""
    
    def __init__(self):
        self.config = Config()
        self._load_patterns()
        
    def _load_patterns(self):
        """Load regex patterns for entity extraction."""
        self.patterns = {
            EntityType.LEGAL_REFERENCE: [
                r'Lei\s+(?:nº\s*)?(\d+\.?\d*)/(\d{4})',
                r'Decreto\s+(?:nº\s*)?(\d+\.?\d*)/(\d{4})',
                r'Portaria\s+(?:nº\s*)?(\d+\.?\d*)/(\d{4})',
                r'Resolução\s+(?:nº\s*)?(\d+\.?\d*)/(\d{4})',
                r'Medida Provisória\s+(?:nº\s*)?(\d+\.?\d*)/(\d{4})',
                r'PEC\s+(?:nº\s*)?(\d+)/(\d{4})',
                r'PL\s+(?:nº\s*)?(\d+)/(\d{4})'
            ],
            EntityType.ORGANIZATION: [
                r'Ministério\s+(?:da\s+|do\s+|de\s+)?[\w\s]+',
                r'Secretaria\s+(?:da\s+|do\s+|de\s+)?[\w\s]+',
                r'Agência\s+Nacional\s+(?:de\s+|do\s+)?[\w\s]+',
                r'ANTT|ANTAQ|ANAC|ANEEL|ANS|ANVISA|ANP|ANATEL|ANA|ANCINE|ANM',
                r'Tribunal\s+(?:de\s+|do\s+)?[\w\s]+',
                r'Câmara\s+dos\s+Deputados',
                r'Senado\s+Federal',
                r'Presidência\s+da\s+República'
            ],
            EntityType.GEOGRAPHIC_LOCATION: [
                r'Estado\s+(?:da\s+|do\s+|de\s+)?[\w\s]+',
                r'Município\s+(?:da\s+|do\s+|de\s+)?[\w\s]+',
                r'(?:São\s+Paulo|Rio\s+de\s+Janeiro|Brasília|Salvador|Fortaleza|Belo\s+Horizonte|Manaus|Curitiba|Recife|Porto\s+Alegre)',
                r'(?:AC|AL|AP|AM|BA|CE|DF|ES|GO|MA|MT|MS|MG|PA|PB|PR|PE|PI|RJ|RN|RS|RO|RR|SC|SP|SE|TO)\b'
            ],
            EntityType.DATE: [
                r'\d{1,2}\s+de\s+(?:janeiro|fevereiro|março|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro)\s+de\s+\d{4}',
                r'\d{1,2}/\d{1,2}/\d{4}',
                r'\d{4}-\d{2}-\d{2}'
            ],
            EntityType.MONETARY_VALUE: [
                r'R\$\s*[\d.,]+(?:\s*(?:mil|milhões?|bilhões?))?',
                r'(?:[\d.,]+)\s*(?:reais|real)'
            ]
        }
        
        # Brazilian government organizations
        self.known_organizations = {
            'ANTT': 'Agência Nacional de Transportes Terrestres',
            'ANTAQ': 'Agência Nacional de Transportes Aquaviários',
            'ANAC': 'Agência Nacional de Aviação Civil',
            'ANEEL': 'Agência Nacional de Energia Elétrica',
            'ANS': 'Agência Nacional de Saúde Suplementar',
            'ANVISA': 'Agência Nacional de Vigilância Sanitária',
            'ANP': 'Agência Nacional do Petróleo, Gás Natural e Biocombustíveis',
            'ANATEL': 'Agência Nacional de Telecomunicações',
            'ANA': 'Agência Nacional de Águas',
            'ANCINE': 'Agência Nacional do Cinema',
            'ANM': 'Agência Nacional de Mineração'
        }
        
        # Brazilian states
        self.brazilian_states = {
            'AC': 'Acre', 'AL': 'Alagoas', 'AP': 'Amapá', 'AM': 'Amazonas',
            'BA': 'Bahia', 'CE': 'Ceará', 'DF': 'Distrito Federal', 'ES': 'Espírito Santo',
            'GO': 'Goiás', 'MA': 'Maranhão', 'MT': 'Mato Grosso', 'MS': 'Mato Grosso do Sul',
            'MG': 'Minas Gerais', 'PA': 'Pará', 'PB': 'Paraíba', 'PR': 'Paraná',
            'PE': 'Pernambuco', 'PI': 'Piauí', 'RJ': 'Rio de Janeiro', 'RN': 'Rio Grande do Norte',
            'RS': 'Rio Grande do Sul', 'RO': 'Rondônia', 'RR': 'Roraima', 'SC': 'Santa Catarina',
            'SP': 'São Paulo', 'SE': 'Sergipe', 'TO': 'Tocantins'
        }
    
    async def extract_entities(self, document: LegislativeDocument) -> List[Entity]:
        """Extract entities from a legislative document."""
        try:
            text = self._get_document_text(document)
            entities = []
            
            # Extract entities using patterns
            for entity_type, patterns in self.patterns.items():
                for pattern in patterns:
                    entities.extend(self._extract_with_pattern(text, pattern, entity_type))
            
            # Extract persons (simplified - in production would use NER)
            entities.extend(self._extract_persons(text))
            
            # Deduplicate and enhance entities
            entities = self._deduplicate_entities(entities)
            entities = self._enhance_entities(entities, document)
            
            logger.info(f"Extracted {len(entities)} entities from document {document.id}")
            return entities
            
        except Exception as e:
            logger.error(f"Entity extraction failed for document {document.id}: {str(e)}")
            return []
    
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
    
    def _extract_with_pattern(self, text: str, pattern: str, entity_type: EntityType) -> List[Entity]:
        """Extract entities using regex pattern."""
        entities = []
        
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entity_text = match.group(0).strip()
            
            # Clean up the entity text
            entity_text = re.sub(r'\s+', ' ', entity_text)
            
            # Get context (50 chars before and after)
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end].strip()
            
            entity = Entity(
                name=entity_text,
                type=entity_type,
                confidence=0.8,  # Pattern-based extraction has high confidence
                context=context,
                positions=[match.start()],
                metadata={}
            )
            
            # Add specific metadata based on type
            if entity_type == EntityType.LEGAL_REFERENCE:
                parts = match.groups()
                if len(parts) >= 2:
                    entity.metadata['number'] = parts[0]
                    entity.metadata['year'] = parts[1]
            
            entities.append(entity)
        
        return entities
    
    def _extract_persons(self, text: str) -> List[Entity]:
        """Extract person names (simplified version)."""
        entities = []
        
        # Simple pattern for Brazilian names
        # In production, would use proper NER
        patterns = [
            r'(?:Deputad[oa]|Senador[a]?|Ministr[oa]|Presidente|Relator[a]?)\s+(?:[A-Z][a-z]+\s+){1,4}[A-Z][a-z]+',
            r'(?:Sr\.|Sra\.|Dr\.|Dra\.)\s+(?:[A-Z][a-z]+\s+){1,3}[A-Z][a-z]+'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                person_text = match.group(0).strip()
                
                # Extract just the name part
                name_parts = person_text.split()
                if len(name_parts) > 1:
                    # Remove title
                    name = ' '.join(name_parts[1:])
                    
                    entity = Entity(
                        name=name,
                        type=EntityType.PERSON,
                        confidence=0.6,  # Lower confidence for pattern-based person extraction
                        context=text[max(0, match.start()-50):min(len(text), match.end()+50)],
                        positions=[match.start()],
                        metadata={'title': name_parts[0]}
                    )
                    entities.append(entity)
        
        return entities
    
    def _deduplicate_entities(self, entities: List[Entity]) -> List[Entity]:
        """Remove duplicate entities."""
        seen = {}
        unique_entities = []
        
        for entity in entities:
            key = (entity.name.lower(), entity.type)
            
            if key not in seen:
                seen[key] = entity
                unique_entities.append(entity)
            else:
                # Merge positions
                seen[key].positions.extend(entity.positions)
                seen[key].positions = sorted(list(set(seen[key].positions)))
                # Keep highest confidence
                seen[key].confidence = max(seen[key].confidence, entity.confidence)
        
        return unique_entities
    
    def _enhance_entities(self, entities: List[Entity], document: LegislativeDocument) -> List[Entity]:
        """Enhance entities with additional metadata."""
        for entity in entities:
            # Enhance organizations
            if entity.type == EntityType.ORGANIZATION:
                for abbr, full_name in self.known_organizations.items():
                    if abbr in entity.name:
                        entity.metadata['full_name'] = full_name
                        entity.metadata['abbreviation'] = abbr
                        entity.confidence = 0.95
            
            # Enhance geographic locations
            elif entity.type == EntityType.GEOGRAPHIC_LOCATION:
                for abbr, state_name in self.brazilian_states.items():
                    if abbr in entity.name or state_name in entity.name:
                        entity.metadata['state_code'] = abbr
                        entity.metadata['state_name'] = state_name
                        entity.confidence = 0.95
            
            # Add document reference
            entity.metadata['document_id'] = document.id
            entity.metadata['document_type'] = document.document_type
            
        return entities
    
    def get_entity_summary(self, entities: List[Entity]) -> Dict[str, Any]:
        """Get summary statistics of extracted entities."""
        summary = {
            'total_entities': len(entities),
            'by_type': {},
            'top_entities': [],
            'confidence_stats': {
                'mean': 0,
                'min': 0,
                'max': 0
            }
        }
        
        if not entities:
            return summary
        
        # Count by type
        type_counts = {}
        entity_counts = {}
        
        for entity in entities:
            # Count by type
            type_name = entity.type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            
            # Count entity occurrences
            entity_key = (entity.name, entity.type.value)
            entity_counts[entity_key] = entity_counts.get(entity_key, 0) + len(entity.positions)
        
        summary['by_type'] = type_counts
        
        # Top entities
        top_entities = sorted(entity_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        summary['top_entities'] = [
            {
                'name': name,
                'type': entity_type,
                'count': count
            }
            for (name, entity_type), count in top_entities
        ]
        
        # Confidence stats
        confidences = [e.confidence for e in entities]
        summary['confidence_stats'] = {
            'mean': sum(confidences) / len(confidences),
            'min': min(confidences),
            'max': max(confidences)
        }
        
        return summary