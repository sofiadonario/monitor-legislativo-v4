"""
LexML Vocabulary and API Configuration
======================================

Centralized configuration for LexML-related services, including:
- SKOS vocabulary endpoints and local file paths
- Cache settings for vocabularies
- API settings for the enhanced LexML search
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Base path for local vocabulary files (can be overridden by environment variables)
# Assumes a 'vocabularies' directory at the project root
VOCABULARY_BASE_PATH = os.environ.get(
    "VOCABULARY_PATH", 
    os.path.join(os.path.dirname(__file__), "..", "..", "vocabularies")
)

@dataclass
class VocabularyConfig:
    """Configuration for a single SKOS vocabulary."""
    name: str
    url: Optional[str] = None  # Remote URL for fetching the vocabulary
    local_file: Optional[str] = None  # Local file name (relative to VOCABULARY_BASE_PATH)
    format: str = "xml"  # RDF/XML, turtle, etc.
    description: Optional[str] = None

@dataclass
class LexMLConfig:
    """Main configuration for LexML services."""
    
    # Path to the SQLite database for caching vocabularies
    database_path: str = os.path.join(VOCABULARY_BASE_PATH, "lexml_vocab.db")
    
    # Timeout for fetching remote vocabularies (in seconds)
    fetch_timeout: int = 60
    
    # List of vocabularies to be loaded and managed
    vocabularies: Dict[str, VocabularyConfig] = field(default_factory=lambda: {
        # Core Vocabularies from LexML Brasil
        "autoridade": VocabularyConfig(
            name="autoridade",
            url="http://projeto.lexml.gov.br/vocabulario/autoridade.rdf",
            local_file="autoridade.rdf",
            description="Vocabulário de Autoridades do LexML Brasil."
        ),
        "evento": VocabularyConfig(
            name="evento",
            url="http://projeto.lexml.gov.br/vocabulario/evento.rdf",
            local_file="evento.rdf",
            description="Vocabulário de Eventos Legislativos."
        ),
        "tipo_documento": VocabularyConfig(
            name="tipo_documento",
            url="http://projeto.lexml.gov.br/vocabulario/tipo_documento.rdf",
            local_file="tipo_documento.rdf",
            description="Vocabulário de Tipos de Documento."
        ),
        
        # Domain-Specific Vocabularies
        "transport_terms": VocabularyConfig(
            name="transport_terms",
            local_file="transport_terms.rdf",  # Assuming a custom, local vocabulary
            description="Vocabulário controlado para o domínio de transportes."
        ),
        "regulatory_agencies": VocabularyConfig(
            name="regulatory_agencies",
            local_file="regulatory_agencies.rdf",
            description="Vocabulário para agências reguladoras brasileiras."
        ),
    })

    # User-Agent for making HTTP requests to LexML services
    user_agent: str = "MonitorLegislativoV4/1.0 (Academic Research; mailto:user@example.com)"

# Instantiate a default config object for easy import
default_lexml_config = LexMLConfig()