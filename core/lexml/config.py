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
from typing import Dict, List, Optional, Any

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

# ---------------------------------------------------------------------------
# Backward-compatibility constants for legacy imports
# ---------------------------------------------------------------------------
# Some modules still import module-level constants that existed before this
# refactor (e.g., VOCABULARY_ENDPOINTS, CACHE_SETTINGS, etc.). To avoid
# widespread breakage while the codebase transitions to the new dataclass-
# driven configuration, we expose shim constants that map to the new config.

# Map of vocabulary name → remote URL (if available)
VOCABULARY_ENDPOINTS: Dict[str, str] = {
    name: vocab.url or "" for name, vocab in default_lexml_config.vocabularies.items()
}

# Database path constant
DATABASE_PATH: str = default_lexml_config.database_path

# Cache configuration (default values)
CACHE_SETTINGS: Dict[str, Any] = {
    "vocabulary_ttl": 24 * 60 * 60,  # 24h
    "search_results_ttl": 60 * 60,   # 1h
    "max_cache_size": 100 * 1024 * 1024,  # 100 MB
    "cleanup_interval": 2 * 60 * 60  # 2h
}

# HTTP request defaults for downloading vocabularies / SRU queries
HTTP_SETTINGS: Dict[str, Any] = {
    "timeout": 30,
    "max_retries": 3,
    "retry_delay": 1,
    "user_agent": default_lexml_config.user_agent,
    "headers": {
        "Accept": "application/rdf+xml, text/turtle, application/json",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
        "Cache-Control": "max-age=3600",
        "User-Agent": default_lexml_config.user_agent,
    },
}

# SKOS processing settings
SKOS_SETTINGS: Dict[str, Any] = {
    "supported_formats": ["rdf+xml", "turtle", "json-ld"],
    "preferred_format": "rdf+xml",
    "namespace_prefixes": {
        "skos": "http://www.w3.org/2004/02/skos/core#",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
        "lexml": "http://www.lexml.gov.br/vocabularios/",
        "dc": "http://purl.org/dc/elements/1.1/",
    },
}

# Transport-specific settings (used for generating mock concepts etc.)
TRANSPORT_CONFIG: Dict[str, Any] = {
    "regulatory_agencies": [
        "ANTT",  # Agência Nacional de Transportes Terrestres
        "CONTRAN",  # Conselho Nacional de Trânsito
        "DNIT",  # Departamento Nacional de Infraestrutura de Transportes
        "ANTAQ",  # Agência Nacional de Transportes Aquaviários
        "ANAC",   # Agência Nacional de Aviação Civil
    ]
}