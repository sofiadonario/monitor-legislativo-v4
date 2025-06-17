"""
LexML Brasil Configuration
=========================

Configuration settings for LexML Brasil integration including
SKOS vocabulary endpoints, caching settings, and academic standards.
"""

import os
from pathlib import Path
from typing import Dict, List

# LexML Brasil Official Endpoints
LEXML_BASE_URL = "https://www.lexml.gov.br"
SKOS_VOCABULARIES_URL = f"{LEXML_BASE_URL}/vocabularios"
LEXML_SEARCH_URL = f"{LEXML_BASE_URL}/busca/SRU"
LEXML_OAI_PMH_URL = f"{LEXML_BASE_URL}/oai"

# SKOS Vocabulary Endpoints
VOCABULARY_ENDPOINTS = {
    # Basic Vocabularies (Seção 5.4)
    'natureza_conteudo': f"{SKOS_VOCABULARIES_URL}/natureza-conteudo.skos",
    'lingua': f"{SKOS_VOCABULARIES_URL}/lingua.skos", 
    'evento': f"{SKOS_VOCABULARIES_URL}/evento.skos",
    
    # Specific Vocabularies (Seção 5.5)
    'localidade': f"{SKOS_VOCABULARIES_URL}/localidade.skos",
    'autoridade': f"{SKOS_VOCABULARIES_URL}/autoridade.skos",
    'tipo_documento': f"{SKOS_VOCABULARIES_URL}/tipo-documento.skos",
    
    # Transport-Specific Extensions
    'transport_terms': f"{SKOS_VOCABULARIES_URL}/transport-terms.skos",
    'regulatory_agencies': f"{SKOS_VOCABULARIES_URL}/regulatory-agencies.skos"
}

# Controlled Vocabulary Categories
BASIC_VOCABULARIES = [
    'natureza_conteudo',
    'lingua', 
    'evento'
]

SPECIFIC_VOCABULARIES = [
    'localidade',
    'autoridade', 
    'tipo_documento'
]

TRANSPORT_VOCABULARIES = [
    'transport_terms',
    'regulatory_agencies'
]

# Cache Configuration
CACHE_DIR = Path.home() / '.lexml_cache'
CACHE_DIR.mkdir(exist_ok=True)

CACHE_SETTINGS = {
    'vocabulary_ttl': 86400,  # 24 hours
    'search_results_ttl': 3600,  # 1 hour
    'max_cache_size': 100 * 1024 * 1024,  # 100MB
    'cleanup_interval': 7200  # 2 hours
}

# Database Configuration
DATABASE_PATH = CACHE_DIR / 'lexml_vocabularies.db'

# HTTP Configuration
HTTP_SETTINGS = {
    'timeout': 30,
    'max_retries': 3,
    'retry_delay': 1,
    'user_agent': 'Academic-Transport-Legislation-Monitor/1.0 (LexML Integration)',
    'headers': {
        'Accept': 'application/rdf+xml, text/turtle, application/json',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Cache-Control': 'max-age=3600'
    }
}

# SKOS Processing Configuration
SKOS_SETTINGS = {
    'supported_formats': ['rdf+xml', 'turtle', 'json-ld'],
    'preferred_format': 'rdf+xml',
    'namespace_prefixes': {
        'skos': 'http://www.w3.org/2004/02/skos/core#',
        'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
        'rdfs': 'http://www.w3.org/2000/01/rdf-schema#',
        'lexml': 'http://www.lexml.gov.br/vocabularios/',
        'dc': 'http://purl.org/dc/elements/1.1/'
    }
}

# FRBROO Configuration
FRBROO_SETTINGS = {
    'work_types': ['F1_Work', 'F14_Individual_Work', 'F15_Complex_Work'],
    'expression_types': ['F2_Expression', 'F22_Self_Contained_Expression'],
    'manifestation_types': ['F3_Manifestation_Product_Type', 'F4_Manifestation_Singleton'],
    'item_types': ['F5_Item']
}

# Academic Citation Configuration
CITATION_STANDARDS = {
    'abnt': {
        'standard': 'ABNT NBR 6023:2018',
        'format': 'brazilian',
        'date_format': '%d de %B de %Y'
    },
    'apa': {
        'standard': 'APA 7th Edition',
        'format': 'american',
        'date_format': '%Y, %B %d'
    },
    'bibtex': {
        'standard': 'BibTeX',
        'format': 'latex',
        'entry_types': ['legislation', 'misc', 'techreport']
    },
    'skos_rdf': {
        'standard': 'W3C SKOS',
        'format': 'rdf+xml',
        'namespace': 'http://www.w3.org/2004/02/skos/core#'
    }
}

# Transport-Specific Configuration
TRANSPORT_CONFIG = {
    'regulatory_agencies': [
        'ANTT',  # Agência Nacional de Transportes Terrestres
        'CONTRAN',  # Conselho Nacional de Trânsito
        'DNIT',  # Departamento Nacional de Infraestrutura de Transportes
        'ANTAQ',  # Agência Nacional de Transportes Aquaviários
        'ANAC'   # Agência Nacional de Aviação Civil
    ],
    'transport_programs': [
        'Rota 2030',
        'PATEN',
        'Marco Legal do Saneamento',
        'Novo Marco Legal do Gás',
        'Marco Legal das Ferrovias'
    ],
    'priority_terms': [
        'transporte de carga',
        'mobilidade urbana',
        'combustível sustentável',
        'descarbonização',
        'veículos elétricos',
        'infraestrutura de transportes'
    ]
}

# Error Handling Configuration
ERROR_HANDLING = {
    'max_vocabulary_load_attempts': 3,
    'fallback_to_cache': True,
    'graceful_degradation': True,
    'error_reporting': True,
    'log_level': 'INFO'
}

# Academic Compliance Settings
ACADEMIC_COMPLIANCE = {
    'require_source_attribution': True,
    'enforce_citation_standards': True,
    'validate_controlled_vocabularies': True,
    'temporal_precision_required': True,
    'frbroo_compliance_required': True
}

# Performance Configuration
PERFORMANCE_SETTINGS = {
    'vocabulary_preload': True,
    'concurrent_vocabulary_loading': True,
    'search_result_pagination': 50,
    'max_concurrent_requests': 5,
    'connection_pool_size': 10
}

# Development and Testing Configuration
DEVELOPMENT_CONFIG = {
    'debug_mode': os.getenv('LEXML_DEBUG', 'False').lower() == 'true',
    'test_mode': os.getenv('LEXML_TEST_MODE', 'False').lower() == 'true',
    'mock_vocabularies': os.getenv('LEXML_MOCK_VOCABULARIES', 'False').lower() == 'true',
    'verbose_logging': os.getenv('LEXML_VERBOSE', 'False').lower() == 'true'
}

def get_vocabulary_url(vocabulary_name: str) -> str:
    """Get the SKOS vocabulary URL for a given vocabulary name."""
    return VOCABULARY_ENDPOINTS.get(vocabulary_name)

def get_cache_path(vocabulary_name: str) -> Path:
    """Get the cache file path for a vocabulary."""
    return CACHE_DIR / f"{vocabulary_name}.cache"

def get_all_vocabularies() -> List[str]:
    """Get list of all available vocabulary names."""
    return list(VOCABULARY_ENDPOINTS.keys())

def is_transport_vocabulary(vocabulary_name: str) -> bool:
    """Check if a vocabulary is transport-specific."""
    return vocabulary_name in TRANSPORT_VOCABULARIES