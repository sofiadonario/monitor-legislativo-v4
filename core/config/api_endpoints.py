"""
API endpoints and HTML selectors configuration
Centralized configuration for all API integrations
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class EndpointConfig:
    """Configuration for an API endpoint"""
    base_url: str
    search_path: str
    details_path: Optional[str] = None
    health_path: Optional[str] = None
    params_mapping: Dict[str, str] = None
    
    def __post_init__(self):
        if self.params_mapping is None:
            self.params_mapping = {}


@dataclass 
class ScraperConfig:
    """Configuration for web scraping"""
    search_url: str
    selectors: Dict[str, str]
    pagination_selector: Optional[str] = None
    requires_javascript: bool = False
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


# Government APIs
CAMARA_ENDPOINTS = EndpointConfig(
    base_url="https://dadosabertos.camara.leg.br/api/v2",
    search_path="/proposicoes",
    details_path="/proposicoes/{id}",
    health_path="/referencias/proposicoes/codTipoTramitacao",
    params_mapping={
        "keywords": "keywords",
        "siglaTipo": "type",
        "ano": "year",
        "dataInicio": "start_date",
        "dataFim": "end_date",
        "pagina": "page",
        "itens": "items_per_page"
    }
)

SENADO_ENDPOINTS = EndpointConfig(
    base_url="https://www25.senado.leg.br/web/senadores/em-exercicio",
    search_path="/-/e/por-nome",
    details_path="/materia/{id}",
    health_path="/-/e/por-nome"
)

# Regulatory Agencies Configurations
REGULATORY_SCRAPERS = {
    "ANEEL": ScraperConfig(
        search_url="https://www.gov.br/aneel/pt-br/assuntos/consultas-publicas",
        selectors={
            "results_container": ".search-results, .consultas-list",
            "result_item": ".resultado-item, .consulta-item",
            "title": "h3, .titulo-consulta",
            "link": "a[href]",
            "date": ".data-publicacao, .date",
            "summary": ".resumo, .descricao",
            "document_number": ".numero-resolucao"
        },
        pagination_selector=".pagination a.next"
    ),
    
    "ANATEL": ScraperConfig(
        search_url="https://www.gov.br/anatel/pt-br/assuntos/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": ".tileHeadline",
            "link": ".tileHeadline a",
            "date": ".documentByLine",
            "summary": ".description"
        }
    ),
    
    "ANVISA": ScraperConfig(
        search_url="https://www.gov.br/anvisa/pt-br/assuntos/regulamentacao/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": ".tileHeadline",
            "link": ".tileHeadline a",
            "date": ".documentByLine",
            "summary": ".description"
        },
        requires_javascript=True
    ),
    
    "ANS": ScraperConfig(
        search_url="https://www.gov.br/ans/pt-br/assuntos/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": "article.tileItem",
            "title": "h2.tileHeadline",
            "link": "h2.tileHeadline a",
            "date": ".documentByLine .value",
            "summary": ".tileBody span.description"
        }
    ),
    
    "ANA": ScraperConfig(
        search_url="https://www.gov.br/ana/pt-br/acesso-a-informacao/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": ".tileHeadline a",
            "link": ".tileHeadline a",
            "date": ".documentByLine",
            "summary": ".description"
        }
    ),
    
    "ANCINE": ScraperConfig(
        search_url="https://www.gov.br/ancine/pt-br/acesso-a-informacao/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": ".tileHeadline",
            "link": ".tileHeadline a",
            "date": ".documentByLine",
            "summary": ".description"
        }
    ),
    
    "ANTT": ScraperConfig(
        search_url="https://www.gov.br/antt/pt-br/acesso-a-informacao/participacao-social/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": "article",
            "title": "h2 a",
            "link": "h2 a",
            "date": ".documentByLine",
            "summary": ".description"
        }
    ),
    
    "ANTAQ": ScraperConfig(
        search_url="https://www.gov.br/antaq/pt-br/acesso-a-informacao/consultas-e-audiencias-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": ".tileHeadline",
            "link": ".tileHeadline a", 
            "date": ".documentByLine",
            "summary": ".description"
        }
    ),
    
    "ANAC": ScraperConfig(
        search_url="https://www.anac.gov.br/participacao-social/consultas-publicas",
        selectors={
            "results_container": ".view-content",
            "result_item": ".views-row",
            "title": ".field-content a",
            "link": ".field-content a",
            "date": ".date-display-single",
            "summary": ".field-type-text-with-summary"
        }
    ),
    
    "ANP": ScraperConfig(
        search_url="https://www.gov.br/anp/pt-br/acesso-a-informacao/consultas-e-audiencias-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": ".tileHeadline",
            "link": ".tileHeadline a",
            "date": ".documentByLine",
            "summary": ".description"
        }
    ),
    
    "ANM": ScraperConfig(
        search_url="https://www.gov.br/anm/pt-br/acesso-a-informacao/consultas-publicas",
        selectors={
            "results_container": "#content-core", 
            "result_item": ".tileItem",
            "title": ".tileHeadline",
            "link": ".tileHeadline a",
            "date": ".documentByLine",
            "summary": ".description"
        }
    )
}

# Search patterns for document type extraction
DOCUMENT_TYPE_PATTERNS = {
    "resolucao": [
        r"resolu[çc][ãa]o\s*n[º°]?\s*(\d+)",
        r"resolu[çc][ãa]o\s*(\d+)",
        r"RES\s*n[º°]?\s*(\d+)"
    ],
    "portaria": [
        r"portaria\s*n[º°]?\s*(\d+)",
        r"portaria\s*(\d+)",
        r"PORT\s*n[º°]?\s*(\d+)"
    ],
    "instrucao_normativa": [
        r"instru[çc][ãa]o\s*normativa\s*n[º°]?\s*(\d+)",
        r"IN\s*n[º°]?\s*(\d+)",
        r"instru[çc][ãa]o\s*(\d+)"
    ],
    "circular": [
        r"circular\s*n[º°]?\s*(\d+)",
        r"CIRC\s*n[º°]?\s*(\d+)"
    ],
    "deliberacao": [
        r"delibera[çc][ãa]o\s*n[º°]?\s*(\d+)",
        r"DELIB\s*n[º°]?\s*(\d+)"
    ],
    "ato": [
        r"ato\s*n[º°]?\s*(\d+)",
        r"ato\s*regulat[óo]rio\s*n[º°]?\s*(\d+)"
    ],
    "consulta_publica": [
        r"consulta\s*p[úu]blica\s*n[º°]?\s*(\d+)",
        r"CP\s*n[º°]?\s*(\d+)"
    ],
    "audiencia_publica": [
        r"audi[êe]ncia\s*p[úu]blica\s*n[º°]?\s*(\d+)",
        r"AP\s*n[º°]?\s*(\d+)"
    ]
}

# Date extraction patterns
DATE_PATTERNS = [
    r"(\d{1,2})[/-](\d{1,2})[/-](\d{4})",  # DD/MM/YYYY or DD-MM-YYYY
    r"(\d{1,2})\s*de\s*(\w+)\s*de\s*(\d{4})",  # DD de mês de YYYY
    r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})",  # YYYY-MM-DD
]

# Month names mapping
MONTH_NAMES = {
    "janeiro": 1, "jan": 1,
    "fevereiro": 2, "fev": 2,
    "março": 3, "mar": 3,
    "abril": 4, "abr": 4,
    "maio": 5, "mai": 5,
    "junho": 6, "jun": 6,
    "julho": 7, "jul": 7,
    "agosto": 8, "ago": 8,
    "setembro": 9, "set": 9,
    "outubro": 10, "out": 10,
    "novembro": 11, "nov": 11,
    "dezembro": 12, "dez": 12
}