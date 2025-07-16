"""
Sistema LexML Refinado v2.0
Módulo integrado para análise legislativa com classificação hierárquica

Componentes:
- RefinedDocumentClassifier: Classificação hierárquica em 3 níveis
- IntegratedParsingSystem: Parsing especializado por tipo de documento
- ThematicEnrichmentSystem: Enriquecimento temático avançado
- ParsingQualityController: Controle de qualidade automatizado
- EnhancedLexMLStrategy: Estratégia principal integrada

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

from .classification_system import RefinedDocumentClassifier
from .parsing_prompts import IntegratedParsingSystem
from .thematic_enrichment import ThematicEnrichmentSystem
from .quality_controller import ParsingQualityController
from .enhanced_strategy import EnhancedLexMLStrategy

__version__ = "2.0"
__author__ = "Manus AI"
__email__ = "dev@mackintegridade.com"

__all__ = [
    'RefinedDocumentClassifier',
    'IntegratedParsingSystem', 
    'ThematicEnrichmentSystem',
    'ParsingQualityController',
    'EnhancedLexMLStrategy'
]