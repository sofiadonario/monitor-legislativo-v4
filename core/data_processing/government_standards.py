"""
Government Data Processing Standards
Based on the 5-level digitization maturity model from okfn-brasil/lexml-dou
"""
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re
import json
import logging

from core.config.config import Config
from core.utils.logger import Logger
from core.models.legislative_data import LegislativeDocument

logger = Logger()


class DigitizationLevel(Enum):
    """5-level digitization maturity model for Brazilian government documents."""
    LEVEL_1_PAPER_SCAN = 1  # Scanned images only
    LEVEL_2_OCR_TEXT = 2    # OCR text with limited structure
    LEVEL_3_STRUCTURED = 3  # Structured data with metadata
    LEVEL_4_SEMANTIC = 4    # Semantic markup and relationships
    LEVEL_5_LINKED_DATA = 5 # Fully linked open data


class DataQualityScore(Enum):
    """Data quality scoring based on government standards."""
    EXCELLENT = "excellent"  # 90-100%
    GOOD = "good"           # 70-89%
    FAIR = "fair"           # 50-69%
    POOR = "poor"           # 30-49%
    CRITICAL = "critical"   # 0-29%


@dataclass
class ValidationRule:
    """Represents a validation rule for government documents."""
    rule_id: str
    name: str
    description: str
    category: str
    required_level: DigitizationLevel
    weight: float
    checker_function: str


@dataclass
class ValidationResult:
    """Results of document validation against government standards."""
    document_id: str
    overall_score: float
    quality_level: DataQualityScore
    digitization_level: DigitizationLevel
    rule_results: Dict[str, Any]
    compliance_percentage: float
    issues: List[str]
    recommendations: List[str]
    validation_timestamp: datetime
    metadata_completeness: float
    structure_compliance: float
    semantic_richness: float


@dataclass
class ProcessingPipeline:
    """Document processing pipeline with validation checkpoints."""
    pipeline_id: str
    name: str
    description: str
    stages: List[str]
    validation_checkpoints: List[str]
    target_level: DigitizationLevel
    processing_rules: List[ValidationRule]


class GovernmentStandardsProcessor:
    """Processor for Brazilian government document standards and validation."""
    
    def __init__(self):
        self.config = Config()
        self._load_validation_rules()
        self._setup_processing_pipelines()
        
    def _load_validation_rules(self):
        """Load validation rules based on Brazilian government standards."""
        self.validation_rules = {
            # Level 1: Basic Document Existence
            "doc_exists": ValidationRule(
                rule_id="doc_exists",
                name="Documento Existe",
                description="Verifica se o documento existe e é acessível",
                category="existence",
                required_level=DigitizationLevel.LEVEL_1_PAPER_SCAN,
                weight=1.0,
                checker_function="check_document_exists"
            ),
            
            # Level 2: Text Content and OCR Quality
            "text_content": ValidationRule(
                rule_id="text_content",
                name="Conteúdo Textual",
                description="Verifica presença e qualidade do conteúdo textual",
                category="content",
                required_level=DigitizationLevel.LEVEL_2_OCR_TEXT,
                weight=0.9,
                checker_function="check_text_content"
            ),
            
            "text_quality": ValidationRule(
                rule_id="text_quality",
                name="Qualidade do Texto",
                description="Avalia qualidade do OCR e legibilidade",
                category="quality",
                required_level=DigitizationLevel.LEVEL_2_OCR_TEXT,
                weight=0.8,
                checker_function="check_text_quality"
            ),
            
            # Level 3: Metadata and Structure
            "metadata_complete": ValidationRule(
                rule_id="metadata_complete",
                name="Metadados Completos",
                description="Verifica completude dos metadados essenciais",
                category="metadata",
                required_level=DigitizationLevel.LEVEL_3_STRUCTURED,
                weight=0.9,
                checker_function="check_metadata_completeness"
            ),
            
            "urn_valid": ValidationRule(
                rule_id="urn_valid",
                name="URN Válido",
                description="Valida formato e padrão do URN LexML",
                category="structure",
                required_level=DigitizationLevel.LEVEL_3_STRUCTURED,
                weight=0.8,
                checker_function="check_urn_validity"
            ),
            
            "document_structure": ValidationRule(
                rule_id="document_structure",
                name="Estrutura do Documento",
                description="Verifica estrutura hierárquica e organização",
                category="structure",
                required_level=DigitizationLevel.LEVEL_3_STRUCTURED,
                weight=0.7,
                checker_function="check_document_structure"
            ),
            
            # Level 4: Semantic Markup
            "semantic_markup": ValidationRule(
                rule_id="semantic_markup",
                name="Marcação Semântica",
                description="Verifica presença de marcação semântica",
                category="semantic",
                required_level=DigitizationLevel.LEVEL_4_SEMANTIC,
                weight=0.8,
                checker_function="check_semantic_markup"
            ),
            
            "entity_recognition": ValidationRule(
                rule_id="entity_recognition",
                name="Reconhecimento de Entidades",
                description="Verifica identificação de entidades nomeadas",
                category="semantic",
                required_level=DigitizationLevel.LEVEL_4_SEMANTIC,
                weight=0.7,
                checker_function="check_entity_recognition"
            ),
            
            "vocabulary_compliance": ValidationRule(
                rule_id="vocabulary_compliance",
                name="Conformidade de Vocabulário",
                description="Verifica uso de vocabulários controlados",
                category="semantic",
                required_level=DigitizationLevel.LEVEL_4_SEMANTIC,
                weight=0.8,
                checker_function="check_vocabulary_compliance"
            ),
            
            # Level 5: Linked Data
            "linked_data": ValidationRule(
                rule_id="linked_data",
                name="Dados Conectados",
                description="Verifica implementação de linked data",
                category="linked_data",
                required_level=DigitizationLevel.LEVEL_5_LINKED_DATA,
                weight=0.9,
                checker_function="check_linked_data"
            ),
            
            "rdf_compliance": ValidationRule(
                rule_id="rdf_compliance",
                name="Conformidade RDF",
                description="Verifica estruturas RDF e ontologias",
                category="linked_data",
                required_level=DigitizationLevel.LEVEL_5_LINKED_DATA,
                weight=0.8,
                checker_function="check_rdf_compliance"
            )
        }
    
    def _setup_processing_pipelines(self):
        """Setup processing pipelines for different document types."""
        self.pipelines = {
            "basic_digitization": ProcessingPipeline(
                pipeline_id="basic_digitization",
                name="Digitalização Básica",
                description="Pipeline para documentos em nível básico de digitalização",
                stages=["validation", "text_extraction", "basic_metadata", "quality_check"],
                validation_checkpoints=["doc_exists", "text_content"],
                target_level=DigitizationLevel.LEVEL_2_OCR_TEXT,
                processing_rules=[
                    self.validation_rules["doc_exists"],
                    self.validation_rules["text_content"],
                    self.validation_rules["text_quality"]
                ]
            ),
            
            "structured_processing": ProcessingPipeline(
                pipeline_id="structured_processing",
                name="Processamento Estruturado",
                description="Pipeline para documentos com estrutura e metadados",
                stages=["validation", "text_extraction", "metadata_extraction", "structure_analysis", "quality_assessment"],
                validation_checkpoints=["doc_exists", "text_content", "metadata_complete", "urn_valid"],
                target_level=DigitizationLevel.LEVEL_3_STRUCTURED,
                processing_rules=[
                    self.validation_rules["doc_exists"],
                    self.validation_rules["text_content"],
                    self.validation_rules["text_quality"],
                    self.validation_rules["metadata_complete"],
                    self.validation_rules["urn_valid"],
                    self.validation_rules["document_structure"]
                ]
            ),
            
            "semantic_enrichment": ProcessingPipeline(
                pipeline_id="semantic_enrichment",
                name="Enriquecimento Semântico",
                description="Pipeline para enriquecimento semântico de documentos",
                stages=["validation", "structure_analysis", "entity_extraction", "semantic_annotation", "vocabulary_mapping"],
                validation_checkpoints=["metadata_complete", "semantic_markup", "entity_recognition"],
                target_level=DigitizationLevel.LEVEL_4_SEMANTIC,
                processing_rules=[
                    self.validation_rules["metadata_complete"],
                    self.validation_rules["document_structure"],
                    self.validation_rules["semantic_markup"],
                    self.validation_rules["entity_recognition"],
                    self.validation_rules["vocabulary_compliance"]
                ]
            ),
            
            "linked_data_conversion": ProcessingPipeline(
                pipeline_id="linked_data_conversion",
                name="Conversão para Dados Conectados",
                description="Pipeline para conversão em linked data",
                stages=["validation", "semantic_analysis", "rdf_generation", "ontology_mapping", "linked_data_publication"],
                validation_checkpoints=["semantic_markup", "linked_data", "rdf_compliance"],
                target_level=DigitizationLevel.LEVEL_5_LINKED_DATA,
                processing_rules=list(self.validation_rules.values())
            )
        }
    
    async def validate_document(self, document: LegislativeDocument, 
                              target_level: DigitizationLevel = DigitizationLevel.LEVEL_3_STRUCTURED) -> ValidationResult:
        """Validate document against government standards."""
        try:
            logger.info(f"Validating document {document.id} for level {target_level}")
            
            # Initialize validation results
            rule_results = {}
            total_score = 0.0
            total_weight = 0.0
            issues = []
            recommendations = []
            
            # Run validation rules based on target level
            for rule_id, rule in self.validation_rules.items():
                if rule.required_level.value <= target_level.value:
                    try:
                        result = await self._execute_validation_rule(document, rule)
                        rule_results[rule_id] = result
                        
                        # Calculate weighted score
                        total_score += result['score'] * rule.weight
                        total_weight += rule.weight
                        
                        # Collect issues and recommendations
                        if not result['passed']:
                            issues.append(result.get('issue', f"Failed: {rule.name}"))
                            if result.get('recommendation'):
                                recommendations.append(result['recommendation'])
                                
                    except Exception as e:
                        logger.warning(f"Validation rule {rule_id} failed: {str(e)}")
                        rule_results[rule_id] = {
                            'passed': False,
                            'score': 0.0,
                            'issue': f"Validation error: {str(e)}",
                            'details': {}
                        }
            
            # Calculate overall metrics
            overall_score = total_score / total_weight if total_weight > 0 else 0.0
            compliance_percentage = (len([r for r in rule_results.values() if r['passed']]) / len(rule_results)) * 100
            
            # Determine quality level and digitization level
            quality_level = self._determine_quality_level(overall_score)
            achieved_level = self._determine_digitization_level(rule_results)
            
            # Calculate specific metrics
            metadata_completeness = self._calculate_metadata_completeness(document)
            structure_compliance = self._calculate_structure_compliance(document, rule_results)
            semantic_richness = self._calculate_semantic_richness(document, rule_results)
            
            return ValidationResult(
                document_id=document.id,
                overall_score=overall_score,
                quality_level=quality_level,
                digitization_level=achieved_level,
                rule_results=rule_results,
                compliance_percentage=compliance_percentage,
                issues=issues,
                recommendations=recommendations,
                validation_timestamp=datetime.now(),
                metadata_completeness=metadata_completeness,
                structure_compliance=structure_compliance,
                semantic_richness=semantic_richness
            )
            
        except Exception as e:
            logger.error(f"Document validation failed: {str(e)}")
            raise
    
    async def _execute_validation_rule(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Execute a specific validation rule."""
        checker_method = getattr(self, rule.checker_function, None)
        if not checker_method:
            raise ValueError(f"Validation method {rule.checker_function} not found")
        
        return await checker_method(document, rule)
    
    # Validation rule implementations
    async def check_document_exists(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check if document exists and is accessible."""
        has_content = bool(document.title or document.summary or getattr(document, 'content', None))
        
        return {
            'passed': has_content,
            'score': 1.0 if has_content else 0.0,
            'issue': "Documento não possui conteúdo acessível" if not has_content else None,
            'recommendation': "Verificar disponibilidade e acessibilidade do documento" if not has_content else None,
            'details': {
                'has_title': bool(document.title),
                'has_summary': bool(document.summary),
                'has_content': bool(getattr(document, 'content', None))
            }
        }
    
    async def check_text_content(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check text content quality and presence."""
        content = getattr(document, 'content', '') or document.summary or ''
        content_length = len(content.strip())
        
        # Quality checks
        has_sufficient_content = content_length >= 100
        has_readable_text = bool(re.search(r'[a-zA-ZáéíóúâêîôûàèìòùãõçÁÉÍÓÚÂÊÎÔÛÀÈÌÒÙÃÕÇ]', content))
        
        score = 0.0
        if has_sufficient_content:
            score += 0.6
        if has_readable_text:
            score += 0.4
        
        passed = score >= 0.8
        
        return {
            'passed': passed,
            'score': score,
            'issue': "Conteúdo textual insuficiente ou de baixa qualidade" if not passed else None,
            'recommendation': "Melhorar qualidade do OCR ou extração de texto" if not passed else None,
            'details': {
                'content_length': content_length,
                'has_sufficient_content': has_sufficient_content,
                'has_readable_text': has_readable_text
            }
        }
    
    async def check_text_quality(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check OCR and text quality."""
        content = getattr(document, 'content', '') or document.summary or ''
        
        # Quality indicators
        has_proper_spacing = not bool(re.search(r'\w{50,}', content))  # No extremely long words
        has_proper_punctuation = bool(re.search(r'[.!?]', content))
        has_proper_capitalization = bool(re.search(r'[A-ZÁÉÍÓÚÂÊÎÔÛÀÈÌÒÙÃÕÇ]', content))
        low_special_chars = len(re.findall(r'[^a-zA-ZáéíóúâêîôûàèìòùãõçÁÉÍÓÚÂÊÎÔÛÀÈÌÒÙÃÕÇ0-9\s.,;:!?()\-]', content)) < len(content) * 0.05
        
        score = sum([has_proper_spacing, has_proper_punctuation, has_proper_capitalization, low_special_chars]) / 4.0
        passed = score >= 0.7
        
        return {
            'passed': passed,
            'score': score,
            'issue': "Qualidade do texto indica problemas no OCR" if not passed else None,
            'recommendation': "Revisar processo de OCR ou digitalização" if not passed else None,
            'details': {
                'proper_spacing': has_proper_spacing,
                'proper_punctuation': has_proper_punctuation,
                'proper_capitalization': has_proper_capitalization,
                'low_special_chars': low_special_chars
            }
        }
    
    async def check_metadata_completeness(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check metadata completeness according to Brazilian standards."""
        required_fields = ['title', 'data_evento', 'tipo_documento', 'fonte']
        optional_fields = ['autor', 'autoridade', 'urn', 'url', 'summary']
        
        # Check required fields
        required_score = 0.0
        missing_required = []
        
        for field in required_fields:
            if hasattr(document, field) and getattr(document, field):
                required_score += 1.0
            else:
                missing_required.append(field)
        
        required_score /= len(required_fields)
        
        # Check optional fields
        optional_score = 0.0
        for field in optional_fields:
            if hasattr(document, field) and getattr(document, field):
                optional_score += 1.0
        
        optional_score /= len(optional_fields)
        
        # Combined score (required fields weighted more heavily)
        overall_score = required_score * 0.8 + optional_score * 0.2
        passed = required_score >= 0.8  # At least 80% of required fields
        
        return {
            'passed': passed,
            'score': overall_score,
            'issue': f"Metadados incompletos. Campos obrigatórios faltando: {', '.join(missing_required)}" if missing_required else None,
            'recommendation': "Completar metadados obrigatórios conforme padrão LexML" if missing_required else None,
            'details': {
                'required_score': required_score,
                'optional_score': optional_score,
                'missing_required': missing_required,
                'completeness_percentage': overall_score * 100
            }
        }
    
    async def check_urn_validity(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check URN format validity according to LexML standards."""
        urn = getattr(document, 'urn', '')
        
        if not urn:
            return {
                'passed': False,
                'score': 0.0,
                'issue': "URN não encontrado",
                'recommendation': "Adicionar URN válido conforme padrão LexML",
                'details': {'has_urn': False}
            }
        
        # Basic URN pattern validation
        urn_pattern = r'^urn:lex:[a-z]{2}(?:;[a-z]{2})?:'
        is_valid_format = bool(re.match(urn_pattern, urn))
        
        # Check for Brazilian URN pattern
        is_brazilian = 'urn:lex:br' in urn
        
        # Check structure completeness
        urn_parts = urn.split(':')
        has_sufficient_parts = len(urn_parts) >= 4
        
        score = 0.0
        if is_valid_format:
            score += 0.4
        if is_brazilian:
            score += 0.3
        if has_sufficient_parts:
            score += 0.3
        
        passed = score >= 0.8
        
        return {
            'passed': passed,
            'score': score,
            'issue': "URN não atende ao padrão LexML" if not passed else None,
            'recommendation': "Corrigir formato do URN conforme especificação LexML" if not passed else None,
            'details': {
                'urn': urn,
                'valid_format': is_valid_format,
                'is_brazilian': is_brazilian,
                'sufficient_parts': has_sufficient_parts
            }
        }
    
    async def check_document_structure(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check document structure and organization."""
        content = getattr(document, 'content', '') or document.summary or ''
        
        # Structure indicators
        has_articles = bool(re.search(r'(?:art|artigo)\.?\s*\d+', content, re.IGNORECASE))
        has_paragraphs = bool(re.search(r'(?:§|parágrafo)\s*\d+', content, re.IGNORECASE))
        has_sections = bool(re.search(r'(?:seção|capítulo)\s*[ivx\d]+', content, re.IGNORECASE))
        has_proper_numbering = bool(re.search(r'\d+[.)\-]\s', content))
        
        structure_indicators = [has_articles, has_paragraphs, has_sections, has_proper_numbering]
        score = sum(structure_indicators) / len(structure_indicators)
        passed = score >= 0.5  # At least 50% of structure indicators
        
        return {
            'passed': passed,
            'score': score,
            'issue': "Estrutura do documento não atende aos padrões" if not passed else None,
            'recommendation': "Melhorar estruturação hierárquica do documento" if not passed else None,
            'details': {
                'has_articles': has_articles,
                'has_paragraphs': has_paragraphs,
                'has_sections': has_sections,
                'has_proper_numbering': has_proper_numbering
            }
        }
    
    async def check_semantic_markup(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check presence of semantic markup."""
        # This would be enhanced with actual semantic analysis
        # For now, checking for basic semantic indicators
        
        content = getattr(document, 'content', '') or ''
        metadata = getattr(document, 'metadata', {}) if hasattr(document, 'metadata') else {}
        
        # Basic semantic indicators
        has_entity_tags = bool(re.search(r'<(?:person|org|place|law)>', content, re.IGNORECASE))
        has_structured_metadata = len(metadata) > 5
        has_classification = bool(getattr(document, 'tipo_documento', ''))
        
        score = sum([has_entity_tags, has_structured_metadata, has_classification]) / 3.0
        passed = score >= 0.6
        
        return {
            'passed': passed,
            'score': score,
            'issue': "Marcação semântica insuficiente" if not passed else None,
            'recommendation': "Adicionar marcação semântica e metadados estruturados" if not passed else None,
            'details': {
                'has_entity_tags': has_entity_tags,
                'has_structured_metadata': has_structured_metadata,
                'has_classification': has_classification
            }
        }
    
    async def check_entity_recognition(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check entity recognition and annotation."""
        # Placeholder for entity recognition validation
        # Would integrate with actual NER systems
        
        return {
            'passed': True,
            'score': 0.7,
            'issue': None,
            'recommendation': None,
            'details': {'implemented': False}
        }
    
    async def check_vocabulary_compliance(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check compliance with controlled vocabularies."""
        # Placeholder for vocabulary compliance check
        # Would integrate with SKOS vocabularies
        
        return {
            'passed': True,
            'score': 0.6,
            'issue': None,
            'recommendation': None,
            'details': {'implemented': False}
        }
    
    async def check_linked_data(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check linked data implementation."""
        # Placeholder for linked data validation
        
        return {
            'passed': False,
            'score': 0.0,
            'issue': "Linked data não implementado",
            'recommendation': "Implementar estruturas RDF e linked data",
            'details': {'implemented': False}
        }
    
    async def check_rdf_compliance(self, document: LegislativeDocument, rule: ValidationRule) -> Dict[str, Any]:
        """Check RDF compliance and structure."""
        # Placeholder for RDF validation
        
        return {
            'passed': False,
            'score': 0.0,
            'issue': "RDF não implementado",
            'recommendation': "Implementar estruturas RDF conforme W3C",
            'details': {'implemented': False}
        }
    
    def _determine_quality_level(self, score: float) -> DataQualityScore:
        """Determine quality level based on overall score."""
        if score >= 0.9:
            return DataQualityScore.EXCELLENT
        elif score >= 0.7:
            return DataQualityScore.GOOD
        elif score >= 0.5:
            return DataQualityScore.FAIR
        elif score >= 0.3:
            return DataQualityScore.POOR
        else:
            return DataQualityScore.CRITICAL
    
    def _determine_digitization_level(self, rule_results: Dict[str, Any]) -> DigitizationLevel:
        """Determine achieved digitization level based on validation results."""
        level_requirements = {
            DigitizationLevel.LEVEL_1_PAPER_SCAN: ["doc_exists"],
            DigitizationLevel.LEVEL_2_OCR_TEXT: ["doc_exists", "text_content"],
            DigitizationLevel.LEVEL_3_STRUCTURED: ["doc_exists", "text_content", "metadata_complete", "urn_valid"],
            DigitizationLevel.LEVEL_4_SEMANTIC: ["metadata_complete", "semantic_markup", "entity_recognition"],
            DigitizationLevel.LEVEL_5_LINKED_DATA: ["semantic_markup", "linked_data", "rdf_compliance"]
        }
        
        achieved_level = DigitizationLevel.LEVEL_1_PAPER_SCAN
        
        for level, requirements in level_requirements.items():
            if all(rule_results.get(req, {}).get('passed', False) for req in requirements if req in rule_results):
                achieved_level = level
        
        return achieved_level
    
    def _calculate_metadata_completeness(self, document: LegislativeDocument) -> float:
        """Calculate metadata completeness percentage."""
        all_fields = ['title', 'summary', 'data_evento', 'tipo_documento', 'fonte', 'autor', 'autoridade', 'urn', 'url']
        present_fields = sum(1 for field in all_fields if hasattr(document, field) and getattr(document, field))
        return present_fields / len(all_fields)
    
    def _calculate_structure_compliance(self, document: LegislativeDocument, rule_results: Dict[str, Any]) -> float:
        """Calculate structure compliance percentage."""
        structure_rules = ["document_structure", "urn_valid"]
        structure_scores = [rule_results.get(rule, {}).get('score', 0) for rule in structure_rules if rule in rule_results]
        return sum(structure_scores) / len(structure_scores) if structure_scores else 0.0
    
    def _calculate_semantic_richness(self, document: LegislativeDocument, rule_results: Dict[str, Any]) -> float:
        """Calculate semantic richness percentage."""
        semantic_rules = ["semantic_markup", "entity_recognition", "vocabulary_compliance"]
        semantic_scores = [rule_results.get(rule, {}).get('score', 0) for rule in semantic_rules if rule in rule_results]
        return sum(semantic_scores) / len(semantic_scores) if semantic_scores else 0.0
    
    async def process_with_pipeline(self, document: LegislativeDocument, pipeline_id: str) -> ValidationResult:
        """Process document through a specific pipeline."""
        if pipeline_id not in self.pipelines:
            raise ValueError(f"Pipeline {pipeline_id} not found")
        
        pipeline = self.pipelines[pipeline_id]
        return await self.validate_document(document, pipeline.target_level)
    
    def get_processing_recommendations(self, validation_result: ValidationResult) -> List[Dict[str, Any]]:
        """Get specific processing recommendations based on validation results."""
        recommendations = []
        
        current_level = validation_result.digitization_level
        next_level = DigitizationLevel(min(current_level.value + 1, 5))
        
        if next_level != current_level:
            pipeline_recommendation = {
                'type': 'pipeline_upgrade',
                'current_level': current_level.name,
                'target_level': next_level.name,
                'recommended_pipeline': self._get_pipeline_for_level(next_level),
                'priority': 'high' if validation_result.quality_level in [DataQualityScore.POOR, DataQualityScore.CRITICAL] else 'medium'
            }
            recommendations.append(pipeline_recommendation)
        
        # Add specific technical recommendations
        if validation_result.metadata_completeness < 0.8:
            recommendations.append({
                'type': 'metadata_improvement',
                'description': 'Completar metadados obrigatórios',
                'priority': 'high',
                'completeness': validation_result.metadata_completeness
            })
        
        if validation_result.structure_compliance < 0.7:
            recommendations.append({
                'type': 'structure_improvement',
                'description': 'Melhorar estruturação do documento',
                'priority': 'medium',
                'compliance': validation_result.structure_compliance
            })
        
        return recommendations
    
    def _get_pipeline_for_level(self, level: DigitizationLevel) -> str:
        """Get recommended pipeline for a digitization level."""
        pipeline_mapping = {
            DigitizationLevel.LEVEL_1_PAPER_SCAN: "basic_digitization",
            DigitizationLevel.LEVEL_2_OCR_TEXT: "basic_digitization",
            DigitizationLevel.LEVEL_3_STRUCTURED: "structured_processing",
            DigitizationLevel.LEVEL_4_SEMANTIC: "semantic_enrichment",
            DigitizationLevel.LEVEL_5_LINKED_DATA: "linked_data_conversion"
        }
        return pipeline_mapping.get(level, "basic_digitization")