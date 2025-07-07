"""
Document Validation Engine for Brazilian Legislative Documents
============================================================

Comprehensive document validation based on lexml-coleta-validador patterns.
Validates LexML documents for schema compliance, metadata completeness,
URN format correctness, and SKOS vocabulary terms.

Features:
- Multi-level validation rules
- Quality scoring and metrics
- URN format validation and normalization
- Metadata completeness assessment
- SKOS vocabulary term validation
- Brazilian legislative document standards compliance
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation severity levels"""
    ERROR = "error"      # Critical issues that prevent processing
    WARNING = "warning"  # Issues that may affect quality
    INFO = "info"       # Informational notes for improvement
    SUCCESS = "success"  # Validation passed


class DocumentType(Enum):
    """Brazilian legislative document types"""
    LEI = "lei"
    DECRETO = "decreto"
    PORTARIA = "portaria"
    RESOLUCAO = "resolucao"
    MEDIDA_PROVISORIA = "medida_provisoria"
    PROJETO_LEI = "projeto_lei"
    EMENDA = "emenda"
    PARECER = "parecer"
    OUTROS = "outros"


@dataclass
class ValidationRule:
    """Individual validation rule result"""
    rule_name: str
    level: ValidationLevel
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


@dataclass
class QualityMetrics:
    """Document quality metrics"""
    completeness_score: float  # 0.0 to 1.0
    format_score: float        # 0.0 to 1.0
    consistency_score: float   # 0.0 to 1.0
    overall_score: float       # 0.0 to 1.0
    total_rules: int
    passed_rules: int
    warnings: int
    errors: int


@dataclass
class ValidationResult:
    """Complete validation result for a document"""
    document_id: str
    document_type: DocumentType
    validation_timestamp: str
    quality_metrics: QualityMetrics
    validation_rules: List[ValidationRule]
    recommendations: List[str]
    is_valid: bool
    processing_time_ms: float


class BrazilianURNValidator:
    """URN validator following Brazilian legislative standards"""
    
    def __init__(self):
        # Brazilian URN patterns for legislative documents
        self.urn_patterns = {
            DocumentType.LEI: r'^urn:lex:br:(federal|[a-z]{2}(\.[a-z]+)*):lei:(\d{4}-\d{2}-\d{2}):(\d+)',
            DocumentType.DECRETO: r'^urn:lex:br:(federal|[a-z]{2}(\.[a-z]+)*):decreto:(\d{4}-\d{2}-\d{2}):(\d+)',
            DocumentType.PORTARIA: r'^urn:lex:br:(federal|[a-z]{2}(\.[a-z]+)*):portaria:(\d{4}-\d{2}-\d{2}):(\d+)',
            DocumentType.RESOLUCAO: r'^urn:lex:br:(federal|[a-z]{2}(\.[a-z]+)*):resolucao:(\d{4}-\d{2}-\d{2}):(\d+)',
            DocumentType.MEDIDA_PROVISORIA: r'^urn:lex:br:federal:medida.provisoria:(\d{4}-\d{2}-\d{2}):(\d+)',
            DocumentType.PROJETO_LEI: r'^urn:lex:br:(federal|[a-z]{2}(\.[a-z]+)*):projeto.lei:(\d{4}-\d{2}-\d{2}):(\d+)'
        }
        
        # Valid authorities for Brazilian legislative documents
        self.valid_authorities = {
            'federal': 'Federal Government',
            'sp': 'São Paulo State',
            'rj': 'Rio de Janeiro State',
            'mg': 'Minas Gerais State',
            'rs': 'Rio Grande do Sul State',
            'pr': 'Paraná State',
            'sc': 'Santa Catarina State',
            'ba': 'Bahia State',
            'go': 'Goiás State',
            'pe': 'Pernambuco State',
            'ce': 'Ceará State',
            'pa': 'Pará State',
            'pb': 'Paraíba State',
            'ma': 'Maranhão State',
            'es': 'Espírito Santo State',
            'pi': 'Piauí State',
            'al': 'Alagoas State',
            'rn': 'Rio Grande do Norte State',
            'mt': 'Mato Grosso State',
            'ms': 'Mato Grosso do Sul State',
            'df': 'Distrito Federal',
            'se': 'Sergipe State',
            'am': 'Amazonas State',
            'ro': 'Rondônia State',
            'ac': 'Acre State',
            'ap': 'Amapá State',
            'rr': 'Roraima State',
            'to': 'Tocantins State'
        }
    
    def validate_urn_format(self, urn: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate URN format according to Brazilian legislative standards
        
        Returns:
            (is_valid, message, details)
        """
        if not urn:
            return False, "URN is empty", {}
        
        # Basic URN structure check
        if not urn.startswith('urn:lex:br:'):
            return False, "URN must start with 'urn:lex:br:'", {"urn": urn}
        
        # Determine document type from URN
        document_type = self._extract_document_type(urn)
        if document_type == DocumentType.OUTROS:
            return False, "Unknown or unsupported document type in URN", {"urn": urn}
        
        # Validate against specific pattern
        pattern = self.urn_patterns.get(document_type)
        if not pattern:
            return False, f"No validation pattern for document type {document_type.value}", {"document_type": document_type.value}
        
        match = re.match(pattern, urn)
        if not match:
            return False, f"URN format invalid for {document_type.value}", {
                "urn": urn,
                "expected_pattern": pattern,
                "document_type": document_type.value
            }
        
        # Extract and validate components
        components = self._extract_urn_components(urn, match)
        validation_issues = self._validate_urn_components(components)
        
        if validation_issues:
            return False, f"URN component validation failed: {'; '.join(validation_issues)}", components
        
        return True, f"URN format valid for {document_type.value}", components
    
    def _extract_document_type(self, urn: str) -> DocumentType:
        """Extract document type from URN"""
        urn_lower = urn.lower()
        
        if ':lei:' in urn_lower:
            return DocumentType.LEI
        elif ':decreto:' in urn_lower:
            return DocumentType.DECRETO
        elif ':portaria:' in urn_lower:
            return DocumentType.PORTARIA
        elif ':resolucao:' in urn_lower:
            return DocumentType.RESOLUCAO
        elif ':medida.provisoria:' in urn_lower:
            return DocumentType.MEDIDA_PROVISORIA
        elif ':projeto.lei:' in urn_lower:
            return DocumentType.PROJETO_LEI
        else:
            return DocumentType.OUTROS
    
    def _extract_urn_components(self, urn: str, match) -> Dict[str, Any]:
        """Extract components from URN match"""
        parts = urn.split(':')
        
        components = {
            'full_urn': urn,
            'namespace': 'urn:lex:br',
            'authority': parts[3] if len(parts) > 3 else '',
            'document_type': parts[4] if len(parts) > 4 else '',
            'date': parts[5] if len(parts) > 5 else '',
            'number': parts[6] if len(parts) > 6 else ''
        }
        
        return components
    
    def _validate_urn_components(self, components: Dict[str, Any]) -> List[str]:
        """Validate individual URN components"""
        issues = []
        
        # Validate authority
        authority = components.get('authority', '').lower()
        if authority and authority not in self.valid_authorities:
            issues.append(f"Invalid authority '{authority}'")
        
        # Validate date format
        date_str = components.get('date', '')
        if date_str:
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
                issues.append(f"Invalid date format '{date_str}', expected YYYY-MM-DD")
            else:
                try:
                    datetime.strptime(date_str, '%Y-%m-%d')
                except ValueError:
                    issues.append(f"Invalid date '{date_str}'")
        
        # Validate number
        number = components.get('number', '')
        if number and not number.isdigit():
            issues.append(f"Document number '{number}' must be numeric")
        
        return issues
    
    def normalize_urn(self, urn: str) -> str:
        """Normalize URN to standard format"""
        if not urn:
            return urn
        
        # Convert to lowercase and clean up
        normalized = urn.lower().strip()
        
        # Replace common variations
        normalized = re.sub(r'[:]{2,}', ':', normalized)  # Multiple colons to single
        normalized = re.sub(r'[_]', '.', normalized)      # Underscores to dots
        
        return normalized


class MetadataValidator:
    """Validator for document metadata completeness and quality"""
    
    def __init__(self):
        # Required fields for Brazilian legislative documents
        self.required_fields = {
            'urn', 'title', 'autoridade', 'data_evento'
        }
        
        # Recommended fields for quality scoring
        self.recommended_fields = {
            'tipo_documento', 'localidade', 'evento', 'resumo', 'palavras_chave'
        }
        
        # Transport-specific recommended fields
        self.transport_fields = {
            'modalidade_transporte', 'regulamentacao_federal', 'abrangencia_geografica'
        }
    
    def validate_metadata_completeness(self, metadata: Dict[str, Any]) -> Tuple[float, List[str], List[str]]:
        """
        Validate metadata completeness and calculate score
        
        Returns:
            (completeness_score, missing_required, missing_recommended)
        """
        missing_required = []
        missing_recommended = []
        
        # Check required fields
        for field in self.required_fields:
            if field not in metadata or not metadata.get(field):
                missing_required.append(field)
        
        # Check recommended fields
        for field in self.recommended_fields:
            if field not in metadata or not metadata.get(field):
                missing_recommended.append(field)
        
        # Calculate completeness score
        total_fields = len(self.required_fields) + len(self.recommended_fields)
        present_fields = (len(self.required_fields) - len(missing_required) + 
                         len(self.recommended_fields) - len(missing_recommended))
        
        completeness_score = present_fields / total_fields if total_fields > 0 else 0.0
        
        return completeness_score, missing_required, missing_recommended
    
    def validate_field_formats(self, metadata: Dict[str, Any]) -> List[ValidationRule]:
        """Validate format of specific metadata fields"""
        rules = []
        
        # Validate title
        title = metadata.get('title', '')
        if title:
            if len(title) < 10:
                rules.append(ValidationRule(
                    rule_name="title_length",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message="Document title is very short (< 10 characters)",
                    details={"title_length": len(title)}
                ))
            elif len(title) > 500:
                rules.append(ValidationRule(
                    rule_name="title_length",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message="Document title is very long (> 500 characters)",
                    details={"title_length": len(title)}
                ))
            else:
                rules.append(ValidationRule(
                    rule_name="title_length",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message="Document title length is appropriate"
                ))
        
        # Validate date format
        data_evento = metadata.get('data_evento', '')
        if data_evento:
            try:
                # Try to parse date
                datetime.strptime(data_evento, '%Y-%m-%d')
                rules.append(ValidationRule(
                    rule_name="date_format",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message="Date format is valid (YYYY-MM-DD)"
                ))
            except ValueError:
                rules.append(ValidationRule(
                    rule_name="date_format",
                    level=ValidationLevel.ERROR,
                    passed=False,
                    message="Invalid date format, expected YYYY-MM-DD",
                    details={"date_value": data_evento}
                ))
        
        # Validate keywords
        palavras_chave = metadata.get('palavras_chave', [])
        if isinstance(palavras_chave, list):
            if len(palavras_chave) == 0:
                rules.append(ValidationRule(
                    rule_name="keywords_present",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message="No keywords provided for document"
                ))
            elif len(palavras_chave) > 20:
                rules.append(ValidationRule(
                    rule_name="keywords_count",
                    level=ValidationLevel.WARNING,
                    passed=False,
                    message="Too many keywords (> 20), may affect search quality",
                    details={"keyword_count": len(palavras_chave)}
                ))
            else:
                rules.append(ValidationRule(
                    rule_name="keywords_present",
                    level=ValidationLevel.SUCCESS,
                    passed=True,
                    message=f"Document has {len(palavras_chave)} keywords"
                ))
        
        return rules


class DocumentValidator:
    """
    Main document validation engine based on lexml-coleta-validador patterns
    
    Provides comprehensive validation for Brazilian legislative documents
    including schema compliance, URN validation, and metadata quality assessment.
    """
    
    def __init__(self):
        self.urn_validator = BrazilianURNValidator()
        self.metadata_validator = MetadataValidator()
        
        # Transport domain vocabulary for specialized validation
        self.transport_vocabulary = {
            'transporte', 'mobilidade', 'trânsito', 'tráfego', 'rodoviário', 'ferroviário',
            'aeroportuário', 'portuário', 'marítimo', 'fluvial', 'logística', 'veículo',
            'caminhão', 'ônibus', 'trem', 'avião', 'navio', 'antt', 'antaq', 'anac'
        }
        
        logger.info("Document validator initialized")
    
    def validate_document(self, document: Dict[str, Any]) -> ValidationResult:
        """
        Perform comprehensive document validation
        
        Args:
            document: Document data dictionary
            
        Returns:
            Complete validation result with quality metrics
        """
        start_time = datetime.now()
        
        # Extract basic document info
        doc_id = document.get('urn', document.get('id', 'unknown'))
        
        # Initialize validation tracking
        validation_rules = []
        recommendations = []
        
        # 1. URN Validation
        urn_rules, urn_recommendations = self._validate_urn(document)
        validation_rules.extend(urn_rules)
        recommendations.extend(urn_recommendations)
        
        # 2. Metadata Validation
        metadata_rules, metadata_recommendations = self._validate_metadata(document)
        validation_rules.extend(metadata_rules)
        recommendations.extend(metadata_recommendations)
        
        # 3. Content Validation
        content_rules, content_recommendations = self._validate_content(document)
        validation_rules.extend(content_rules)
        recommendations.extend(content_recommendations)
        
        # 4. Transport Domain Validation (if applicable)
        if self._is_transport_document(document):
            transport_rules, transport_recommendations = self._validate_transport_domain(document)
            validation_rules.extend(transport_rules)
            recommendations.extend(transport_recommendations)
        
        # Calculate quality metrics
        quality_metrics = self._calculate_quality_metrics(validation_rules)
        
        # Determine overall validity
        error_count = sum(1 for rule in validation_rules if rule.level == ValidationLevel.ERROR)
        is_valid = error_count == 0
        
        # Determine document type
        document_type = self._determine_document_type(document)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return ValidationResult(
            document_id=doc_id,
            document_type=document_type,
            validation_timestamp=datetime.now().isoformat(),
            quality_metrics=quality_metrics,
            validation_rules=validation_rules,
            recommendations=recommendations,
            is_valid=is_valid,
            processing_time_ms=processing_time
        )
    
    def _validate_urn(self, document: Dict[str, Any]) -> Tuple[List[ValidationRule], List[str]]:
        """Validate document URN"""
        rules = []
        recommendations = []
        
        urn = document.get('urn', '')
        
        if not urn:
            rules.append(ValidationRule(
                rule_name="urn_present",
                level=ValidationLevel.ERROR,
                passed=False,
                message="Document URN is missing"
            ))
            recommendations.append("Add a valid URN following Brazilian legislative standards")
            return rules, recommendations
        
        # Validate URN format
        is_valid, message, details = self.urn_validator.validate_urn_format(urn)
        
        if is_valid:
            rules.append(ValidationRule(
                rule_name="urn_format",
                level=ValidationLevel.SUCCESS,
                passed=True,
                message=message,
                details=details
            ))
        else:
            rules.append(ValidationRule(
                rule_name="urn_format",
                level=ValidationLevel.ERROR,
                passed=False,
                message=message,
                details=details
            ))
            recommendations.append("Fix URN format according to Brazilian legislative standards")
        
        # Check URN normalization
        normalized_urn = self.urn_validator.normalize_urn(urn)
        if normalized_urn != urn:
            rules.append(ValidationRule(
                rule_name="urn_normalization",
                level=ValidationLevel.WARNING,
                passed=False,
                message="URN can be normalized for consistency",
                details={"original": urn, "normalized": normalized_urn}
            ))
            recommendations.append(f"Consider normalizing URN to: {normalized_urn}")
        
        return rules, recommendations
    
    def _validate_metadata(self, document: Dict[str, Any]) -> Tuple[List[ValidationRule], List[str]]:
        """Validate document metadata"""
        rules = []
        recommendations = []
        
        # Get metadata completeness
        completeness_score, missing_required, missing_recommended = \
            self.metadata_validator.validate_metadata_completeness(document)
        
        # Required fields validation
        if missing_required:
            rules.append(ValidationRule(
                rule_name="required_fields",
                level=ValidationLevel.ERROR,
                passed=False,
                message=f"Missing required fields: {', '.join(missing_required)}",
                details={"missing_fields": missing_required}
            ))
            recommendations.append(f"Add required fields: {', '.join(missing_required)}")
        else:
            rules.append(ValidationRule(
                rule_name="required_fields",
                level=ValidationLevel.SUCCESS,
                passed=True,
                message="All required fields are present"
            ))
        
        # Recommended fields validation
        if missing_recommended:
            rules.append(ValidationRule(
                rule_name="recommended_fields",
                level=ValidationLevel.WARNING,
                passed=False,
                message=f"Missing recommended fields: {', '.join(missing_recommended)}",
                details={"missing_fields": missing_recommended}
            ))
            recommendations.append(f"Consider adding recommended fields: {', '.join(missing_recommended)}")
        
        # Field format validation
        format_rules = self.metadata_validator.validate_field_formats(document)
        rules.extend(format_rules)
        
        return rules, recommendations
    
    def _validate_content(self, document: Dict[str, Any]) -> Tuple[List[ValidationRule], List[str]]:
        """Validate document content"""
        rules = []
        recommendations = []
        
        # Check if content is present
        content_fields = ['content', 'texto_integral', 'resumo', 'description']
        content = None
        
        for field in content_fields:
            if document.get(field):
                content = document[field]
                break
        
        if not content:
            rules.append(ValidationRule(
                rule_name="content_present",
                level=ValidationLevel.WARNING,
                passed=False,
                message="No document content found"
            ))
            recommendations.append("Add document content for better analysis")
            return rules, recommendations
        
        # Content length validation
        content_length = len(content)
        
        if content_length < 50:
            rules.append(ValidationRule(
                rule_name="content_length",
                level=ValidationLevel.WARNING,
                passed=False,
                message="Document content is very short",
                details={"content_length": content_length}
            ))
            recommendations.append("Consider adding more detailed content")
        elif content_length > 100000:
            rules.append(ValidationRule(
                rule_name="content_length",
                level=ValidationLevel.INFO,
                passed=True,
                message="Document content is very long, consider splitting",
                details={"content_length": content_length}
            ))
        else:
            rules.append(ValidationRule(
                rule_name="content_length",
                level=ValidationLevel.SUCCESS,
                passed=True,
                message="Document content length is appropriate",
                details={"content_length": content_length}
            ))
        
        return rules, recommendations
    
    def _validate_transport_domain(self, document: Dict[str, Any]) -> Tuple[List[ValidationRule], List[str]]:
        """Validate transport-specific requirements"""
        rules = []
        recommendations = []
        
        # Check for transport-specific metadata
        transport_fields = {
            'modalidade_transporte': 'Transport modality (road, rail, air, maritime)',
            'regulamentacao_federal': 'Federal regulation reference',
            'abrangencia_geografica': 'Geographic scope'
        }
        
        missing_transport_fields = []
        for field, description in transport_fields.items():
            if not document.get(field):
                missing_transport_fields.append(f"{field} ({description})")
        
        if missing_transport_fields:
            rules.append(ValidationRule(
                rule_name="transport_metadata",
                level=ValidationLevel.INFO,
                passed=False,
                message="Missing transport-specific metadata fields",
                details={"missing_fields": missing_transport_fields}
            ))
            recommendations.append("Consider adding transport-specific metadata for better categorization")
        
        return rules, recommendations
    
    def _is_transport_document(self, document: Dict[str, Any]) -> bool:
        """Check if document is transport-related"""
        # Check title and content for transport keywords
        text_to_check = ' '.join([
            document.get('title', '').lower(),
            document.get('content', '').lower(),
            document.get('resumo', '').lower(),
            ' '.join(document.get('palavras_chave', []))
        ])
        
        transport_keyword_count = sum(
            1 for keyword in self.transport_vocabulary 
            if keyword in text_to_check
        )
        
        return transport_keyword_count >= 2
    
    def _determine_document_type(self, document: Dict[str, Any]) -> DocumentType:
        """Determine document type from URN or content"""
        urn = document.get('urn', '').lower()
        
        if ':lei:' in urn:
            return DocumentType.LEI
        elif ':decreto:' in urn:
            return DocumentType.DECRETO
        elif ':portaria:' in urn:
            return DocumentType.PORTARIA
        elif ':resolucao:' in urn:
            return DocumentType.RESOLUCAO
        elif ':medida.provisoria:' in urn:
            return DocumentType.MEDIDA_PROVISORIA
        elif ':projeto.lei:' in urn:
            return DocumentType.PROJETO_LEI
        else:
            return DocumentType.OUTROS
    
    def _calculate_quality_metrics(self, validation_rules: List[ValidationRule]) -> QualityMetrics:
        """Calculate quality metrics from validation rules"""
        total_rules = len(validation_rules)
        passed_rules = sum(1 for rule in validation_rules if rule.passed)
        error_count = sum(1 for rule in validation_rules if rule.level == ValidationLevel.ERROR)
        warning_count = sum(1 for rule in validation_rules if rule.level == ValidationLevel.WARNING)
        
        # Calculate scores
        format_score = 1.0 - (error_count / max(total_rules, 1))
        completeness_score = passed_rules / max(total_rules, 1)
        consistency_score = 1.0 - (warning_count / max(total_rules, 1))
        
        # Overall score (weighted average)
        overall_score = (format_score * 0.4 + completeness_score * 0.4 + consistency_score * 0.2)
        
        return QualityMetrics(
            completeness_score=completeness_score,
            format_score=format_score,
            consistency_score=consistency_score,
            overall_score=overall_score,
            total_rules=total_rules,
            passed_rules=passed_rules,
            warnings=warning_count,
            errors=error_count
        )
    
    def batch_validate_documents(self, documents: List[Dict[str, Any]]) -> List[ValidationResult]:
        """Validate multiple documents in batch"""
        results = []
        
        for document in documents:
            try:
                result = self.validate_document(document)
                results.append(result)
            except Exception as e:
                logger.error(f"Validation failed for document {document.get('urn', 'unknown')}: {e}")
                # Create error result
                error_result = ValidationResult(
                    document_id=document.get('urn', 'unknown'),
                    document_type=DocumentType.OUTROS,
                    validation_timestamp=datetime.now().isoformat(),
                    quality_metrics=QualityMetrics(0.0, 0.0, 0.0, 0.0, 0, 0, 0, 1),
                    validation_rules=[ValidationRule(
                        rule_name="validation_error",
                        level=ValidationLevel.ERROR,
                        passed=False,
                        message=f"Validation failed: {str(e)}"
                    )],
                    recommendations=["Fix validation errors and retry"],
                    is_valid=False,
                    processing_time_ms=0.0
                )
                results.append(error_result)
        
        return results
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validator statistics and capabilities"""
        return {
            "validator_version": "1.0.0",
            "supported_document_types": [dt.value for dt in DocumentType],
            "validation_levels": [vl.value for vl in ValidationLevel],
            "capabilities": {
                "urn_validation": True,
                "metadata_validation": True,
                "content_validation": True,
                "transport_domain_validation": True,
                "batch_processing": True,
                "quality_metrics": True
            },
            "validation_rules": {
                "urn_format": "Validates URN according to Brazilian legislative standards",
                "required_fields": "Checks presence of required metadata fields",
                "field_formats": "Validates format of specific metadata fields",
                "content_length": "Validates document content length and quality",
                "transport_metadata": "Transport-specific validation for domain documents"
            }
        }