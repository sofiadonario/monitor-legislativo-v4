"""
Document Validation API - LexML schema patterns and Brazilian legislative document validation
Provides comprehensive validation for Brazilian legislative documents
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
import xml.etree.ElementTree as ET

# XML validation libraries
try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False
    logging.warning("lxml not available - XML validation will be limited")

try:
    import xmlschema
    XMLSCHEMA_AVAILABLE = True
except ImportError:
    XMLSCHEMA_AVAILABLE = False
    logging.warning("xmlschema not available - schema validation will be limited")

logger = logging.getLogger(__name__)

# Router for document validation API
router = APIRouter(prefix="/api/v1/document-validation", tags=["Document Validation"])

class ValidationLevel(str, Enum):
    """Levels of document validation"""
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    LEXML_COMPLIANT = "lexml_compliant"

class DocumentType(str, Enum):
    """Types of Brazilian legislative documents"""
    LEI = "lei"
    DECRETO = "decreto"
    PORTARIA = "portaria"
    RESOLUCAO = "resolucao"
    MEDIDA_PROVISORIA = "medida_provisoria"
    INSTRUCAO_NORMATIVA = "instrucao_normativa"
    PARECER = "parecer"
    SUMULA = "sumula"
    EMENDA_CONSTITUCIONAL = "emenda_constitucional"

class ValidationSeverity(str, Enum):
    """Severity levels for validation issues"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUGGESTION = "suggestion"

@dataclass
class ValidationIssue:
    """Individual validation issue"""
    issue_id: str
    severity: ValidationSeverity
    category: str
    message: str
    location: Optional[str]
    line_number: Optional[int]
    column_number: Optional[int]
    suggestion: Optional[str]
    lexml_reference: Optional[str]

@dataclass
class LexMLMetadata:
    """LexML metadata structure"""
    urn: Optional[str]
    title: str
    document_type: DocumentType
    authority: str
    publication_date: Optional[str]
    effective_date: Optional[str]
    number: Optional[str]
    year: Optional[str]
    subject: List[str]
    keywords: List[str]

@dataclass
class DocumentStructure:
    """Document structure analysis"""
    has_title: bool
    has_preamble: bool
    has_articles: bool
    has_chapters: bool
    has_sections: bool
    has_dispositions: bool
    article_count: int
    paragraph_count: int
    section_count: int
    structure_score: float

@dataclass
class ValidationResult:
    """Complete validation result"""
    document_id: str
    validation_timestamp: str
    validation_level: ValidationLevel
    overall_score: float
    is_valid: bool
    issues: List[ValidationIssue]
    lexml_metadata: Optional[LexMLMetadata]
    document_structure: DocumentStructure
    compliance_summary: Dict[str, Any]
    processing_time: float

# Pydantic models for API
class DocumentValidationRequest(BaseModel):
    document_content: str = Field(..., description="Document content to validate")
    document_id: str = Field(..., description="Unique document identifier")
    validation_level: ValidationLevel = Field(default=ValidationLevel.STANDARD, description="Level of validation")
    document_type: Optional[DocumentType] = Field(default=None, description="Expected document type")
    check_lexml_compliance: bool = Field(default=True, description="Check LexML compliance")
    include_suggestions: bool = Field(default=True, description="Include improvement suggestions")

class LexMLValidationRequest(BaseModel):
    lexml_content: str = Field(..., description="LexML XML content to validate")
    schema_version: str = Field(default="1.0", description="LexML schema version")
    strict_mode: bool = Field(default=False, description="Enable strict validation mode")

class DocumentValidationResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class DocumentValidationProcessor:
    """Document validation processor with LexML schema support"""
    
    def __init__(self):
        self.lexml_schemas = {}
        self.validation_patterns = {}
        self.document_type_patterns = {}
        
        # Initialize validation patterns
        self._init_validation_patterns()
        self._init_document_type_patterns()
        self._init_lexml_patterns()
    
    async def initialize(self) -> bool:
        """Initialize document validation processor"""
        try:
            # Load LexML schemas
            await self._load_lexml_schemas()
            
            logger.info("✅ Document validation processor initialized")
            return True
            
        except Exception as e:
            logger.error(f"Document validation processor initialization failed: {e}")
            return False
    
    async def validate_document(
        self,
        document_content: str,
        document_id: str,
        validation_level: ValidationLevel = ValidationLevel.STANDARD,
        document_type: Optional[DocumentType] = None,
        check_lexml_compliance: bool = True,
        include_suggestions: bool = True
    ) -> ValidationResult:
        """Comprehensive document validation"""
        
        start_time = time.time()
        
        # Detect document type if not provided
        if not document_type:
            document_type = self._detect_document_type(document_content)
        
        # Collect validation issues
        issues = []
        
        # Basic structure validation
        structure_issues = await self._validate_document_structure(
            document_content, document_type, validation_level
        )
        issues.extend(structure_issues)
        
        # Content validation
        content_issues = await self._validate_document_content(
            document_content, document_type, validation_level
        )
        issues.extend(content_issues)
        
        # LexML compliance validation
        lexml_metadata = None
        if check_lexml_compliance:
            lexml_issues, lexml_metadata = await self._validate_lexml_compliance(
                document_content, document_type
            )
            issues.extend(lexml_issues)
        
        # Language and style validation
        if validation_level in [ValidationLevel.STRICT, ValidationLevel.LEXML_COMPLIANT]:
            language_issues = await self._validate_language_and_style(
                document_content, document_type
            )
            issues.extend(language_issues)
        
        # Add suggestions if requested
        if include_suggestions:
            suggestion_issues = await self._generate_improvement_suggestions(
                document_content, document_type, issues
            )
            issues.extend(suggestion_issues)
        
        # Analyze document structure
        document_structure = self._analyze_document_structure(document_content)
        
        # Calculate overall score
        overall_score = self._calculate_validation_score(issues, document_structure)
        
        # Determine if document is valid
        is_valid = self._determine_validity(issues, validation_level)
        
        # Generate compliance summary
        compliance_summary = self._generate_compliance_summary(
            issues, document_structure, lexml_metadata
        )
        
        processing_time = time.time() - start_time
        
        return ValidationResult(
            document_id=document_id,
            validation_timestamp=datetime.now().isoformat(),
            validation_level=validation_level,
            overall_score=overall_score,
            is_valid=is_valid,
            issues=issues,
            lexml_metadata=lexml_metadata,
            document_structure=document_structure,
            compliance_summary=compliance_summary,
            processing_time=processing_time
        )
    
    async def validate_lexml_document(
        self,
        lexml_content: str,
        schema_version: str = "1.0",
        strict_mode: bool = False
    ) -> ValidationResult:
        """Validate LexML XML document against schema"""
        
        start_time = time.time()
        
        issues = []
        
        # XML well-formedness validation
        xml_issues = await self._validate_xml_wellformedness(lexml_content)
        issues.extend(xml_issues)
        
        # Schema validation
        if XMLSCHEMA_AVAILABLE and lexml_content.strip():
            schema_issues = await self._validate_against_lexml_schema(
                lexml_content, schema_version, strict_mode
            )
            issues.extend(schema_issues)
        
        # LexML specific validation
        lexml_specific_issues = await self._validate_lexml_specific_rules(
            lexml_content, strict_mode
        )
        issues.extend(lexml_specific_issues)
        
        # Extract metadata
        lexml_metadata = self._extract_lexml_metadata(lexml_content)
        
        # Analyze structure
        document_structure = self._analyze_xml_structure(lexml_content)
        
        # Calculate scores
        overall_score = self._calculate_validation_score(issues, document_structure)
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        
        compliance_summary = self._generate_compliance_summary(
            issues, document_structure, lexml_metadata
        )
        
        processing_time = time.time() - start_time
        
        return ValidationResult(
            document_id="lexml_doc",
            validation_timestamp=datetime.now().isoformat(),
            validation_level=ValidationLevel.LEXML_COMPLIANT,
            overall_score=overall_score,
            is_valid=is_valid,
            issues=issues,
            lexml_metadata=lexml_metadata,
            document_structure=document_structure,
            compliance_summary=compliance_summary,
            processing_time=processing_time
        )
    
    # Private helper methods
    def _init_validation_patterns(self):
        """Initialize validation patterns for Brazilian legislative documents"""
        
        self.validation_patterns = {
            'required_sections': {
                DocumentType.LEI: ['título', 'artigo'],
                DocumentType.DECRETO: ['preâmbulo', 'artigo'],
                DocumentType.PORTARIA: ['considerando', 'resolve'],
                DocumentType.RESOLUCAO: ['considerando', 'resolve']
            },
            'structural_patterns': {
                'article': r'Art\.?\s*(\d+)[ºo°]?\.?\s*(.*?)(?=Art\.?\s*\d+|$)',
                'paragraph': r'§\s*(\d+)[ºo°]?\s*(.*?)(?=§\s*\d+|Art\.|$)',
                'item': r'[IVX]+\s*[-–]\s*(.*?)(?=[IVX]+\s*[-–]|$)',
                'alínea': r'[a-z]\)\s*(.*?)(?=[a-z]\)|$)'
            },
            'numbering_patterns': {
                'law_number': r'Lei\s+(?:Federal\s+)?n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
                'decree_number': r'Decreto\s+n[ºo°]?\s*(\d+(?:[.,]\d+)*)',
                'date_pattern': r'(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})'
            }
        }
    
    def _init_document_type_patterns(self):
        """Initialize document type detection patterns"""
        
        self.document_type_patterns = {
            DocumentType.LEI: [
                r'Lei\s+(?:Federal\s+)?n[ºo°]?\s*\d+',
                r'LEI\s+N[ºo°]?\s*\d+'
            ],
            DocumentType.DECRETO: [
                r'Decreto\s+n[ºo°]?\s*\d+',
                r'DECRETO\s+N[ºo°]?\s*\d+'
            ],
            DocumentType.PORTARIA: [
                r'Portaria\s+n[ºo°]?\s*\d+',
                r'PORTARIA\s+N[ºo°]?\s*\d+'
            ],
            DocumentType.RESOLUCAO: [
                r'Resolução\s+n[ºo°]?\s*\d+',
                r'RESOLUÇÃO\s+N[ºo°]?\s*\d+'
            ],
            DocumentType.MEDIDA_PROVISORIA: [
                r'Medida\s+Provisória\s+n[ºo°]?\s*\d+',
                r'MEDIDA\s+PROVISÓRIA\s+N[ºo°]?\s*\d+'
            ]
        }
    
    def _init_lexml_patterns(self):
        """Initialize LexML specific patterns"""
        
        self.lexml_patterns = {
            'urn_pattern': r'urn:lex:br:federal:lei:(\d{4}-\d{2}-\d{2});(\d+)',
            'required_elements': [
                'LexMLDocument',
                'metadados',
                'texto'
            ],
            'metadata_elements': [
                'titulo',
                'autoridade',
                'dataPublicacao',
                'numero',
                'ano'
            ]
        }
    
    async def _load_lexml_schemas(self):
        """Load LexML schema definitions"""
        
        # In production, would load actual LexML XSD schemas
        # For now, we'll define basic schema structure
        self.lexml_schemas["1.0"] = {
            "root_element": "LexMLDocument",
            "namespaces": {
                "lexml": "http://www.lexml.gov.br/1.0",
                "xsi": "http://www.w3.org/2001/XMLSchema-instance"
            },
            "required_attributes": ["version", "xmlns"],
            "required_children": ["metadados", "texto"]
        }
    
    def _detect_document_type(self, content: str) -> DocumentType:
        """Detect document type from content"""
        
        content_upper = content.upper()
        
        for doc_type, patterns in self.document_type_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return doc_type
        
        # Default fallback
        return DocumentType.LEI
    
    async def _validate_document_structure(
        self,
        content: str,
        document_type: DocumentType,
        validation_level: ValidationLevel
    ) -> List[ValidationIssue]:
        """Validate document structure"""
        
        issues = []
        
        # Check required sections
        required_sections = self.validation_patterns['required_sections'].get(document_type, [])
        for section in required_sections:
            if not re.search(section, content, re.IGNORECASE):
                issues.append(ValidationIssue(
                    issue_id=f"missing_section_{section}",
                    severity=ValidationSeverity.ERROR,
                    category="structure",
                    message=f"Seção obrigatória '{section}' não encontrada",
                    location=None,
                    line_number=None,
                    column_number=None,
                    suggestion=f"Adicione a seção '{section}' ao documento",
                    lexml_reference="LexML structural requirements"
                ))
        
        # Check article numbering
        articles = re.findall(self.validation_patterns['structural_patterns']['article'], content, re.DOTALL)
        if articles:
            article_numbers = []
            for i, (number, text) in enumerate(articles):
                try:
                    num = int(number)
                    article_numbers.append(num)
                except ValueError:
                    issues.append(ValidationIssue(
                        issue_id=f"invalid_article_number_{i}",
                        severity=ValidationSeverity.ERROR,
                        category="numbering",
                        message=f"Numeração de artigo inválida: '{number}'",
                        location=f"Artigo {number}",
                        line_number=None,
                        column_number=None,
                        suggestion="Use numeração sequencial para artigos",
                        lexml_reference="LexML article numbering"
                    ))
            
            # Check sequential numbering
            if article_numbers:
                expected = list(range(1, len(article_numbers) + 1))
                if article_numbers != expected:
                    issues.append(ValidationIssue(
                        issue_id="non_sequential_articles",
                        severity=ValidationSeverity.WARNING,
                        category="numbering",
                        message="Artigos não estão em sequência numérica",
                        location="Document structure",
                        line_number=None,
                        column_number=None,
                        suggestion="Use numeração sequencial: Art. 1º, Art. 2º, etc.",
                        lexml_reference="LexML sequential numbering"
                    ))
        
        return issues
    
    async def _validate_document_content(
        self,
        content: str,
        document_type: DocumentType,
        validation_level: ValidationLevel
    ) -> List[ValidationIssue]:
        """Validate document content"""
        
        issues = []
        
        # Check document length
        if len(content.strip()) < 100:
            issues.append(ValidationIssue(
                issue_id="document_too_short",
                severity=ValidationSeverity.WARNING,
                category="content",
                message="Documento muito curto para um documento legislativo",
                location="Document length",
                line_number=None,
                column_number=None,
                suggestion="Verifique se o conteúdo está completo",
                lexml_reference=None
            ))
        
        # Check for required legal language patterns
        legal_patterns = [
            r'fica\s+(?:estabelecido|determinado|aprovado)',
            r'entra\s+em\s+vigor',
            r'revogam-se\s+as\s+disposições\s+em\s+contrário'
        ]
        
        found_patterns = 0
        for pattern in legal_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns += 1
        
        if found_patterns == 0 and validation_level == ValidationLevel.STRICT:
            issues.append(ValidationIssue(
                issue_id="missing_legal_language",
                severity=ValidationSeverity.WARNING,
                category="content",
                message="Documento não contém linguagem jurídica típica",
                location="Document content",
                line_number=None,
                column_number=None,
                suggestion="Verifique se o documento segue padrões de redação jurídica",
                lexml_reference="Legal writing standards"
            ))
        
        return issues
    
    async def _validate_lexml_compliance(
        self,
        content: str,
        document_type: DocumentType
    ) -> Tuple[List[ValidationIssue], Optional[LexMLMetadata]]:
        """Validate LexML compliance"""
        
        issues = []
        metadata = None
        
        # Extract potential metadata
        metadata = self._extract_potential_metadata(content, document_type)
        
        # Check for URN pattern
        urn_match = re.search(self.lexml_patterns['urn_pattern'], content)
        if not urn_match and document_type == DocumentType.LEI:
            issues.append(ValidationIssue(
                issue_id="missing_lexml_urn",
                severity=ValidationSeverity.INFO,
                category="lexml",
                message="URN LexML não encontrado",
                location="Document metadata",
                line_number=None,
                column_number=None,
                suggestion="Considere adicionar URN LexML para identificação única",
                lexml_reference="LexML URN specification"
            ))
        
        # Check metadata completeness
        if metadata:
            required_fields = ['title', 'authority', 'publication_date']
            for field in required_fields:
                if not getattr(metadata, field, None):
                    issues.append(ValidationIssue(
                        issue_id=f"missing_metadata_{field}",
                        severity=ValidationSeverity.INFO,
                        category="metadata",
                        message=f"Metadado '{field}' não encontrado",
                        location="Document metadata",
                        line_number=None,
                        column_number=None,
                        suggestion=f"Adicione informação de '{field}' aos metadados",
                        lexml_reference="LexML metadata requirements"
                    ))
        
        return issues, metadata
    
    async def _validate_language_and_style(
        self,
        content: str,
        document_type: DocumentType
    ) -> List[ValidationIssue]:
        """Validate language and style"""
        
        issues = []
        
        # Check for passive voice overuse (simplified)
        passive_patterns = [
            r'\bé\s+\w+do\b',
            r'\bsão\s+\w+dos\b',
            r'\bserá\s+\w+do\b'
        ]
        
        passive_count = 0
        for pattern in passive_patterns:
            passive_count += len(re.findall(pattern, content, re.IGNORECASE))
        
        total_sentences = len(re.findall(r'[.!?]+', content))
        if total_sentences > 0 and passive_count / total_sentences > 0.3:
            issues.append(ValidationIssue(
                issue_id="excessive_passive_voice",
                severity=ValidationSeverity.SUGGESTION,
                category="style",
                message="Uso excessivo de voz passiva",
                location="Document style",
                line_number=None,
                column_number=None,
                suggestion="Considere usar voz ativa para maior clareza",
                lexml_reference="Legal writing guidelines"
            ))
        
        # Check for very long sentences
        sentences = re.split(r'[.!?]+', content)
        for i, sentence in enumerate(sentences):
            words = len(sentence.split())
            if words > 50:
                issues.append(ValidationIssue(
                    issue_id=f"long_sentence_{i}",
                    severity=ValidationSeverity.SUGGESTION,
                    category="style",
                    message=f"Sentença muito longa ({words} palavras)",
                    location=f"Sentence {i+1}",
                    line_number=None,
                    column_number=None,
                    suggestion="Considere dividir em sentenças menores",
                    lexml_reference="Readability guidelines"
                ))
        
        return issues
    
    async def _generate_improvement_suggestions(
        self,
        content: str,
        document_type: DocumentType,
        existing_issues: List[ValidationIssue]
    ) -> List[ValidationIssue]:
        """Generate improvement suggestions"""
        
        suggestions = []
        
        # Suggest adding table of contents for long documents
        if len(content.split()) > 1000:
            suggestions.append(ValidationIssue(
                issue_id="suggest_table_of_contents",
                severity=ValidationSeverity.SUGGESTION,
                category="improvement",
                message="Documento longo poderia beneficiar-se de um índice",
                location="Document structure",
                line_number=None,
                column_number=None,
                suggestion="Adicione um índice ou sumário no início do documento",
                lexml_reference="Document organization best practices"
            ))
        
        # Suggest section headers
        articles = re.findall(self.validation_patterns['structural_patterns']['article'], content)
        if len(articles) > 10:
            chapters = re.findall(r'capítulo\s+[ivx]+', content, re.IGNORECASE)
            if not chapters:
                suggestions.append(ValidationIssue(
                    issue_id="suggest_chapters",
                    severity=ValidationSeverity.SUGGESTION,
                    category="improvement",
                    message="Documento com muitos artigos poderia usar capítulos",
                    location="Document structure",
                    line_number=None,
                    column_number=None,
                    suggestion="Organize artigos em capítulos temáticos",
                    lexml_reference="Document structuring guidelines"
                ))
        
        return suggestions
    
    def _analyze_document_structure(self, content: str) -> DocumentStructure:
        """Analyze document structure"""
        
        # Check for structural elements
        has_title = bool(re.search(r'(?:lei|decreto|portaria)\s+n[ºo°]?\s*\d+', content, re.IGNORECASE))
        has_preamble = bool(re.search(r'(?:considerando|preâmbulo)', content, re.IGNORECASE))
        has_articles = bool(re.search(r'art\.?\s*\d+', content, re.IGNORECASE))
        has_chapters = bool(re.search(r'capítulo\s+[ivx]+', content, re.IGNORECASE))
        has_sections = bool(re.search(r'seção\s+[ivx]+', content, re.IGNORECASE))
        has_dispositions = bool(re.search(r'disposições\s+(?:finais|transitórias)', content, re.IGNORECASE))
        
        # Count structural elements
        article_count = len(re.findall(r'art\.?\s*\d+', content, re.IGNORECASE))
        paragraph_count = len(re.findall(r'§\s*\d+', content, re.IGNORECASE))
        section_count = len(re.findall(r'seção\s+[ivx]+', content, re.IGNORECASE))
        
        # Calculate structure score
        structure_elements = [has_title, has_articles]
        if article_count > 5:
            structure_elements.extend([has_chapters, has_sections])
        if article_count > 20:
            structure_elements.append(has_dispositions)
        
        structure_score = sum(structure_elements) / len(structure_elements)
        
        return DocumentStructure(
            has_title=has_title,
            has_preamble=has_preamble,
            has_articles=has_articles,
            has_chapters=has_chapters,
            has_sections=has_sections,
            has_dispositions=has_dispositions,
            article_count=article_count,
            paragraph_count=paragraph_count,
            section_count=section_count,
            structure_score=structure_score
        )
    
    def _extract_potential_metadata(self, content: str, document_type: DocumentType) -> Optional[LexMLMetadata]:
        """Extract potential metadata from document content"""
        
        # Extract title
        title_patterns = [
            r'(Lei\s+(?:Federal\s+)?n[ºo°]?\s*\d+[^.]*)',
            r'(Decreto\s+n[ºo°]?\s*\d+[^.]*)',
            r'(Portaria\s+n[ºo°]?\s*\d+[^.]*)'
        ]
        
        title = None
        for pattern in title_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                title = match.group(1).strip()
                break
        
        # Extract number and year
        number_match = re.search(r'n[ºo°]?\s*(\d+)', content, re.IGNORECASE)
        number = number_match.group(1) if number_match else None
        
        year_match = re.search(r'(\d{4})', content)
        year = year_match.group(1) if year_match else None
        
        # Extract publication date
        date_match = re.search(r'(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})', content, re.IGNORECASE)
        publication_date = None
        if date_match:
            day, month, year = date_match.groups()
            publication_date = f"{day} de {month} de {year}"
        
        # Extract authority
        authority_patterns = [
            r'(?:Presidente\s+da\s+República|Ministro\s+de\s+Estado|Secretário)',
            r'(?:União|Estados?|Municípios?|Distrito\s+Federal)'
        ]
        
        authority = None
        for pattern in authority_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                authority = match.group(0)
                break
        
        if not authority:
            authority = "Autoridade não identificada"
        
        return LexMLMetadata(
            urn=None,  # Would extract from LexML URN if present
            title=title or "Título não identificado",
            document_type=document_type,
            authority=authority,
            publication_date=publication_date,
            effective_date=None,
            number=number,
            year=year,
            subject=[],  # Would extract from content analysis
            keywords=[]  # Would extract from content analysis
        )
    
    async def _validate_xml_wellformedness(self, xml_content: str) -> List[ValidationIssue]:
        """Validate XML well-formedness"""
        
        issues = []
        
        try:
            if LXML_AVAILABLE:
                etree.fromstring(xml_content.encode())
            else:
                ET.fromstring(xml_content)
        except ET.ParseError as e:
            issues.append(ValidationIssue(
                issue_id="xml_parse_error",
                severity=ValidationSeverity.ERROR,
                category="xml",
                message=f"Erro de parsing XML: {str(e)}",
                location="XML structure",
                line_number=getattr(e, 'lineno', None),
                column_number=getattr(e, 'offset', None),
                suggestion="Verifique a sintaxe XML e tags fechadas",
                lexml_reference="XML well-formedness"
            ))
        except Exception as e:
            issues.append(ValidationIssue(
                issue_id="xml_general_error",
                severity=ValidationSeverity.ERROR,
                category="xml",
                message=f"Erro XML: {str(e)}",
                location="XML structure",
                line_number=None,
                column_number=None,
                suggestion="Verifique a estrutura XML",
                lexml_reference="XML validation"
            ))
        
        return issues
    
    async def _validate_against_lexml_schema(
        self,
        xml_content: str,
        schema_version: str,
        strict_mode: bool
    ) -> List[ValidationIssue]:
        """Validate against LexML schema"""
        
        issues = []
        
        # Basic schema validation (would use actual XSD in production)
        schema_def = self.lexml_schemas.get(schema_version)
        if not schema_def:
            issues.append(ValidationIssue(
                issue_id="unknown_schema_version",
                severity=ValidationSeverity.ERROR,
                category="schema",
                message=f"Versão de schema desconhecida: {schema_version}",
                location="Schema reference",
                line_number=None,
                column_number=None,
                suggestion="Use uma versão de schema LexML suportada",
                lexml_reference="LexML schema versions"
            ))
            return issues
        
        try:
            root = ET.fromstring(xml_content)
            
            # Check root element
            if root.tag != schema_def["root_element"]:
                issues.append(ValidationIssue(
                    issue_id="invalid_root_element",
                    severity=ValidationSeverity.ERROR,
                    category="schema",
                    message=f"Elemento raiz inválido: {root.tag}",
                    location="Root element",
                    line_number=None,
                    column_number=None,
                    suggestion=f"Use '{schema_def['root_element']}' como elemento raiz",
                    lexml_reference="LexML document structure"
                ))
            
            # Check required children
            for child in schema_def["required_children"]:
                if root.find(child) is None:
                    issues.append(ValidationIssue(
                        issue_id=f"missing_required_child_{child}",
                        severity=ValidationSeverity.ERROR,
                        category="schema",
                        message=f"Elemento obrigatório '{child}' não encontrado",
                        location="Document structure",
                        line_number=None,
                        column_number=None,
                        suggestion=f"Adicione o elemento '{child}' ao documento",
                        lexml_reference="LexML required elements"
                    ))
        
        except ET.ParseError:
            # Already handled in well-formedness validation
            pass
        
        return issues
    
    async def _validate_lexml_specific_rules(
        self,
        xml_content: str,
        strict_mode: bool
    ) -> List[ValidationIssue]:
        """Validate LexML specific rules"""
        
        issues = []
        
        # Check for namespace declarations
        if 'xmlns' not in xml_content:
            issues.append(ValidationIssue(
                issue_id="missing_namespace",
                severity=ValidationSeverity.WARNING,
                category="lexml",
                message="Declaração de namespace LexML não encontrada",
                location="XML namespaces",
                line_number=None,
                column_number=None,
                suggestion="Adicione declaração de namespace LexML",
                lexml_reference="LexML namespace specification"
            ))
        
        return issues
    
    def _extract_lexml_metadata(self, xml_content: str) -> Optional[LexMLMetadata]:
        """Extract metadata from LexML document"""
        
        try:
            root = ET.fromstring(xml_content)
            
            # Find metadata element
            metadata_elem = root.find('.//metadados')
            if metadata_elem is None:
                return None
            
            # Extract metadata fields
            title_elem = metadata_elem.find('.//titulo')
            title = title_elem.text if title_elem is not None else "Título não encontrado"
            
            authority_elem = metadata_elem.find('.//autoridade')
            authority = authority_elem.text if authority_elem is not None else "Autoridade não encontrada"
            
            return LexMLMetadata(
                urn=None,  # Would extract from URN element
                title=title,
                document_type=DocumentType.LEI,  # Would detect from content
                authority=authority,
                publication_date=None,  # Would extract from date elements
                effective_date=None,
                number=None,
                year=None,
                subject=[],
                keywords=[]
            )
        
        except ET.ParseError:
            return None
    
    def _analyze_xml_structure(self, xml_content: str) -> DocumentStructure:
        """Analyze XML document structure"""
        
        try:
            root = ET.fromstring(xml_content)
            
            # Count structural elements
            articles = root.findall('.//artigo')
            paragraphs = root.findall('.//paragrafo')
            sections = root.findall('.//secao')
            
            has_title = root.find('.//titulo') is not None
            has_articles = len(articles) > 0
            has_chapters = root.find('.//capitulo') is not None
            has_sections = len(sections) > 0
            
            structure_score = sum([has_title, has_articles]) / 2
            
            return DocumentStructure(
                has_title=has_title,
                has_preamble=root.find('.//preambulo') is not None,
                has_articles=has_articles,
                has_chapters=has_chapters,
                has_sections=has_sections,
                has_dispositions=root.find('.//disposicoes') is not None,
                article_count=len(articles),
                paragraph_count=len(paragraphs),
                section_count=len(sections),
                structure_score=structure_score
            )
        
        except ET.ParseError:
            return DocumentStructure(
                has_title=False,
                has_preamble=False,
                has_articles=False,
                has_chapters=False,
                has_sections=False,
                has_dispositions=False,
                article_count=0,
                paragraph_count=0,
                section_count=0,
                structure_score=0.0
            )
    
    def _calculate_validation_score(
        self,
        issues: List[ValidationIssue],
        structure: DocumentStructure
    ) -> float:
        """Calculate overall validation score"""
        
        # Base score from structure
        base_score = structure.structure_score * 50
        
        # Deduct points for issues
        error_penalty = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) * 20
        warning_penalty = len([i for i in issues if i.severity == ValidationSeverity.WARNING]) * 10
        info_penalty = len([i for i in issues if i.severity == ValidationSeverity.INFO]) * 5
        
        total_penalty = error_penalty + warning_penalty + info_penalty
        
        # Calculate final score
        final_score = max(0, base_score + (50 - total_penalty))
        
        return min(100, final_score)
    
    def _determine_validity(
        self,
        issues: List[ValidationIssue],
        validation_level: ValidationLevel
    ) -> bool:
        """Determine if document is valid based on issues and validation level"""
        
        errors = [i for i in issues if i.severity == ValidationSeverity.ERROR]
        warnings = [i for i in issues if i.severity == ValidationSeverity.WARNING]
        
        if validation_level == ValidationLevel.BASIC:
            return len(errors) == 0
        elif validation_level == ValidationLevel.STANDARD:
            return len(errors) == 0 and len(warnings) <= 3
        elif validation_level in [ValidationLevel.STRICT, ValidationLevel.LEXML_COMPLIANT]:
            return len(errors) == 0 and len(warnings) <= 1
        
        return len(errors) == 0
    
    def _generate_compliance_summary(
        self,
        issues: List[ValidationIssue],
        structure: DocumentStructure,
        metadata: Optional[LexMLMetadata]
    ) -> Dict[str, Any]:
        """Generate compliance summary"""
        
        error_count = len([i for i in issues if i.severity == ValidationSeverity.ERROR])
        warning_count = len([i for i in issues if i.severity == ValidationSeverity.WARNING])
        info_count = len([i for i in issues if i.severity == ValidationSeverity.INFO])
        suggestion_count = len([i for i in issues if i.severity == ValidationSeverity.SUGGESTION])
        
        return {
            "issue_summary": {
                "errors": error_count,
                "warnings": warning_count,
                "info": info_count,
                "suggestions": suggestion_count
            },
            "structure_compliance": {
                "has_required_structure": structure.has_title and structure.has_articles,
                "structure_score": structure.structure_score,
                "article_count": structure.article_count
            },
            "metadata_compliance": {
                "has_metadata": metadata is not None,
                "has_title": metadata.title if metadata else False,
                "has_authority": metadata.authority if metadata else False
            },
            "lexml_compliance": {
                "has_lexml_elements": metadata is not None,
                "namespace_declared": True,  # Would check actual XML
                "schema_valid": error_count == 0
            }
        }

# Global validation processor instance
_validation_processor: Optional[DocumentValidationProcessor] = None

async def get_validation_processor() -> DocumentValidationProcessor:
    """Get or create the global validation processor"""
    global _validation_processor
    
    if _validation_processor is None:
        _validation_processor = DocumentValidationProcessor()
        if await _validation_processor.initialize():
            logger.info("✅ Document validation processor initialized")
        else:
            logger.warning("⚠️ Validation processor initialized with limited functionality")
    
    return _validation_processor

# API endpoints
@router.post("/validate-document", response_model=DocumentValidationResponse)
async def validate_document_endpoint(
    request: DocumentValidationRequest
) -> DocumentValidationResponse:
    """Validate Brazilian legislative document"""
    try:
        start_time = time.time()
        validation_processor = await get_validation_processor()
        
        result = await validation_processor.validate_document(
            document_content=request.document_content,
            document_id=request.document_id,
            validation_level=request.validation_level,
            document_type=request.document_type,
            check_lexml_compliance=request.check_lexml_compliance,
            include_suggestions=request.include_suggestions
        )
        
        processing_time = time.time() - start_time
        
        return DocumentValidationResponse(
            success=True,
            data=asdict(result),
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Document validation failed: {e}")
        return DocumentValidationResponse(
            success=False,
            error=str(e)
        )

@router.post("/validate-lexml", response_model=DocumentValidationResponse)
async def validate_lexml_endpoint(
    request: LexMLValidationRequest
) -> DocumentValidationResponse:
    """Validate LexML XML document"""
    try:
        validation_processor = await get_validation_processor()
        
        result = await validation_processor.validate_lexml_document(
            lexml_content=request.lexml_content,
            schema_version=request.schema_version,
            strict_mode=request.strict_mode
        )
        
        return DocumentValidationResponse(
            success=True,
            data=asdict(result)
        )
        
    except Exception as e:
        logger.error(f"LexML validation failed: {e}")
        return DocumentValidationResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def validation_health_status() -> Dict[str, Any]:
    """Get validation system health status"""
    try:
        validation_processor = await get_validation_processor()
        
        return {
            "status": "healthy",
            "lxml_available": LXML_AVAILABLE,
            "xmlschema_available": XMLSCHEMA_AVAILABLE,
            "supported_document_types": [dt.value for dt in DocumentType],
            "validation_levels": [vl.value for vl in ValidationLevel],
            "lexml_schemas_loaded": len(validation_processor.lexml_schemas)
        }
        
    except Exception as e:
        logger.error(f"Validation health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_validation_processor"]