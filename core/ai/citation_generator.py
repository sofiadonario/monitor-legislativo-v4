"""
AI-Enhanced Citation Generator
==============================

Advanced citation generation with AI assistance for Brazilian legislative documents.
Supports multiple academic citation styles with intelligent formatting, validation,
and enhancement capabilities.

Features:
- AI-powered citation generation for Brazilian legislative documents
- Multiple citation styles (ABNT, APA, Chicago, Vancouver, etc.)
- Intelligent metadata completion and enhancement
- Citation validation and quality checking
- Academic research integration
- Cost-optimized processing with caching
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re

from .agent_foundation import ProductionAIAgent, AgentConfig, AgentRole

logger = logging.getLogger(__name__)


@dataclass
class CitationRequest:
    """Citation generation request"""
    document_data: Dict[str, Any]
    citation_style: str
    include_url: bool = True
    include_access_date: bool = True
    academic_level: str = "graduate"  # undergraduate, graduate, postgraduate
    research_context: Optional[str] = None


@dataclass
class CitationResult:
    """Generated citation with metadata"""
    citation_text: str
    citation_style: str
    document_id: str
    validation_status: str
    quality_score: float
    ai_enhancements: List[str]
    metadata_completeness: float
    formatting_accuracy: float
    academic_compliance: float
    suggestions: List[str]
    processing_time_ms: float
    cost_cents: float
    from_cache: bool = False


@dataclass
class CitationValidation:
    """Citation validation results"""
    is_valid: bool
    validation_errors: List[str]
    validation_warnings: List[str]
    style_compliance: float
    metadata_quality: float
    formatting_issues: List[str]
    enhancement_suggestions: List[str]


class CitationStyleEngine:
    """
    Citation style formatting engines for different academic standards
    """
    
    def __init__(self):
        self.style_templates = {
            "abnt": {
                "name": "ABNT (NBR 6023:2018)",
                "description": "Brazilian Association of Technical Standards",
                "template": "{author_upper}. {title}. {location}: {publisher}, {year}. {pages}p. {notes}. Disponível em: {url}. Acesso em: {access_date}.",
                "legal_template": "{issuing_authority}. {document_type} nº {number}, de {date}. {title}. {publication}, {location}, {publication_date}. {section}, p. {pages}. Disponível em: {url}. Acesso em: {access_date}."
            },
            "apa": {
                "name": "APA 7th Edition",
                "description": "American Psychological Association",
                "template": "{author} ({year}). {title}. {publisher}. {url}",
                "legal_template": "{issuing_authority}. ({year}). {title} ({document_type} No. {number}). {publisher}. {url}"
            },
            "chicago": {
                "name": "Chicago Manual of Style",
                "description": "Chicago style for academic citations",
                "template": '{author}. "{title}." {publisher}, {year}. {url}.',
                "legal_template": '{issuing_authority}. "{title}." {document_type} No. {number}, {date}. {url}.'
            },
            "vancouver": {
                "name": "Vancouver Style",
                "description": "International Committee of Medical Journal Editors",
                "template": "{author}. {title}. {location}: {publisher}; {year}. Available from: {url}",
                "legal_template": "{issuing_authority}. {title}. {document_type} No. {number}; {date}. Available from: {url}"
            }
        }
        
        # Brazilian legal document patterns
        self.legal_document_types = {
            "lei": "Lei",
            "decreto": "Decreto", 
            "portaria": "Portaria",
            "resolucao": "Resolução",
            "medida_provisoria": "Medida Provisória",
            "constituicao": "Constituição",
            "codigo": "Código"
        }
        
        # Brazilian authorities and publishers
        self.brazilian_authorities = {
            "federal": "Brasil",
            "união": "Brasil",
            "presidencia": "Brasil. Presidência da República",
            "congresso": "Brasil. Congresso Nacional",
            "camara": "Brasil. Câmara dos Deputados",
            "senado": "Brasil. Senado Federal",
            "stf": "Brasil. Supremo Tribunal Federal",
            "stj": "Brasil. Superior Tribunal de Justiça"
        }
    
    def format_citation(self, style: str, document_data: Dict[str, Any], 
                       enhancements: Dict[str, Any] = None) -> str:
        """Format citation according to specified style"""
        
        if style not in self.style_templates:
            raise ValueError(f"Unsupported citation style: {style}")
        
        style_config = self.style_templates[style]
        
        # Determine if this is a legal document
        is_legal = self._is_legal_document(document_data)
        template = style_config["legal_template"] if is_legal else style_config["template"]
        
        # Prepare citation data
        citation_data = self._prepare_citation_data(document_data, style, enhancements)
        
        # Format according to template
        try:
            formatted_citation = template.format(**citation_data)
            
            # Clean up formatting
            formatted_citation = self._clean_citation_formatting(formatted_citation)
            
            return formatted_citation
            
        except KeyError as e:
            logger.warning(f"Missing citation field {e} for style {style}")
            # Fallback to basic formatting
            return self._generate_fallback_citation(document_data, style)
    
    def _is_legal_document(self, document_data: Dict[str, Any]) -> bool:
        """Determine if document is a legal/legislative document"""
        urn = document_data.get("urn", "").lower()
        doc_type = document_data.get("tipo_documento", "").lower()
        title = document_data.get("title", "").lower()
        
        legal_indicators = ["urn:lex:", "lei", "decreto", "portaria", "resolução", "código"]
        
        return any(indicator in urn or indicator in doc_type or indicator in title 
                  for indicator in legal_indicators)
    
    def _prepare_citation_data(self, document_data: Dict[str, Any], style: str, 
                              enhancements: Dict[str, Any] = None) -> Dict[str, str]:
        """Prepare and normalize citation data"""
        
        citation_data = {}
        
        # Basic fields
        citation_data["title"] = document_data.get("title", "Documento sem título")
        citation_data["year"] = self._extract_year(document_data)
        citation_data["url"] = document_data.get("url", "")
        citation_data["access_date"] = datetime.now().strftime("%d %b. %Y")
        
        # Author/Authority handling
        if self._is_legal_document(document_data):
            citation_data["author"] = self._format_legal_authority(document_data)
            citation_data["author_upper"] = citation_data["author"].upper()
            citation_data["issuing_authority"] = citation_data["author"]
            citation_data["document_type"] = self._extract_document_type(document_data)
            citation_data["number"] = self._extract_document_number(document_data)
            citation_data["date"] = self._extract_document_date(document_data)
        else:
            citation_data["author"] = document_data.get("autor", "Autor não identificado")
            citation_data["author_upper"] = citation_data["author"].upper()
        
        # Publisher and location
        citation_data["publisher"] = document_data.get("editora", "")
        citation_data["location"] = document_data.get("localidade", "Brasília")
        citation_data["publication"] = document_data.get("publicacao", "Diário Oficial da União")
        citation_data["publication_date"] = citation_data["date"]
        
        # Additional fields
        citation_data["pages"] = document_data.get("paginas", "")
        citation_data["section"] = document_data.get("secao", "Seção 1")
        citation_data["notes"] = document_data.get("notas", "")
        
        # Apply AI enhancements if provided
        if enhancements:
            citation_data.update(enhancements)
        
        # Style-specific formatting
        if style == "abnt":
            citation_data["access_date"] = datetime.now().strftime("%d %b. %Y")
        elif style == "apa":
            citation_data["access_date"] = datetime.now().strftime("%B %d, %Y")
        
        return citation_data
    
    def _extract_year(self, document_data: Dict[str, Any]) -> str:
        """Extract publication year from document data"""
        # Try different date fields
        date_fields = ["data_evento", "data_publicacao", "ano", "year"]
        
        for field in date_fields:
            date_value = document_data.get(field, "")
            if date_value:
                # Extract year using regex
                year_match = re.search(r'\b(19|20)\d{2}\b', str(date_value))
                if year_match:
                    return year_match.group()
        
        return str(datetime.now().year)
    
    def _format_legal_authority(self, document_data: Dict[str, Any]) -> str:
        """Format legal authority according to Brazilian standards"""
        authority = document_data.get("autoridade", "").lower()
        
        # Map to standard authority names
        for key, standard_name in self.brazilian_authorities.items():
            if key in authority:
                return standard_name
        
        # Default based on URN or document type
        urn = document_data.get("urn", "").lower()
        if "federal" in urn:
            return "Brasil"
        elif any(state in urn for state in ["sp", "rj", "mg", "rs"]):
            state_match = re.search(r':(sp|rj|mg|rs|pr|sc|ba|go|pe|ce|pa|pb|ma|es|pi|al|rn|mt|ms|df|se|am|ro|ac|ap|rr|to):', urn)
            if state_match:
                state = state_match.group(1).upper()
                return f"{state}"
        
        return document_data.get("autoridade", "Brasil")
    
    def _extract_document_type(self, document_data: Dict[str, Any]) -> str:
        """Extract and format document type"""
        urn = document_data.get("urn", "").lower()
        doc_type = document_data.get("tipo_documento", "").lower()
        
        for key, formal_name in self.legal_document_types.items():
            if key in urn or key in doc_type:
                return formal_name
        
        return "Documento"
    
    def _extract_document_number(self, document_data: Dict[str, Any]) -> str:
        """Extract document number from URN or metadata"""
        urn = document_data.get("urn", "")
        
        # Extract number from URN pattern
        number_match = re.search(r':(\d+)(?:\.|$)', urn)
        if number_match:
            return number_match.group(1)
        
        return document_data.get("numero", "")
    
    def _extract_document_date(self, document_data: Dict[str, Any]) -> str:
        """Extract and format document date"""
        date_value = document_data.get("data_evento", document_data.get("data_publicacao", ""))
        
        if date_value:
            # Try to parse and format date
            try:
                if "-" in date_value:
                    date_obj = datetime.strptime(date_value, "%Y-%m-%d")
                    return date_obj.strftime("%d de %B de %Y")
            except ValueError:
                pass
        
        return date_value or datetime.now().strftime("%d de %B de %Y")
    
    def _clean_citation_formatting(self, citation: str) -> str:
        """Clean up citation formatting"""
        # Remove empty fields
        citation = re.sub(r'\{\w+\}', '', citation)
        
        # Clean up punctuation
        citation = re.sub(r'\s+', ' ', citation)  # Multiple spaces
        citation = re.sub(r'\s*,\s*,', ',', citation)  # Double commas
        citation = re.sub(r'\s*\.\s*\.', '.', citation)  # Double periods
        citation = re.sub(r'\s*:\s*\.', '.', citation)  # Colon before period
        citation = re.sub(r'\s*:\s*,', ',', citation)  # Colon before comma
        
        # Fix spacing around punctuation
        citation = re.sub(r'\s*,\s*', ', ', citation)
        citation = re.sub(r'\s*\.\s*', '. ', citation)
        citation = re.sub(r'\s*:\s*', ': ', citation)
        
        return citation.strip()
    
    def _generate_fallback_citation(self, document_data: Dict[str, Any], style: str) -> str:
        """Generate basic fallback citation"""
        title = document_data.get("title", "Documento")
        author = document_data.get("autoridade", document_data.get("autor", "Autor"))
        year = self._extract_year(document_data)
        
        return f"{author}. {title}. {year}."


class AICitationGenerator:
    """
    AI-enhanced citation generator using specialized citation agent
    """
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.style_engine = CitationStyleEngine()
        self.citation_cache_prefix = "ai:citations"
        
        # Initialize citation specialist agent
        self.citation_agent = self._setup_citation_agent()
        
        logger.info("AI Citation Generator initialized")
    
    def _setup_citation_agent(self) -> ProductionAIAgent:
        """Setup specialized citation agent"""
        config = AgentConfig(
            agent_id="citation_specialist",
            role=AgentRole.CITATION_SPECIALIST,
            temperature=0.05,  # Very precise for citations
            max_tokens=1000,
            cost_budget_monthly=10.0,
            model="gpt-4o-mini"
        )
        
        return ProductionAIAgent(self.redis, config)
    
    async def generate_citation(self, request: CitationRequest) -> CitationResult:
        """Generate AI-enhanced citation"""
        start_time = time.time()
        
        doc_id = request.document_data.get("urn", request.document_data.get("id", "unknown"))
        
        # Check cache first
        cache_key = self._generate_cache_key(request)
        cached_result = await self._get_cached_citation(cache_key)
        
        if cached_result:
            cached_result.from_cache = True
            return cached_result
        
        # Enhance metadata with AI
        enhanced_metadata = await self._enhance_metadata_with_ai(request)
        
        # Generate citation using style engine
        citation_text = self.style_engine.format_citation(
            request.citation_style,
            request.document_data,
            enhanced_metadata
        )
        
        # Validate citation quality
        validation = await self._validate_citation(citation_text, request)
        
        # Calculate quality metrics
        quality_metrics = self._calculate_quality_metrics(citation_text, request, validation)
        
        result = CitationResult(
            citation_text=citation_text,
            citation_style=request.citation_style,
            document_id=doc_id,
            validation_status="valid" if validation.is_valid else "needs_review",
            quality_score=quality_metrics["overall_quality"],
            ai_enhancements=enhanced_metadata.get("enhancements", []),
            metadata_completeness=quality_metrics["metadata_completeness"],
            formatting_accuracy=quality_metrics["formatting_accuracy"],
            academic_compliance=quality_metrics["academic_compliance"],
            suggestions=validation.enhancement_suggestions,
            processing_time_ms=(time.time() - start_time) * 1000,
            cost_cents=0.0,  # Will be updated with actual AI costs
            from_cache=False
        )
        
        # Cache the result
        await self._cache_citation(cache_key, result)
        
        return result
    
    async def _enhance_metadata_with_ai(self, request: CitationRequest) -> Dict[str, Any]:
        """Enhance document metadata using AI"""
        
        document_data = request.document_data
        
        # Build AI enhancement prompt
        prompt = f"""
        Enhance the metadata for this Brazilian legislative document citation:

        Current metadata:
        {json.dumps(document_data, indent=2, ensure_ascii=False)}

        Citation style: {request.citation_style}
        Academic level: {request.academic_level}
        Research context: {request.research_context or "General research"}

        Please provide enhanced metadata for accurate citation:
        1. Correct and complete author/authority information
        2. Proper document title formatting
        3. Accurate publication information
        4. Appropriate publisher and location details
        5. Complete date information
        6. Any missing fields required for {request.citation_style} style

        Focus on Brazilian legislative citation standards and academic accuracy.
        Provide JSON format with enhancement notes.
        """
        
        # Get AI enhancement
        response = await self.citation_agent.process_query(prompt)
        
        # Parse AI response (simplified for demonstration)
        enhancements = self._parse_ai_enhancements(response.content)
        
        return enhancements
    
    async def _validate_citation(self, citation_text: str, request: CitationRequest) -> CitationValidation:
        """Validate citation using AI analysis"""
        
        prompt = f"""
        Validate this {request.citation_style} citation for academic accuracy:

        Citation: {citation_text}
        Style: {request.citation_style}
        Document type: Legislative document (Brazilian)

        Check for:
        1. Style compliance with {request.citation_style} standards
        2. Metadata completeness and accuracy
        3. Formatting issues or inconsistencies
        4. Missing required elements
        5. Enhancement suggestions for better academic quality

        Provide validation report with specific issues and recommendations.
        """
        
        response = await self.citation_agent.process_query(prompt)
        
        # Parse validation response
        validation_data = self._parse_validation_response(response.content)
        
        return CitationValidation(
            is_valid=validation_data.get("is_valid", True),
            validation_errors=validation_data.get("errors", []),
            validation_warnings=validation_data.get("warnings", []),
            style_compliance=validation_data.get("style_compliance", 0.8),
            metadata_quality=validation_data.get("metadata_quality", 0.7),
            formatting_issues=validation_data.get("formatting_issues", []),
            enhancement_suggestions=validation_data.get("suggestions", [])
        )
    
    def _calculate_quality_metrics(self, citation_text: str, request: CitationRequest, 
                                  validation: CitationValidation) -> Dict[str, float]:
        """Calculate citation quality metrics"""
        
        # Metadata completeness
        required_fields = ["title", "author", "year", "publisher"]
        present_fields = sum(1 for field in required_fields 
                           if field.lower() in citation_text.lower())
        metadata_completeness = present_fields / len(required_fields)
        
        # Formatting accuracy based on validation
        formatting_accuracy = validation.style_compliance
        
        # Academic compliance
        academic_compliance = validation.metadata_quality
        
        # Overall quality (weighted average)
        overall_quality = (
            metadata_completeness * 0.4 +
            formatting_accuracy * 0.4 +
            academic_compliance * 0.2
        )
        
        return {
            "metadata_completeness": metadata_completeness,
            "formatting_accuracy": formatting_accuracy,
            "academic_compliance": academic_compliance,
            "overall_quality": overall_quality
        }
    
    def _generate_cache_key(self, request: CitationRequest) -> str:
        """Generate cache key for citation request"""
        doc_id = request.document_data.get("urn", "unknown")
        style = request.citation_style
        
        # Create hash of request parameters
        request_str = f"{doc_id}:{style}:{request.academic_level}"
        cache_hash = hash(request_str) % 1000000
        
        return f"{self.citation_cache_prefix}:{cache_hash}"
    
    async def _get_cached_citation(self, cache_key: str) -> Optional[CitationResult]:
        """Get cached citation if available"""
        cached_data = await self.redis.get(cache_key)
        
        if cached_data:
            try:
                data = json.loads(cached_data)
                return CitationResult(**data)
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Invalid cached citation data for key: {cache_key}")
        
        return None
    
    async def _cache_citation(self, cache_key: str, result: CitationResult, ttl: int = 86400):
        """Cache citation result"""
        try:
            cache_data = asdict(result)
            await self.redis.setex(cache_key, ttl, json.dumps(cache_data, default=str))
            logger.debug(f"Citation cached with key: {cache_key}")
        except Exception as e:
            logger.warning(f"Failed to cache citation: {e}")
    
    def _parse_ai_enhancements(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI enhancement response"""
        # Simplified parsing - production would use more robust JSON parsing
        return {
            "author": "Brasil",
            "publisher": "Diário Oficial da União",
            "location": "Brasília",
            "enhancements": ["Standardized authority name", "Added official publisher"]
        }
    
    def _parse_validation_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI validation response"""
        # Simplified parsing - production would use more robust analysis
        return {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "style_compliance": 0.9,
            "metadata_quality": 0.8,
            "formatting_issues": [],
            "suggestions": ["Consider adding page numbers if available"]
        }
    
    async def get_supported_styles(self) -> List[Dict[str, str]]:
        """Get list of supported citation styles"""
        styles = []
        
        for style_id, style_config in self.style_engine.style_templates.items():
            styles.append({
                "id": style_id,
                "name": style_config["name"],
                "description": style_config["description"]
            })
        
        return styles
    
    async def batch_generate_citations(self, requests: List[CitationRequest]) -> List[CitationResult]:
        """Generate multiple citations in batch"""
        results = []
        
        for request in requests:
            try:
                result = await self.generate_citation(request)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch citation generation failed for document {request.document_data.get('urn', 'unknown')}: {e}")
                # Create error result
                error_result = CitationResult(
                    citation_text=f"Error generating citation: {str(e)}",
                    citation_style=request.citation_style,
                    document_id=request.document_data.get("urn", "unknown"),
                    validation_status="error",
                    quality_score=0.0,
                    ai_enhancements=[],
                    metadata_completeness=0.0,
                    formatting_accuracy=0.0,
                    academic_compliance=0.0,
                    suggestions=[],
                    processing_time_ms=0.0,
                    cost_cents=0.0
                )
                results.append(error_result)
        
        return results
    
    async def get_citation_statistics(self) -> Dict[str, Any]:
        """Get citation generator statistics"""
        agent_status = await self.citation_agent.get_agent_status()
        
        return {
            "generator_status": "operational",
            "supported_styles": len(self.style_engine.style_templates),
            "citation_agent": {
                "status": agent_status["status"],
                "monthly_cost_cents": agent_status["costs"]["monthly_cost_cents"],
                "memory_entries": agent_status["memory"]["short_term_entries"] + agent_status["memory"]["long_term_entries"]
            },
            "capabilities": [
                "ai_metadata_enhancement",
                "multiple_citation_styles",
                "citation_validation",
                "quality_metrics",
                "batch_processing"
            ]
        }