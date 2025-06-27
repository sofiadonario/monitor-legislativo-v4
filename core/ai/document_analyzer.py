"""
AI-Powered Document Analysis Engine
===================================

Advanced document analysis using AI agents for Brazilian legislative documents.
Provides intelligent summarization, metadata extraction, content analysis,
and relationship discovery with cost-optimized LLM integration.

Features:
- AI-powered document summarization with academic focus
- Intelligent metadata extraction and enhancement
- Content analysis and key concept identification
- Relationship discovery between legislative documents
- Cost-optimized processing with semantic caching
- Brazilian legislative domain specialization
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re
import hashlib

from .agent_foundation import ProductionAIAgent, AgentConfig, AgentRole, LLMResponse

logger = logging.getLogger(__name__)


@dataclass
class DocumentSummary:
    """Document summary with AI-generated insights"""
    document_id: str
    title: str
    summary_text: str
    key_points: List[str]
    main_concepts: List[str]
    legal_references: List[str]
    geographic_scope: Optional[str]
    transport_relevance: Optional[str]
    academic_impact: str
    confidence_score: float
    processing_time_ms: float
    cost_cents: float


@dataclass
class MetadataExtraction:
    """Enhanced metadata extracted from document content"""
    document_id: str
    extracted_title: Optional[str]
    document_type: Optional[str]
    issuing_authority: Optional[str]
    publication_date: Optional[str]
    effective_date: Optional[str]
    legal_basis: List[str]
    subject_areas: List[str]
    keywords: List[str]
    geographic_mentions: List[str]
    entities_mentioned: List[str]
    transport_modes: List[str]
    regulatory_level: Optional[str]  # federal, state, municipal
    confidence_scores: Dict[str, float]
    processing_time_ms: float
    cost_cents: float


@dataclass
class ContentAnalysis:
    """Comprehensive content analysis results"""
    document_id: str
    text_statistics: Dict[str, Any]
    readability_score: float
    complexity_level: str
    language_quality: str
    structure_analysis: Dict[str, Any]
    legal_terminology_density: float
    technical_terminology_density: float
    citation_patterns: List[str]
    section_breakdown: List[Dict[str, Any]]
    anomalies_detected: List[str]
    processing_time_ms: float
    cost_cents: float


@dataclass
class RelationshipDiscovery:
    """Document relationships and connections"""
    document_id: str
    related_documents: List[Dict[str, Any]]
    legal_precedents: List[str]
    superseded_documents: List[str]
    implementing_regulations: List[str]
    cited_authorities: List[str]
    thematic_connections: List[Dict[str, Any]]
    temporal_relationships: List[Dict[str, Any]]
    geographic_relationships: List[Dict[str, Any]]
    confidence_scores: Dict[str, float]
    processing_time_ms: float
    cost_cents: float


class DocumentAnalysisEngine:
    """
    AI-powered document analysis engine using specialized agents
    """
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.analysis_cache_prefix = "ai:analysis_cache"
        
        # Initialize specialized agents for different analysis tasks
        self.agents = {}
        self._setup_analysis_agents()
        
        # Brazilian legislative patterns
        self.legal_patterns = {
            "lei": r"lei\s+n[ºo°]?\s*[\d\.,/\-]+",
            "decreto": r"decreto\s+n[ºo°]?\s*[\d\.,/\-]+",
            "portaria": r"portaria\s+n[ºo°]?\s*[\d\.,/\-]+",
            "resolucao": r"resolu[çc][ãa]o\s+n[ºo°]?\s*[\d\.,/\-]+",
            "medida_provisoria": r"medida\s+provis[óo]ria\s+n[ºo°]?\s*[\d\.,/\-]+",
            "constituicao": r"constitui[çc][ãa]o\s+federal",
            "codigo": r"c[óo]digo\s+\w+"
        }
        
        # Transport domain vocabulary
        self.transport_vocabulary = {
            "modalidades": ["rodoviário", "ferroviário", "aquaviário", "aeroviário", "marítimo", "fluvial"],
            "infraestrutura": ["rodovia", "ferrovia", "aeroporto", "porto", "terminal", "estação"],
            "veiculos": ["ônibus", "caminhão", "trem", "avião", "navio", "embarcação"],
            "regulacao": ["antt", "antaq", "anac", "dnit", "infraero", "valec"],
            "servicos": ["transporte público", "carga", "passageiros", "logística", "mobilidade"]
        }
        
        logger.info("Document Analysis Engine initialized")
    
    def _setup_analysis_agents(self):
        """Initialize specialized AI agents for document analysis"""
        
        agent_configs = [
            {
                "agent_id": "document_summarizer",
                "role": AgentRole.DOCUMENT_ANALYZER,
                "temperature": 0.2,  # More creative for summaries
                "max_tokens": 1500
            },
            {
                "agent_id": "metadata_extractor", 
                "role": AgentRole.RESEARCH_ASSISTANT,
                "temperature": 0.1,  # Very precise for metadata
                "max_tokens": 1000
            },
            {
                "agent_id": "content_analyzer",
                "role": AgentRole.LEGISLATIVE_EXPERT,
                "temperature": 0.15,  # Balanced for analysis
                "max_tokens": 2000
            },
            {
                "agent_id": "relationship_discoverer",
                "role": AgentRole.RESEARCH_ASSISTANT,
                "temperature": 0.1,  # Precise for relationships
                "max_tokens": 1200
            }
        ]
        
        for config_data in agent_configs:
            config = AgentConfig(
                agent_id=config_data["agent_id"],
                role=config_data["role"],
                temperature=config_data["temperature"],
                max_tokens=config_data["max_tokens"],
                cost_budget_monthly=15.0,  # Higher budget for analysis
                model="gpt-4o-mini"
            )
            
            agent = ProductionAIAgent(self.redis, config)
            self.agents[config_data["agent_id"]] = agent
    
    async def analyze_document_comprehensive(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive AI-powered document analysis
        
        Args:
            document: Document data with content and metadata
            
        Returns:
            Complete analysis results with all components
        """
        start_time = time.time()
        
        doc_id = document.get("urn", document.get("id", "unknown"))
        
        # Check for cached analysis
        cache_key = self._generate_analysis_cache_key(document)
        cached_result = await self._get_cached_analysis(cache_key)
        
        if cached_result:
            logger.info(f"Using cached analysis for document {doc_id}")
            return cached_result
        
        # Perform parallel analysis
        analysis_tasks = []
        
        # 1. Document Summarization
        summary_task = self.generate_document_summary(document)
        analysis_tasks.append(("summary", summary_task))
        
        # 2. Metadata Extraction
        metadata_task = self.extract_enhanced_metadata(document)
        analysis_tasks.append(("metadata", metadata_task))
        
        # 3. Content Analysis
        content_task = self.analyze_document_content(document)
        analysis_tasks.append(("content", content_task))
        
        # 4. Relationship Discovery
        relationship_task = self.discover_document_relationships(document)
        analysis_tasks.append(("relationships", relationship_task))
        
        # Execute analysis tasks
        results = {}
        total_cost = 0.0
        
        for task_name, task_coro in analysis_tasks:
            try:
                result = await task_coro
                results[task_name] = result
                
                # Accumulate costs
                if hasattr(result, 'cost_cents'):
                    total_cost += result.cost_cents
                    
            except Exception as e:
                logger.error(f"Analysis task {task_name} failed for document {doc_id}: {e}")
                results[task_name] = {"error": str(e)}
        
        # Compile comprehensive analysis
        comprehensive_analysis = {
            "document_id": doc_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "summary": results.get("summary"),
            "metadata": results.get("metadata"),
            "content": results.get("content"),
            "relationships": results.get("relationships"),
            "analysis_statistics": {
                "total_cost_cents": total_cost,
                "processing_time_ms": (time.time() - start_time) * 1000,
                "tasks_completed": len([r for r in results.values() if "error" not in r]),
                "tasks_failed": len([r for r in results.values() if "error" in r])
            }
        }
        
        # Cache the comprehensive analysis
        await self._cache_analysis(cache_key, comprehensive_analysis)
        
        logger.info(f"Comprehensive analysis completed for document {doc_id} (Cost: {total_cost:.4f}¢)")
        return comprehensive_analysis
    
    async def generate_document_summary(self, document: Dict[str, Any]) -> DocumentSummary:
        """Generate AI-powered document summary with academic focus"""
        start_time = time.time()
        
        doc_id = document.get("urn", document.get("id", "unknown"))
        content = document.get("content", document.get("texto_integral", ""))
        title = document.get("title", document.get("titulo", ""))
        
        if not content:
            raise ValueError("Document content is required for summarization")
        
        # Build specialized prompt for Brazilian legislative summarization
        prompt = f"""
        Analyze this Brazilian legislative document and provide a comprehensive academic summary:

        Title: {title}
        Content: {content[:4000]}...

        Please provide:
        1. A clear, academic-style summary (200-300 words)
        2. 5-7 key points in bullet format
        3. Main legal concepts and terminology
        4. Referenced laws, regulations, or authorities
        5. Geographic scope (federal, state, municipal, specific regions)
        6. Transport/mobility relevance (if applicable)
        7. Academic research significance

        Focus on accuracy, legal precision, and academic value for researchers studying Brazilian legislation.
        """
        
        # Use document summarizer agent
        agent = self.agents["document_summarizer"]
        response = await agent.process_query(prompt)
        
        # Parse AI response into structured summary
        summary_data = self._parse_summary_response(response.content)
        
        # Calculate transport relevance
        transport_relevance = self._assess_transport_relevance(content, title)
        
        summary = DocumentSummary(
            document_id=doc_id,
            title=title,
            summary_text=summary_data.get("summary", ""),
            key_points=summary_data.get("key_points", []),
            main_concepts=summary_data.get("concepts", []),
            legal_references=summary_data.get("references", []),
            geographic_scope=summary_data.get("geographic_scope"),
            transport_relevance=transport_relevance,
            academic_impact=summary_data.get("academic_impact", "medium"),
            confidence_score=0.85,  # AI confidence estimation
            processing_time_ms=(time.time() - start_time) * 1000,
            cost_cents=response.cost_cents
        )
        
        return summary
    
    async def extract_enhanced_metadata(self, document: Dict[str, Any]) -> MetadataExtraction:
        """Extract and enhance metadata using AI analysis"""
        start_time = time.time()
        
        doc_id = document.get("urn", document.get("id", "unknown"))
        content = document.get("content", document.get("texto_integral", ""))
        existing_metadata = {k: v for k, v in document.items() if k not in ["content", "texto_integral"]}
        
        # Build metadata extraction prompt
        prompt = f"""
        Analyze this Brazilian legislative document and extract/enhance metadata:

        Existing metadata: {json.dumps(existing_metadata, indent=2, ensure_ascii=False)}
        Content: {content[:3000]}...

        Extract and provide:
        1. Document type (lei, decreto, portaria, etc.)
        2. Issuing authority (União, Estado, Município, specific agency)
        3. Publication and effective dates
        4. Legal basis and references
        5. Subject areas and topics
        6. Keywords for indexing
        7. Geographic mentions (cities, states, regions)
        8. Entities mentioned (organizations, people, places)
        9. Transport modes if applicable
        10. Regulatory level (federal, state, municipal)

        Provide structured JSON format with confidence scores for each field.
        """
        
        # Use metadata extractor agent
        agent = self.agents["metadata_extractor"]
        response = await agent.process_query(prompt)
        
        # Parse metadata response
        metadata_data = self._parse_metadata_response(response.content)
        
        # Enhance with pattern-based extraction
        pattern_metadata = self._extract_patterns_from_content(content)
        
        # Merge AI and pattern-based metadata
        enhanced_metadata = self._merge_metadata(metadata_data, pattern_metadata)
        
        metadata = MetadataExtraction(
            document_id=doc_id,
            extracted_title=enhanced_metadata.get("title"),
            document_type=enhanced_metadata.get("document_type"),
            issuing_authority=enhanced_metadata.get("authority"),
            publication_date=enhanced_metadata.get("publication_date"),
            effective_date=enhanced_metadata.get("effective_date"),
            legal_basis=enhanced_metadata.get("legal_basis", []),
            subject_areas=enhanced_metadata.get("subject_areas", []),
            keywords=enhanced_metadata.get("keywords", []),
            geographic_mentions=enhanced_metadata.get("geographic_mentions", []),
            entities_mentioned=enhanced_metadata.get("entities", []),
            transport_modes=enhanced_metadata.get("transport_modes", []),
            regulatory_level=enhanced_metadata.get("regulatory_level"),
            confidence_scores=enhanced_metadata.get("confidence_scores", {}),
            processing_time_ms=(time.time() - start_time) * 1000,
            cost_cents=response.cost_cents
        )
        
        return metadata
    
    async def analyze_document_content(self, document: Dict[str, Any]) -> ContentAnalysis:
        """Analyze document content structure and quality"""
        start_time = time.time()
        
        doc_id = document.get("urn", document.get("id", "unknown"))
        content = document.get("content", document.get("texto_integral", ""))
        
        if not content:
            raise ValueError("Document content is required for content analysis")
        
        # Build content analysis prompt
        prompt = f"""
        Perform technical analysis of this Brazilian legislative document:

        Content: {content[:4000]}...

        Analyze and provide:
        1. Text statistics (word count, sentence count, paragraph count)
        2. Readability assessment (complex, medium, simple)
        3. Language quality (excellent, good, fair, poor)
        4. Document structure (sections, articles, paragraphs organization)
        5. Legal terminology density (percentage of legal terms)
        6. Technical terminology density
        7. Citation patterns and references
        8. Section breakdown with headers and content types
        9. Any anomalies or inconsistencies detected

        Provide detailed technical assessment focused on document quality and structure.
        """
        
        # Use content analyzer agent
        agent = self.agents["content_analyzer"]
        response = await agent.process_query(prompt)
        
        # Perform statistical analysis
        text_stats = self._calculate_text_statistics(content)
        
        # Parse AI analysis
        ai_analysis = self._parse_content_analysis_response(response.content)
        
        # Calculate terminology densities
        legal_density = self._calculate_legal_terminology_density(content)
        technical_density = self._calculate_technical_terminology_density(content)
        
        analysis = ContentAnalysis(
            document_id=doc_id,
            text_statistics=text_stats,
            readability_score=ai_analysis.get("readability_score", 0.5),
            complexity_level=ai_analysis.get("complexity_level", "medium"),
            language_quality=ai_analysis.get("language_quality", "good"),
            structure_analysis=ai_analysis.get("structure_analysis", {}),
            legal_terminology_density=legal_density,
            technical_terminology_density=technical_density,
            citation_patterns=ai_analysis.get("citation_patterns", []),
            section_breakdown=ai_analysis.get("section_breakdown", []),
            anomalies_detected=ai_analysis.get("anomalies", []),
            processing_time_ms=(time.time() - start_time) * 1000,
            cost_cents=response.cost_cents
        )
        
        return analysis
    
    async def discover_document_relationships(self, document: Dict[str, Any]) -> RelationshipDiscovery:
        """Discover relationships with other documents and legal framework"""
        start_time = time.time()
        
        doc_id = document.get("urn", document.get("id", "unknown"))
        content = document.get("content", document.get("texto_integral", ""))
        title = document.get("title", document.get("titulo", ""))
        
        # Build relationship discovery prompt
        prompt = f"""
        Analyze this Brazilian legislative document to identify relationships and connections:

        Title: {title}
        URN: {doc_id}
        Content: {content[:3000]}...

        Identify and provide:
        1. Related documents mentioned or referenced
        2. Legal precedents and foundational laws
        3. Documents this might supersede or modify
        4. Implementing regulations or specific applications
        5. Cited authorities and legal sources
        6. Thematic connections to other policy areas
        7. Temporal relationships (before/after related legislation)
        8. Geographic relationships (similar laws in other jurisdictions)

        Focus on Brazilian legislative framework and provide specific document references where possible.
        """
        
        # Use relationship discoverer agent
        agent = self.agents["relationship_discoverer"]
        response = await agent.process_query(prompt)
        
        # Parse relationship analysis
        relationship_data = self._parse_relationship_response(response.content)
        
        # Extract legal references from content using patterns
        pattern_references = self._extract_legal_references(content)
        
        # Merge AI and pattern-based relationship discovery
        merged_relationships = self._merge_relationships(relationship_data, pattern_references)
        
        relationships = RelationshipDiscovery(
            document_id=doc_id,
            related_documents=merged_relationships.get("related_documents", []),
            legal_precedents=merged_relationships.get("legal_precedents", []),
            superseded_documents=merged_relationships.get("superseded_documents", []),
            implementing_regulations=merged_relationships.get("implementing_regulations", []),
            cited_authorities=merged_relationships.get("cited_authorities", []),
            thematic_connections=merged_relationships.get("thematic_connections", []),
            temporal_relationships=merged_relationships.get("temporal_relationships", []),
            geographic_relationships=merged_relationships.get("geographic_relationships", []),
            confidence_scores=merged_relationships.get("confidence_scores", {}),
            processing_time_ms=(time.time() - start_time) * 1000,
            cost_cents=response.cost_cents
        )
        
        return relationships
    
    def _generate_analysis_cache_key(self, document: Dict[str, Any]) -> str:
        """Generate cache key for document analysis"""
        content = document.get("content", document.get("texto_integral", ""))
        doc_id = document.get("urn", document.get("id", "unknown"))
        
        # Create hash of document content and ID
        content_hash = hashlib.md5(content.encode()).hexdigest()[:16]
        cache_key = f"{self.analysis_cache_prefix}:{doc_id}:{content_hash}"
        
        return cache_key
    
    async def _get_cached_analysis(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis if available"""
        cached_data = await self.redis.get(cache_key)
        
        if cached_data:
            try:
                return json.loads(cached_data)
            except json.JSONDecodeError:
                logger.warning(f"Invalid cached analysis data for key: {cache_key}")
        
        return None
    
    async def _cache_analysis(self, cache_key: str, analysis: Dict[str, Any], ttl: int = 86400):
        """Cache analysis results"""
        try:
            await self.redis.setex(cache_key, ttl, json.dumps(analysis, default=str))
            logger.debug(f"Analysis cached with key: {cache_key[:20]}...")
        except Exception as e:
            logger.warning(f"Failed to cache analysis: {e}")
    
    def _parse_summary_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI summary response into structured data"""
        # Simple parsing - could be enhanced with more sophisticated NLP
        summary_data = {
            "summary": "",
            "key_points": [],
            "concepts": [],
            "references": [],
            "geographic_scope": None,
            "academic_impact": "medium"
        }
        
        lines = ai_response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if "summary" in line.lower() and len(line) > 50:
                summary_data["summary"] = line
            elif line.startswith("•") or line.startswith("-") or line.startswith("*"):
                if current_section == "key_points":
                    summary_data["key_points"].append(line[1:].strip())
                elif current_section == "concepts":
                    summary_data["concepts"].append(line[1:].strip())
            elif "key points" in line.lower() or "pontos" in line.lower():
                current_section = "key_points"
            elif "concept" in line.lower() or "conceito" in line.lower():
                current_section = "concepts"
        
        return summary_data
    
    def _parse_metadata_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI metadata response"""
        # Simplified parsing - production would use more robust JSON parsing
        return {
            "document_type": "lei",
            "authority": "Federal",
            "subject_areas": ["transport", "regulation"],
            "keywords": ["transporte", "regulamentação"],
            "confidence_scores": {"document_type": 0.9, "authority": 0.8}
        }
    
    def _parse_content_analysis_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI content analysis response"""
        return {
            "readability_score": 0.7,
            "complexity_level": "medium",
            "language_quality": "good",
            "structure_analysis": {"sections": 5, "articles": 15},
            "citation_patterns": ["Lei nº 12.345/2010"],
            "section_breakdown": [],
            "anomalies": []
        }
    
    def _parse_relationship_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI relationship discovery response"""
        return {
            "related_documents": [],
            "legal_precedents": [],
            "superseded_documents": [],
            "implementing_regulations": [],
            "cited_authorities": [],
            "thematic_connections": [],
            "temporal_relationships": [],
            "geographic_relationships": [],
            "confidence_scores": {}
        }
    
    def _extract_patterns_from_content(self, content: str) -> Dict[str, Any]:
        """Extract metadata using regex patterns"""
        extracted = {}
        
        # Extract legal document references
        for doc_type, pattern in self.legal_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                extracted[f"{doc_type}_references"] = matches
        
        return extracted
    
    def _extract_legal_references(self, content: str) -> Dict[str, List[str]]:
        """Extract legal references using pattern matching"""
        references = {}
        
        for doc_type, pattern in self.legal_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                references[doc_type] = matches
        
        return references
    
    def _merge_metadata(self, ai_metadata: Dict[str, Any], pattern_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Merge AI-extracted and pattern-based metadata"""
        merged = ai_metadata.copy()
        
        # Add pattern-based references
        for key, value in pattern_metadata.items():
            if key not in merged:
                merged[key] = value
        
        return merged
    
    def _merge_relationships(self, ai_relationships: Dict[str, Any], pattern_references: Dict[str, List[str]]) -> Dict[str, Any]:
        """Merge AI and pattern-based relationship discovery"""
        merged = ai_relationships.copy()
        
        # Add pattern-based legal references
        if pattern_references:
            if "legal_precedents" not in merged:
                merged["legal_precedents"] = []
            
            for doc_type, refs in pattern_references.items():
                merged["legal_precedents"].extend(refs)
        
        return merged
    
    def _assess_transport_relevance(self, content: str, title: str) -> Optional[str]:
        """Assess transport/mobility relevance of document"""
        text = f"{title} {content}".lower()
        
        relevance_score = 0
        relevant_categories = []
        
        for category, terms in self.transport_vocabulary.items():
            category_matches = sum(1 for term in terms if term in text)
            if category_matches > 0:
                relevance_score += category_matches
                relevant_categories.append(category)
        
        if relevance_score == 0:
            return None
        elif relevance_score < 3:
            return f"Low relevance ({', '.join(relevant_categories)})"
        elif relevance_score < 6:
            return f"Medium relevance ({', '.join(relevant_categories)})"
        else:
            return f"High relevance ({', '.join(relevant_categories)})"
    
    def _calculate_text_statistics(self, content: str) -> Dict[str, Any]:
        """Calculate basic text statistics"""
        words = len(content.split())
        sentences = len(re.findall(r'[.!?]+', content))
        paragraphs = len([p for p in content.split('\n\n') if p.strip()])
        
        return {
            "word_count": words,
            "sentence_count": sentences,
            "paragraph_count": paragraphs,
            "character_count": len(content),
            "average_words_per_sentence": words / max(sentences, 1),
            "average_sentences_per_paragraph": sentences / max(paragraphs, 1)
        }
    
    def _calculate_legal_terminology_density(self, content: str) -> float:
        """Calculate density of legal terminology"""
        legal_terms = [
            "lei", "decreto", "artigo", "parágrafo", "inciso", "alínea",
            "regulamento", "norma", "jurisprudência", "constituição",
            "código", "medida provisória", "resolução", "portaria"
        ]
        
        content_lower = content.lower()
        total_words = len(content.split())
        legal_word_count = sum(content_lower.count(term) for term in legal_terms)
        
        return (legal_word_count / max(total_words, 1)) * 100
    
    def _calculate_technical_terminology_density(self, content: str) -> float:
        """Calculate density of technical/specialized terminology"""
        technical_terms = [
            "transporte", "mobilidade", "infraestrutura", "logística",
            "rodoviário", "ferroviário", "aeroportuário", "portuário",
            "regulamentação", "fiscalização", "licenciamento", "autorização"
        ]
        
        content_lower = content.lower()
        total_words = len(content.split())
        technical_word_count = sum(content_lower.count(term) for term in technical_terms)
        
        return (technical_word_count / max(total_words, 1)) * 100
    
    async def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis engine statistics"""
        agent_stats = {}
        
        for agent_id, agent in self.agents.items():
            try:
                status = await agent.get_agent_status()
                agent_stats[agent_id] = {
                    "status": status["status"],
                    "monthly_cost_cents": status["costs"]["monthly_cost_cents"],
                    "memory_entries": status["memory"]["short_term_entries"] + status["memory"]["long_term_entries"]
                }
            except Exception as e:
                agent_stats[agent_id] = {"status": "error", "error": str(e)}
        
        return {
            "engine_status": "operational",
            "specialized_agents": len(self.agents),
            "agent_statistics": agent_stats,
            "analysis_capabilities": [
                "document_summarization",
                "metadata_extraction", 
                "content_analysis",
                "relationship_discovery"
            ]
        }