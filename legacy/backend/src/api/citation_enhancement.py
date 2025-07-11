"""
Citation Enhancement API - Multiple citation formats (APA, Vancouver, BibTeX) and LaTeX integration
Provides comprehensive citation generation for Brazilian legislative documents
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

logger = logging.getLogger(__name__)

# Router for citation enhancement API
router = APIRouter(prefix="/api/v1/citation-enhancement", tags=["Citation Enhancement"])

class CitationStyle(str, Enum):
    """Supported citation styles"""
    ABNT = "abnt"
    APA = "apa"
    VANCOUVER = "vancouver"
    BIBTEX = "bibtex"
    CHICAGO = "chicago"
    MLA = "mla"
    LEXML = "lexml"

class DocumentClass(str, Enum):
    """Document classes for LaTeX"""
    ARTICLE = "article"
    BOOK = "book"
    THESIS = "thesis"
    REPORT = "report"
    PRESENTATION = "presentation"

class OutputFormat(str, Enum):
    """Output formats for citations"""
    TEXT = "text"
    HTML = "html"
    LATEX = "latex"
    MARKDOWN = "markdown"
    XML = "xml"

@dataclass
class Author:
    """Author information"""
    first_name: str
    last_name: str
    middle_name: Optional[str] = None
    institution: Optional[str] = None
    role: Optional[str] = None

@dataclass
class CitationData:
    """Complete citation data"""
    title: str
    authors: List[Author]
    publication_date: str
    document_type: str
    authority: str
    number: Optional[str] = None
    year: Optional[str] = None
    url: Optional[str] = None
    urn: Optional[str] = None
    pages: Optional[str] = None
    volume: Optional[str] = None
    issue: Optional[str] = None
    publisher: Optional[str] = None
    place_of_publication: Optional[str] = None
    access_date: Optional[str] = None
    doi: Optional[str] = None
    isbn: Optional[str] = None

@dataclass
class FormattedCitation:
    """Formatted citation result"""
    citation_id: str
    style: CitationStyle
    format: OutputFormat
    content: str
    bibtex_key: Optional[str] = None
    latex_packages: List[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class BibliographyEntry:
    """Bibliography entry"""
    key: str
    entry_type: str
    fields: Dict[str, str]
    formatted_entry: str

@dataclass
class LaTeXDocument:
    """Complete LaTeX document with citations"""
    document_class: DocumentClass
    packages: List[str]
    preamble: str
    body: str
    bibliography: str
    citations: List[FormattedCitation]

# Pydantic models for API
class CitationRequest(BaseModel):
    citation_data: Dict[str, Any] = Field(..., description="Citation data")
    styles: List[CitationStyle] = Field(default=[CitationStyle.ABNT], description="Citation styles to generate")
    output_formats: List[OutputFormat] = Field(default=[OutputFormat.TEXT], description="Output formats")
    include_latex: bool = Field(default=False, description="Include LaTeX formatting")
    locale: str = Field(default="pt-BR", description="Locale for formatting")

class BibliographyRequest(BaseModel):
    citations: List[Dict[str, Any]] = Field(..., description="List of citations")
    style: CitationStyle = Field(default=CitationStyle.ABNT, description="Bibliography style")
    sort_order: str = Field(default="alphabetical", description="Sort order (alphabetical, chronological, appearance)")
    include_urls: bool = Field(default=True, description="Include URLs in bibliography")

class LaTeXDocumentRequest(BaseModel):
    document_class: DocumentClass = Field(default=DocumentClass.ARTICLE, description="LaTeX document class")
    title: str = Field(..., description="Document title")
    authors: List[str] = Field(..., description="Document authors")
    citations: List[Dict[str, Any]] = Field(..., description="Citations to include")
    content: Optional[str] = Field(default=None, description="Document content")
    bibliography_style: CitationStyle = Field(default=CitationStyle.ABNT, description="Bibliography style")

class CitationResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class CitationEnhancementProcessor:
    """Citation enhancement processor with multiple formats and LaTeX support"""
    
    def __init__(self):
        self.citation_cache = {}
        self.style_formatters = {}
        self.latex_templates = {}
        
        # Initialize formatters and templates
        self._init_style_formatters()
        self._init_latex_templates()
    
    async def initialize(self) -> bool:
        """Initialize citation enhancement processor"""
        try:
            logger.info("✅ Citation enhancement processor initialized")
            return True
            
        except Exception as e:
            logger.error(f"Citation enhancement processor initialization failed: {e}")
            return False
    
    async def generate_citations(
        self,
        citation_data: Dict[str, Any],
        styles: List[CitationStyle],
        output_formats: List[OutputFormat],
        include_latex: bool = False,
        locale: str = "pt-BR"
    ) -> List[FormattedCitation]:
        """Generate citations in multiple styles and formats"""
        
        # Parse citation data
        parsed_data = self._parse_citation_data(citation_data)
        
        citations = []
        
        for style in styles:
            for output_format in output_formats:
                citation = await self._format_citation(
                    parsed_data, style, output_format, include_latex, locale
                )
                citations.append(citation)
        
        return citations
    
    async def generate_bibliography(
        self,
        citations_data: List[Dict[str, Any]],
        style: CitationStyle,
        sort_order: str = "alphabetical",
        include_urls: bool = True
    ) -> Dict[str, Any]:
        """Generate complete bibliography"""
        
        # Parse all citations
        parsed_citations = [self._parse_citation_data(data) for data in citations_data]
        
        # Sort citations
        sorted_citations = self._sort_citations(parsed_citations, sort_order)
        
        # Generate bibliography entries
        entries = []
        for i, citation_data in enumerate(sorted_citations):
            entry = await self._generate_bibliography_entry(
                citation_data, style, i + 1, include_urls
            )
            entries.append(entry)
        
        # Format complete bibliography
        formatted_bibliography = self._format_bibliography(entries, style)
        
        return {
            "style": style.value,
            "sort_order": sort_order,
            "entry_count": len(entries),
            "entries": [asdict(entry) for entry in entries],
            "formatted_text": formatted_bibliography["text"],
            "formatted_html": formatted_bibliography["html"],
            "formatted_latex": formatted_bibliography["latex"],
            "bibtex_entries": formatted_bibliography["bibtex"]
        }
    
    async def generate_latex_document(
        self,
        document_class: DocumentClass,
        title: str,
        authors: List[str],
        citations_data: List[Dict[str, Any]],
        content: Optional[str] = None,
        bibliography_style: CitationStyle = CitationStyle.ABNT
    ) -> LaTeXDocument:
        """Generate complete LaTeX document with citations"""
        
        # Parse citations
        parsed_citations = [self._parse_citation_data(data) for data in citations_data]
        
        # Generate bibliography
        bibliography_result = await self.generate_bibliography(
            citations_data, bibliography_style, "alphabetical", True
        )
        
        # Generate formatted citations
        formatted_citations = []
        for citation_data in parsed_citations:
            citation = await self._format_citation(
                citation_data, bibliography_style, OutputFormat.LATEX, True, "pt-BR"
            )
            formatted_citations.append(citation)
        
        # Get document template
        template = self.latex_templates[document_class.value]
        
        # Required packages
        packages = [
            "babel[brazilian]",
            "fontenc[T1]",
            "inputenc[utf8]",
            "geometry[margin=2.5cm]",
            "setspace",
            "abntex2cite" if bibliography_style == CitationStyle.ABNT else "natbib",
            "url",
            "hyperref"
        ]
        
        # Generate preamble
        preamble = self._generate_latex_preamble(title, authors, packages)
        
        # Generate body
        body = self._generate_latex_body(content or "", formatted_citations)
        
        # Generate bibliography
        bibliography = bibliography_result["formatted_latex"]
        
        return LaTeXDocument(
            document_class=document_class,
            packages=packages,
            preamble=preamble,
            body=body,
            bibliography=bibliography,
            citations=formatted_citations
        )
    
    # Private helper methods
    def _init_style_formatters(self):
        """Initialize citation style formatters"""
        
        self.style_formatters = {
            CitationStyle.ABNT: self._format_abnt_citation,
            CitationStyle.APA: self._format_apa_citation,
            CitationStyle.VANCOUVER: self._format_vancouver_citation,
            CitationStyle.BIBTEX: self._format_bibtex_citation,
            CitationStyle.CHICAGO: self._format_chicago_citation,
            CitationStyle.MLA: self._format_mla_citation,
            CitationStyle.LEXML: self._format_lexml_citation
        }
    
    def _init_latex_templates(self):
        """Initialize LaTeX document templates"""
        
        self.latex_templates = {
            DocumentClass.ARTICLE.value: {
                "class": "article",
                "options": ["12pt", "a4paper"],
                "structure": ["title", "author", "abstract", "sections", "bibliography"]
            },
            DocumentClass.BOOK.value: {
                "class": "book",
                "options": ["12pt", "a4paper"],
                "structure": ["title", "author", "chapters", "bibliography"]
            },
            DocumentClass.THESIS.value: {
                "class": "report",
                "options": ["12pt", "a4paper"],
                "structure": ["title", "author", "abstract", "chapters", "bibliography"]
            },
            DocumentClass.REPORT.value: {
                "class": "report",
                "options": ["12pt", "a4paper"],
                "structure": ["title", "author", "sections", "bibliography"]
            }
        }
    
    def _parse_citation_data(self, data: Dict[str, Any]) -> CitationData:
        """Parse citation data from dictionary"""
        
        # Parse authors
        authors = []
        author_data = data.get("authors", [])
        if isinstance(author_data, list):
            for author in author_data:
                if isinstance(author, str):
                    # Simple string format: "First Last"
                    parts = author.split()
                    if len(parts) >= 2:
                        authors.append(Author(
                            first_name=parts[0],
                            last_name=" ".join(parts[1:])
                        ))
                elif isinstance(author, dict):
                    authors.append(Author(**author))
        
        return CitationData(
            title=data.get("title", ""),
            authors=authors,
            publication_date=data.get("publication_date", ""),
            document_type=data.get("document_type", ""),
            authority=data.get("authority", ""),
            number=data.get("number"),
            year=data.get("year"),
            url=data.get("url"),
            urn=data.get("urn"),
            pages=data.get("pages"),
            volume=data.get("volume"),
            issue=data.get("issue"),
            publisher=data.get("publisher"),
            place_of_publication=data.get("place_of_publication"),
            access_date=data.get("access_date"),
            doi=data.get("doi"),
            isbn=data.get("isbn")
        )
    
    async def _format_citation(
        self,
        citation_data: CitationData,
        style: CitationStyle,
        output_format: OutputFormat,
        include_latex: bool,
        locale: str
    ) -> FormattedCitation:
        """Format citation in specified style and format"""
        
        # Get formatter for style
        formatter = self.style_formatters.get(style)
        if not formatter:
            raise ValueError(f"Unsupported citation style: {style}")
        
        # Generate base citation
        base_citation = formatter(citation_data, locale)
        
        # Format for output
        formatted_content = self._format_for_output(base_citation, output_format)
        
        # Generate citation ID
        citation_id = self._generate_citation_id(citation_data, style)
        
        # LaTeX packages
        latex_packages = []
        if include_latex:
            latex_packages = self._get_required_latex_packages(style)
        
        return FormattedCitation(
            citation_id=citation_id,
            style=style,
            format=output_format,
            content=formatted_content,
            bibtex_key=self._generate_bibtex_key(citation_data) if style == CitationStyle.BIBTEX else None,
            latex_packages=latex_packages if include_latex else None,
            metadata={
                "title": citation_data.title,
                "authors": [f"{a.first_name} {a.last_name}" for a in citation_data.authors],
                "year": citation_data.year,
                "document_type": citation_data.document_type
            }
        )
    
    def _format_abnt_citation(self, data: CitationData, locale: str) -> str:
        """Format citation in ABNT style (NBR 6023:2018)"""
        
        # Author(s)
        authors_str = self._format_abnt_authors(data.authors)
        
        # Title
        title = data.title.upper() if data.title else "TÍTULO NÃO ESPECIFICADO"
        
        # Publication info
        pub_info = []
        if data.place_of_publication:
            pub_info.append(data.place_of_publication)
        if data.authority:
            pub_info.append(data.authority)
        if data.publication_date:
            pub_info.append(data.publication_date)
        
        # URL and access date
        url_info = ""
        if data.url:
            url_info = f" Disponível em: {data.url}."
            if data.access_date:
                url_info += f" Acesso em: {data.access_date}."
        
        # Assemble citation
        citation_parts = [authors_str, title]
        if pub_info:
            citation_parts.append(": ".join(pub_info))
        
        citation = ". ".join(filter(None, citation_parts)) + "." + url_info
        
        return citation
    
    def _format_apa_citation(self, data: CitationData, locale: str) -> str:
        """Format citation in APA style (7th edition)"""
        
        # Author(s)
        authors_str = self._format_apa_authors(data.authors)
        
        # Year
        year = f"({data.year})" if data.year else "(s.d.)"
        
        # Title (italicized for legal documents)
        title = f"*{data.title}*" if data.title else "*Título não especificado*"
        
        # Publisher/Authority
        publisher = data.authority or data.publisher or "Autoridade não especificada"
        
        # URL
        url_info = f" {data.url}" if data.url else ""
        
        # Assemble citation
        citation = f"{authors_str} {year}. {title}. {publisher}.{url_info}"
        
        return citation
    
    def _format_vancouver_citation(self, data: CitationData, locale: str) -> str:
        """Format citation in Vancouver style"""
        
        # Author(s)
        authors_str = self._format_vancouver_authors(data.authors)
        
        # Title
        title = data.title if data.title else "Título não especificado"
        
        # Publication info
        pub_info = data.authority or data.publisher or "Autoridade não especificada"
        
        # Year
        year = data.year or "ano não especificado"
        
        # URL
        url_info = f" [citado {data.access_date or datetime.now().strftime('%Y %b %d')}]. Disponível em: {data.url}" if data.url else ""
        
        # Assemble citation
        citation = f"{authors_str}. {title}. {pub_info}; {year}.{url_info}"
        
        return citation
    
    def _format_bibtex_citation(self, data: CitationData, locale: str) -> str:
        """Format citation as BibTeX entry"""
        
        # Determine entry type
        entry_type = self._determine_bibtex_entry_type(data.document_type)
        
        # Generate key
        key = self._generate_bibtex_key(data)
        
        # Build fields
        fields = []
        
        # Title
        if data.title:
            fields.append(f'  title = {{{data.title}}}')
        
        # Author(s)
        if data.authors:
            authors_bibtex = " and ".join([f"{a.last_name}, {a.first_name}" for a in data.authors])
            fields.append(f'  author = {{{authors_bibtex}}}')
        
        # Year
        if data.year:
            fields.append(f'  year = {{{data.year}}}')
        
        # Institution/Publisher
        if data.authority:
            fields.append(f'  institution = {{{data.authority}}}')
        
        # Number
        if data.number:
            fields.append(f'  number = {{{data.number}}}')
        
        # URL
        if data.url:
            fields.append(f'  url = {{{data.url}}}')
        
        # Access date
        if data.access_date:
            fields.append(f'  urldate = {{{data.access_date}}}')
        
        # Note about document type
        if data.document_type:
            fields.append(f'  note = {{{data.document_type}}}')
        
        # Assemble BibTeX entry
        bibtex_entry = f"@{entry_type}{{{key},\n" + ",\n".join(fields) + "\n}"
        
        return bibtex_entry
    
    def _format_chicago_citation(self, data: CitationData, locale: str) -> str:
        """Format citation in Chicago style"""
        
        # Author(s)
        authors_str = self._format_chicago_authors(data.authors)
        
        # Title (quoted for shorter works, italicized for longer works)
        title = f'"{data.title}"' if data.title else '"Título não especificado"'
        
        # Publication info
        pub_info = []
        if data.authority:
            pub_info.append(data.authority)
        if data.publication_date:
            pub_info.append(data.publication_date)
        
        # URL and access date
        url_info = ""
        if data.url:
            url_info = f", acessado {data.access_date or 'data não especificada'}, {data.url}"
        
        # Assemble citation
        citation_parts = [authors_str, title]
        if pub_info:
            citation_parts.append("(" + ", ".join(pub_info) + ")")
        
        citation = ". ".join(filter(None, citation_parts)) + url_info + "."
        
        return citation
    
    def _format_mla_citation(self, data: CitationData, locale: str) -> str:
        """Format citation in MLA style"""
        
        # Author(s)
        authors_str = self._format_mla_authors(data.authors)
        
        # Title (italicized)
        title = f"*{data.title}*" if data.title else "*Título não especificado*"
        
        # Publisher
        publisher = data.authority or data.publisher or "Autoridade não especificada"
        
        # Date
        date = data.publication_date or data.year or "Data não especificada"
        
        # Web info
        web_info = ""
        if data.url:
            web_info = f" Web. {data.access_date or datetime.now().strftime('%d %b %Y')}."
        
        # Assemble citation
        citation = f"{authors_str}. {title}. {publisher}, {date}.{web_info}"
        
        return citation
    
    def _format_lexml_citation(self, data: CitationData, locale: str) -> str:
        """Format citation in LexML style"""
        
        # URN (if available)
        urn_info = f"URN: {data.urn}. " if data.urn else ""
        
        # Authority
        authority = data.authority or "Autoridade não especificada"
        
        # Title
        title = data.title or "Título não especificado"
        
        # Number and date
        number_date = []
        if data.number:
            number_date.append(f"nº {data.number}")
        if data.publication_date:
            number_date.append(data.publication_date)
        
        number_date_str = ", ".join(number_date)
        
        # URL
        url_info = f" Disponível em: <{data.url}>." if data.url else ""
        
        # Access date
        access_info = f" Acesso em: {data.access_date}." if data.access_date else ""
        
        # Assemble citation
        citation = f"{urn_info}{authority}. {title}"
        if number_date_str:
            citation += f", {number_date_str}"
        citation += f".{url_info}{access_info}"
        
        return citation
    
    def _format_abnt_authors(self, authors: List[Author]) -> str:
        """Format authors in ABNT style"""
        if not authors:
            return "AUTOR NÃO ESPECIFICADO"
        
        if len(authors) == 1:
            author = authors[0]
            return f"{author.last_name.upper()}, {author.first_name}"
        elif len(authors) <= 3:
            formatted_authors = []
            for author in authors:
                formatted_authors.append(f"{author.last_name.upper()}, {author.first_name}")
            return "; ".join(formatted_authors)
        else:
            first_author = authors[0]
            return f"{first_author.last_name.upper()}, {first_author.first_name} et al."
    
    def _format_apa_authors(self, authors: List[Author]) -> str:
        """Format authors in APA style"""
        if not authors:
            return "Autor não especificado"
        
        if len(authors) == 1:
            author = authors[0]
            return f"{author.last_name}, {author.first_name[0]}."
        elif len(authors) <= 20:
            formatted_authors = []
            for i, author in enumerate(authors):
                if i == len(authors) - 1 and len(authors) > 1:
                    formatted_authors.append(f"& {author.last_name}, {author.first_name[0]}.")
                else:
                    formatted_authors.append(f"{author.last_name}, {author.first_name[0]}.")
            return " ".join(formatted_authors)
        else:
            # For more than 20 authors, list first 19, then "..." then last author
            formatted_authors = []
            for i in range(19):
                author = authors[i]
                formatted_authors.append(f"{author.last_name}, {author.first_name[0]}.")
            
            last_author = authors[-1]
            formatted_authors.append(f"... & {last_author.last_name}, {last_author.first_name[0]}.")
            
            return " ".join(formatted_authors)
    
    def _format_vancouver_authors(self, authors: List[Author]) -> str:
        """Format authors in Vancouver style"""
        if not authors:
            return "Autor não especificado"
        
        if len(authors) <= 6:
            formatted_authors = []
            for author in authors:
                formatted_authors.append(f"{author.last_name} {author.first_name[0]}")
            return ", ".join(formatted_authors)
        else:
            # List first 6 authors, then "et al."
            formatted_authors = []
            for i in range(6):
                author = authors[i]
                formatted_authors.append(f"{author.last_name} {author.first_name[0]}")
            formatted_authors.append("et al")
            return ", ".join(formatted_authors)
    
    def _format_chicago_authors(self, authors: List[Author]) -> str:
        """Format authors in Chicago style"""
        if not authors:
            return "Autor não especificado"
        
        if len(authors) == 1:
            author = authors[0]
            return f"{author.last_name}, {author.first_name}"
        elif len(authors) <= 3:
            formatted_authors = []
            for i, author in enumerate(authors):
                if i == 0:
                    formatted_authors.append(f"{author.last_name}, {author.first_name}")
                elif i == len(authors) - 1:
                    formatted_authors.append(f"and {author.first_name} {author.last_name}")
                else:
                    formatted_authors.append(f"{author.first_name} {author.last_name}")
            return ", ".join(formatted_authors)
        else:
            first_author = authors[0]
            return f"{first_author.last_name}, {first_author.first_name}, et al."
    
    def _format_mla_authors(self, authors: List[Author]) -> str:
        """Format authors in MLA style"""
        if not authors:
            return "Autor não especificado"
        
        if len(authors) == 1:
            author = authors[0]
            return f"{author.last_name}, {author.first_name}"
        elif len(authors) == 2:
            author1, author2 = authors
            return f"{author1.last_name}, {author1.first_name}, and {author2.first_name} {author2.last_name}"
        else:
            first_author = authors[0]
            return f"{first_author.last_name}, {first_author.first_name}, et al."
    
    def _format_for_output(self, citation: str, output_format: OutputFormat) -> str:
        """Format citation for specific output format"""
        
        if output_format == OutputFormat.TEXT:
            return citation
        elif output_format == OutputFormat.HTML:
            # Convert basic formatting to HTML
            html_citation = citation
            html_citation = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html_citation)  # Italics
            html_citation = re.sub(r'\"(.*?)\"', r'<q>\1</q>', html_citation)     # Quotes
            return html_citation
        elif output_format == OutputFormat.LATEX:
            # Convert basic formatting to LaTeX
            latex_citation = citation
            latex_citation = re.sub(r'\*(.*?)\*', r'\\textit{\1}', latex_citation)  # Italics
            latex_citation = re.sub(r'\"(.*?)\"', r'``\1\'\'', latex_citation)       # Quotes
            latex_citation = latex_citation.replace('&', '\\&')                     # Escape ampersand
            latex_citation = latex_citation.replace('%', '\\%')                     # Escape percent
            return latex_citation
        elif output_format == OutputFormat.MARKDOWN:
            # Convert basic formatting to Markdown
            markdown_citation = citation
            markdown_citation = re.sub(r'\*(.*?)\*', r'*\1*', markdown_citation)   # Keep italics
            return markdown_citation
        elif output_format == OutputFormat.XML:
            # Convert to basic XML structure
            xml_citation = f"<citation>{citation}</citation>"
            return xml_citation
        
        return citation
    
    def _generate_citation_id(self, data: CitationData, style: CitationStyle) -> str:
        """Generate unique citation ID"""
        
        # Use first author's last name, year, and style
        first_author = data.authors[0].last_name if data.authors else "NoAuthor"
        year = data.year or "NoYear"
        
        return f"{first_author}_{year}_{style.value}".replace(" ", "_")
    
    def _generate_bibtex_key(self, data: CitationData) -> str:
        """Generate BibTeX key"""
        
        # Use first author's last name and year
        first_author = data.authors[0].last_name if data.authors else "NoAuthor"
        year = data.year or "NoYear"
        
        # Clean and format
        key = f"{first_author}{year}".replace(" ", "").replace("-", "")
        
        return key
    
    def _determine_bibtex_entry_type(self, document_type: str) -> str:
        """Determine BibTeX entry type from document type"""
        
        type_mapping = {
            "lei": "misc",
            "decreto": "misc", 
            "portaria": "misc",
            "resolução": "misc",
            "medida provisória": "misc",
            "instrução normativa": "misc",
            "parecer": "techreport",
            "súmula": "misc",
            "emenda constitucional": "misc"
        }
        
        return type_mapping.get(document_type.lower(), "misc")
    
    def _get_required_latex_packages(self, style: CitationStyle) -> List[str]:
        """Get required LaTeX packages for citation style"""
        
        base_packages = ["babel[brazilian]", "fontenc[T1]", "inputenc[utf8]"]
        
        style_packages = {
            CitationStyle.ABNT: ["abntex2cite"],
            CitationStyle.APA: ["apacite"],
            CitationStyle.VANCOUVER: ["natbib"],
            CitationStyle.BIBTEX: ["natbib"],
            CitationStyle.CHICAGO: ["natbib"],
            CitationStyle.MLA: ["mla"],
            CitationStyle.LEXML: ["url", "hyperref"]
        }
        
        return base_packages + style_packages.get(style, ["natbib"])
    
    def _sort_citations(self, citations: List[CitationData], sort_order: str) -> List[CitationData]:
        """Sort citations according to specified order"""
        
        if sort_order == "alphabetical":
            return sorted(citations, key=lambda c: (
                c.authors[0].last_name.lower() if c.authors else "z",
                c.year or "9999"
            ))
        elif sort_order == "chronological":
            return sorted(citations, key=lambda c: c.year or "9999")
        else:  # appearance order
            return citations
    
    async def _generate_bibliography_entry(
        self,
        citation_data: CitationData,
        style: CitationStyle,
        number: int,
        include_urls: bool
    ) -> BibliographyEntry:
        """Generate bibliography entry"""
        
        # Generate formatted citation
        formatted_citation = await self._format_citation(
            citation_data, style, OutputFormat.TEXT, False, "pt-BR"
        )
        
        # Generate key
        key = self._generate_bibtex_key(citation_data)
        
        # Create entry
        return BibliographyEntry(
            key=key,
            entry_type=self._determine_bibtex_entry_type(citation_data.document_type),
            fields={
                "title": citation_data.title,
                "author": ", ".join([f"{a.first_name} {a.last_name}" for a in citation_data.authors]),
                "year": citation_data.year or "",
                "authority": citation_data.authority or ""
            },
            formatted_entry=formatted_citation
        )
    
    def _format_bibliography(self, entries: List[BibliographyEntry], style: CitationStyle) -> Dict[str, str]:
        """Format complete bibliography in multiple formats"""
        
        # Text format
        text_entries = []
        for entry in entries:
            text_entries.append(entry.formatted_entry)
        text_bibliography = "\n\n".join(text_entries)
        
        # HTML format
        html_entries = []
        for entry in entries:
            html_entry = self._format_for_output(entry.formatted_entry, OutputFormat.HTML)
            html_entries.append(f"<p>{html_entry}</p>")
        html_bibliography = "\n".join(html_entries)
        
        # LaTeX format
        latex_entries = []
        for entry in entries:
            latex_entry = self._format_for_output(entry.formatted_entry, OutputFormat.LATEX)
            latex_entries.append(f"\\bibitem{{{entry.key}}} {latex_entry}")
        latex_bibliography = "\\begin{thebibliography}{99}\n" + "\n\n".join(latex_entries) + "\n\\end{thebibliography}"
        
        # BibTeX format
        bibtex_entries = []
        for entry in entries:
            # Generate full BibTeX entry
            fields = []
            for field, value in entry.fields.items():
                if value:
                    fields.append(f"  {field} = {{{value}}}")
            
            bibtex_entry = f"@{entry.entry_type}{{{entry.key},\n" + ",\n".join(fields) + "\n}"
            bibtex_entries.append(bibtex_entry)
        
        bibtex_bibliography = "\n\n".join(bibtex_entries)
        
        return {
            "text": text_bibliography,
            "html": html_bibliography,
            "latex": latex_bibliography,
            "bibtex": bibtex_bibliography
        }
    
    def _generate_latex_preamble(self, title: str, authors: List[str], packages: List[str]) -> str:
        """Generate LaTeX document preamble"""
        
        preamble_parts = []
        
        # Document class
        preamble_parts.append("\\documentclass[12pt,a4paper]{article}")
        
        # Packages
        for package in packages:
            if "[" in package:
                # Package with options
                pkg_name = package.split("[")[0]
                options = package.split("[")[1].split("]")[0]
                preamble_parts.append(f"\\usepackage[{options}]{{{pkg_name}}}")
            else:
                preamble_parts.append(f"\\usepackage{{{package}}}")
        
        # Title and author
        preamble_parts.append(f"\\title{{{title}}}")
        if authors:
            authors_str = " \\and ".join(authors)
            preamble_parts.append(f"\\author{{{authors_str}}}")
        
        # Date
        preamble_parts.append("\\date{\\today}")
        
        return "\n".join(preamble_parts)
    
    def _generate_latex_body(self, content: str, citations: List[FormattedCitation]) -> str:
        """Generate LaTeX document body"""
        
        body_parts = []
        
        # Begin document
        body_parts.append("\\begin{document}")
        body_parts.append("\\maketitle")
        
        # Content
        if content:
            body_parts.append(content)
        else:
            body_parts.append("\\section{Introdução}")
            body_parts.append("Este documento contém as citações bibliográficas formatadas.")
        
        # Example citations section
        if citations:
            body_parts.append("\\section{Citações}")
            body_parts.append("Exemplos de citações incluídas neste documento:")
            body_parts.append("\\begin{itemize}")
            
            for citation in citations[:5]:  # Limit to first 5 citations
                body_parts.append(f"\\item {citation.content}")
            
            body_parts.append("\\end{itemize}")
        
        # End document
        body_parts.append("\\end{document}")
        
        return "\n\n".join(body_parts)

# Global citation processor instance
_citation_processor: Optional[CitationEnhancementProcessor] = None

async def get_citation_processor() -> CitationEnhancementProcessor:
    """Get or create the global citation processor"""
    global _citation_processor
    
    if _citation_processor is None:
        _citation_processor = CitationEnhancementProcessor()
        if await _citation_processor.initialize():
            logger.info("✅ Citation enhancement processor initialized")
        else:
            logger.warning("⚠️ Citation processor initialized with limited functionality")
    
    return _citation_processor

# API endpoints
@router.post("/generate-citations", response_model=CitationResponse)
async def generate_citations_endpoint(
    request: CitationRequest
) -> CitationResponse:
    """Generate citations in multiple styles and formats"""
    try:
        start_time = time.time()
        citation_processor = await get_citation_processor()
        
        citations = await citation_processor.generate_citations(
            citation_data=request.citation_data,
            styles=request.styles,
            output_formats=request.output_formats,
            include_latex=request.include_latex,
            locale=request.locale
        )
        
        processing_time = time.time() - start_time
        
        return CitationResponse(
            success=True,
            data={
                "citations": [asdict(citation) for citation in citations],
                "total_generated": len(citations)
            },
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Citation generation failed: {e}")
        return CitationResponse(
            success=False,
            error=str(e)
        )

@router.post("/generate-bibliography", response_model=CitationResponse)
async def generate_bibliography_endpoint(
    request: BibliographyRequest
) -> CitationResponse:
    """Generate complete bibliography"""
    try:
        citation_processor = await get_citation_processor()
        
        bibliography = await citation_processor.generate_bibliography(
            citations_data=request.citations,
            style=request.style,
            sort_order=request.sort_order,
            include_urls=request.include_urls
        )
        
        return CitationResponse(
            success=True,
            data=bibliography
        )
        
    except Exception as e:
        logger.error(f"Bibliography generation failed: {e}")
        return CitationResponse(
            success=False,
            error=str(e)
        )

@router.post("/generate-latex-document", response_model=CitationResponse)
async def generate_latex_document_endpoint(
    request: LaTeXDocumentRequest
) -> CitationResponse:
    """Generate complete LaTeX document with citations"""
    try:
        citation_processor = await get_citation_processor()
        
        latex_doc = await citation_processor.generate_latex_document(
            document_class=request.document_class,
            title=request.title,
            authors=request.authors,
            citations_data=request.citations,
            content=request.content,
            bibliography_style=request.bibliography_style
        )
        
        return CitationResponse(
            success=True,
            data=asdict(latex_doc)
        )
        
    except Exception as e:
        logger.error(f"LaTeX document generation failed: {e}")
        return CitationResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def citation_health_status() -> Dict[str, Any]:
    """Get citation system health status"""
    try:
        citation_processor = await get_citation_processor()
        
        return {
            "status": "healthy",
            "supported_styles": [style.value for style in CitationStyle],
            "supported_formats": [fmt.value for fmt in OutputFormat],
            "latex_document_classes": [dc.value for dc in DocumentClass],
            "cached_citations": len(citation_processor.citation_cache)
        }
        
    except Exception as e:
        logger.error(f"Citation health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and processor getter
__all__ = ["router", "get_citation_processor"]