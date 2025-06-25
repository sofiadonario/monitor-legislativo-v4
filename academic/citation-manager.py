# Academic Citation Management System for Monitor Legislativo v4
# Phase 5 Week 17: Advanced citation tools for Brazilian legislative research
# Supports multiple citation formats with academic standards compliance

import re
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum
import unicodedata
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class CitationFormat(Enum):
    """Academic citation formats"""
    ABNT = "abnt"              # Brazilian standard (NBR 6023:2018)
    APA = "apa"                # American Psychological Association
    CHICAGO = "chicago"        # Chicago Manual of Style
    MLA = "mla"               # Modern Language Association
    VANCOUVER = "vancouver"    # Vancouver style (biomedical)
    HARVARD = "harvard"       # Harvard referencing
    IEEE = "ieee"             # Institute of Electrical and Electronics Engineers
    BLUEBOOK = "bluebook"     # Legal citation (Bluebook)

class DocumentType(Enum):
    """Types of legislative documents"""
    LEI = "lei"                           # Law
    DECRETO = "decreto"                   # Decree
    RESOLUCAO = "resolucao"              # Resolution
    PORTARIA = "portaria"                # Ordinance
    INSTRUCAO_NORMATIVA = "instrucao_normativa"  # Normative Instruction
    MEDIDA_PROVISORIA = "medida_provisoria"      # Provisional Measure
    PROJETO_LEI = "projeto_lei"          # Bill
    EMENDA = "emenda"                    # Amendment
    PARECER = "parecer"                  # Opinion
    RELATORIO = "relatorio"              # Report
    ATA = "ata"                         # Minutes
    ACORDAO = "acordao"                 # Court Decision
    JURISPRUDENCIA = "jurisprudencia"   # Case Law

class PublicationLevel(Enum):
    """Government level of publication"""
    FEDERAL = "federal"
    ESTADUAL = "estadual"
    MUNICIPAL = "municipal"
    DISTRITAL = "distrital"

@dataclass
class Author:
    """Author information for citations"""
    name: str
    role: Optional[str] = None          # e.g., "Relator", "Deputado"
    institution: Optional[str] = None    # e.g., "Câmara dos Deputados"
    
    def format_name_abnt(self) -> str:
        """Format name according to ABNT (surname, given names)"""
        parts = self.name.strip().split()
        if len(parts) <= 1:
            return self.name.upper()
        
        # Handle Brazilian name patterns
        surname = parts[-1]
        given_names = ' '.join(parts[:-1])
        
        # Handle compound surnames (e.g., "da Silva", "dos Santos")
        prepositions = ['da', 'das', 'de', 'del', 'do', 'dos', 'e', 'von', 'van']
        if len(parts) > 2 and parts[-2].lower() in prepositions:
            surname = f"{parts[-2]} {parts[-1]}"
            given_names = ' '.join(parts[:-2])
        
        return f"{surname.upper()}, {given_names}"
    
    def format_name_apa(self) -> str:
        """Format name according to APA (surname, initials)"""
        parts = self.name.strip().split()
        if len(parts) <= 1:
            return self.name
        
        surname = parts[-1]
        initials = '. '.join([name[0].upper() for name in parts[:-1]]) + '.'
        return f"{surname}, {initials}"

@dataclass
class LegislativeDocument:
    """Legislative document for citation"""
    title: str
    document_type: DocumentType
    number: Optional[str] = None         # Document number
    year: Optional[int] = None          # Year of publication
    date: Optional[date] = None         # Specific date
    authors: List[Author] = field(default_factory=list)
    institution: Optional[str] = None    # Publishing institution
    publication_level: Optional[PublicationLevel] = None
    publication_source: Optional[str] = None  # e.g., "Diário Oficial"
    url: Optional[str] = None
    access_date: Optional[date] = None
    pages: Optional[str] = None         # Page numbers
    volume: Optional[str] = None        # Volume number
    issue: Optional[str] = None         # Issue number
    doi: Optional[str] = None          # Digital Object Identifier
    legal_basis: Optional[str] = None   # Legal foundation
    regulatory_agency: Optional[str] = None  # ANTT, ANTAQ, etc.
    keywords: List[str] = field(default_factory=list)
    abstract: Optional[str] = None
    full_text_url: Optional[str] = None
    lexml_id: Optional[str] = None      # LexML identifier
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['document_type'] = self.document_type.value
        if self.publication_level:
            result['publication_level'] = self.publication_level.value
        if self.date:
            result['date'] = self.date.isoformat()
        if self.access_date:
            result['access_date'] = self.access_date.isoformat()
        return result

class CitationManager:
    """
    Advanced citation management system for Brazilian legislative research
    
    Features:
    - Multiple citation formats (ABNT, APA, Chicago, etc.)
    - Brazilian legislative document specialization
    - Academic standards compliance
    - Bulk citation generation
    - Bibliography export
    - Integration with reference managers
    """
    
    def __init__(self):
        self.citation_cache = {}
        self.format_handlers = {
            CitationFormat.ABNT: self._format_abnt,
            CitationFormat.APA: self._format_apa,
            CitationFormat.CHICAGO: self._format_chicago,
            CitationFormat.MLA: self._format_mla,
            CitationFormat.VANCOUVER: self._format_vancouver,
            CitationFormat.HARVARD: self._format_harvard,
            CitationFormat.IEEE: self._format_ieee,
            CitationFormat.BLUEBOOK: self._format_bluebook
        }
        
        # Document type translations for citations
        self.document_type_names = {
            DocumentType.LEI: {"pt": "Lei", "en": "Law"},
            DocumentType.DECRETO: {"pt": "Decreto", "en": "Decree"},
            DocumentType.RESOLUCAO: {"pt": "Resolução", "en": "Resolution"},
            DocumentType.PORTARIA: {"pt": "Portaria", "en": "Ordinance"},
            DocumentType.INSTRUCAO_NORMATIVA: {"pt": "Instrução Normativa", "en": "Normative Instruction"},
            DocumentType.MEDIDA_PROVISORIA: {"pt": "Medida Provisória", "en": "Provisional Measure"},
            DocumentType.PROJETO_LEI: {"pt": "Projeto de Lei", "en": "Bill"},
            DocumentType.EMENDA: {"pt": "Emenda", "en": "Amendment"},
            DocumentType.PARECER: {"pt": "Parecer", "en": "Opinion"},
            DocumentType.RELATORIO: {"pt": "Relatório", "en": "Report"},
            DocumentType.ATA: {"pt": "Ata", "en": "Minutes"},
            DocumentType.ACORDAO: {"pt": "Acórdão", "en": "Court Decision"},
            DocumentType.JURISPRUDENCIA: {"pt": "Jurisprudência", "en": "Case Law"}
        }
    
    def generate_citation(self, document: LegislativeDocument, 
                         format_type: CitationFormat = CitationFormat.ABNT,
                         language: str = "pt") -> str:
        """Generate citation for a legislative document"""
        
        # Check cache first
        cache_key = f"{hash(str(document.to_dict()))}_{format_type.value}_{language}"
        if cache_key in self.citation_cache:
            return self.citation_cache[cache_key]
        
        # Generate citation
        try:
            handler = self.format_handlers.get(format_type)
            if not handler:
                raise ValueError(f"Unsupported citation format: {format_type}")
            
            citation = handler(document, language)
            
            # Cache result
            self.citation_cache[cache_key] = citation
            return citation
        
        except Exception as e:
            logger.error(f"Error generating citation: {e}")
            return self._generate_fallback_citation(document, language)
    
    def _format_abnt(self, doc: LegislativeDocument, language: str = "pt") -> str:
        """Format citation according to ABNT NBR 6023:2018"""
        
        parts = []
        
        # Authors (if any)
        if doc.authors:
            if len(doc.authors) == 1:
                parts.append(doc.authors[0].format_name_abnt())
            elif len(doc.authors) <= 3:
                author_names = [author.format_name_abnt() for author in doc.authors]
                parts.append('; '.join(author_names[:-1]) + '; ' + author_names[-1])
            else:
                parts.append(f"{doc.authors[0].format_name_abnt()} et al.")
        elif doc.institution:
            parts.append(doc.institution.upper())
        else:
            parts.append("BRASIL")
        
        # Title
        title_formatted = f"**{doc.title}**" if doc.title else "Documento sem título"
        parts.append(title_formatted)
        
        # Document type and number
        doc_type_name = self.document_type_names.get(doc.document_type, {}).get(language, doc.document_type.value)
        if doc.number:
            doc_info = f"{doc_type_name} nº {doc.number}"
            if doc.year:
                doc_info += f", de {doc.year}"
        else:
            doc_info = doc_type_name
            if doc.year:
                doc_info += f" de {doc.year}"
        
        # Publication information
        pub_info = []
        if doc.publication_source:
            pub_info.append(doc.publication_source)
        
        if doc.date:
            pub_info.append(doc.date.strftime("%d %b. %Y").replace(" ", " "))
        elif doc.year:
            pub_info.append(str(doc.year))
        
        if doc.pages:
            pub_info.append(f"p. {doc.pages}")
        
        if pub_info:
            parts.append(', '.join(pub_info))
        
        # URL and access date
        if doc.url:
            url_part = f"Disponível em: {doc.url}"
            if doc.access_date:
                url_part += f". Acesso em: {doc.access_date.strftime('%d %b. %Y')}"
            parts.append(url_part)
        
        # Join all parts
        citation = '. '.join(parts)
        if not citation.endswith('.'):
            citation += '.'
        
        return citation
    
    def _format_apa(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to APA 7th edition"""
        
        parts = []
        
        # Authors
        if doc.authors:
            if len(doc.authors) == 1:
                parts.append(doc.authors[0].format_name_apa())
            elif len(doc.authors) <= 20:
                author_names = [author.format_name_apa() for author in doc.authors]
                if len(author_names) <= 2:
                    parts.append(' & '.join(author_names))
                else:
                    parts.append(', '.join(author_names[:-1]) + ', & ' + author_names[-1])
            else:
                author_names = [author.format_name_apa() for author in doc.authors[:19]]
                parts.append(', '.join(author_names) + ', ... ' + doc.authors[-1].format_name_apa())
        elif doc.institution:
            parts.append(doc.institution)
        else:
            parts.append("Government of Brazil")
        
        # Year
        year_part = f"({doc.year})" if doc.year else "(n.d.)"
        parts.append(year_part)
        
        # Title (italicized)
        title_part = f"*{doc.title}*" if doc.title else "*Untitled document*"
        
        # Document type and number
        doc_type_name = self.document_type_names.get(doc.document_type, {}).get(language, doc.document_type.value.title())
        if doc.number:
            title_part += f" [{doc_type_name} No. {doc.number}]"
        else:
            title_part += f" [{doc_type_name}]"
        
        parts.append(title_part)
        
        # Publication information
        if doc.institution and doc.institution not in parts[0]:
            parts.append(doc.institution)
        
        # URL
        if doc.url:
            parts.append(doc.url)
        
        return '. '.join(parts) + '.'
    
    def _format_chicago(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to Chicago Manual of Style (17th ed.)"""
        
        parts = []
        
        # Authors
        if doc.authors:
            if len(doc.authors) == 1:
                author = doc.authors[0]
                parts.append(f"{author.name}")
            else:
                author_names = [author.name for author in doc.authors]
                if len(author_names) == 2:
                    parts.append(f"{author_names[0]} and {author_names[1]}")
                else:
                    parts.append(', '.join(author_names[:-1]) + ', and ' + author_names[-1])
        
        # Title
        title_part = f'"{doc.title}"' if doc.title else '"Untitled Document"'
        parts.append(title_part)
        
        # Document type and number
        doc_type_name = self.document_type_names.get(doc.document_type, {}).get(language, doc.document_type.value.title())
        if doc.number:
            parts.append(f"{doc_type_name} No. {doc.number}")
        else:
            parts.append(doc_type_name)
        
        # Institution
        if doc.institution:
            parts.append(doc.institution)
        
        # Date
        if doc.date:
            parts.append(doc.date.strftime("%B %d, %Y"))
        elif doc.year:
            parts.append(str(doc.year))
        
        # URL and access date
        if doc.url:
            url_part = doc.url
            if doc.access_date:
                url_part += f" (accessed {doc.access_date.strftime('%B %d, %Y')})"
            parts.append(url_part)
        
        return '. '.join(parts) + '.'
    
    def _format_mla(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to MLA 8th edition"""
        
        elements = []
        
        # Author
        if doc.authors:
            if len(doc.authors) == 1:
                author = doc.authors[0]
                name_parts = author.name.split()
                if len(name_parts) > 1:
                    elements.append(f"{name_parts[-1]}, {' '.join(name_parts[:-1])}")
                else:
                    elements.append(author.name)
            else:
                elements.append("Multiple Authors")
        
        # Title of source
        title = f'"{doc.title}"' if doc.title else '"Untitled Document"'
        elements.append(title)
        
        # Container (publication)
        if doc.publication_source:
            elements.append(f"*{doc.publication_source}*")
        
        # Other contributors
        if doc.institution:
            elements.append(doc.institution)
        
        # Version (document type and number)
        doc_type_name = self.document_type_names.get(doc.document_type, {}).get(language, doc.document_type.value.title())
        if doc.number:
            elements.append(f"{doc_type_name} {doc.number}")
        
        # Number (volume/issue)
        if doc.volume:
            elements.append(f"vol. {doc.volume}")
        
        # Publisher
        if not doc.institution and doc.publication_level:
            elements.append("Government of Brazil")
        
        # Publication date
        if doc.date:
            elements.append(doc.date.strftime("%d %b %Y"))
        elif doc.year:
            elements.append(str(doc.year))
        
        # Location (URL)
        if doc.url:
            elements.append(doc.url)
        
        # Date of access
        if doc.access_date and doc.url:
            elements.append(f"Accessed {doc.access_date.strftime('%d %b %Y')}")
        
        return ', '.join(elements) + '.'
    
    def _format_vancouver(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to Vancouver style"""
        
        parts = []
        
        # Authors
        if doc.authors:
            author_names = []
            for author in doc.authors[:6]:  # Vancouver limits to 6 authors
                name_parts = author.name.split()
                if len(name_parts) > 1:
                    surname = name_parts[-1]
                    initials = ''.join([name[0].upper() for name in name_parts[:-1]])
                    author_names.append(f"{surname} {initials}")
                else:
                    author_names.append(author.name)
            
            if len(doc.authors) > 6:
                author_names.append("et al")
            
            parts.append(', '.join(author_names))
        
        # Title
        parts.append(doc.title if doc.title else "Untitled document")
        
        # Source
        if doc.publication_source:
            parts.append(doc.publication_source)
        
        # Year
        if doc.year:
            year_part = str(doc.year)
            if doc.date:
                year_part += f" {doc.date.strftime('%b %d')}"
            parts.append(year_part)
        
        # URL
        if doc.url:
            url_part = f"Available from: {doc.url}"
            parts.append(url_part)
        
        return '. '.join(parts) + '.'
    
    def _format_harvard(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to Harvard referencing style"""
        
        parts = []
        
        # Authors and year
        if doc.authors:
            if len(doc.authors) == 1:
                author_part = f"{doc.authors[0].name} {doc.year or 'n.d.'}"
            else:
                author_names = [author.name for author in doc.authors]
                if len(author_names) <= 3:
                    author_part = f"{', '.join(author_names[:-1])} & {author_names[-1]} {doc.year or 'n.d.'}"
                else:
                    author_part = f"{author_names[0]} et al. {doc.year or 'n.d.'}"
            parts.append(author_part)
        else:
            parts.append(f"{doc.institution or 'Government of Brazil'} {doc.year or 'n.d.'}")
        
        # Title
        title_part = f"'{doc.title}'" if doc.title else "'Untitled document'"
        
        # Document type
        doc_type_name = self.document_type_names.get(doc.document_type, {}).get(language, doc.document_type.value.title())
        if doc.number:
            title_part += f", {doc_type_name} {doc.number}"
        
        parts.append(title_part)
        
        # Access information
        if doc.url:
            access_part = f"viewed {doc.access_date.strftime('%d %B %Y') if doc.access_date else 'n.d.'}, <{doc.url}>"
            parts.append(access_part)
        
        return ', '.join(parts) + '.'
    
    def _format_ieee(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to IEEE style"""
        
        parts = []
        
        # Authors
        if doc.authors:
            author_names = []
            for author in doc.authors:
                name_parts = author.name.split()
                if len(name_parts) > 1:
                    given_names = ' '.join([f"{name[0]}." for name in name_parts[:-1]])
                    author_names.append(f"{given_names} {name_parts[-1]}")
                else:
                    author_names.append(author.name)
            
            if len(author_names) <= 6:
                parts.append(', '.join(author_names))
            else:
                parts.append(', '.join(author_names[:6]) + ', et al.')
        
        # Title
        title_part = f'"{doc.title}"' if doc.title else '"Untitled document"'
        parts.append(title_part)
        
        # Publication info
        pub_info = []
        if doc.institution:
            pub_info.append(doc.institution)
        
        doc_type_name = self.document_type_names.get(doc.document_type, {}).get(language, doc.document_type.value.title())
        if doc.number:
            pub_info.append(f"{doc_type_name} {doc.number}")
        
        if doc.year:
            pub_info.append(str(doc.year))
        
        if pub_info:
            parts.append(', '.join(pub_info))
        
        # URL
        if doc.url:
            parts.append(f"[Online]. Available: {doc.url}")
            if doc.access_date:
                parts.append(f"[Accessed: {doc.access_date.strftime('%d-%b-%Y')}]")
        
        return ', '.join(parts) + '.'
    
    def _format_bluebook(self, doc: LegislativeDocument, language: str = "en") -> str:
        """Format citation according to Bluebook (legal citation)"""
        
        parts = []
        
        # Title (if it's a named act/law)
        if doc.title and doc.document_type in [DocumentType.LEI, DocumentType.DECRETO]:
            parts.append(doc.title)
        
        # Document type and number
        doc_type_abbrev = {
            DocumentType.LEI: "Lei",
            DocumentType.DECRETO: "Decreto",
            DocumentType.RESOLUCAO: "Resolução",
            DocumentType.PORTARIA: "Portaria"
        }.get(doc.document_type, doc.document_type.value.title())
        
        if doc.number:
            doc_part = f"{doc_type_abbrev} No. {doc.number}"
            if doc.year:
                doc_part += f" ({doc.year})"
            parts.append(doc_part)
        
        # Publication source
        if doc.publication_source:
            parts.append(doc.publication_source)
        
        # Date
        if doc.date:
            parts.append(doc.date.strftime("%b. %d, %Y"))
        
        # URL
        if doc.url:
            parts.append(doc.url)
        
        return ', '.join(parts) + '.'
    
    def _generate_fallback_citation(self, doc: LegislativeDocument, language: str = "pt") -> str:
        """Generate a basic fallback citation"""
        parts = []
        
        if doc.authors:
            parts.append(doc.authors[0].name)
        elif doc.institution:
            parts.append(doc.institution)
        else:
            parts.append("Brasil")
        
        if doc.title:
            parts.append(doc.title)
        
        if doc.year:
            parts.append(str(doc.year))
        
        if doc.url:
            parts.append(f"Disponível em: {doc.url}")
        
        return '. '.join(parts) + '.'
    
    def generate_bibliography(self, documents: List[LegislativeDocument],
                            format_type: CitationFormat = CitationFormat.ABNT,
                            sort_alphabetically: bool = True,
                            language: str = "pt") -> str:
        """Generate a complete bibliography"""
        
        citations = []
        for doc in documents:
            citation = self.generate_citation(doc, format_type, language)
            citations.append(citation)
        
        if sort_alphabetically:
            # Sort by first word (usually author or institution)
            citations.sort(key=lambda x: self._extract_sort_key(x))
        
        # Format bibliography
        if format_type == CitationFormat.ABNT:
            # ABNT uses single spacing between entries
            return '\n\n'.join(citations)
        else:
            # Other formats typically use hanging indent
            formatted_citations = []
            for citation in citations:
                # Add hanging indent (could be implemented with HTML/CSS)
                formatted_citations.append(citation)
            return '\n\n'.join(formatted_citations)
    
    def _extract_sort_key(self, citation: str) -> str:
        """Extract sorting key from citation"""
        # Remove formatting and get first word
        clean_citation = re.sub(r'[*_]', '', citation)  # Remove bold/italic markers
        first_word = clean_citation.split()[0] if citation else ""
        
        # Normalize for sorting (remove accents, convert to lowercase)
        normalized = unicodedata.normalize('NFD', first_word)
        ascii_word = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')
        return ascii_word.lower()
    
    def export_to_bibtex(self, documents: List[LegislativeDocument]) -> str:
        """Export documents to BibTeX format"""
        
        bibtex_entries = []
        
        for doc in documents:
            # Generate citation key
            citation_key = self._generate_bibtex_key(doc)
            
            # Determine entry type
            entry_type = "misc"  # Default for government documents
            if doc.document_type in [DocumentType.LEI, DocumentType.DECRETO]:
                entry_type = "legislation"
            elif doc.document_type in [DocumentType.RELATORIO, DocumentType.PARECER]:
                entry_type = "techreport"
            
            # Build BibTeX entry
            entry_lines = [f"@{entry_type}{{{citation_key},"]
            
            # Title
            if doc.title:
                entry_lines.append(f'  title = {{{doc.title}}},')
            
            # Authors
            if doc.authors:
                authors = ' and '.join([author.name for author in doc.authors])
                entry_lines.append(f'  author = {{{authors}}},')
            elif doc.institution:
                entry_lines.append(f'  author = {{{doc.institution}}},')
            
            # Year
            if doc.year:
                entry_lines.append(f'  year = {{{doc.year}}},')
            
            # Institution/Publisher
            if doc.institution:
                entry_lines.append(f'  institution = {{{doc.institution}}},')
            
            # Type and number
            doc_type_name = self.document_type_names.get(doc.document_type, {}).get("pt", doc.document_type.value)
            if doc.number:
                entry_lines.append(f'  type = {{{doc_type_name} {doc.number}}},')
            else:
                entry_lines.append(f'  type = {{{doc_type_name}}},')
            
            # URL
            if doc.url:
                entry_lines.append(f'  url = {{{doc.url}}},')
            
            # Access date
            if doc.access_date:
                entry_lines.append(f'  note = {{Accessed: {doc.access_date.isoformat()}}},')
            
            # Keywords
            if doc.keywords:
                entry_lines.append(f'  keywords = {{{", ".join(doc.keywords)}}},')
            
            # Abstract
            if doc.abstract:
                # Clean abstract for BibTeX
                clean_abstract = doc.abstract.replace('{', '\\{').replace('}', '\\}')
                entry_lines.append(f'  abstract = {{{clean_abstract}}},')
            
            # DOI
            if doc.doi:
                entry_lines.append(f'  doi = {{{doc.doi}}},')
            
            # Remove trailing comma from last entry
            if entry_lines[-1].endswith(','):
                entry_lines[-1] = entry_lines[-1][:-1]
            
            entry_lines.append('}')
            bibtex_entries.append('\n'.join(entry_lines))
        
        return '\n\n'.join(bibtex_entries)
    
    def _generate_bibtex_key(self, doc: LegislativeDocument) -> str:
        """Generate BibTeX citation key"""
        
        key_parts = []
        
        # Author or institution
        if doc.authors:
            # Use first author's surname
            author_name = doc.authors[0].name.split()[-1]
            # Remove accents and special characters
            clean_name = unicodedata.normalize('NFD', author_name)
            clean_name = ''.join(c for c in clean_name if unicodedata.category(c) != 'Mn')
            key_parts.append(clean_name.lower())
        elif doc.institution:
            # Use first word of institution
            inst_word = doc.institution.split()[0]
            clean_inst = re.sub(r'[^\w]', '', inst_word)
            key_parts.append(clean_inst.lower())
        else:
            key_parts.append("brasil")
        
        # Year
        if doc.year:
            key_parts.append(str(doc.year))
        
        # Document type and number
        if doc.document_type and doc.number:
            doc_type_short = doc.document_type.value[:3]
            key_parts.append(f"{doc_type_short}{doc.number}")
        
        return '_'.join(key_parts)
    
    def export_to_ris(self, documents: List[LegislativeDocument]) -> str:
        """Export documents to RIS format (Research Information Systems)"""
        
        ris_entries = []
        
        for doc in documents:
            lines = []
            
            # Type of reference
            ref_type = "GOVDOC"  # Government document
            if doc.document_type in [DocumentType.RELATORIO, DocumentType.PARECER]:
                ref_type = "RPRT"  # Report
            elif doc.document_type == DocumentType.JURISPRUDENCIA:
                ref_type = "CASE"  # Legal case
            
            lines.append(f"TY  - {ref_type}")
            
            # Title
            if doc.title:
                lines.append(f"TI  - {doc.title}")
            
            # Authors
            for author in doc.authors:
                lines.append(f"AU  - {author.name}")
            
            # Institution
            if doc.institution:
                lines.append(f"AD  - {doc.institution}")
            
            # Year
            if doc.year:
                lines.append(f"PY  - {doc.year}")
            
            # Date
            if doc.date:
                lines.append(f"DA  - {doc.date.strftime('%Y/%m/%d')}")
            
            # Document type and number
            doc_type_name = self.document_type_names.get(doc.document_type, {}).get("pt", doc.document_type.value)
            if doc.number:
                lines.append(f"T2  - {doc_type_name} {doc.number}")
            else:
                lines.append(f"T2  - {doc_type_name}")
            
            # Publication
            if doc.publication_source:
                lines.append(f"JF  - {doc.publication_source}")
            
            # URL
            if doc.url:
                lines.append(f"UR  - {doc.url}")
            
            # Abstract
            if doc.abstract:
                lines.append(f"AB  - {doc.abstract}")
            
            # Keywords
            for keyword in doc.keywords:
                lines.append(f"KW  - {keyword}")
            
            # End of record
            lines.append("ER  - ")
            
            ris_entries.append('\n'.join(lines))
        
        return '\n\n'.join(ris_entries)
    
    def validate_citation(self, citation: str, format_type: CitationFormat) -> Dict[str, Any]:
        """Validate citation format compliance"""
        
        validation_result = {
            "valid": True,
            "format": format_type.value,
            "errors": [],
            "warnings": [],
            "suggestions": []
        }
        
        if format_type == CitationFormat.ABNT:
            validation_result.update(self._validate_abnt_citation(citation))
        elif format_type == CitationFormat.APA:
            validation_result.update(self._validate_apa_citation(citation))
        # Add other format validations as needed
        
        return validation_result
    
    def _validate_abnt_citation(self, citation: str) -> Dict[str, Any]:
        """Validate ABNT citation format"""
        
        errors = []
        warnings = []
        suggestions = []
        
        # Check for required elements
        if not citation.endswith('.'):
            errors.append("Citation must end with a period")
        
        # Check for proper title formatting (should be bold)
        if '**' not in citation and '*' not in citation:
            warnings.append("Title should be formatted in bold")
        
        # Check for URL access date
        if 'http' in citation and 'Acesso em:' not in citation:
            warnings.append("Online sources should include access date")
        
        # Check author name format
        if ',' in citation and not re.search(r'^[A-Z]+,', citation):
            suggestions.append("Author surnames should be in uppercase")
        
        return {
            "errors": errors,
            "warnings": warnings,
            "suggestions": suggestions,
            "valid": len(errors) == 0
        }
    
    def _validate_apa_citation(self, citation: str) -> Dict[str, Any]:
        """Validate APA citation format"""
        
        errors = []
        warnings = []
        suggestions = []
        
        # Check for year in parentheses
        if not re.search(r'\(\d{4}\)', citation):
            errors.append("APA citations must include year in parentheses")
        
        # Check for italicized title
        if '*' not in citation:
            warnings.append("Title should be italicized in APA format")
        
        # Check DOI format
        doi_match = re.search(r'doi:', citation)
        if doi_match and not re.search(r'https://doi\.org/', citation):
            suggestions.append("DOI should be formatted as URL (https://doi.org/...)")
        
        return {
            "errors": errors,
            "warnings": warnings,
            "suggestions": suggestions,
            "valid": len(errors) == 0
        }

# Factory function for easy creation
def create_citation_manager() -> CitationManager:
    """Create and initialize citation manager"""
    return CitationManager()

# Export main classes
__all__ = [
    'CitationManager',
    'LegislativeDocument',
    'Author',
    'CitationFormat',
    'DocumentType',
    'PublicationLevel',
    'create_citation_manager'
]