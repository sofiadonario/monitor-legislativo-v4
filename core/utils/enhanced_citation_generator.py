"""
Enhanced Citation Generator with FRBROO and SKOS Support
========================================================

Academic citation generator that supports multiple citation standards
with FRBROO document model integration and SKOS vocabulary metadata.

Supported formats:
- ABNT NBR 6023:2018 (Brazilian standard)
- APA 7th Edition
- BibTeX with enhanced metadata
- SKOS-RDF export format
- MLA 9th Edition
- Chicago 17th Edition

Features:
- FRBROO-aware citation generation
- Controlled vocabulary metadata inclusion
- Temporal control support
- DOI and URN integration
- Academic metadata enhancement

Author: Academic Legislative Monitor Development Team
Created: June 2025
Version: 1.0.0
"""

import re
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
import json
import locale
from dataclasses import dataclass

from ..models.frbroo_document import (
    FRBROODocument, F1Work, F2Expression, F3Manifestation, 
    ControlledVocabularyTag, LegislativeEventType
)
from ..models.models import Proposition, PropositionType
from ..lexml.config import CITATION_STANDARDS


# Set Brazilian locale for date formatting
try:
    locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_TIME, 'pt_BR')
    except:
        # Fallback to default if Brazilian locale not available
        pass


@dataclass
class CitationMetadata:
    """Additional metadata for academic citations."""
    doi: Optional[str] = None
    isbn: Optional[str] = None
    issn: Optional[str] = None
    url: Optional[str] = None
    access_date: Optional[datetime] = None
    edition: Optional[str] = None
    volume: Optional[str] = None
    pages: Optional[str] = None
    series: Optional[str] = None
    publisher_location: str = "Brasília, DF"
    language: str = "pt-BR"
    

class FRBROOCitationGenerator:
    """
    Academic citation generator with FRBROO and SKOS support.
    
    This class generates citations that include:
    - FRBROO metadata (Work, Expression, Manifestation levels)
    - SKOS controlled vocabulary terms
    - Temporal control information
    - Multiple citation standards compliance
    """
    
    def __init__(self):
        """Initialize the citation generator."""
        self.standards = CITATION_STANDARDS
        self.month_names_pt = {
            1: "janeiro", 2: "fevereiro", 3: "março", 4: "abril",
            5: "maio", 6: "junho", 7: "julho", 8: "agosto",
            9: "setembro", 10: "outubro", 11: "novembro", 12: "dezembro"
        }
    
    def generate_citation(self, document: FRBROODocument, 
                         standard: str = "ABNT",
                         expression_id: Optional[str] = None,
                         include_vocabularies: bool = True,
                         metadata: Optional[CitationMetadata] = None) -> str:
        """
        Generate academic citation for a FRBROO document.
        
        Args:
            document: FRBROO document to cite
            standard: Citation standard (ABNT, APA, BibTeX, MLA, Chicago, SKOS-RDF)
            expression_id: Specific expression to cite (default: current)
            include_vocabularies: Include controlled vocabulary terms
            metadata: Additional citation metadata
            
        Returns:
            Formatted citation string
        """
        # Get the expression to cite
        if expression_id:
            expression = next((exp for exp in document.expressions if exp.expression_id == expression_id), None)
        else:
            expression = document.get_current_expression()
        
        if not expression:
            return ""
        
        # Get metadata if not provided
        if not metadata:
            metadata = self._extract_metadata(document, expression)
        
        # Generate citation based on standard
        standard_upper = standard.upper()
        
        if standard_upper == "ABNT":
            return self._generate_abnt(document, expression, metadata, include_vocabularies)
        elif standard_upper == "APA":
            return self._generate_apa(document, expression, metadata, include_vocabularies)
        elif standard_upper == "BIBTEX":
            return self._generate_bibtex(document, expression, metadata, include_vocabularies)
        elif standard_upper == "MLA":
            return self._generate_mla(document, expression, metadata, include_vocabularies)
        elif standard_upper == "CHICAGO":
            return self._generate_chicago(document, expression, metadata, include_vocabularies)
        elif standard_upper == "SKOS-RDF" or standard_upper == "SKOS_RDF":
            return self._generate_skos_rdf(document, expression, metadata)
        else:
            # Default to ABNT
            return self._generate_abnt(document, expression, metadata, include_vocabularies)
    
    def _extract_metadata(self, document: FRBROODocument, expression: F2Expression) -> CitationMetadata:
        """Extract metadata from document and expression."""
        metadata = CitationMetadata()
        
        # Try to find official manifestation
        official_manifestations = [
            man for man in document.manifestations 
            if man.expression == expression and man.is_official
        ]
        
        if official_manifestations:
            manifestation = official_manifestations[0]
            metadata.doi = manifestation.doi
            metadata.isbn = manifestation.isbn_issn
            metadata.publisher_location = manifestation.publication_place
        
        # Try to find accessible item for URL
        accessible_items = document.get_accessible_items()
        if accessible_items:
            metadata.url = accessible_items[0].location
            metadata.access_date = accessible_items[0].access_date
        
        return metadata
    
    def _format_authors_abnt(self, expression: F2Expression) -> str:
        """Format authors according to ABNT standard."""
        if not expression.authors:
            return "BRASIL"
        
        # For legislative documents, use the authority
        if len(expression.authors) == 1 and expression.authors[0].type in ["Órgão", "Instituição"]:
            return expression.authors[0].name.upper()
        
        # Multiple authors
        author_names = []
        for i, author in enumerate(expression.authors[:3]):  # Limit to 3 authors
            # Last name, First name format
            name_parts = author.name.split()
            if len(name_parts) > 1:
                last_name = name_parts[-1].upper()
                first_names = " ".join(name_parts[:-1])
                author_names.append(f"{last_name}, {first_names}")
            else:
                author_names.append(author.name.upper())
        
        if len(expression.authors) > 3:
            author_names.append("et al.")
        
        return "; ".join(author_names)
    
    def _format_date_abnt(self, date: datetime) -> str:
        """Format date according to ABNT standard."""
        day = date.day
        month = self.month_names_pt.get(date.month, str(date.month))
        year = date.year
        return f"{day} de {month} de {year}"
    
    def _generate_abnt(self, document: FRBROODocument, expression: F2Expression,
                      metadata: CitationMetadata, include_vocabularies: bool) -> str:
        """Generate ABNT NBR 6023:2018 citation."""
        parts = []
        
        # Authors
        authors = self._format_authors_abnt(expression)
        parts.append(authors)
        
        # Title
        title = document.work.title
        if document.work.document_type == PropositionType.PL:
            title = f"Projeto de Lei {title}"
        parts.append(f"{title}.")
        
        # Document type and number
        doc_info = f"{document.work.document_type.value}"
        if hasattr(expression, 'number'):
            doc_info += f" nº {expression.number}"
        parts.append(f"{doc_info}.")
        
        # Publisher location and authority
        parts.append(f"{metadata.publisher_location}: {document.work.authority},")
        
        # Date
        date_str = self._format_date_abnt(expression.expression_date)
        parts.append(f"{date_str}.")
        
        # URL and access date
        if metadata.url:
            parts.append(f"Disponível em: {metadata.url}.")
            if metadata.access_date:
                access_date_str = self._format_date_abnt(metadata.access_date)
                parts.append(f"Acesso em: {access_date_str}.")
        
        # DOI
        if metadata.doi:
            parts.append(f"DOI: {metadata.doi}.")
        
        # Controlled vocabularies (optional)
        if include_vocabularies and document.work.controlled_vocabulary_tags:
            vocab_terms = [tag.label for tag in document.work.controlled_vocabulary_tags[:3]]
            parts.append(f"Termos indexados: {', '.join(vocab_terms)}.")
        
        return " ".join(parts)
    
    def _generate_apa(self, document: FRBROODocument, expression: F2Expression,
                     metadata: CitationMetadata, include_vocabularies: bool) -> str:
        """Generate APA 7th Edition citation."""
        parts = []
        
        # Authors
        if expression.authors:
            author_names = []
            for author in expression.authors[:3]:
                name_parts = author.name.split()
                if len(name_parts) > 1:
                    # Last name, First initial.
                    last_name = name_parts[-1]
                    initials = "".join([name[0].upper() + "." for name in name_parts[:-1]])
                    author_names.append(f"{last_name}, {initials}")
                else:
                    author_names.append(author.name)
            
            if len(expression.authors) > 3:
                author_names.append("et al.")
            
            parts.append(", ".join(author_names))
        else:
            parts.append(document.work.authority)
        
        # Year
        parts.append(f"({expression.expression_date.year}).")
        
        # Title (italicized in APA)
        title = f"_{document.work.title}_"
        if document.work.document_type == PropositionType.PL:
            title = f"_Projeto de Lei {document.work.title}_"
        
        # Document info
        doc_info = f"({document.work.document_type.value}"
        if hasattr(expression, 'number'):
            doc_info += f" No. {expression.number}"
        doc_info += ")."
        
        parts.append(f"{title} {doc_info}")
        
        # Publisher
        parts.append(f"{document.work.authority}.")
        
        # URL
        if metadata.url:
            parts.append(metadata.url)
        
        # DOI
        if metadata.doi:
            parts.append(f"https://doi.org/{metadata.doi}")
        
        return " ".join(parts)
    
    def _generate_bibtex(self, document: FRBROODocument, expression: F2Expression,
                        metadata: CitationMetadata, include_vocabularies: bool) -> str:
        """Generate BibTeX entry with enhanced metadata."""
        # Generate citation key
        year = expression.expression_date.year
        first_author = expression.authors[0].name.split()[-1].lower() if expression.authors else "brasil"
        doc_type = document.work.document_type.name.lower()
        key = f"{first_author}{year}{doc_type}"
        
        # BibTeX entry type
        entry_type = "legislation"
        if document.work.document_type in [PropositionType.PL, PropositionType.PLP, PropositionType.PEC]:
            entry_type = "misc"
        
        # Build BibTeX entry
        lines = [f"@{entry_type}{{{key},"]
        
        # Authors
        if expression.authors:
            author_names = [author.name for author in expression.authors]
            lines.append(f'  author = "{" and ".join(author_names)}",')
        else:
            lines.append(f'  author = "{{{document.work.authority}}}",')
        
        # Title
        lines.append(f'  title = "{{{document.work.title}}}",')
        
        # Year
        lines.append(f'  year = {{{year}}},')
        
        # Month
        month = expression.expression_date.strftime("%B").lower()
        lines.append(f'  month = {{{month}}},')
        
        # Type
        lines.append(f'  type = "{{{document.work.document_type.value}}}",')
        
        # Number
        if hasattr(expression, 'number'):
            lines.append(f'  number = "{{{expression.number}}}",')
        
        # Publisher
        lines.append(f'  publisher = "{{{document.work.authority}}}",')
        lines.append(f'  address = "{{{metadata.publisher_location}}}",')
        
        # URL
        if metadata.url:
            lines.append(f'  url = "{{{metadata.url}}}",')
            lines.append(f'  urldate = "{{{metadata.access_date.strftime("%Y-%m-%d") if metadata.access_date else datetime.now().strftime("%Y-%m-%d")}}}",')
        
        # DOI
        if metadata.doi:
            lines.append(f'  doi = "{{{metadata.doi}}}",')
        
        # Language
        lines.append(f'  language = "{{{metadata.language}}}",')
        
        # FRBROO metadata
        lines.append(f'  note = "{{FRBROO Work: {document.work.work_id}}}",')
        lines.append(f'  annote = "{{Expression: {expression.expression_id}, Version: {expression.version}}}",')
        
        # Controlled vocabularies
        if include_vocabularies and document.work.controlled_vocabulary_tags:
            keywords = [tag.label for tag in document.work.controlled_vocabulary_tags]
            lines.append(f'  keywords = "{{{", ".join(keywords)}}}",')
        
        # LexML URN
        lines.append(f'  howpublished = "{{LexML URN: {document.lexml_identifier.urn}}}",')
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def _generate_mla(self, document: FRBROODocument, expression: F2Expression,
                     metadata: CitationMetadata, include_vocabularies: bool) -> str:
        """Generate MLA 9th Edition citation."""
        parts = []
        
        # Authors (Last, First)
        if expression.authors:
            if len(expression.authors) == 1:
                author = expression.authors[0]
                name_parts = author.name.split()
                if len(name_parts) > 1:
                    parts.append(f"{name_parts[-1]}, {' '.join(name_parts[:-1])}.")
                else:
                    parts.append(f"{author.name}.")
            elif len(expression.authors) == 2:
                # Two authors
                author1 = expression.authors[0].name
                author2 = expression.authors[1].name
                parts.append(f"{author1}, and {author2}.")
            else:
                # Three or more authors
                author = expression.authors[0]
                name_parts = author.name.split()
                if len(name_parts) > 1:
                    parts.append(f"{name_parts[-1]}, {' '.join(name_parts[:-1])}, et al.")
                else:
                    parts.append(f"{author.name}, et al.")
        else:
            parts.append(f"{document.work.authority}.")
        
        # Title (italicized)
        parts.append(f'"{document.work.title}."')
        
        # Document type and number
        doc_info = f"{document.work.document_type.value}"
        if hasattr(expression, 'number'):
            doc_info += f" {expression.number}"
        parts.append(f"{doc_info},")
        
        # Publisher
        parts.append(f"{document.work.authority},")
        
        # Date
        date_str = expression.expression_date.strftime("%d %b. %Y")
        parts.append(f"{date_str}.")
        
        # Web
        if metadata.url:
            parts.append("Web.")
            if metadata.access_date:
                access_str = metadata.access_date.strftime("%d %b. %Y")
                parts.append(f"{access_str}.")
        
        return " ".join(parts)
    
    def _generate_chicago(self, document: FRBROODocument, expression: F2Expression,
                         metadata: CitationMetadata, include_vocabularies: bool) -> str:
        """Generate Chicago 17th Edition citation (Notes-Bibliography style)."""
        parts = []
        
        # Authors
        if expression.authors:
            author_names = []
            for i, author in enumerate(expression.authors[:3]):
                if i == 0:
                    # First author: Last, First
                    name_parts = author.name.split()
                    if len(name_parts) > 1:
                        author_names.append(f"{name_parts[-1]}, {' '.join(name_parts[:-1])}")
                    else:
                        author_names.append(author.name)
                else:
                    # Other authors: First Last
                    author_names.append(author.name)
            
            if len(expression.authors) > 3:
                author_names.append("et al.")
            
            parts.append(", ".join(author_names) + ".")
        else:
            parts.append(f"{document.work.authority}.")
        
        # Title (italicized)
        parts.append(f'_{document.work.title}_.')
        
        # Document info
        doc_info = f"{document.work.document_type.value}"
        if hasattr(expression, 'number'):
            doc_info += f" {expression.number}"
        parts.append(f"{doc_info}.")
        
        # Place: Publisher
        parts.append(f"{metadata.publisher_location}: {document.work.authority},")
        
        # Date
        parts.append(f"{expression.expression_date.year}.")
        
        # URL
        if metadata.url:
            parts.append(f"Accessed {metadata.access_date.strftime('%B %d, %Y') if metadata.access_date else 'n.d.'}.")
            parts.append(metadata.url + ".")
        
        return " ".join(parts)
    
    def _generate_skos_rdf(self, document: FRBROODocument, expression: F2Expression,
                          metadata: CitationMetadata) -> str:
        """Generate SKOS-RDF representation."""
        # This would generate actual RDF/XML in production
        # For now, return a structured representation
        
        rdf_data = {
            "@context": {
                "skos": "http://www.w3.org/2004/02/skos/core#",
                "dc": "http://purl.org/dc/elements/1.1/",
                "frbroo": "http://iflastandards.info/ns/fr/frbr/frbroo/",
                "lexml": "http://www.lexml.gov.br/vocabularios/"
            },
            "@id": document.lexml_identifier.urn,
            "@type": ["frbroo:F1_Work", "skos:Concept"],
            "dc:title": document.work.title,
            "dc:creator": [author.name for author in expression.authors],
            "dc:date": expression.expression_date.isoformat(),
            "dc:type": document.work.document_type.value,
            "dc:publisher": document.work.authority,
            "dc:identifier": document.lexml_identifier.urn,
            "frbroo:R3_is_realised_in": {
                "@id": expression.expression_id,
                "@type": "frbroo:F2_Expression",
                "dc:language": expression.language,
                "frbroo:version": expression.version
            },
            "skos:prefLabel": document.work.title,
            "skos:notation": document.work.document_type.name,
            "skos:subject": []
        }
        
        # Add controlled vocabulary terms
        for tag in document.work.controlled_vocabulary_tags:
            rdf_data["skos:subject"].append({
                "@id": tag.uri,
                "@type": "skos:Concept",
                "skos:prefLabel": tag.label,
                "skos:inScheme": tag.vocabulary
            })
        
        # Add URL if available
        if metadata.url:
            rdf_data["dc:source"] = metadata.url
        
        # Add DOI if available
        if metadata.doi:
            rdf_data["dc:identifier"] = [document.lexml_identifier.urn, f"doi:{metadata.doi}"]
        
        return json.dumps(rdf_data, ensure_ascii=False, indent=2)
    
    def generate_bibliography(self, documents: List[FRBROODocument],
                            standard: str = "ABNT",
                            sort_by: str = "date",
                            include_vocabularies: bool = True) -> str:
        """
        Generate a complete bibliography from multiple documents.
        
        Args:
            documents: List of FRBROO documents
            standard: Citation standard to use
            sort_by: Sort criteria (date, author, title)
            include_vocabularies: Include controlled vocabulary terms
            
        Returns:
            Formatted bibliography
        """
        # Sort documents
        if sort_by == "date":
            documents.sort(key=lambda d: d.get_current_expression().expression_date if d.get_current_expression() else datetime.min)
        elif sort_by == "author":
            documents.sort(key=lambda d: d.get_current_expression().authors[0].name if d.get_current_expression() and d.get_current_expression().authors else "")
        elif sort_by == "title":
            documents.sort(key=lambda d: d.work.title)
        
        # Generate citations
        citations = []
        for doc in documents:
            citation = self.generate_citation(doc, standard, include_vocabularies=include_vocabularies)
            if citation:
                citations.append(citation)
        
        # Format based on standard
        if standard.upper() == "BIBTEX":
            return "\n\n".join(citations)
        else:
            return "\n\n".join(citations)
    
    def export_citations(self, documents: List[FRBROODocument],
                        output_path: Path,
                        standards: List[str] = ["ABNT", "APA", "BibTeX"],
                        format: str = "TXT") -> bool:
        """
        Export citations in multiple standards to a file.
        
        Args:
            documents: List of FRBROO documents
            output_path: Path to save the file
            standards: List of citation standards to include
            format: Output format (TXT, JSON, HTML)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            content = {}
            
            # Generate citations for each standard
            for standard in standards:
                bibliography = self.generate_bibliography(documents, standard)
                content[standard] = bibliography
            
            # Write to file based on format
            if format.upper() == "JSON":
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(content, f, ensure_ascii=False, indent=2)
            
            elif format.upper() == "HTML":
                html_content = self._generate_html_bibliography(content)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            
            else:  # Default to TXT
                with open(output_path, 'w', encoding='utf-8') as f:
                    for standard, bibliography in content.items():
                        f.write(f"{'=' * 60}\n")
                        f.write(f"{standard} Citations\n")
                        f.write(f"{'=' * 60}\n\n")
                        f.write(bibliography)
                        f.write("\n\n")
            
            return True
            
        except Exception as e:
            print(f"Error exporting citations: {e}")
            return False
    
    def _generate_html_bibliography(self, content: Dict[str, str]) -> str:
        """Generate HTML formatted bibliography."""
        html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bibliografia - Monitor Legislativo</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .citation { margin-bottom: 20px; padding: 10px; background-color: #f9f9f9; }
        .standard { margin-bottom: 40px; }
        pre { background-color: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Bibliografia - Legislação de Transportes</h1>
    <p>Gerado em: {}</p>
""".format(datetime.now().strftime("%d/%m/%Y %H:%M"))
        
        for standard, bibliography in content.items():
            html += f'<div class="standard">\n'
            html += f'<h2>{standard}</h2>\n'
            
            if standard == "BibTeX":
                html += f'<pre>{bibliography}</pre>\n'
            else:
                citations = bibliography.split("\n\n")
                for citation in citations:
                    if citation.strip():
                        html += f'<div class="citation">{citation}</div>\n'
            
            html += '</div>\n'
        
        html += """
</body>
</html>
"""
        return html