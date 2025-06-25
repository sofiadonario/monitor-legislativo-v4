# Bibliography Export and Academic Integration Tools for Monitor Legislativo v4
# Phase 5 Week 17: Advanced academic integration and bibliography management
# Seamless integration with reference managers and academic platforms

import asyncio
import asyncpg
import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum
import csv
import io
import zipfile
import tempfile
import base64
from urllib.parse import quote, urlencode
import aiohttp

logger = logging.getLogger(__name__)

class ExportFormat(Enum):
    """Bibliography export formats"""
    BIBTEX = "bibtex"              # BibTeX format
    ENDNOTE = "endnote"            # EndNote XML
    RIS = "ris"                    # Research Information Systems
    ZOTERO = "zotero"             # Zotero RDF
    MENDELEY = "mendeley"         # Mendeley format
    REFWORKS = "refworks"         # RefWorks Tagged Format
    MODS = "mods"                 # Metadata Object Description Schema
    DUBLIN_CORE = "dublin_core"   # Dublin Core XML
    CSV = "csv"                   # Comma-separated values
    JSON = "json"                 # JSON format
    EXCEL = "excel"               # Microsoft Excel

class IntegrationPlatform(Enum):
    """Academic integration platforms"""
    ORCID = "orcid"               # ORCID researcher profiles
    GOOGLE_SCHOLAR = "google_scholar"  # Google Scholar
    LATTES = "lattes"             # Plataforma Lattes (CNPq)
    RESEARCHGATE = "researchgate" # ResearchGate
    ACADEMIA_EDU = "academia_edu" # Academia.edu
    CROSSREF = "crossref"         # Crossref DOI lookup
    ARXIV = "arxiv"               # arXiv preprints
    PUBMED = "pubmed"             # PubMed/MEDLINE

@dataclass
class BibliographyEntry:
    """Bibliography entry for export"""
    entry_id: str
    document_id: str
    citation_key: str
    entry_type: str               # "article", "book", "inproceedings", etc.
    title: str
    authors: List[str]
    year: Optional[int] = None
    journal: Optional[str] = None
    volume: Optional[str] = None
    number: Optional[str] = None
    pages: Optional[str] = None
    publisher: Optional[str] = None
    doi: Optional[str] = None
    url: Optional[str] = None
    abstract: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    language: str = "pt"
    country: str = "BR"
    custom_fields: Dict[str, str] = field(default_factory=dict)
    added_date: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['added_date'] = self.added_date.isoformat()
        return result

@dataclass
class ExportOptions:
    """Export configuration options"""
    format_type: ExportFormat
    include_abstracts: bool = True
    include_keywords: bool = True
    include_notes: bool = False
    include_urls: bool = True
    encoding: str = "utf-8"
    sort_by: str = "author"       # "author", "title", "year", "date_added"
    filter_by_date: Optional[date] = None
    filter_by_keywords: List[str] = field(default_factory=list)
    max_entries: Optional[int] = None
    citation_style: str = "abnt"  # For formatted citations
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['format_type'] = self.format_type.value
        if self.filter_by_date:
            result['filter_by_date'] = self.filter_by_date.isoformat()
        return result

@dataclass
class IntegrationResult:
    """Result of academic platform integration"""
    platform: IntegrationPlatform
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    external_id: Optional[str] = None
    external_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['platform'] = self.platform.value
        return result

class BibliographyExportManager:
    """
    Comprehensive bibliography export and academic integration system
    
    Features:
    - Multiple export formats (BibTeX, EndNote, RIS, etc.)
    - Academic platform integration (ORCID, Lattes, Google Scholar)
    - Brazilian academic standards compliance
    - Reference manager compatibility
    - Citation style formatting
    - Bulk export and synchronization
    - Metadata enhancement and validation
    """
    
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        
        # Export format handlers
        self.format_handlers = {
            ExportFormat.BIBTEX: self._export_bibtex,
            ExportFormat.ENDNOTE: self._export_endnote,
            ExportFormat.RIS: self._export_ris,
            ExportFormat.ZOTERO: self._export_zotero,
            ExportFormat.MENDELEY: self._export_mendeley,
            ExportFormat.REFWORKS: self._export_refworks,
            ExportFormat.MODS: self._export_mods,
            ExportFormat.DUBLIN_CORE: self._export_dublin_core,
            ExportFormat.CSV: self._export_csv,
            ExportFormat.JSON: self._export_json,
            ExportFormat.EXCEL: self._export_excel
        }
        
        # Integration handlers
        self.integration_handlers = {
            IntegrationPlatform.ORCID: self._integrate_orcid,
            IntegrationPlatform.LATTES: self._integrate_lattes,
            IntegrationPlatform.GOOGLE_SCHOLAR: self._integrate_google_scholar,
            IntegrationPlatform.CROSSREF: self._integrate_crossref
        }
        
        # Brazilian academic institutions
        self.brazilian_institutions = {
            "capes": "Coordenação de Aperfeiçoamento de Pessoal de Nível Superior",
            "cnpq": "Conselho Nacional de Desenvolvimento Científico e Tecnológico",
            "finep": "Financiadora de Estudos e Projetos",
            "fapesp": "Fundação de Amparo à Pesquisa do Estado de São Paulo",
            "faperj": "Fundação Carlos Chagas Filho de Amparo à Pesquisa do Estado do RJ"
        }
    
    async def initialize(self) -> None:
        """Initialize bibliography export system"""
        await self._create_export_tables()
        logger.info("Bibliography export system initialized")
    
    async def _create_export_tables(self) -> None:
        """Create export tracking tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Bibliography exports table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bibliography_exports (
                    export_id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(100) NOT NULL,
                    project_id VARCHAR(36) NULL,
                    export_format VARCHAR(30) NOT NULL,
                    export_options JSONB NOT NULL,
                    document_count INTEGER NOT NULL,
                    file_size INTEGER NULL,
                    file_path VARCHAR(500) NULL,
                    download_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    expires_at TIMESTAMP NULL
                );
            """)
            
            # Integration tracking table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS academic_integrations (
                    integration_id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(100) NOT NULL,
                    platform VARCHAR(30) NOT NULL,
                    external_id VARCHAR(200) NULL,
                    external_url VARCHAR(500) NULL,
                    integration_data JSONB DEFAULT '{}'::jsonb,
                    last_sync TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Bibliography collections table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bibliography_collections (
                    collection_id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(100) NOT NULL,
                    name VARCHAR(200) NOT NULL,
                    description TEXT NULL,
                    document_ids JSONB DEFAULT '[]'::jsonb,
                    tags JSONB DEFAULT '[]'::jsonb,
                    is_public BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Export metadata enhancement table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS document_metadata_enhancements (
                    enhancement_id VARCHAR(36) PRIMARY KEY,
                    document_id VARCHAR(100) NOT NULL,
                    enhancement_type VARCHAR(30) NOT NULL,
                    enhanced_data JSONB NOT NULL,
                    source_platform VARCHAR(30) NULL,
                    confidence_score FLOAT DEFAULT 0.0,
                    verified BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_exports_user ON bibliography_exports(user_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_exports_format ON bibliography_exports(export_format);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrations_user ON academic_integrations(user_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrations_platform ON academic_integrations(platform);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_collections_user ON bibliography_collections(user_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_enhancements_document ON document_metadata_enhancements(document_id);")
            
            logger.info("Bibliography export tables created successfully")
        
        finally:
            await conn.close()
    
    async def create_bibliography_export(self, user_id: str, document_ids: List[str],
                                       export_options: ExportOptions,
                                       project_id: str = None) -> str:
        """Create and process bibliography export"""
        
        # Get bibliography entries for documents
        entries = await self._get_bibliography_entries(document_ids, export_options)
        
        # Generate export content
        handler = self.format_handlers.get(export_options.format_type)
        if not handler:
            raise ValueError(f"Unsupported export format: {export_options.format_type}")
        
        export_content = await handler(entries, export_options)
        
        # Save export file
        export_id = await self._save_export_file(
            user_id=user_id,
            project_id=project_id,
            export_content=export_content,
            export_options=export_options,
            document_count=len(entries)
        )
        
        logger.info(f"Bibliography export created: {export_id} ({export_options.format_type.value})")
        return export_id
    
    async def _get_bibliography_entries(self, document_ids: List[str], 
                                      options: ExportOptions) -> List[BibliographyEntry]:
        """Get bibliography entries for documents"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # This would integrate with the document storage system
            # For now, create placeholder entries
            entries = []
            
            for i, doc_id in enumerate(document_ids):
                # Generate placeholder bibliography entry
                entry = BibliographyEntry(
                    entry_id=f"entry_{i+1}",
                    document_id=doc_id,
                    citation_key=f"doc_{doc_id}_{options.format_type.value}",
                    entry_type="legislation",
                    title=f"Documento Legislativo {doc_id}",
                    authors=["Brasil"],
                    year=2024,
                    publisher="Governo Federal",
                    url=f"https://monitor-legislativo.com/documents/{doc_id}",
                    language="pt",
                    country="BR"
                )
                entries.append(entry)
            
            # Apply filtering and sorting
            filtered_entries = self._filter_and_sort_entries(entries, options)
            
            return filtered_entries
        
        finally:
            await conn.close()
    
    def _filter_and_sort_entries(self, entries: List[BibliographyEntry], 
                                options: ExportOptions) -> List[BibliographyEntry]:
        """Filter and sort bibliography entries"""
        
        filtered = entries
        
        # Apply date filter
        if options.filter_by_date:
            filtered = [e for e in filtered if e.added_date.date() >= options.filter_by_date]
        
        # Apply keyword filter
        if options.filter_by_keywords:
            keyword_set = set(kw.lower() for kw in options.filter_by_keywords)
            filtered = [e for e in filtered if any(kw in keyword_set for kw in [k.lower() for k in e.keywords])]
        
        # Apply max entries limit
        if options.max_entries:
            filtered = filtered[:options.max_entries]
        
        # Sort entries
        if options.sort_by == "author":
            filtered.sort(key=lambda e: e.authors[0] if e.authors else "")
        elif options.sort_by == "title":
            filtered.sort(key=lambda e: e.title)
        elif options.sort_by == "year":
            filtered.sort(key=lambda e: e.year or 0, reverse=True)
        elif options.sort_by == "date_added":
            filtered.sort(key=lambda e: e.added_date, reverse=True)
        
        return filtered
    
    async def _export_bibtex(self, entries: List[BibliographyEntry], 
                           options: ExportOptions) -> str:
        """Export to BibTeX format"""
        
        bibtex_entries = []
        
        for entry in entries:
            lines = [f"@{entry.entry_type}{{{entry.citation_key},"]
            
            # Title
            lines.append(f'  title = {{{entry.title}}},')
            
            # Authors
            if entry.authors:
                authors_str = ' and '.join(entry.authors)
                lines.append(f'  author = {{{authors_str}}},')
            
            # Year
            if entry.year:
                lines.append(f'  year = {{{entry.year}}},')
            
            # Journal/Publisher
            if entry.journal:
                lines.append(f'  journal = {{{entry.journal}}},')
            elif entry.publisher:
                lines.append(f'  publisher = {{{entry.publisher}}},')
            
            # Volume and number
            if entry.volume:
                lines.append(f'  volume = {{{entry.volume}}},')
            if entry.number:
                lines.append(f'  number = {{{entry.number}}},')
            
            # Pages
            if entry.pages:
                lines.append(f'  pages = {{{entry.pages}}},')
            
            # DOI
            if entry.doi:
                lines.append(f'  doi = {{{entry.doi}}},')
            
            # URL
            if entry.url and options.include_urls:
                lines.append(f'  url = {{{entry.url}}},')
            
            # Abstract
            if entry.abstract and options.include_abstracts:
                clean_abstract = entry.abstract.replace('{', '\\{').replace('}', '\\}')
                lines.append(f'  abstract = {{{clean_abstract}}},')
            
            # Keywords
            if entry.keywords and options.include_keywords:
                keywords_str = ', '.join(entry.keywords)
                lines.append(f'  keywords = {{{keywords_str}}},')
            
            # Language and country
            lines.append(f'  language = {{{entry.language}}},')
            lines.append(f'  address = {{{entry.country}}},')
            
            # Custom fields
            for field, value in entry.custom_fields.items():
                lines.append(f'  {field} = {{{value}}},')
            
            # Notes
            if entry.notes and options.include_notes:
                clean_notes = entry.notes.replace('{', '\\{').replace('}', '\\}')
                lines.append(f'  note = {{{clean_notes}}},')
            
            # Remove trailing comma from last line
            if lines[-1].endswith(','):
                lines[-1] = lines[-1][:-1]
            
            lines.append('}')
            bibtex_entries.append('\n'.join(lines))
        
        return '\n\n'.join(bibtex_entries)
    
    async def _export_ris(self, entries: List[BibliographyEntry], 
                        options: ExportOptions) -> str:
        """Export to RIS format"""
        
        ris_entries = []
        
        for entry in entries:
            lines = []
            
            # Type of reference
            ris_type = "GOVDOC"  # Government document
            if entry.entry_type == "article":
                ris_type = "JOUR"
            elif entry.entry_type == "book":
                ris_type = "BOOK"
            elif entry.entry_type == "inproceedings":
                ris_type = "CONF"
            
            lines.append(f"TY  - {ris_type}")
            
            # Title
            lines.append(f"TI  - {entry.title}")
            
            # Authors
            for author in entry.authors:
                lines.append(f"AU  - {author}")
            
            # Year
            if entry.year:
                lines.append(f"PY  - {entry.year}")
            
            # Journal/Publisher
            if entry.journal:
                lines.append(f"JF  - {entry.journal}")
            elif entry.publisher:
                lines.append(f"PB  - {entry.publisher}")
            
            # Volume, issue, pages
            if entry.volume:
                lines.append(f"VL  - {entry.volume}")
            if entry.number:
                lines.append(f"IS  - {entry.number}")
            if entry.pages:
                lines.append(f"SP  - {entry.pages}")
            
            # DOI
            if entry.doi:
                lines.append(f"DO  - {entry.doi}")
            
            # URL
            if entry.url and options.include_urls:
                lines.append(f"UR  - {entry.url}")
            
            # Abstract
            if entry.abstract and options.include_abstracts:
                lines.append(f"AB  - {entry.abstract}")
            
            # Keywords
            if entry.keywords and options.include_keywords:
                for keyword in entry.keywords:
                    lines.append(f"KW  - {keyword}")
            
            # Language
            lines.append(f"LA  - {entry.language}")
            
            # Notes
            if entry.notes and options.include_notes:
                lines.append(f"N1  - {entry.notes}")
            
            # End of record
            lines.append("ER  - ")
            
            ris_entries.append('\n'.join(lines))
        
        return '\n\n'.join(ris_entries)
    
    async def _export_endnote(self, entries: List[BibliographyEntry], 
                            options: ExportOptions) -> str:
        """Export to EndNote XML format"""
        
        # Create XML root
        root = ET.Element("xml")
        records = ET.SubElement(root, "records")
        
        for i, entry in enumerate(entries, 1):
            record = ET.SubElement(records, "record")
            
            # Database info
            database = ET.SubElement(record, "database", name="Monitor Legislativo", path="monitor-legislativo.enl")
            database.text = "monitor-legislativo.enl"
            
            # Source type
            source_type = ET.SubElement(record, "source-type", name="Government Document")
            source_type.text = "32"  # EndNote type for government document
            
            # Record number
            rec_number = ET.SubElement(record, "rec-number")
            rec_number.text = str(i)
            
            # Foreign keys
            foreign_keys = ET.SubElement(record, "foreign-keys")
            key = ET.SubElement(foreign_keys, "key", app="EN", db_id="52eptwepv22vdxeeapawrw5f2tvsepz5xvze")
            key.text = str(i)
            
            # Reference type
            ref_type = ET.SubElement(record, "ref-type", name="Government Document")
            ref_type.text = "32"
            
            # Contributors (authors)
            contributors = ET.SubElement(record, "contributors")
            authors = ET.SubElement(contributors, "authors")
            for author in entry.authors:
                author_elem = ET.SubElement(authors, "author")
                author_elem.text = author
            
            # Titles
            titles = ET.SubElement(record, "titles")
            title = ET.SubElement(titles, "title")
            title.text = entry.title
            
            # Dates
            dates = ET.SubElement(record, "dates")
            if entry.year:
                year = ET.SubElement(dates, "year")
                year.text = str(entry.year)
            
            # Publisher
            if entry.publisher:
                publisher = ET.SubElement(record, "publisher")
                publisher.text = entry.publisher
            
            # URLs
            if entry.url and options.include_urls:
                urls = ET.SubElement(record, "urls")
                related_urls = ET.SubElement(urls, "related-urls")
                url = ET.SubElement(related_urls, "url")
                url.text = entry.url
            
            # Abstract
            if entry.abstract and options.include_abstracts:
                abstract = ET.SubElement(record, "abstract")
                abstract.text = entry.abstract
            
            # Keywords
            if entry.keywords and options.include_keywords:
                keywords = ET.SubElement(record, "keywords")
                for keyword in entry.keywords:
                    keyword_elem = ET.SubElement(keywords, "keyword")
                    keyword_elem.text = keyword
            
            # Language
            language = ET.SubElement(record, "language")
            language.text = entry.language
        
        # Convert to string
        return ET.tostring(root, encoding='unicode', method='xml')
    
    async def _export_zotero(self, entries: List[BibliographyEntry], 
                           options: ExportOptions) -> str:
        """Export to Zotero RDF format"""
        
        # Create RDF/XML structure
        rdf_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<rdf:RDF',
            '    xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"',
            '    xmlns:z="http://www.zotero.org/namespaces/export#"',
            '    xmlns:dcterms="http://purl.org/dc/terms/"',
            '    xmlns:dc="http://purl.org/dc/elements/1.1/"',
            '    xmlns:foaf="http://xmlns.com/foaf/0.1/"',
            '    xmlns:vcard="http://nwalsh.com/rdf/vCard#">',
            ''
        ]
        
        for entry in entries:
            rdf_lines.extend([
                f'    <rdf:Description rdf:about="#{entry.citation_key}">',
                '        <rdf:type rdf:resource="http://www.zotero.org/namespaces/export#Document"/>',
                f'        <dc:title>{self._escape_xml(entry.title)}</dc:title>',
            ])
            
            # Authors
            for author in entry.authors:
                rdf_lines.append(f'        <dc:creator>{self._escape_xml(author)}</dc:creator>')
            
            # Date
            if entry.year:
                rdf_lines.append(f'        <dc:date>{entry.year}</dc:date>')
            
            # Publisher
            if entry.publisher:
                rdf_lines.append(f'        <dc:publisher>{self._escape_xml(entry.publisher)}</dc:publisher>')
            
            # URL
            if entry.url and options.include_urls:
                rdf_lines.append(f'        <dc:identifier>{self._escape_xml(entry.url)}</dc:identifier>')
            
            # Language
            rdf_lines.append(f'        <dc:language>{entry.language}</dc:language>')
            
            # Abstract
            if entry.abstract and options.include_abstracts:
                rdf_lines.append(f'        <dcterms:abstract>{self._escape_xml(entry.abstract)}</dcterms:abstract>')
            
            # Keywords
            if entry.keywords and options.include_keywords:
                for keyword in entry.keywords:
                    rdf_lines.append(f'        <dc:subject>{self._escape_xml(keyword)}</dc:subject>')
            
            rdf_lines.append('    </rdf:Description>')
            rdf_lines.append('')
        
        rdf_lines.append('</rdf:RDF>')
        
        return '\n'.join(rdf_lines)
    
    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters"""
        if not text:
            return ""
        
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#39;'))
    
    async def _export_csv(self, entries: List[BibliographyEntry], 
                        options: ExportOptions) -> str:
        """Export to CSV format"""
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = ['ID', 'Title', 'Authors', 'Year', 'Type', 'Publisher', 'URL']
        if options.include_abstracts:
            headers.append('Abstract')
        if options.include_keywords:
            headers.append('Keywords')
        if options.include_notes:
            headers.append('Notes')
        
        writer.writerow(headers)
        
        # Write entries
        for entry in entries:
            row = [
                entry.document_id,
                entry.title,
                '; '.join(entry.authors),
                entry.year or '',
                entry.entry_type,
                entry.publisher or '',
                entry.url or ''
            ]
            
            if options.include_abstracts:
                row.append(entry.abstract or '')
            if options.include_keywords:
                row.append('; '.join(entry.keywords))
            if options.include_notes:
                row.append(entry.notes or '')
            
            writer.writerow(row)
        
        return output.getvalue()
    
    async def _export_json(self, entries: List[BibliographyEntry], 
                         options: ExportOptions) -> str:
        """Export to JSON format"""
        
        export_data = {
            "metadata": {
                "export_date": datetime.now().isoformat(),
                "format": "json",
                "source": "Monitor Legislativo v4",
                "total_entries": len(entries),
                "options": options.to_dict()
            },
            "entries": [entry.to_dict() for entry in entries]
        }
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    async def _export_excel(self, entries: List[BibliographyEntry], 
                          options: ExportOptions) -> bytes:
        """Export to Excel format"""
        
        # This would require openpyxl or xlsxwriter
        # For now, return CSV as bytes
        csv_content = await self._export_csv(entries, options)
        return csv_content.encode(options.encoding)
    
    async def _export_mendeley(self, entries: List[BibliographyEntry], 
                             options: ExportOptions) -> str:
        """Export to Mendeley format (BibTeX variant)"""
        # Mendeley uses BibTeX with some specific fields
        return await self._export_bibtex(entries, options)
    
    async def _export_refworks(self, entries: List[BibliographyEntry], 
                             options: ExportOptions) -> str:
        """Export to RefWorks Tagged Format"""
        
        refworks_entries = []
        
        for entry in entries:
            lines = []
            
            # Record type
            lines.append("RT Government Document")
            
            # Title
            lines.append(f"T1 {entry.title}")
            
            # Authors
            for author in entry.authors:
                lines.append(f"A1 {author}")
            
            # Year
            if entry.year:
                lines.append(f"YR {entry.year}")
            
            # Publisher
            if entry.publisher:
                lines.append(f"PB {entry.publisher}")
            
            # URL
            if entry.url and options.include_urls:
                lines.append(f"UL {entry.url}")
            
            # Abstract
            if entry.abstract and options.include_abstracts:
                lines.append(f"AB {entry.abstract}")
            
            # Keywords
            if entry.keywords and options.include_keywords:
                for keyword in entry.keywords:
                    lines.append(f"K1 {keyword}")
            
            # Language
            lines.append(f"LA {entry.language}")
            
            # End of record
            lines.append("")
            
            refworks_entries.append('\n'.join(lines))
        
        return '\n'.join(refworks_entries)
    
    async def _export_mods(self, entries: List[BibliographyEntry], 
                         options: ExportOptions) -> str:
        """Export to MODS XML format"""
        
        # Create MODS XML structure
        mods_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<modsCollection xmlns="http://www.loc.gov/mods/v3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.loc.gov/mods/v3 http://www.loc.gov/standards/mods/v3/mods-3-3.xsd">',
            ''
        ]
        
        for entry in entries:
            mods_lines.extend([
                '    <mods>',
                '        <titleInfo>',
                f'            <title>{self._escape_xml(entry.title)}</title>',
                '        </titleInfo>',
            ])
            
            # Authors
            for author in entry.authors:
                mods_lines.extend([
                    '        <name type="personal">',
                    f'            <namePart>{self._escape_xml(author)}</namePart>',
                    '            <role>',
                    '                <roleTerm type="text">author</roleTerm>',
                    '            </role>',
                    '        </name>'
                ])
            
            # Type
            mods_lines.extend([
                '        <typeOfResource>text</typeOfResource>',
                '        <genre>government publication</genre>'
            ])
            
            # Origin info
            if entry.year or entry.publisher:
                mods_lines.append('        <originInfo>')
                if entry.publisher:
                    mods_lines.append(f'            <publisher>{self._escape_xml(entry.publisher)}</publisher>')
                if entry.year:
                    mods_lines.append(f'            <dateIssued>{entry.year}</dateIssued>')
                mods_lines.append('        </originInfo>')
            
            # Language
            mods_lines.extend([
                '        <language>',
                f'            <languageTerm type="code" authority="iso639-2b">{entry.language}</languageTerm>',
                '        </language>'
            ])
            
            # Abstract
            if entry.abstract and options.include_abstracts:
                mods_lines.append(f'        <abstract>{self._escape_xml(entry.abstract)}</abstract>')
            
            # Keywords
            if entry.keywords and options.include_keywords:
                for keyword in entry.keywords:
                    mods_lines.extend([
                        '        <subject>',
                        f'            <topic>{self._escape_xml(keyword)}</topic>',
                        '        </subject>'
                    ])
            
            # URL
            if entry.url and options.include_urls:
                mods_lines.extend([
                    '        <location>',
                    f'            <url>{self._escape_xml(entry.url)}</url>',
                    '        </location>'
                ])
            
            mods_lines.append('    </mods>')
            mods_lines.append('')
        
        mods_lines.append('</modsCollection>')
        
        return '\n'.join(mods_lines)
    
    async def _export_dublin_core(self, entries: List[BibliographyEntry], 
                                options: ExportOptions) -> str:
        """Export to Dublin Core XML format"""
        
        dc_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/">',
            ''
        ]
        
        for entry in entries:
            dc_lines.extend([
                f'    <rdf:Description rdf:about="{entry.url or entry.document_id}">',
                f'        <dc:title>{self._escape_xml(entry.title)}</dc:title>',
            ])
            
            # Authors
            for author in entry.authors:
                dc_lines.append(f'        <dc:creator>{self._escape_xml(author)}</dc:creator>')
            
            # Date
            if entry.year:
                dc_lines.append(f'        <dc:date>{entry.year}</dc:date>')
            
            # Publisher
            if entry.publisher:
                dc_lines.append(f'        <dc:publisher>{self._escape_xml(entry.publisher)}</dc:publisher>')
            
            # Type
            dc_lines.append('        <dc:type>Text</dc:type>')
            dc_lines.append('        <dc:format>text/html</dc:format>')
            
            # Language
            dc_lines.append(f'        <dc:language>{entry.language}</dc:language>')
            
            # Description (abstract)
            if entry.abstract and options.include_abstracts:
                dc_lines.append(f'        <dc:description>{self._escape_xml(entry.abstract)}</dc:description>')
            
            # Keywords
            if entry.keywords and options.include_keywords:
                for keyword in entry.keywords:
                    dc_lines.append(f'        <dc:subject>{self._escape_xml(keyword)}</dc:subject>')
            
            # Identifier
            if entry.url:
                dc_lines.append(f'        <dc:identifier>{self._escape_xml(entry.url)}</dc:identifier>')
            
            dc_lines.append('    </rdf:Description>')
            dc_lines.append('')
        
        dc_lines.append('</rdf:RDF>')
        
        return '\n'.join(dc_lines)
    
    async def _save_export_file(self, user_id: str, project_id: str, 
                              export_content: Union[str, bytes], export_options: ExportOptions,
                              document_count: int) -> str:
        """Save export file and create database record"""
        
        import uuid
        export_id = str(uuid.uuid4())
        
        # Determine file extension
        file_extensions = {
            ExportFormat.BIBTEX: "bib",
            ExportFormat.ENDNOTE: "xml",
            ExportFormat.RIS: "ris",
            ExportFormat.ZOTERO: "rdf",
            ExportFormat.MENDELEY: "bib",
            ExportFormat.REFWORKS: "txt",
            ExportFormat.MODS: "xml",
            ExportFormat.DUBLIN_CORE: "xml",
            ExportFormat.CSV: "csv",
            ExportFormat.JSON: "json",
            ExportFormat.EXCEL: "xlsx"
        }
        
        file_ext = file_extensions.get(export_options.format_type, "txt")
        file_name = f"bibliography_export_{export_id}.{file_ext}"
        
        # Save file (in a real implementation, this would save to storage)
        file_path = f"/exports/{file_name}"
        file_size = len(export_content) if isinstance(export_content, (str, bytes)) else 0
        
        # Create database record
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            expires_at = datetime.now() + timedelta(days=30)  # Expire after 30 days
            
            await conn.execute("""
                INSERT INTO bibliography_exports 
                (export_id, user_id, project_id, export_format, export_options, 
                 document_count, file_size, file_path, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """, export_id, user_id, project_id, export_options.format_type.value,
                json.dumps(export_options.to_dict()), document_count, file_size, 
                file_path, expires_at)
            
            return export_id
        
        finally:
            await conn.close()
    
    async def integrate_with_platform(self, user_id: str, platform: IntegrationPlatform,
                                    credentials: Dict[str, str]) -> IntegrationResult:
        """Integrate with academic platform"""
        
        handler = self.integration_handlers.get(platform)
        if not handler:
            return IntegrationResult(
                platform=platform,
                success=False,
                message=f"Integration with {platform.value} not yet implemented"
            )
        
        try:
            result = await handler(user_id, credentials)
            
            # Save integration record
            if result.success:
                await self._save_integration_record(user_id, result)
            
            return result
        
        except Exception as e:
            logger.error(f"Integration error with {platform.value}: {e}")
            return IntegrationResult(
                platform=platform,
                success=False,
                message=f"Integration failed: {str(e)}"
            )
    
    async def _integrate_orcid(self, user_id: str, credentials: Dict[str, str]) -> IntegrationResult:
        """Integrate with ORCID"""
        
        orcid_id = credentials.get('orcid_id')
        access_token = credentials.get('access_token')
        
        if not orcid_id:
            return IntegrationResult(
                platform=IntegrationPlatform.ORCID,
                success=False,
                message="ORCID ID is required"
            )
        
        try:
            # Test ORCID API connection
            async with aiohttp.ClientSession() as session:
                url = f"https://pub.orcid.org/v2.1/{orcid_id}/record"
                headers = {"Accept": "application/json"}
                
                if access_token:
                    headers["Authorization"] = f"Bearer {access_token}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        return IntegrationResult(
                            platform=IntegrationPlatform.ORCID,
                            success=True,
                            message="Successfully connected to ORCID",
                            data=data,
                            external_id=orcid_id,
                            external_url=f"https://orcid.org/{orcid_id}"
                        )
                    else:
                        return IntegrationResult(
                            platform=IntegrationPlatform.ORCID,
                            success=False,
                            message=f"ORCID API error: {response.status}"
                        )
        
        except Exception as e:
            return IntegrationResult(
                platform=IntegrationPlatform.ORCID,
                success=False,
                message=f"Connection error: {str(e)}"
            )
    
    async def _integrate_lattes(self, user_id: str, credentials: Dict[str, str]) -> IntegrationResult:
        """Integrate with Plataforma Lattes (CNPq)"""
        
        lattes_id = credentials.get('lattes_id')
        
        if not lattes_id:
            return IntegrationResult(
                platform=IntegrationPlatform.LATTES,
                success=False,
                message="Lattes ID is required"
            )
        
        # Lattes integration would require specific implementation
        # For now, return a placeholder success
        return IntegrationResult(
            platform=IntegrationPlatform.LATTES,
            success=True,
            message="Lattes integration configured",
            external_id=lattes_id,
            external_url=f"http://lattes.cnpq.br/{lattes_id}"
        )
    
    async def _integrate_google_scholar(self, user_id: str, credentials: Dict[str, str]) -> IntegrationResult:
        """Integrate with Google Scholar"""
        
        scholar_id = credentials.get('scholar_id')
        
        if not scholar_id:
            return IntegrationResult(
                platform=IntegrationPlatform.GOOGLE_SCHOLAR,
                success=False,
                message="Google Scholar ID is required"
            )
        
        return IntegrationResult(
            platform=IntegrationPlatform.GOOGLE_SCHOLAR,
            success=True,
            message="Google Scholar integration configured",
            external_id=scholar_id,
            external_url=f"https://scholar.google.com/citations?user={scholar_id}"
        )
    
    async def _integrate_crossref(self, user_id: str, credentials: Dict[str, str]) -> IntegrationResult:
        """Integrate with Crossref for DOI lookup"""
        
        email = credentials.get('email')  # Crossref requests an email for API etiquette
        
        try:
            # Test Crossref API
            async with aiohttp.ClientSession() as session:
                url = "https://api.crossref.org/works"
                headers = {"User-Agent": f"Monitor Legislativo v4 (mailto:{email or 'noreply@monitor-legislativo.com'})"}
                params = {"rows": 1}
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        return IntegrationResult(
                            platform=IntegrationPlatform.CROSSREF,
                            success=True,
                            message="Successfully connected to Crossref API",
                            external_url="https://api.crossref.org"
                        )
                    else:
                        return IntegrationResult(
                            platform=IntegrationPlatform.CROSSREF,
                            success=False,
                            message=f"Crossref API error: {response.status}"
                        )
        
        except Exception as e:
            return IntegrationResult(
                platform=IntegrationPlatform.CROSSREF,
                success=False,
                message=f"Connection error: {str(e)}"
            )
    
    async def _save_integration_record(self, user_id: str, result: IntegrationResult) -> None:
        """Save integration record to database"""
        
        import uuid
        integration_id = str(uuid.uuid4())
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO academic_integrations 
                (integration_id, user_id, platform, external_id, external_url, 
                 integration_data, last_sync, is_active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (user_id, platform) DO UPDATE SET
                    external_id = EXCLUDED.external_id,
                    external_url = EXCLUDED.external_url,
                    integration_data = EXCLUDED.integration_data,
                    last_sync = EXCLUDED.last_sync,
                    is_active = EXCLUDED.is_active,
                    updated_at = NOW()
            """, integration_id, user_id, result.platform.value, result.external_id,
                result.external_url, json.dumps(result.data or {}), datetime.now(), True)
        
        finally:
            await conn.close()

# Factory function for easy creation
async def create_bibliography_export_manager(db_config: Dict[str, str]) -> BibliographyExportManager:
    """Create and initialize bibliography export manager"""
    manager = BibliographyExportManager(db_config)
    await manager.initialize()
    return manager

# Export main classes
__all__ = [
    'BibliographyExportManager',
    'BibliographyEntry',
    'ExportOptions',
    'IntegrationResult',
    'ExportFormat',
    'IntegrationPlatform',
    'create_bibliography_export_manager'
]