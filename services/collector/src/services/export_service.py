"""
Automated export service for generating CSV/JSON datasets from collected documents
Supports scheduled exports, filtering, and academic citation formatting
"""

import asyncio
import csv
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import zipfile
import tempfile

from .database_service import CollectionDatabaseService
from ..utils.monitoring import performance_tracker
from ..utils.validation import validate_export_params

logger = logging.getLogger(__name__)


class ExportFormat:
    """Supported export formats"""
    CSV = "csv"
    JSON = "json"
    JSONL = "jsonl"  # JSON Lines
    ZIP = "zip"     # Compressed archives


class ExportService:
    """Service for automated data export generation"""
    
    def __init__(self, export_directory: str = "/tmp/exports"):
        self.db_service: Optional[CollectionDatabaseService] = None
        self.export_directory = Path(export_directory)
        self.export_directory.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.max_records_per_export = 10000
        self.compress_large_exports = True
        self.include_metadata = True
        self.academic_citation_format = True
        
    async def initialize(self):
        """Initialize the export service"""
        self.db_service = CollectionDatabaseService()
        await self.db_service.initialize()
        logger.info("Export service initialized")
    
    async def generate_scheduled_exports(self) -> Dict[str, Any]:
        """Generate all scheduled exports based on search terms configuration"""
        operation_id = "scheduled_exports"
        performance_tracker.start_operation(operation_id, "export_generation")
        
        export_stats = {
            'execution_start': datetime.now().isoformat(),
            'exports_generated': 0,
            'total_records_exported': 0,
            'formats_generated': [],
            'file_paths': [],
            'errors': []
        }
        
        try:
            # Get active search terms that need exports
            search_terms = await self._get_exportable_search_terms()
            
            for term_data in search_terms:
                try:
                    # Generate exports for this search term
                    term_exports = await self._generate_term_exports(term_data)
                    
                    export_stats['exports_generated'] += len(term_exports)
                    export_stats['total_records_exported'] += sum(
                        exp.get('record_count', 0) for exp in term_exports
                    )
                    export_stats['file_paths'].extend([
                        exp.get('file_path') for exp in term_exports if exp.get('file_path')
                    ])
                    
                    # Track formats
                    for exp in term_exports:
                        format_used = exp.get('format')
                        if format_used and format_used not in export_stats['formats_generated']:
                            export_stats['formats_generated'].append(format_used)
                            
                except Exception as e:
                    error_info = {
                        'search_term_id': term_data.get('id'),
                        'search_term': term_data.get('term'),
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                    export_stats['errors'].append(error_info)
                    logger.error(f"Error exporting term {term_data.get('term')}: {e}")
                    continue
            
            # Clean up old export files
            cleaned_count = await self._cleanup_old_exports()
            export_stats['old_files_cleaned'] = cleaned_count
            
            export_stats['execution_time_ms'] = performance_tracker.end_operation(
                operation_id, "completed"
            )
            
            logger.info(f"Scheduled exports completed: {export_stats}")
            return export_stats
            
        except Exception as e:
            export_stats['errors'].append({
                'error': f"Global export error: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })
            performance_tracker.end_operation(operation_id, "failed")
            logger.error(f"Error in scheduled exports: {e}")
            return export_stats
    
    async def export_search_term_data(self, search_term_id: int, 
                                    export_format: str = ExportFormat.CSV,
                                    date_filter: Optional[str] = None,
                                    max_records: Optional[int] = None) -> Dict[str, Any]:
        """Export data for a specific search term"""
        try:
            # Get documents for the search term
            documents = await self._get_documents_for_export(
                search_term_id, date_filter, max_records
            )
            
            if not documents:
                return {
                    'status': 'no_data',
                    'message': 'No documents found for export',
                    'record_count': 0
                }
            
            # Get search term info
            term_info = await self._get_search_term_info(search_term_id)
            
            # Generate filename
            filename = self._generate_filename(term_info, export_format, date_filter)
            file_path = self.export_directory / filename
            
            # Export based on format
            if export_format == ExportFormat.CSV:
                record_count = await self._export_to_csv(documents, file_path, term_info)
            elif export_format == ExportFormat.JSON:
                record_count = await self._export_to_json(documents, file_path, term_info)
            elif export_format == ExportFormat.JSONL:
                record_count = await self._export_to_jsonl(documents, file_path, term_info)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
            
            # Compress if needed
            final_path = file_path
            if self.compress_large_exports and record_count > 1000:
                final_path = await self._compress_export(file_path)
            
            # Update export log
            await self._log_export(search_term_id, export_format, str(final_path), record_count)
            
            return {
                'status': 'success',
                'file_path': str(final_path),
                'format': export_format,
                'record_count': record_count,
                'file_size_bytes': final_path.stat().st_size,
                'search_term': term_info.get('term', '')
            }
            
        except Exception as e:
            logger.error(f"Error exporting search term {search_term_id}: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'search_term_id': search_term_id
            }
    
    async def export_collection_summary(self, export_format: str = ExportFormat.JSON) -> Dict[str, Any]:
        """Export a summary of all collections"""
        try:
            # Get collection summary data
            summary_data = await self._get_collection_summary()
            
            filename = f"collection_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format}"
            file_path = self.export_directory / filename
            
            if export_format == ExportFormat.CSV:
                await self._export_summary_to_csv(summary_data, file_path)
            else:
                await self._export_summary_to_json(summary_data, file_path)
            
            return {
                'status': 'success',
                'file_path': str(file_path),
                'format': export_format,
                'record_count': len(summary_data),
                'file_size_bytes': file_path.stat().st_size
            }
            
        except Exception as e:
            logger.error(f"Error exporting collection summary: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def _get_exportable_search_terms(self) -> List[Dict[str, Any]]:
        """Get search terms that need exports"""
        try:
            async with self.db_service.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT 
                        st.id, st.term, st.category, st.collection_frequency,
                        st.export_enabled, st.last_export, st.created_at,
                        COUNT(ld.id) as document_count,
                        MAX(ld.collection_date) as latest_document
                    FROM search_terms st
                    LEFT JOIN legislative_documents ld ON st.id = ld.search_term_id
                    WHERE st.active = true 
                      AND st.export_enabled = true
                      AND (st.last_export IS NULL OR st.last_export < NOW() - INTERVAL '1 day')
                      AND COUNT(ld.id) > 0
                    GROUP BY st.id, st.term, st.category, st.collection_frequency,
                             st.export_enabled, st.last_export, st.created_at
                    ORDER BY st.last_export ASC NULLS FIRST, st.id ASC
                """)
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting exportable search terms: {e}")
            return []
    
    async def _generate_term_exports(self, term_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate exports for a specific search term"""
        exports = []
        search_term_id = term_data['id']
        
        # Determine export formats based on document count
        document_count = term_data.get('document_count', 0)
        
        formats_to_generate = [ExportFormat.CSV]  # Always generate CSV
        
        if document_count <= 5000:  # Add JSON for smaller datasets
            formats_to_generate.append(ExportFormat.JSON)
        
        if document_count > 1000:  # Add JSONL for larger datasets
            formats_to_generate.append(ExportFormat.JSONL)
        
        # Generate exports in each format
        for export_format in formats_to_generate:
            try:
                export_result = await self.export_search_term_data(
                    search_term_id, export_format
                )
                if export_result.get('status') == 'success':
                    exports.append(export_result)
            except Exception as e:
                logger.error(f"Error generating {export_format} export for term {search_term_id}: {e}")
                continue
        
        return exports
    
    async def _get_documents_for_export(self, search_term_id: int, 
                                      date_filter: Optional[str] = None,
                                      max_records: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get documents for export with optional filtering"""
        try:
            limit = max_records or self.max_records_per_export
            
            query = """
                SELECT 
                    ld.urn, ld.title, ld.description, ld.content,
                    ld.document_type, ld.publication_date, ld.collection_date,
                    ld.source_api, ld.metadata, ld.url,
                    st.term as search_term, st.category as search_category
                FROM legislative_documents ld
                JOIN search_terms st ON ld.search_term_id = st.id
                WHERE ld.search_term_id = $1
            """
            
            params = [search_term_id]
            
            if date_filter:
                if date_filter == 'last_week':
                    query += " AND ld.collection_date >= NOW() - INTERVAL '7 days'"
                elif date_filter == 'last_month':
                    query += " AND ld.collection_date >= NOW() - INTERVAL '30 days'"
                elif date_filter == 'last_year':
                    query += " AND ld.collection_date >= NOW() - INTERVAL '365 days'"
            
            query += " ORDER BY ld.collection_date DESC, ld.publication_date DESC"
            query += f" LIMIT {limit}"
            
            async with self.db_service.pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting documents for export: {e}")
            return []
    
    async def _get_search_term_info(self, search_term_id: int) -> Dict[str, Any]:
        """Get search term information"""
        try:
            async with self.db_service.pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT id, term, category, description, created_at
                    FROM search_terms WHERE id = $1
                """, search_term_id)
                
                return dict(row) if row else {}
                
        except Exception as e:
            logger.error(f"Error getting search term info: {e}")
            return {}
    
    def _generate_filename(self, term_info: Dict[str, Any], 
                          export_format: str, date_filter: Optional[str]) -> str:
        """Generate export filename"""
        term_slug = term_info.get('term', 'unknown').lower()
        term_slug = ''.join(c if c.isalnum() else '_' for c in term_slug)[:30]
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        filter_suffix = f"_{date_filter}" if date_filter else ""
        
        return f"export_{term_slug}{filter_suffix}_{timestamp}.{export_format}"
    
    async def _export_to_csv(self, documents: List[Dict[str, Any]], 
                           file_path: Path, term_info: Dict[str, Any]) -> int:
        """Export documents to CSV format"""
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            # Define CSV columns
            fieldnames = [
                'urn', 'title', 'description', 'document_type',
                'publication_date', 'collection_date', 'source_api',
                'url', 'search_term', 'search_category'
            ]
            
            if self.include_metadata:
                fieldnames.append('metadata_json')
            
            if self.academic_citation_format:
                fieldnames.append('academic_citation')
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for doc in documents:
                row = {key: doc.get(key, '') for key in fieldnames}
                
                # Handle dates
                for date_field in ['publication_date', 'collection_date']:
                    if doc.get(date_field):
                        row[date_field] = doc[date_field].isoformat() if hasattr(doc[date_field], 'isoformat') else str(doc[date_field])
                
                # Handle metadata
                if self.include_metadata and doc.get('metadata'):
                    row['metadata_json'] = json.dumps(doc['metadata'], ensure_ascii=False)
                
                # Generate academic citation
                if self.academic_citation_format:
                    row['academic_citation'] = self._generate_academic_citation(doc)
                
                writer.writerow(row)
        
        return len(documents)
    
    async def _export_to_json(self, documents: List[Dict[str, Any]], 
                            file_path: Path, term_info: Dict[str, Any]) -> int:
        """Export documents to JSON format"""
        export_data = {
            'export_metadata': {
                'generated_at': datetime.now().isoformat(),
                'search_term': term_info.get('term', ''),
                'search_category': term_info.get('category', ''),
                'record_count': len(documents),
                'export_version': '1.0'
            },
            'documents': []
        }
        
        for doc in documents:
            # Convert datetime objects to ISO strings
            doc_copy = dict(doc)
            for key, value in doc_copy.items():
                if hasattr(value, 'isoformat'):
                    doc_copy[key] = value.isoformat()
            
            # Add academic citation if enabled
            if self.academic_citation_format:
                doc_copy['academic_citation'] = self._generate_academic_citation(doc)
            
            export_data['documents'].append(doc_copy)
        
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, ensure_ascii=False, indent=2)
        
        return len(documents)
    
    async def _export_to_jsonl(self, documents: List[Dict[str, Any]], 
                             file_path: Path, term_info: Dict[str, Any]) -> int:
        """Export documents to JSON Lines format"""
        with open(file_path, 'w', encoding='utf-8') as jsonlfile:
            for doc in documents:
                # Convert datetime objects to ISO strings
                doc_copy = dict(doc)
                for key, value in doc_copy.items():
                    if hasattr(value, 'isoformat'):
                        doc_copy[key] = value.isoformat()
                
                # Add academic citation if enabled
                if self.academic_citation_format:
                    doc_copy['academic_citation'] = self._generate_academic_citation(doc)
                
                jsonlfile.write(json.dumps(doc_copy, ensure_ascii=False) + '\n')
        
        return len(documents)
    
    def _generate_academic_citation(self, document: Dict[str, Any]) -> str:
        """Generate academic citation for a document"""
        try:
            title = document.get('title', 'Documento sem título')
            doc_type = document.get('document_type', 'Documento')
            pub_date = document.get('publication_date')
            source = document.get('source_api', '').upper()
            url = document.get('url', '')
            
            # Format publication date
            date_str = ''
            if pub_date:
                if hasattr(pub_date, 'strftime'):
                    date_str = pub_date.strftime('%d/%m/%Y')
                else:
                    date_str = str(pub_date)[:10]  # Take first 10 chars (YYYY-MM-DD)
            
            # Construct citation
            citation_parts = []
            
            if title:
                citation_parts.append(f'"{title}"')
            
            if doc_type:
                citation_parts.append(doc_type)
            
            if source:
                citation_parts.append(f"Fonte: {source}")
            
            if date_str:
                citation_parts.append(f"Data: {date_str}")
            
            if url:
                citation_parts.append(f"Disponível em: {url}")
            
            citation_parts.append(f"Acesso em: {datetime.now().strftime('%d/%m/%Y')}")
            
            return '. '.join(citation_parts) + '.'
            
        except Exception as e:
            logger.error(f"Error generating academic citation: {e}")
            return "Citação não disponível"
    
    async def _compress_export(self, file_path: Path) -> Path:
        """Compress export file to ZIP"""
        zip_path = file_path.with_suffix(file_path.suffix + '.zip')
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(file_path, file_path.name)
        
        # Remove original file
        file_path.unlink()
        
        return zip_path
    
    async def _log_export(self, search_term_id: int, export_format: str, 
                        file_path: str, record_count: int):
        """Log export operation to database"""
        try:
            async with self.db_service.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO export_logs 
                    (search_term_id, export_format, file_path, record_count, created_at)
                    VALUES ($1, $2, $3, $4, NOW())
                """, search_term_id, export_format, file_path, record_count)
                
                # Update search term's last export timestamp
                await conn.execute("""
                    UPDATE search_terms 
                    SET last_export = NOW(), updated_at = NOW()
                    WHERE id = $1
                """, search_term_id)
                
        except Exception as e:
            logger.error(f"Error logging export: {e}")
    
    async def _cleanup_old_exports(self, days_old: int = 30) -> int:
        """Clean up old export files"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            cleaned_count = 0
            
            for file_path in self.export_directory.iterdir():
                if file_path.is_file():
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_mtime < cutoff_date:
                        file_path.unlink()
                        cleaned_count += 1
            
            logger.info(f"Cleaned up {cleaned_count} old export files")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old exports: {e}")
            return 0
    
    async def _get_collection_summary(self) -> List[Dict[str, Any]]:
        """Get collection summary data"""
        try:
            async with self.db_service.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT 
                        st.term, st.category, st.created_at,
                        COUNT(ld.id) as total_documents,
                        MIN(ld.collection_date) as first_collection,
                        MAX(ld.collection_date) as last_collection,
                        COUNT(DISTINCT ld.source_api) as source_count,
                        AVG(LENGTH(ld.content)) as avg_content_length
                    FROM search_terms st
                    LEFT JOIN legislative_documents ld ON st.id = ld.search_term_id
                    WHERE st.active = true
                    GROUP BY st.id, st.term, st.category, st.created_at
                    ORDER BY total_documents DESC
                """)
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting collection summary: {e}")
            return []
    
    async def _export_summary_to_csv(self, summary_data: List[Dict[str, Any]], file_path: Path):
        """Export summary data to CSV"""
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'term', 'category', 'created_at', 'total_documents',
                'first_collection', 'last_collection', 'source_count', 'avg_content_length'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in summary_data:
                # Convert datetime objects to strings
                for key, value in row.items():
                    if hasattr(value, 'isoformat'):
                        row[key] = value.isoformat()
                writer.writerow(row)
    
    async def _export_summary_to_json(self, summary_data: List[Dict[str, Any]], file_path: Path):
        """Export summary data to JSON"""
        # Convert datetime objects to ISO strings
        for row in summary_data:
            for key, value in row.items():
                if hasattr(value, 'isoformat'):
                    row[key] = value.isoformat()
        
        export_data = {
            'export_metadata': {
                'generated_at': datetime.now().isoformat(),
                'export_type': 'collection_summary',
                'record_count': len(summary_data)
            },
            'summary': summary_data
        }
        
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, ensure_ascii=False, indent=2)


# Global instance
export_service = None

async def get_export_service():
    """Get or create global export service instance"""
    global export_service
    if export_service is None:
        export_service = ExportService()
        await export_service.initialize()
    return export_service