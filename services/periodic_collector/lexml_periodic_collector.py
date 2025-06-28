"""
LexML Periodic Collection Service
Automated collection of legislative documents from LexML Brasil API
Stores data in private database for dashboard consumption
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import httpx
from urllib.parse import urlencode
import uuid
import json
import re
import time

import asyncpg
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

logger = logging.getLogger(__name__)


class LexMLPeriodicCollector:
    """
    Automated periodic collection service for LexML Brasil
    Collects legislative documents based on configured search terms
    Stores in private database for dashboard analytics
    """
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.lexml_base_url = "https://www.lexml.gov.br/busca/SRU"
        self.session_factory = None
        self.http_client: Optional[httpx.AsyncClient] = None
        
        # Collection configuration
        self.batch_size = 100  # Documents per API call
        self.max_retries = 3
        self.retry_delay = 2.0
        self.api_delay = 1.0  # Delay between API calls (respectful)
        
        # Initialize database connection
        self._setup_database()
    
    def _setup_database(self):
        """Setup async database connection"""
        try:
            # Convert URL for asyncpg if needed
            db_url = self.database_url
            if db_url.startswith('postgresql://'):
                db_url = db_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
            
            engine = create_async_engine(
                db_url,
                pool_size=3,
                max_overflow=0,
                pool_timeout=60,
                pool_recycle=1800,
                echo=False
            )
            
            self.session_factory = sessionmaker(
                bind=engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            logger.info("Database connection initialized for periodic collector")
            
        except Exception as e:
            logger.error(f"Failed to setup database connection: {e}")
            raise
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.http_client:
            await self.http_client.aclose()
    
    async def get_pending_collections(self) -> List[Dict[str, Any]]:
        """Get search terms that need collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term_name, cql_query, description, collection_frequency,
                           priority_level, last_collected, next_collection
                    FROM search_terms_config 
                    WHERE is_active = true 
                    AND (next_collection IS NULL OR next_collection <= NOW())
                    ORDER BY priority_level ASC, last_collected ASC NULLS FIRST
                """))
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get pending collections: {e}")
            return []
    
    async def start_collection_batch(self, search_term_id: int) -> str:
        """Start a new collection batch and return batch ID"""
        batch_id = str(uuid.uuid4())
        
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    INSERT INTO collection_executions 
                    (batch_id, search_term_id, status, started_at)
                    VALUES (:batch_id, :search_term_id, 'running', NOW())
                """), {
                    'batch_id': batch_id,
                    'search_term_id': search_term_id
                })
                await session.commit()
                
                logger.info(f"Started collection batch {batch_id} for search term {search_term_id}")
                return batch_id
                
        except Exception as e:
            logger.error(f"Failed to start collection batch: {e}")
            raise
    
    async def update_collection_progress(self, batch_id: str, **metrics):
        """Update collection execution metrics"""
        try:
            async with self.session_factory() as session:
                set_clauses = []
                params = {'batch_id': batch_id}
                
                for key, value in metrics.items():
                    set_clauses.append(f"{key} = :{key}")
                    params[key] = value
                
                if set_clauses:
                    query = f"""
                        UPDATE collection_executions 
                        SET {', '.join(set_clauses)}
                        WHERE batch_id = :batch_id
                    """
                    await session.execute(text(query), params)
                    await session.commit()
                    
        except Exception as e:
            logger.error(f"Failed to update collection progress: {e}")
    
    async def search_lexml_api(self, cql_query: str, start_record: int = 1, 
                              max_records: int = 100) -> Tuple[List[Dict], int, bool]:
        """
        Search LexML API using SRU protocol
        Returns: (documents, total_found, has_more)
        """
        params = {
            'operation': 'searchRetrieve',
            'query': cql_query,
            'startRecord': start_record,
            'maximumRecords': max_records,
            'recordSchema': 'oai_dc'
        }
        
        url = f"{self.lexml_base_url}?{urlencode(params)}"
        
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"LexML API request: {url}")
                response = await self.http_client.get(url)
                response.raise_for_status()
                
                documents, total_found = self._parse_sru_response(response.text)
                has_more = (start_record + len(documents)) < total_found
                
                logger.info(f"LexML API returned {len(documents)} documents, "
                           f"total available: {total_found}")
                
                return documents, total_found, has_more
                
            except Exception as e:
                logger.warning(f"LexML API attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                else:
                    raise
    
    def _parse_sru_response(self, xml_content: str) -> Tuple[List[Dict], int]:
        """Parse SRU XML response into document dictionaries"""
        documents = []
        total_found = 0
        
        try:
            root = ET.fromstring(xml_content)
            
            # Extract total number of records
            num_records = root.find('.//{http://www.loc.gov/zing/srw/}numberOfRecords')
            if num_records is not None and num_records.text:
                total_found = int(num_records.text)
            
            # Parse individual records
            records = root.findall('.//{http://www.loc.gov/zing/srw/}record')
            
            for record in records:
                doc = self._parse_single_record(record)
                if doc:
                    documents.append(doc)
                    
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        except Exception as e:
            logger.error(f"SRU response parsing error: {e}")
        
        return documents, total_found
    
    def _parse_single_record(self, record: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse single SRU record into document dictionary"""
        try:
            # Find Dublin Core data
            dc_data = record.find('.//{info:srw/schema/1/dc-schema}dc')
            if dc_data is None:
                dc_data = record.find('.//srw_dc:dc', {'srw_dc': 'info:srw/schema/1/dc-schema'})
            
            if dc_data is None:
                logger.warning("No Dublin Core data found in record")
                return None
            
            # Extract basic fields
            urn = self._get_element_text(dc_data, 'urn') or ''
            title = self._get_element_text(dc_data, 'title') or 'Documento sem título'
            description = self._get_element_text(dc_data, 'description') or ''
            date_str = self._get_element_text(dc_data, 'date') or ''
            
            # Extract faceted fields (LexML specific)
            document_type = self._get_element_text(dc_data, 'tipoDocumento') or ''
            authority = self._get_element_text(dc_data, 'autoridade') or ''
            locality = self._get_element_text(dc_data, 'localidade') or ''
            
            # Extract subject keywords
            subjects = []
            subject_elements = dc_data.findall('.//subject') + dc_data.findall('.//dc:subject', {'dc': 'http://purl.org/dc/elements/1.1/'})
            for elem in subject_elements:
                if elem.text and elem.text.strip():
                    subjects.append(elem.text.strip())
            
            # Parse date
            event_date = self._parse_date(date_str)
            
            # Extract geographic information
            state_info = self._extract_state_info(locality, authority, urn)
            
            # Extract URLs
            identifier = self._get_element_text(dc_data, 'identifier') or ''
            full_text_url = identifier if identifier.startswith('http') else ''
            
            document = {
                'urn': urn,
                'title': title,
                'description': description,
                'document_type': document_type,
                'authority': authority,
                'locality': locality,
                'event_type': 'publicacao',  # Default for LexML documents
                'event_date': event_date,
                'publication_date': event_date,  # Same as event_date for most documents
                'subject_keywords': subjects,
                'full_text_url': full_text_url,
                'source_url': f"https://www.lexml.gov.br/urn/{urn}" if urn else '',
                
                # Geographic analysis
                'state_code': state_info['state_code'],
                'state_name': state_info['state_name'],
                'municipality': state_info['municipality'],
                'geographic_level': state_info['geographic_level'],
                
                # Document analysis (basic)
                'word_count': len(description.split()) if description else 0,
                'language': 'pt'
            }
            
            return document
            
        except Exception as e:
            logger.error(f"Error parsing single record: {e}")
            return None
    
    def _get_element_text(self, parent: ET.Element, tag_name: str) -> Optional[str]:
        """Safely extract text from XML element"""
        # Try direct tag name first
        elem = parent.find(f'.//{tag_name}')
        if elem is not None and elem.text:
            return elem.text.strip()
        
        # Try with Dublin Core namespace
        elem = parent.find(f'.//dc:{tag_name}', {'dc': 'http://purl.org/dc/elements/1.1/'})
        if elem is not None and elem.text:
            return elem.text.strip()
        
        return None
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats from LexML"""
        if not date_str:
            return None
        
        # Common LexML date formats
        formats = [
            '%Y-%m-%d',
            '%d/%m/%Y',
            '%Y-%m-%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).date()
            except ValueError:
                continue
        
        # Try to extract year at least
        year_match = re.search(r'\b(19|20)\d{2}\b', date_str)
        if year_match:
            try:
                year = int(year_match.group())
                return datetime(year, 1, 1).date()
            except ValueError:
                pass
        
        logger.warning(f"Could not parse date: {date_str}")
        return None
    
    def _extract_state_info(self, locality: str, authority: str, urn: str) -> Dict[str, str]:
        """Extract state information from document metadata"""
        
        # Brazilian state mappings
        state_mappings = {
            'acre': ('AC', 'Acre'),
            'alagoas': ('AL', 'Alagoas'),
            'amapá': ('AP', 'Amapá'),
            'amazonas': ('AM', 'Amazonas'),
            'bahia': ('BA', 'Bahia'),
            'ceará': ('CE', 'Ceará'),
            'distrito federal': ('DF', 'Distrito Federal'),
            'espírito santo': ('ES', 'Espírito Santo'),
            'goiás': ('GO', 'Goiás'),
            'maranhão': ('MA', 'Maranhão'),
            'mato grosso': ('MT', 'Mato Grosso'),
            'mato grosso do sul': ('MS', 'Mato Grosso do Sul'),
            'minas gerais': ('MG', 'Minas Gerais'),
            'pará': ('PA', 'Pará'),
            'paraíba': ('PB', 'Paraíba'),
            'paraná': ('PR', 'Paraná'),
            'pernambuco': ('PE', 'Pernambuco'),
            'piauí': ('PI', 'Piauí'),
            'rio de janeiro': ('RJ', 'Rio de Janeiro'),
            'rio grande do norte': ('RN', 'Rio Grande do Norte'),
            'rio grande do sul': ('RS', 'Rio Grande do Sul'),
            'rondônia': ('RO', 'Rondônia'),
            'roraima': ('RR', 'Roraima'),
            'santa catarina': ('SC', 'Santa Catarina'),
            'são paulo': ('SP', 'São Paulo'),
            'sergipe': ('SE', 'Sergipe'),
            'tocantins': ('TO', 'Tocantins')
        }
        
        state_code = None
        state_name = None
        municipality = None
        geographic_level = 'federal'  # Default
        
        # Determine geographic level from authority
        if authority:
            auth_lower = authority.lower()
            if 'federal' in auth_lower or 'união' in auth_lower:
                geographic_level = 'federal'
            elif 'estadual' in auth_lower or 'estado' in auth_lower:
                geographic_level = 'estadual'
            elif 'municipal' in auth_lower or 'município' in auth_lower or 'prefeitura' in auth_lower:
                geographic_level = 'municipal'
        
        # Extract state from locality
        if locality:
            loc_lower = locality.lower()
            for state_full, (code, name) in state_mappings.items():
                if state_full in loc_lower or code.lower() in loc_lower:
                    state_code = code
                    state_name = name
                    break
            
            # If municipal level, try to extract municipality name
            if geographic_level == 'municipal' and state_code:
                # Remove state name from locality to get municipality
                municipality = locality.replace(state_name, '').replace(state_code, '').strip(' -,')
        
        # Try to extract from URN if not found
        if not state_code and urn:
            urn_lower = urn.lower()
            for state_full, (code, name) in state_mappings.items():
                if f';{state_full}:' in urn_lower or f';{code.lower()}:' in urn_lower:
                    state_code = code
                    state_name = name
                    break
        
        # Default to BR for federal documents
        if not state_code and geographic_level == 'federal':
            state_code = 'BR'
            state_name = 'Brasil'
        
        return {
            'state_code': state_code,
            'state_name': state_name,
            'municipality': municipality,
            'geographic_level': geographic_level
        }
    
    async def save_documents(self, documents: List[Dict[str, Any]], 
                            search_term_id: int, batch_id: str) -> Tuple[int, int, int]:
        """
        Save documents to private database
        Returns: (new_count, updated_count, skipped_count)
        """
        new_count = 0
        updated_count = 0
        skipped_count = 0
        
        try:
            async with self.session_factory() as session:
                for doc in documents:
                    # Check if document already exists
                    existing = await session.execute(text("""
                        SELECT id FROM private_legislative_documents 
                        WHERE urn = :urn
                    """), {'urn': doc['urn']})
                    
                    if existing.fetchone():
                        # Update existing document
                        await session.execute(text("""
                            UPDATE private_legislative_documents SET
                                title = :title,
                                description = :description,
                                document_type = :document_type,
                                authority = :authority,
                                locality = :locality,
                                event_type = :event_type,
                                event_date = :event_date,
                                publication_date = :publication_date,
                                subject_keywords = :subject_keywords,
                                full_text_url = :full_text_url,
                                source_url = :source_url,
                                state_code = :state_code,
                                state_name = :state_name,
                                municipality = :municipality,
                                geographic_level = :geographic_level,
                                word_count = :word_count,
                                language = :language,
                                updated_at = NOW()
                            WHERE urn = :urn
                        """), doc)
                        updated_count += 1
                    else:
                        # Insert new document
                        doc.update({
                            'search_term_id': search_term_id,
                            'collection_batch_id': batch_id
                        })
                        
                        await session.execute(text("""
                            INSERT INTO private_legislative_documents (
                                urn, title, description, document_type, authority, locality,
                                event_type, event_date, publication_date, subject_keywords,
                                full_text_url, source_url, search_term_id, collection_batch_id,
                                state_code, state_name, municipality, geographic_level,
                                word_count, language
                            ) VALUES (
                                :urn, :title, :description, :document_type, :authority, :locality,
                                :event_type, :event_date, :publication_date, :subject_keywords,
                                :full_text_url, :source_url, :search_term_id, :collection_batch_id,
                                :state_code, :state_name, :municipality, :geographic_level,
                                :word_count, :language
                            )
                        """), doc)
                        new_count += 1
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to save documents: {e}")
            skipped_count = len(documents) - new_count - updated_count
        
        return new_count, updated_count, skipped_count
    
    async def update_state_density_stats(self):
        """Update state document density statistics"""
        try:
            async with self.session_factory() as session:
                # Update state density table
                await session.execute(text("""
                    INSERT INTO state_document_density (state_code, state_name, total_documents, 
                                                       documents_last_month, documents_last_year)
                    SELECT 
                        state_code,
                        state_name,
                        COUNT(*) as total_documents,
                        COUNT(*) FILTER (WHERE collected_at >= NOW() - INTERVAL '30 days') as documents_last_month,
                        COUNT(*) FILTER (WHERE collected_at >= NOW() - INTERVAL '365 days') as documents_last_year
                    FROM private_legislative_documents 
                    WHERE state_code IS NOT NULL
                    GROUP BY state_code, state_name
                    ON CONFLICT (state_code) DO UPDATE SET
                        state_name = EXCLUDED.state_name,
                        total_documents = EXCLUDED.total_documents,
                        documents_last_month = EXCLUDED.documents_last_month,
                        documents_last_year = EXCLUDED.documents_last_year,
                        last_updated = NOW()
                """))
                
                await session.commit()
                logger.info("Updated state density statistics")
                
        except Exception as e:
            logger.error(f"Failed to update state density stats: {e}")
    
    async def complete_collection_batch(self, batch_id: str, status: str = 'completed', 
                                      error_message: str = None):
        """Mark collection batch as completed"""
        try:
            async with self.session_factory() as session:
                await session.execute(text("""
                    UPDATE collection_executions SET
                        status = :status,
                        completed_at = NOW(),
                        error_message = :error_message
                    WHERE batch_id = :batch_id
                """), {
                    'batch_id': batch_id,
                    'status': status,
                    'error_message': error_message
                })
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to complete collection batch: {e}")
    
    async def update_search_term_schedule(self, search_term_id: int, frequency: str):
        """Update next collection time for search term"""
        try:
            # Calculate next collection time based on frequency
            next_collection = datetime.now()
            if frequency == 'daily':
                next_collection += timedelta(days=1)
            elif frequency == 'weekly':
                next_collection += timedelta(weeks=1)
            elif frequency == 'monthly':
                next_collection += timedelta(days=30)
            else:  # custom or default
                next_collection += timedelta(days=30)
            
            async with self.session_factory() as session:
                await session.execute(text("""
                    UPDATE search_terms_config SET
                        last_collected = NOW(),
                        next_collection = :next_collection
                    WHERE id = :search_term_id
                """), {
                    'search_term_id': search_term_id,
                    'next_collection': next_collection
                })
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to update search term schedule: {e}")
    
    async def collect_search_term(self, search_term: Dict[str, Any]) -> Dict[str, Any]:
        """Collect documents for a single search term"""
        search_term_id = search_term['id']
        term_name = search_term['term_name']
        cql_query = search_term['cql_query']
        
        logger.info(f"Starting collection for search term: {term_name}")
        
        batch_id = await self.start_collection_batch(search_term_id)
        start_time = time.time()
        
        total_documents = 0
        total_new = 0
        total_updated = 0
        total_skipped = 0
        api_calls = 0
        
        try:
            # Collect documents in batches
            start_record = 1
            has_more = True
            
            while has_more:
                documents, total_found, has_more = await self.search_lexml_api(
                    cql_query, start_record, self.batch_size
                )
                
                api_calls += 1
                
                if documents:
                    new_count, updated_count, skipped_count = await self.save_documents(
                        documents, search_term_id, batch_id
                    )
                    
                    total_new += new_count
                    total_updated += updated_count
                    total_skipped += skipped_count
                    total_documents += len(documents)
                    
                    logger.info(f"Processed batch: {len(documents)} documents "
                               f"(new: {new_count}, updated: {updated_count}, skipped: {skipped_count})")
                
                # Update progress
                await self.update_collection_progress(batch_id,
                    documents_found=total_found,
                    documents_new=total_new,
                    documents_updated=total_updated,
                    documents_skipped=total_skipped,
                    api_calls_made=api_calls
                )
                
                start_record += self.batch_size
                
                # Respectful delay between API calls
                if has_more:
                    await asyncio.sleep(self.api_delay)
            
            # Update execution metrics
            execution_time = int((time.time() - start_time) * 1000)  # milliseconds
            
            await self.update_collection_progress(batch_id,
                execution_time_seconds=int(execution_time / 1000)
            )
            
            # Mark as completed
            await self.complete_collection_batch(batch_id, 'completed')
            
            # Update search term schedule
            await self.update_search_term_schedule(
                search_term_id, search_term['collection_frequency']
            )
            
            logger.info(f"Completed collection for {term_name}: "
                       f"{total_documents} documents processed "
                       f"(new: {total_new}, updated: {total_updated})")
            
            return {
                'search_term_id': search_term_id,
                'term_name': term_name,
                'status': 'completed',
                'total_documents': total_documents,
                'new_documents': total_new,
                'updated_documents': total_updated,
                'execution_time_seconds': int(execution_time / 1000),
                'api_calls': api_calls
            }
            
        except Exception as e:
            logger.error(f"Collection failed for {term_name}: {e}")
            await self.complete_collection_batch(batch_id, 'failed', str(e))
            
            return {
                'search_term_id': search_term_id,
                'term_name': term_name,
                'status': 'failed',
                'error': str(e)
            }
    
    async def run_periodic_collection(self) -> Dict[str, Any]:
        """Run periodic collection for all pending search terms"""
        logger.info("Starting periodic collection run")
        
        start_time = time.time()
        pending_terms = await self.get_pending_collections()
        
        if not pending_terms:
            logger.info("No pending collections found")
            return {
                'status': 'completed',
                'message': 'No pending collections',
                'total_terms': 0,
                'execution_time_seconds': 0
            }
        
        logger.info(f"Found {len(pending_terms)} pending collections")
        
        results = []
        for term in pending_terms:
            try:
                result = await self.collect_search_term(term)
                results.append(result)
                
                # Brief pause between search terms
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Failed to collect term {term['term_name']}: {e}")
                results.append({
                    'search_term_id': term['id'],
                    'term_name': term['term_name'],
                    'status': 'failed',
                    'error': str(e)
                })
        
        # Update state density statistics
        await self.update_state_density_stats()
        
        execution_time = int(time.time() - start_time)
        
        # Summary statistics
        completed = sum(1 for r in results if r['status'] == 'completed')
        failed = sum(1 for r in results if r['status'] == 'failed')
        total_docs = sum(r.get('total_documents', 0) for r in results)
        total_new = sum(r.get('new_documents', 0) for r in results)
        
        logger.info(f"Periodic collection completed: {completed} succeeded, {failed} failed, "
                   f"{total_docs} documents processed ({total_new} new)")
        
        return {
            'status': 'completed',
            'total_terms': len(pending_terms),
            'completed_terms': completed,
            'failed_terms': failed,
            'total_documents': total_docs,
            'new_documents': total_new,
            'execution_time_seconds': execution_time,
            'results': results
        }


# Standalone execution for testing
async def main():
    """Test the periodic collector"""
    import os
    
    database_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/legislativo')
    
    async with LexMLPeriodicCollector(database_url) as collector:
        result = await collector.run_periodic_collection()
        print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main()) 