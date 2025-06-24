"""
Advanced deduplication service with content versioning and incremental updates
Handles document fingerprinting, change detection, and version management
"""

import asyncio
import logging
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes detected in documents"""
    NEW = "new"
    UPDATED = "updated" 
    CONTENT_CHANGED = "content_changed"
    METADATA_CHANGED = "metadata_changed"
    NO_CHANGE = "no_change"


@dataclass
class DocumentFingerprint:
    """Document fingerprint for deduplication and change detection"""
    urn: str
    title_hash: str
    content_hash: str
    metadata_hash: str
    full_hash: str
    size_bytes: int
    word_count: int
    last_seen: datetime
    version: int


@dataclass
class ChangeDetectionResult:
    """Result of change detection analysis"""
    change_type: ChangeType
    old_fingerprint: Optional[DocumentFingerprint]
    new_fingerprint: DocumentFingerprint
    changed_fields: List[str]
    similarity_score: float
    should_update: bool


class DeduplicationService:
    """Advanced deduplication service with versioning capabilities"""
    
    def __init__(self, db_service):
        self.db_service = db_service
        self.fingerprint_cache = {}
        self.similarity_threshold = 0.95
        self.content_change_threshold = 0.8
        
    async def process_document_batch(self, documents: List[Dict[str, Any]], 
                                   search_term_id: int, source_api: str) -> Dict[str, Any]:
        """
        Process a batch of documents with advanced deduplication and versioning
        
        Returns:
            Dict with statistics about processing results
        """
        stats = {
            'total_processed': len(documents),
            'new_documents': 0,
            'updated_documents': 0,
            'content_changes': 0,
            'metadata_changes': 0,
            'duplicates_skipped': 0,
            'errors': 0,
            'processing_time_ms': 0
        }
        
        start_time = datetime.now()
        
        try:
            # Generate fingerprints for all documents
            fingerprints = await self._generate_fingerprints_batch(documents)
            
            # Get existing fingerprints from database
            urns = [fp.urn for fp in fingerprints]
            existing_fingerprints = await self._get_existing_fingerprints(urns)
            
            # Analyze changes for each document
            change_results = []
            for i, fingerprint in enumerate(fingerprints):
                try:
                    existing_fp = existing_fingerprints.get(fingerprint.urn)
                    change_result = await self._detect_changes(
                        documents[i], fingerprint, existing_fp
                    )
                    change_results.append(change_result)
                except Exception as e:
                    logger.error(f"Error analyzing document {fingerprint.urn}: {e}")
                    stats['errors'] += 1
                    continue
            
            # Process documents based on change analysis
            processed_docs = await self._process_changes(
                documents, change_results, search_term_id, source_api
            )
            
            # Update statistics
            for result in change_results:
                if result.change_type == ChangeType.NEW:
                    stats['new_documents'] += 1
                elif result.change_type == ChangeType.UPDATED:
                    stats['updated_documents'] += 1
                elif result.change_type == ChangeType.CONTENT_CHANGED:
                    stats['content_changes'] += 1
                elif result.change_type == ChangeType.METADATA_CHANGED:
                    stats['metadata_changes'] += 1
                elif result.change_type == ChangeType.NO_CHANGE:
                    stats['duplicates_skipped'] += 1
            
            # Store updated fingerprints
            await self._store_fingerprints([r.new_fingerprint for r in change_results 
                                          if r.should_update])
            
            stats['processing_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
            
            logger.info(f"Batch processing completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error in batch processing: {e}")
            stats['errors'] = len(documents)
            stats['processing_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
            return stats
    
    async def _generate_fingerprints_batch(self, documents: List[Dict[str, Any]]) -> List[DocumentFingerprint]:
        """Generate fingerprints for a batch of documents efficiently"""
        fingerprints = []
        
        for doc in documents:
            try:
                fingerprint = await self._generate_document_fingerprint(doc)
                fingerprints.append(fingerprint)
            except Exception as e:
                logger.error(f"Error generating fingerprint for {doc.get('urn', 'unknown')}: {e}")
                continue
        
        return fingerprints
    
    async def _generate_document_fingerprint(self, document: Dict[str, Any]) -> DocumentFingerprint:
        """Generate comprehensive fingerprint for a document"""
        urn = document['urn']
        title = document.get('title', '')
        content = document.get('content', '')
        description = document.get('description', '')
        metadata = document.get('metadata', {})
        
        # Create normalized content for hashing
        normalized_title = self._normalize_text(title)
        normalized_content = self._normalize_text(content + ' ' + description)
        normalized_metadata = self._normalize_metadata(metadata)
        
        # Generate individual hashes
        title_hash = self._hash_text(normalized_title)
        content_hash = self._hash_text(normalized_content)
        metadata_hash = self._hash_text(json.dumps(normalized_metadata, sort_keys=True))
        
        # Generate composite hash
        full_content = f"{normalized_title}|{normalized_content}|{json.dumps(normalized_metadata, sort_keys=True)}"
        full_hash = self._hash_text(full_content)
        
        # Calculate document metrics
        size_bytes = len(full_content.encode('utf-8'))
        word_count = len(normalized_content.split())
        
        return DocumentFingerprint(
            urn=urn,
            title_hash=title_hash,
            content_hash=content_hash, 
            metadata_hash=metadata_hash,
            full_hash=full_hash,
            size_bytes=size_bytes,
            word_count=word_count,
            last_seen=datetime.now(),
            version=1
        )
    
    async def _get_existing_fingerprints(self, urns: List[str]) -> Dict[str, DocumentFingerprint]:
        """Get existing fingerprints from database for given URNs"""
        try:
            # Query database for existing document fingerprints
            async with self.db_service.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT urn, title_hash, content_hash, metadata_hash, full_hash,
                           size_bytes, word_count, last_seen, version
                    FROM document_fingerprints 
                    WHERE urn = ANY($1)
                """, urns)
                
                fingerprints = {}
                for row in rows:
                    fp = DocumentFingerprint(
                        urn=row['urn'],
                        title_hash=row['title_hash'],
                        content_hash=row['content_hash'],
                        metadata_hash=row['metadata_hash'],
                        full_hash=row['full_hash'],
                        size_bytes=row['size_bytes'],
                        word_count=row['word_count'],
                        last_seen=row['last_seen'],
                        version=row['version']
                    )
                    fingerprints[row['urn']] = fp
                
                return fingerprints
                
        except Exception as e:
            logger.error(f"Error getting existing fingerprints: {e}")
            return {}
    
    async def _detect_changes(self, document: Dict[str, Any], 
                            new_fingerprint: DocumentFingerprint,
                            existing_fingerprint: Optional[DocumentFingerprint]) -> ChangeDetectionResult:
        """Detect what type of changes occurred in a document"""
        
        if not existing_fingerprint:
            return ChangeDetectionResult(
                change_type=ChangeType.NEW,
                old_fingerprint=None,
                new_fingerprint=new_fingerprint,
                changed_fields=[],
                similarity_score=0.0,
                should_update=True
            )
        
        # Calculate similarity score
        similarity_score = await self._calculate_similarity(new_fingerprint, existing_fingerprint)
        
        # Determine change type
        changed_fields = []
        
        if new_fingerprint.full_hash == existing_fingerprint.full_hash:
            # No changes detected
            change_type = ChangeType.NO_CHANGE
            should_update = False
        else:
            # Some changes detected
            should_update = True
            
            if new_fingerprint.title_hash != existing_fingerprint.title_hash:
                changed_fields.append('title')
            
            if new_fingerprint.content_hash != existing_fingerprint.content_hash:
                changed_fields.append('content')
                
            if new_fingerprint.metadata_hash != existing_fingerprint.metadata_hash:
                changed_fields.append('metadata')
            
            # Determine specific change type
            if 'content' in changed_fields and similarity_score < self.content_change_threshold:
                change_type = ChangeType.CONTENT_CHANGED
            elif 'content' in changed_fields or 'title' in changed_fields:
                change_type = ChangeType.UPDATED
            else:
                change_type = ChangeType.METADATA_CHANGED
        
        # Update version number
        if should_update:
            new_fingerprint.version = existing_fingerprint.version + 1
        
        return ChangeDetectionResult(
            change_type=change_type,
            old_fingerprint=existing_fingerprint,
            new_fingerprint=new_fingerprint,
            changed_fields=changed_fields,
            similarity_score=similarity_score,
            should_update=should_update
        )
    
    async def _calculate_similarity(self, fp1: DocumentFingerprint, fp2: DocumentFingerprint) -> float:
        """Calculate similarity score between two document fingerprints"""
        # Simple similarity based on word count and size
        if fp1.word_count == 0 and fp2.word_count == 0:
            return 1.0
        
        word_count_ratio = min(fp1.word_count, fp2.word_count) / max(fp1.word_count, fp2.word_count)
        size_ratio = min(fp1.size_bytes, fp2.size_bytes) / max(fp1.size_bytes, fp2.size_bytes)
        
        # Weight the ratios
        similarity = (word_count_ratio * 0.6) + (size_ratio * 0.4)
        
        return similarity
    
    async def _process_changes(self, documents: List[Dict[str, Any]], 
                             change_results: List[ChangeDetectionResult],
                             search_term_id: int, source_api: str) -> List[Dict[str, Any]]:
        """Process documents based on change detection results"""
        processed_docs = []
        
        for i, (doc, result) in enumerate(zip(documents, change_results)):
            if result.should_update:
                # Add change tracking metadata
                doc['change_info'] = {
                    'change_type': result.change_type.value,
                    'changed_fields': result.changed_fields,
                    'similarity_score': result.similarity_score,
                    'version': result.new_fingerprint.version,
                    'previous_version': result.old_fingerprint.version if result.old_fingerprint else 0,
                    'detected_at': datetime.now().isoformat()
                }
                
                processed_docs.append(doc)
        
        # Store processed documents
        if processed_docs:
            await self.db_service.store_collected_documents(
                processed_docs, search_term_id, source_api
            )
        
        return processed_docs
    
    async def _store_fingerprints(self, fingerprints: List[DocumentFingerprint]):
        """Store or update document fingerprints in database"""
        if not fingerprints:
            return
        
        try:
            async with self.db_service.pool.acquire() as conn:
                # Prepare data for batch upsert
                records = []
                for fp in fingerprints:
                    records.append((
                        fp.urn, fp.title_hash, fp.content_hash, fp.metadata_hash,
                        fp.full_hash, fp.size_bytes, fp.word_count, fp.last_seen, fp.version
                    ))
                
                # Use ON CONFLICT to handle updates
                await conn.executemany("""
                    INSERT INTO document_fingerprints 
                    (urn, title_hash, content_hash, metadata_hash, full_hash,
                     size_bytes, word_count, last_seen, version)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (urn) DO UPDATE SET
                        title_hash = EXCLUDED.title_hash,
                        content_hash = EXCLUDED.content_hash,
                        metadata_hash = EXCLUDED.metadata_hash,
                        full_hash = EXCLUDED.full_hash,
                        size_bytes = EXCLUDED.size_bytes,
                        word_count = EXCLUDED.word_count,
                        last_seen = EXCLUDED.last_seen,
                        version = EXCLUDED.version
                """, records)
                
                logger.info(f"Stored {len(fingerprints)} fingerprints")
                
        except Exception as e:
            logger.error(f"Error storing fingerprints: {e}")
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for consistent hashing"""
        if not text:
            return ""
        
        # Basic normalization
        normalized = text.lower().strip()
        
        # Remove extra whitespace
        import re
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Remove common punctuation variations
        normalized = re.sub(r'[^\w\s]', ' ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized
    
    def _normalize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize metadata for consistent hashing"""
        if not metadata:
            return {}
        
        normalized = {}
        for key, value in metadata.items():
            if isinstance(value, str):
                normalized[key.lower()] = self._normalize_text(value)
            elif isinstance(value, (list, tuple)):
                normalized[key.lower()] = [
                    self._normalize_text(str(item)) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                normalized[key.lower()] = value
        
        return normalized
    
    def _hash_text(self, text: str) -> str:
        """Generate consistent hash for text"""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    async def cleanup_old_fingerprints(self, days_old: int = 90):
        """Clean up old fingerprints that are no longer needed"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            async with self.db_service.pool.acquire() as conn:
                deleted_count = await conn.fetchval("""
                    DELETE FROM document_fingerprints 
                    WHERE last_seen < $1
                    RETURNING COUNT(*)
                """, cutoff_date)
                
                logger.info(f"Cleaned up {deleted_count} old fingerprints")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up fingerprints: {e}")
            return 0
    
    async def get_deduplication_stats(self) -> Dict[str, Any]:
        """Get statistics about deduplication performance"""
        try:
            async with self.db_service.pool.acquire() as conn:
                stats = await conn.fetchrow("""
                    SELECT 
                        COUNT(*) as total_fingerprints,
                        COUNT(DISTINCT urn) as unique_documents,
                        AVG(version) as avg_version,
                        MAX(version) as max_version,
                        MIN(last_seen) as oldest_fingerprint,
                        MAX(last_seen) as newest_fingerprint
                    FROM document_fingerprints
                """)
                
                return dict(stats) if stats else {}
                
        except Exception as e:
            logger.error(f"Error getting deduplication stats: {e}")
            return {}


# Global instance
deduplication_service = None

async def get_deduplication_service(db_service):
    """Get or create global deduplication service instance"""
    global deduplication_service
    if deduplication_service is None:
        deduplication_service = DeduplicationService(db_service)
    return deduplication_service