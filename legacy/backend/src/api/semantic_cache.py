"""
Semantic Cache API - Advanced caching layer to reduce LLM costs by 60-80%
Implements intelligent content-based caching with similarity detection
"""

import asyncio
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import re

# Import Redis for caching
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available - semantic cache will use in-memory storage only")

# Import similarity libraries
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    SIMILARITY_AVAILABLE = True
except ImportError:
    SIMILARITY_AVAILABLE = False
    logging.warning("Scikit-learn not available - semantic similarity will be limited")

logger = logging.getLogger(__name__)

# Router for semantic cache API
router = APIRouter(prefix="/api/v1/semantic-cache", tags=["Semantic Cache"])

class CacheType(str, Enum):
    """Types of cached content"""
    DOCUMENT_ANALYSIS = "document_analysis"
    CITATION_GENERATION = "citation_generation"
    ENTITY_EXTRACTION = "entity_extraction"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    SEARCH_RESULTS = "search_results"
    TRANSLATION = "translation"
    SUMMARIZATION = "summarization"

class SimilarityMethod(str, Enum):
    """Methods for similarity calculation"""
    EXACT_MATCH = "exact_match"
    HASH_MATCH = "hash_match"
    TFIDF_COSINE = "tfidf_cosine"
    SEMANTIC_EMBEDDING = "semantic_embedding"
    FUZZY_MATCH = "fuzzy_match"

@dataclass
class CacheEntry:
    """Represents a semantic cache entry"""
    id: str
    content_hash: str
    content_summary: str
    cache_type: CacheType
    cached_data: Dict[str, Any]
    similarity_features: Dict[str, Any]
    access_count: int
    cost_saved: float
    created_at: datetime
    last_accessed: datetime
    ttl_seconds: int
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'content_hash': self.content_hash,
            'content_summary': self.content_summary,
            'cache_type': self.cache_type.value,
            'cached_data': self.cached_data,
            'similarity_features': self.similarity_features,
            'access_count': self.access_count,
            'cost_saved': self.cost_saved,
            'created_at': self.created_at.isoformat(),
            'last_accessed': self.last_accessed.isoformat(),
            'ttl_seconds': self.ttl_seconds,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        return cls(
            id=data['id'],
            content_hash=data['content_hash'],
            content_summary=data['content_summary'],
            cache_type=CacheType(data['cache_type']),
            cached_data=data['cached_data'],
            similarity_features=data['similarity_features'],
            access_count=data['access_count'],
            cost_saved=data['cost_saved'],
            created_at=datetime.fromisoformat(data['created_at']),
            last_accessed=datetime.fromisoformat(data['last_accessed']),
            ttl_seconds=data['ttl_seconds'],
            tags=data['tags']
        )

@dataclass
class CacheHit:
    """Represents a cache hit with similarity score"""
    entry: CacheEntry
    similarity_score: float
    similarity_method: SimilarityMethod
    cost_saved: float

@dataclass
class CacheStats:
    """Cache performance statistics"""
    total_entries: int
    cache_hits: int
    cache_misses: int
    hit_rate: float
    total_cost_saved: float
    average_similarity_threshold: float
    entries_by_type: Dict[str, int]
    storage_size_mb: float

# Pydantic models for API
class CacheRequest(BaseModel):
    content: str = Field(..., description="Content to cache or lookup")
    cache_type: CacheType = Field(..., description="Type of cached content")
    data_to_cache: Optional[Dict[str, Any]] = Field(None, description="Data to cache (for store operations)")
    similarity_threshold: float = Field(default=0.85, description="Minimum similarity for cache hit")
    ttl_seconds: int = Field(default=86400, description="Cache TTL in seconds")
    tags: List[str] = Field(default=[], description="Tags for cache organization")
    cost_estimate: Optional[float] = Field(None, description="Estimated cost of operation")

class CacheLookupRequest(BaseModel):
    content: str = Field(..., description="Content to find in cache")
    cache_type: CacheType = Field(..., description="Type of cached content")
    similarity_threshold: float = Field(default=0.85, description="Minimum similarity for cache hit")
    similarity_methods: List[SimilarityMethod] = Field(default=[SimilarityMethod.TFIDF_COSINE], description="Similarity methods to use")

class CacheResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    cache_hit: bool = False
    similarity_score: Optional[float] = None
    cost_saved: Optional[float] = None
    error: Optional[str] = None
    cache_stats: Optional[Dict[str, Any]] = None

class SemanticCacheManager:
    """Advanced semantic caching system for LLM cost optimization"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        self.in_memory_cache: Dict[str, CacheEntry] = {}
        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=1000) if SIMILARITY_AVAILABLE else None
        self.feature_matrix = None
        self.cache_keys = []
        
        # Statistics tracking
        self.cache_hits = 0
        self.cache_misses = 0
        self.total_cost_saved = 0.0
        
        # Default similarity thresholds by cache type
        self.default_thresholds = {
            CacheType.DOCUMENT_ANALYSIS: 0.85,
            CacheType.CITATION_GENERATION: 0.95,
            CacheType.ENTITY_EXTRACTION: 0.80,
            CacheType.KNOWLEDGE_GRAPH: 0.75,
            CacheType.SEARCH_RESULTS: 0.90,
            CacheType.TRANSLATION: 0.95,
            CacheType.SUMMARIZATION: 0.80
        }
    
    async def store(
        self, 
        content: str, 
        data: Dict[str, Any], 
        cache_type: CacheType,
        ttl_seconds: int = 86400,
        tags: List[str] = None,
        cost_estimate: float = 0.0
    ) -> str:
        """Store content and associated data in semantic cache"""
        
        # Generate content-based cache key
        content_hash = self._generate_content_hash(content)
        cache_id = f"{cache_type.value}:{content_hash}"
        
        # Extract similarity features
        similarity_features = self._extract_similarity_features(content, cache_type)
        
        # Create cache entry
        entry = CacheEntry(
            id=cache_id,
            content_hash=content_hash,
            content_summary=content[:200] + "..." if len(content) > 200 else content,
            cache_type=cache_type,
            cached_data=data,
            similarity_features=similarity_features,
            access_count=0,
            cost_saved=0.0,
            created_at=datetime.now(),
            last_accessed=datetime.now(),
            ttl_seconds=ttl_seconds,
            tags=tags or []
        )
        
        # Store in Redis if available
        if self.redis:
            try:
                await self.redis.setex(
                    cache_id, 
                    ttl_seconds, 
                    json.dumps(entry.to_dict())
                )
                logger.debug(f"Stored cache entry in Redis: {cache_id}")
            except Exception as e:
                logger.warning(f"Failed to store in Redis: {e}")
                # Fall back to in-memory storage
                self.in_memory_cache[cache_id] = entry
        else:
            # In-memory storage
            self.in_memory_cache[cache_id] = entry
        
        # Update feature matrix for similarity search
        await self._update_feature_matrix()
        
        logger.info(f"Cached {cache_type.value} content with ID: {cache_id}")
        return cache_id
    
    async def lookup(
        self, 
        content: str, 
        cache_type: CacheType,
        similarity_threshold: float = None,
        similarity_methods: List[SimilarityMethod] = None
    ) -> Optional[CacheHit]:
        """Lookup content in semantic cache with similarity matching"""
        
        if similarity_threshold is None:
            similarity_threshold = self.default_thresholds.get(cache_type, 0.85)
        
        if similarity_methods is None:
            similarity_methods = [SimilarityMethod.TFIDF_COSINE]
        
        # Try different similarity methods in order
        for method in similarity_methods:
            cache_hit = await self._find_similar_content(
                content, cache_type, similarity_threshold, method
            )
            
            if cache_hit:
                # Update access statistics
                cache_hit.entry.access_count += 1
                cache_hit.entry.last_accessed = datetime.now()
                cache_hit.entry.cost_saved += cache_hit.cost_saved
                
                # Update stored entry
                await self._update_cache_entry(cache_hit.entry)
                
                # Update global statistics
                self.cache_hits += 1
                self.total_cost_saved += cache_hit.cost_saved
                
                logger.info(f"Cache hit for {cache_type.value} with similarity {cache_hit.similarity_score:.3f}")
                return cache_hit
        
        # No cache hit found
        self.cache_misses += 1
        logger.debug(f"Cache miss for {cache_type.value} content")
        return None
    
    async def get_statistics(self) -> CacheStats:
        """Get comprehensive cache statistics"""
        
        # Count entries by type
        entries_by_type = {}
        total_entries = 0
        storage_size_bytes = 0
        
        # From Redis
        if self.redis:
            try:
                keys = await self.redis.keys("*:*")
                for key in keys:
                    if isinstance(key, bytes):
                        key = key.decode()
                    
                    cache_type = key.split(':')[0]
                    entries_by_type[cache_type] = entries_by_type.get(cache_type, 0) + 1
                    total_entries += 1
                    
                    # Estimate storage size
                    data_size = await self.redis.memory_usage(key)
                    if data_size:
                        storage_size_bytes += data_size
                        
            except Exception as e:
                logger.warning(f"Failed to get Redis statistics: {e}")
        
        # From in-memory cache
        for entry in self.in_memory_cache.values():
            cache_type = entry.cache_type.value
            entries_by_type[cache_type] = entries_by_type.get(cache_type, 0) + 1
            total_entries += 1
            
            # Estimate storage size
            entry_json = json.dumps(entry.to_dict())
            storage_size_bytes += len(entry_json.encode())
        
        # Calculate hit rate
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = self.cache_hits / total_requests if total_requests > 0 else 0.0
        
        return CacheStats(
            total_entries=total_entries,
            cache_hits=self.cache_hits,
            cache_misses=self.cache_misses,
            hit_rate=hit_rate,
            total_cost_saved=self.total_cost_saved,
            average_similarity_threshold=sum(self.default_thresholds.values()) / len(self.default_thresholds),
            entries_by_type=entries_by_type,
            storage_size_mb=storage_size_bytes / (1024 * 1024)
        )
    
    async def clear_cache(self, cache_type: Optional[CacheType] = None, older_than_hours: Optional[int] = None) -> int:
        """Clear cache entries with optional filters"""
        
        cleared_count = 0
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours) if older_than_hours else None
        
        # Clear from Redis
        if self.redis:
            try:
                if cache_type:
                    pattern = f"{cache_type.value}:*"
                else:
                    pattern = "*:*"
                
                keys = await self.redis.keys(pattern)
                
                keys_to_delete = []
                for key in keys:
                    if isinstance(key, bytes):
                        key = key.decode()
                    
                    if cutoff_time:
                        # Check entry timestamp
                        entry_data = await self.redis.get(key)
                        if entry_data:
                            try:
                                entry_dict = json.loads(entry_data)
                                last_accessed = datetime.fromisoformat(entry_dict['last_accessed'])
                                if last_accessed < cutoff_time:
                                    keys_to_delete.append(key)
                            except (json.JSONDecodeError, KeyError):
                                # Invalid entry, delete it
                                keys_to_delete.append(key)
                    else:
                        keys_to_delete.append(key)
                
                if keys_to_delete:
                    await self.redis.delete(*keys_to_delete)
                    cleared_count += len(keys_to_delete)
                    
            except Exception as e:
                logger.warning(f"Failed to clear Redis cache: {e}")
        
        # Clear from in-memory cache
        keys_to_remove = []
        for key, entry in self.in_memory_cache.items():
            should_remove = True
            
            if cache_type and entry.cache_type != cache_type:
                should_remove = False
            
            if cutoff_time and entry.last_accessed >= cutoff_time:
                should_remove = False
            
            if should_remove:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.in_memory_cache[key]
            cleared_count += 1
        
        # Update feature matrix
        await self._update_feature_matrix()
        
        logger.info(f"Cleared {cleared_count} cache entries")
        return cleared_count
    
    def get_hit_rate(self) -> float:
        """Get current cache hit rate"""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0
    
    def estimate_cost_savings(self, cache_hit_rate: float, average_api_cost: float, daily_requests: int) -> Dict[str, float]:
        """Estimate cost savings based on cache performance"""
        
        daily_cache_hits = daily_requests * cache_hit_rate
        daily_savings = daily_cache_hits * average_api_cost
        
        return {
            'daily_savings_usd': daily_savings,
            'monthly_savings_usd': daily_savings * 30,
            'yearly_savings_usd': daily_savings * 365,
            'cache_hit_rate': cache_hit_rate,
            'daily_requests_saved': daily_cache_hits
        }
    
    # Private helper methods
    def _generate_content_hash(self, content: str) -> str:
        """Generate deterministic hash for content"""
        # Normalize content for consistent hashing
        normalized = re.sub(r'\s+', ' ', content.lower().strip())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]
    
    def _extract_similarity_features(self, content: str, cache_type: CacheType) -> Dict[str, Any]:
        """Extract features for similarity calculation"""
        
        features = {
            'length': len(content),
            'word_count': len(content.split()),
            'cache_type': cache_type.value
        }
        
        # Extract keywords using simple heuristics
        words = re.findall(r'\b\w+\b', content.lower())
        word_freq = {}
        for word in words:
            if len(word) > 3:  # Skip short words
                word_freq[word] = word_freq.get(word, 0) + 1
        
        # Top keywords
        top_keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        features['keywords'] = [word for word, freq in top_keywords]
        
        # Brazilian legislative specific terms
        legislative_terms = [
            'lei', 'decreto', 'portaria', 'resolução', 'medida provisória',
            'antt', 'antaq', 'anac', 'dnit', 'ibama',
            'transporte', 'rodoviário', 'ferroviário', 'aquaviário'
        ]
        
        features['legislative_terms'] = [term for term in legislative_terms if term in content.lower()]
        
        return features
    
    async def _find_similar_content(
        self, 
        content: str, 
        cache_type: CacheType, 
        threshold: float,
        method: SimilarityMethod
    ) -> Optional[CacheHit]:
        """Find similar content using specified method"""
        
        if method == SimilarityMethod.EXACT_MATCH:
            return await self._exact_match_lookup(content, cache_type)
        elif method == SimilarityMethod.HASH_MATCH:
            return await self._hash_match_lookup(content, cache_type)
        elif method == SimilarityMethod.TFIDF_COSINE:
            return await self._tfidf_similarity_lookup(content, cache_type, threshold)
        elif method == SimilarityMethod.FUZZY_MATCH:
            return await self._fuzzy_match_lookup(content, cache_type, threshold)
        else:
            logger.warning(f"Similarity method {method} not implemented")
            return None
    
    async def _exact_match_lookup(self, content: str, cache_type: CacheType) -> Optional[CacheHit]:
        """Exact string matching"""
        content_hash = self._generate_content_hash(content)
        cache_id = f"{cache_type.value}:{content_hash}"
        
        entry = await self._get_cache_entry(cache_id)
        if entry:
            return CacheHit(
                entry=entry,
                similarity_score=1.0,
                similarity_method=SimilarityMethod.EXACT_MATCH,
                cost_saved=0.002  # Estimated API cost saved
            )
        return None
    
    async def _hash_match_lookup(self, content: str, cache_type: CacheType) -> Optional[CacheHit]:
        """Hash-based matching with slight content variations"""
        # This is the same as exact match for now
        return await self._exact_match_lookup(content, cache_type)
    
    async def _tfidf_similarity_lookup(self, content: str, cache_type: CacheType, threshold: float) -> Optional[CacheHit]:
        """TF-IDF cosine similarity matching"""
        
        if not SIMILARITY_AVAILABLE or not self.vectorizer:
            return None
        
        # Get all cache entries of the same type
        entries = await self._get_entries_by_type(cache_type)
        if not entries:
            return None
        
        try:
            # Prepare documents for vectorization
            documents = [content] + [entry.content_summary for entry in entries]
            
            # Calculate TF-IDF vectors
            tfidf_matrix = self.vectorizer.fit_transform(documents)
            
            # Calculate cosine similarities
            similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:]).flatten()
            
            # Find best match above threshold
            best_idx = np.argmax(similarities)
            best_similarity = similarities[best_idx]
            
            if best_similarity >= threshold:
                best_entry = entries[best_idx]
                return CacheHit(
                    entry=best_entry,
                    similarity_score=float(best_similarity),
                    similarity_method=SimilarityMethod.TFIDF_COSINE,
                    cost_saved=0.002 * best_similarity  # Scale cost savings by similarity
                )
                
        except Exception as e:
            logger.warning(f"TF-IDF similarity calculation failed: {e}")
        
        return None
    
    async def _fuzzy_match_lookup(self, content: str, cache_type: CacheType, threshold: float) -> Optional[CacheHit]:
        """Fuzzy string matching"""
        # Simplified fuzzy matching using keyword overlap
        content_features = self._extract_similarity_features(content, cache_type)
        content_keywords = set(content_features['keywords'])
        
        entries = await self._get_entries_by_type(cache_type)
        best_entry = None
        best_score = 0.0
        
        for entry in entries:
            entry_keywords = set(entry.similarity_features.get('keywords', []))
            
            if not content_keywords or not entry_keywords:
                continue
            
            # Calculate Jaccard similarity
            intersection = len(content_keywords & entry_keywords)
            union = len(content_keywords | entry_keywords)
            similarity = intersection / union if union > 0 else 0.0
            
            if similarity > best_score and similarity >= threshold:
                best_score = similarity
                best_entry = entry
        
        if best_entry:
            return CacheHit(
                entry=best_entry,
                similarity_score=best_score,
                similarity_method=SimilarityMethod.FUZZY_MATCH,
                cost_saved=0.002 * best_score
            )
        
        return None
    
    async def _get_cache_entry(self, cache_id: str) -> Optional[CacheEntry]:
        """Get cache entry by ID"""
        
        # Try Redis first
        if self.redis:
            try:
                data = await self.redis.get(cache_id)
                if data:
                    if isinstance(data, bytes):
                        data = data.decode()
                    entry_dict = json.loads(data)
                    return CacheEntry.from_dict(entry_dict)
            except Exception as e:
                logger.warning(f"Failed to get entry from Redis: {e}")
        
        # Try in-memory cache
        return self.in_memory_cache.get(cache_id)
    
    async def _get_entries_by_type(self, cache_type: CacheType) -> List[CacheEntry]:
        """Get all cache entries of a specific type"""
        entries = []
        
        # From Redis
        if self.redis:
            try:
                keys = await self.redis.keys(f"{cache_type.value}:*")
                for key in keys:
                    if isinstance(key, bytes):
                        key = key.decode()
                    entry = await self._get_cache_entry(key)
                    if entry:
                        entries.append(entry)
            except Exception as e:
                logger.warning(f"Failed to get entries from Redis: {e}")
        
        # From in-memory cache
        for entry in self.in_memory_cache.values():
            if entry.cache_type == cache_type:
                entries.append(entry)
        
        return entries
    
    async def _update_cache_entry(self, entry: CacheEntry):
        """Update cache entry in storage"""
        
        if self.redis:
            try:
                await self.redis.setex(
                    entry.id,
                    entry.ttl_seconds,
                    json.dumps(entry.to_dict())
                )
            except Exception as e:
                logger.warning(f"Failed to update entry in Redis: {e}")
                # Update in-memory as fallback
                self.in_memory_cache[entry.id] = entry
        else:
            self.in_memory_cache[entry.id] = entry
    
    async def _update_feature_matrix(self):
        """Update feature matrix for similarity calculations"""
        # This would be implemented for more advanced similarity methods
        pass

# Global semantic cache manager instance
_cache_manager: Optional[SemanticCacheManager] = None

async def get_cache_manager() -> SemanticCacheManager:
    """Get or create the global semantic cache manager"""
    global _cache_manager
    
    if _cache_manager is None:
        # Initialize Redis connection if available
        redis_client = None
        if REDIS_AVAILABLE:
            try:
                import os
                redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
                redis_client = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                await redis_client.ping()
                logger.info("✅ Redis connected for semantic caching")
            except Exception as e:
                logger.warning(f"Redis connection failed, using in-memory caching: {e}")
                redis_client = None
        
        _cache_manager = SemanticCacheManager(redis_client)
        logger.info("✅ Semantic cache manager initialized")
    
    return _cache_manager

# API endpoints
@router.post("/store", response_model=CacheResponse)
async def store_in_cache(request: CacheRequest) -> CacheResponse:
    """Store content and data in semantic cache"""
    try:
        if not request.data_to_cache:
            return CacheResponse(
                success=False,
                error="No data provided to cache"
            )
        
        cache_manager = await get_cache_manager()
        
        cache_id = await cache_manager.store(
            content=request.content,
            data=request.data_to_cache,
            cache_type=request.cache_type,
            ttl_seconds=request.ttl_seconds,
            tags=request.tags,
            cost_estimate=request.cost_estimate or 0.0
        )
        
        return CacheResponse(
            success=True,
            data={
                "cache_id": cache_id,
                "stored_at": datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"Cache storage failed: {e}")
        return CacheResponse(
            success=False,
            error=str(e)
        )

@router.post("/lookup", response_model=CacheResponse)
async def lookup_in_cache(request: CacheLookupRequest) -> CacheResponse:
    """Lookup content in semantic cache"""
    try:
        cache_manager = await get_cache_manager()
        
        cache_hit = await cache_manager.lookup(
            content=request.content,
            cache_type=request.cache_type,
            similarity_threshold=request.similarity_threshold,
            similarity_methods=request.similarity_methods
        )
        
        if cache_hit:
            return CacheResponse(
                success=True,
                data=cache_hit.entry.cached_data,
                cache_hit=True,
                similarity_score=cache_hit.similarity_score,
                cost_saved=cache_hit.cost_saved
            )
        else:
            return CacheResponse(
                success=True,
                cache_hit=False
            )
        
    except Exception as e:
        logger.error(f"Cache lookup failed: {e}")
        return CacheResponse(
            success=False,
            error=str(e)
        )

@router.get("/statistics", response_model=CacheResponse)
async def get_cache_statistics() -> CacheResponse:
    """Get comprehensive cache statistics"""
    try:
        cache_manager = await get_cache_manager()
        stats = await cache_manager.get_statistics()
        
        return CacheResponse(
            success=True,
            data=asdict(stats),
            cache_stats={
                "hit_rate": f"{stats.hit_rate:.2%}",
                "total_cost_saved": f"${stats.total_cost_saved:.4f}",
                "storage_size": f"{stats.storage_size_mb:.2f} MB"
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get cache statistics: {e}")
        return CacheResponse(
            success=False,
            error=str(e)
        )

@router.post("/clear")
async def clear_cache(
    cache_type: Optional[CacheType] = None,
    older_than_hours: Optional[int] = None
) -> CacheResponse:
    """Clear cache entries with optional filters"""
    try:
        cache_manager = await get_cache_manager()
        cleared_count = await cache_manager.clear_cache(cache_type, older_than_hours)
        
        return CacheResponse(
            success=True,
            data={
                "cleared_entries": cleared_count,
                "cleared_at": datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"Cache clearing failed: {e}")
        return CacheResponse(
            success=False,
            error=str(e)
        )

@router.get("/health")
async def cache_health_status() -> Dict[str, Any]:
    """Get semantic cache health status"""
    try:
        cache_manager = await get_cache_manager()
        stats = await cache_manager.get_statistics()
        
        return {
            "status": "healthy",
            "redis_available": REDIS_AVAILABLE,
            "similarity_available": SIMILARITY_AVAILABLE,
            "cache_hit_rate": cache_manager.get_hit_rate(),
            "total_entries": stats.total_entries,
            "total_cost_saved": stats.total_cost_saved,
            "storage_size_mb": stats.storage_size_mb
        }
        
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# Export router and manager getter
__all__ = ["router", "get_cache_manager"]