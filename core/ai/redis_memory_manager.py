"""
Redis Memory Manager for AI Agents
==================================

Enhanced Redis infrastructure for AI agent memory management.
Extends existing Redis configuration with AI-specific patterns,
memory persistence, retrieval optimization, and cleanup strategies.

Features:
- AI-specific Redis configuration and connection management
- Memory persistence patterns for agent conversations
- Retrieval optimization with indexing and search
- Cleanup strategies for memory management
- Performance monitoring for Redis operations
- Backup and recovery for critical agent memory
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
import asyncio
import hashlib

logger = logging.getLogger(__name__)


class RedisMemoryManager:
    """
    Enhanced Redis manager specifically for AI agent memory operations
    Built on top of existing Redis infrastructure with AI-optimized patterns
    """
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.memory_prefix = "ai:memory"
        self.index_prefix = "ai:index"
        self.stats_prefix = "ai:stats"
        self.backup_prefix = "ai:backup"
        
        # Performance tracking
        self.operation_stats = {
            "reads": 0,
            "writes": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cleanup_operations": 0
        }
        
        logger.info("Redis Memory Manager initialized for AI agents")
    
    async def initialize_ai_redis_structure(self):
        """Initialize Redis structure optimized for AI agent operations"""
        
        # Create AI-specific Redis structures
        structures = {
            "ai:config": {
                "version": "1.0.0",
                "memory_ttl_default": 86400,  # 24 hours
                "max_memory_per_agent": 10000,  # entries
                "cleanup_interval": 3600,  # 1 hour
                "backup_interval": 43200,  # 12 hours
                "initialized_at": datetime.now().isoformat()
            },
            "ai:global_stats": {
                "total_agents": 0,
                "total_memory_entries": 0,
                "total_cost_cents": 0.0,
                "cache_hit_rate": 0.0,
                "last_cleanup": datetime.now().isoformat()
            }
        }
        
        for key, data in structures.items():
            await self.redis.hset(key, mapping={k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in data.items()})
        
        logger.info("AI Redis structure initialized successfully")
    
    async def create_memory_indexes(self, agent_id: str):
        """Create optimized indexes for memory retrieval"""
        
        # Create timestamp index for chronological retrieval
        timestamp_index = f"{self.index_prefix}:timestamp:{agent_id}"
        
        # Create keyword index for semantic search
        keyword_index = f"{self.index_prefix}:keywords:{agent_id}"
        
        # Create cost index for budget tracking
        cost_index = f"{self.index_prefix}:costs:{agent_id}"
        
        # Initialize empty indexes
        await self.redis.delete(timestamp_index, keyword_index, cost_index)
        
        logger.info(f"Memory indexes created for agent {agent_id}")
    
    async def store_memory_with_indexing(self, agent_id: str, memory_entry: Dict[str, Any]) -> str:
        """Store memory entry with automatic indexing for fast retrieval"""
        
        entry_id = memory_entry.get("entry_id")
        if not entry_id:
            entry_id = f"mem_{int(time.time() * 1000)}_{agent_id}"
            memory_entry["entry_id"] = entry_id
        
        # Store main memory entry
        memory_key = f"{self.memory_prefix}:entries:{agent_id}"
        await self.redis.hset(memory_key, entry_id, json.dumps(memory_entry, default=str))
        
        # Update indexes
        await self._update_indexes(agent_id, entry_id, memory_entry)
        
        # Update statistics
        await self._update_agent_stats(agent_id, "memory_stored")
        
        # Set TTL if specified
        if memory_entry.get("ttl"):
            await self.redis.expire(f"{memory_key}:{entry_id}", memory_entry["ttl"])
        
        self.operation_stats["writes"] += 1
        logger.debug(f"Memory entry {entry_id} stored for agent {agent_id}")
        
        return entry_id
    
    async def retrieve_memory_by_timerange(self, agent_id: str, start_time: datetime, 
                                         end_time: datetime, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve memory entries within time range using timestamp index"""
        
        timestamp_index = f"{self.index_prefix}:timestamp:{agent_id}"
        
        # Convert datetime to timestamp for Redis sorted set operations
        start_ts = start_time.timestamp()
        end_ts = end_time.timestamp()
        
        # Get entry IDs from timestamp index
        entry_ids = await self.redis.zrangebyscore(timestamp_index, start_ts, end_ts, start=0, num=limit)
        
        if not entry_ids:
            self.operation_stats["cache_misses"] += 1
            return []
        
        # Retrieve actual memory entries
        memory_entries = await self._get_memory_entries(agent_id, entry_ids)
        
        self.operation_stats["reads"] += 1
        self.operation_stats["cache_hits"] += 1
        
        return memory_entries
    
    async def search_memory_by_keywords(self, agent_id: str, keywords: List[str], 
                                      limit: int = 20) -> List[Dict[str, Any]]:
        """Search memory using keyword index with scoring"""
        
        keyword_index = f"{self.index_prefix}:keywords:{agent_id}"
        
        # Build search terms
        search_results = {}
        
        for keyword in keywords:
            keyword_lower = keyword.lower()
            # Use Redis SCAN to find matching keyword entries
            cursor = 0
            while True:
                cursor, keys = await self.redis.scan(cursor, match=f"{keyword_index}:{keyword_lower}*")
                
                for key in keys:
                    # Extract entry IDs from keyword index
                    entry_ids = await self.redis.smembers(key)
                    for entry_id in entry_ids:
                        if entry_id not in search_results:
                            search_results[entry_id] = 0
                        search_results[entry_id] += 1  # Simple scoring
                
                if cursor == 0:
                    break
        
        # Sort by score and get top results
        sorted_entries = sorted(search_results.items(), key=lambda x: x[1], reverse=True)[:limit]
        entry_ids = [entry_id for entry_id, score in sorted_entries]
        
        if not entry_ids:
            self.operation_stats["cache_misses"] += 1
            return []
        
        # Retrieve actual memory entries
        memory_entries = await self._get_memory_entries(agent_id, entry_ids)
        
        self.operation_stats["reads"] += 1
        self.operation_stats["cache_hits"] += 1
        
        return memory_entries
    
    async def get_memory_by_cost_range(self, agent_id: str, min_cost: float, 
                                     max_cost: float, limit: int = 30) -> List[Dict[str, Any]]:
        """Retrieve memory entries by cost range for budget analysis"""
        
        cost_index = f"{self.index_prefix}:costs:{agent_id}"
        
        # Get entry IDs from cost index (sorted set with cost as score)
        entry_ids = await self.redis.zrangebyscore(cost_index, min_cost, max_cost, start=0, num=limit)
        
        if not entry_ids:
            return []
        
        # Retrieve actual memory entries
        memory_entries = await self._get_memory_entries(agent_id, entry_ids)
        
        return memory_entries
    
    async def _update_indexes(self, agent_id: str, entry_id: str, memory_entry: Dict[str, Any]):
        """Update all indexes when storing memory entry"""
        
        # Update timestamp index
        timestamp_index = f"{self.index_prefix}:timestamp:{agent_id}"
        if "timestamp" in memory_entry:
            timestamp = datetime.fromisoformat(memory_entry["timestamp"]).timestamp()
            await self.redis.zadd(timestamp_index, {entry_id: timestamp})
        
        # Update keyword index
        keyword_index = f"{self.index_prefix}:keywords:{agent_id}"
        content = memory_entry.get("content", "")
        keywords = self._extract_keywords(content)
        
        for keyword in keywords:
            keyword_key = f"{keyword_index}:{keyword.lower()}"
            await self.redis.sadd(keyword_key, entry_id)
            await self.redis.expire(keyword_key, 86400 * 7)  # Keep keywords for 7 days
        
        # Update cost index
        cost_index = f"{self.index_prefix}:costs:{agent_id}"
        if "cost_cents" in memory_entry:
            cost = float(memory_entry["cost_cents"])
            await self.redis.zadd(cost_index, {entry_id: cost})
    
    async def _get_memory_entries(self, agent_id: str, entry_ids: List[str]) -> List[Dict[str, Any]]:
        """Retrieve memory entries by IDs"""
        
        memory_key = f"{self.memory_prefix}:entries:{agent_id}"
        
        # Use pipeline for efficient bulk retrieval
        pipe = self.redis.pipeline()
        for entry_id in entry_ids:
            pipe.hget(memory_key, entry_id)
        
        results = await pipe.execute()
        
        memory_entries = []
        for result in results:
            if result:
                try:
                    entry = json.loads(result)
                    # Convert timestamp string back to datetime
                    if "timestamp" in entry:
                        entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
                    memory_entries.append(entry)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid memory entry JSON: {e}")
        
        return memory_entries
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extract keywords from content for indexing"""
        
        # Simple keyword extraction - could be enhanced with NLP
        stop_words = {
            "o", "a", "os", "as", "de", "da", "do", "das", "dos", "em", "na", "no", 
            "para", "com", "por", "que", "se", "não", "um", "uma", "como", "mais",
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "by", "is", "are", "was", "were", "be", "been", "being"
        }
        
        # Extract words and filter
        words = content.lower().split()
        keywords = []
        
        for word in words:
            # Clean word
            word = ''.join(c for c in word if c.isalnum())
            
            # Filter by length and stop words
            if len(word) > 2 and word not in stop_words:
                keywords.append(word)
        
        # Return unique keywords, limited to prevent index bloat
        return list(set(keywords))[:20]
    
    async def cleanup_expired_memory(self, agent_id: str) -> Dict[str, int]:
        """Clean up expired memory entries and update indexes"""
        
        cleanup_stats = {
            "entries_removed": 0,
            "indexes_updated": 0,
            "bytes_freed": 0
        }
        
        memory_key = f"{self.memory_prefix}:entries:{agent_id}"
        
        # Get all memory entries for agent
        all_entries = await self.redis.hgetall(memory_key)
        current_time = datetime.now()
        
        entries_to_remove = []
        
        for entry_id, entry_data in all_entries.items():
            try:
                entry = json.loads(entry_data)
                
                # Check if entry has expired
                if "timestamp" in entry and "ttl" in entry:
                    entry_time = datetime.fromisoformat(entry["timestamp"])
                    ttl_seconds = int(entry["ttl"])
                    
                    if (current_time - entry_time).total_seconds() > ttl_seconds:
                        entries_to_remove.append(entry_id)
                        cleanup_stats["bytes_freed"] += len(entry_data)
                
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.warning(f"Invalid entry during cleanup: {e}")
                entries_to_remove.append(entry_id)
        
        # Remove expired entries
        if entries_to_remove:
            await self.redis.hdel(memory_key, *entries_to_remove)
            cleanup_stats["entries_removed"] = len(entries_to_remove)
            
            # Update indexes by removing references to deleted entries
            await self._cleanup_indexes(agent_id, entries_to_remove)
            cleanup_stats["indexes_updated"] = 3  # timestamp, keyword, cost indexes
        
        # Update cleanup statistics
        await self._update_agent_stats(agent_id, "cleanup_performed", cleanup_stats)
        
        self.operation_stats["cleanup_operations"] += 1
        logger.info(f"Cleanup completed for agent {agent_id}: {cleanup_stats}")
        
        return cleanup_stats
    
    async def _cleanup_indexes(self, agent_id: str, entry_ids: List[str]):
        """Remove references from indexes for deleted entries"""
        
        # Clean timestamp index
        timestamp_index = f"{self.index_prefix}:timestamp:{agent_id}"
        await self.redis.zrem(timestamp_index, *entry_ids)
        
        # Clean cost index
        cost_index = f"{self.index_prefix}:costs:{agent_id}"
        await self.redis.zrem(cost_index, *entry_ids)
        
        # Clean keyword indexes (more complex due to multiple keyword keys)
        keyword_index_pattern = f"{self.index_prefix}:keywords:{agent_id}:*"
        cursor = 0
        
        while True:
            cursor, keys = await self.redis.scan(cursor, match=keyword_index_pattern)
            
            for key in keys:
                await self.redis.srem(key, *entry_ids)
                
                # Remove empty keyword sets
                if await self.redis.scard(key) == 0:
                    await self.redis.delete(key)
            
            if cursor == 0:
                break
    
    async def backup_agent_memory(self, agent_id: str) -> str:
        """Create backup of agent memory for recovery"""
        
        backup_id = f"backup_{agent_id}_{int(time.time())}"
        backup_key = f"{self.backup_prefix}:{backup_id}"
        
        # Get all memory entries
        memory_key = f"{self.memory_prefix}:entries:{agent_id}"
        all_entries = await self.redis.hgetall(memory_key)
        
        # Create backup data structure
        backup_data = {
            "backup_id": backup_id,
            "agent_id": agent_id,
            "created_at": datetime.now().isoformat(),
            "entry_count": len(all_entries),
            "entries": all_entries
        }
        
        # Store backup
        await self.redis.setex(backup_key, 86400 * 30, json.dumps(backup_data, default=str))  # Keep for 30 days
        
        logger.info(f"Memory backup created for agent {agent_id}: {backup_id}")
        return backup_id
    
    async def restore_agent_memory(self, agent_id: str, backup_id: str) -> bool:
        """Restore agent memory from backup"""
        
        backup_key = f"{self.backup_prefix}:{backup_id}"
        backup_data = await self.redis.get(backup_key)
        
        if not backup_data:
            logger.error(f"Backup {backup_id} not found")
            return False
        
        try:
            backup = json.loads(backup_data)
            
            # Verify backup is for correct agent
            if backup["agent_id"] != agent_id:
                logger.error(f"Backup {backup_id} is for different agent")
                return False
            
            # Restore memory entries
            memory_key = f"{self.memory_prefix}:entries:{agent_id}"
            await self.redis.delete(memory_key)  # Clear existing
            
            if backup["entries"]:
                await self.redis.hset(memory_key, mapping=backup["entries"])
            
            # Rebuild indexes
            await self._rebuild_indexes(agent_id, backup["entries"])
            
            logger.info(f"Memory restored for agent {agent_id} from backup {backup_id}")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid backup data: {e}")
            return False
    
    async def _rebuild_indexes(self, agent_id: str, entries: Dict[str, str]):
        """Rebuild all indexes after memory restore"""
        
        # Clear existing indexes
        await self.create_memory_indexes(agent_id)
        
        # Rebuild indexes for each entry
        for entry_id, entry_data in entries.items():
            try:
                entry = json.loads(entry_data)
                await self._update_indexes(agent_id, entry_id, entry)
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid entry during index rebuild: {e}")
    
    async def _update_agent_stats(self, agent_id: str, operation: str, data: Any = None):
        """Update agent-specific statistics"""
        
        stats_key = f"{self.stats_prefix}:agent:{agent_id}"
        timestamp = datetime.now().isoformat()
        
        # Update operation counter
        await self.redis.hincrby(stats_key, f"operations_{operation}", 1)
        await self.redis.hset(stats_key, f"last_{operation}", timestamp)
        
        # Store operation data if provided
        if data:
            await self.redis.hset(stats_key, f"data_{operation}", json.dumps(data, default=str))
        
        # Set TTL for stats
        await self.redis.expire(stats_key, 86400 * 90)  # Keep stats for 90 days
    
    async def get_memory_performance_stats(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Get performance statistics for memory operations"""
        
        if agent_id:
            # Agent-specific stats
            stats_key = f"{self.stats_prefix}:agent:{agent_id}"
            agent_stats = await self.redis.hgetall(stats_key)
            
            return {
                "agent_id": agent_id,
                "agent_stats": agent_stats,
                "memory_operations": self.operation_stats
            }
        else:
            # Global stats
            global_stats = await self.redis.hgetall("ai:global_stats")
            
            return {
                "global_stats": global_stats,
                "memory_operations": self.operation_stats,
                "performance_metrics": {
                    "cache_hit_rate": (self.operation_stats["cache_hits"] / 
                                     max(self.operation_stats["cache_hits"] + self.operation_stats["cache_misses"], 1)) * 100,
                    "total_operations": sum(self.operation_stats.values()),
                    "read_write_ratio": self.operation_stats["reads"] / max(self.operation_stats["writes"], 1)
                }
            }
    
    async def optimize_memory_storage(self, agent_id: str) -> Dict[str, Any]:
        """Optimize memory storage for better performance"""
        
        optimization_results = {
            "memory_compacted": False,
            "indexes_optimized": False,
            "duplicate_entries_removed": 0,
            "storage_saved_bytes": 0
        }
        
        memory_key = f"{self.memory_prefix}:entries:{agent_id}"
        all_entries = await self.redis.hgetall(memory_key)
        
        # Find and remove duplicate entries based on content hash
        content_hashes = {}
        duplicates_to_remove = []
        
        for entry_id, entry_data in all_entries.items():
            try:
                entry = json.loads(entry_data)
                content = entry.get("content", "")
                content_hash = hashlib.md5(content.encode()).hexdigest()
                
                if content_hash in content_hashes:
                    # Duplicate found - keep the newer one
                    existing_entry_id = content_hashes[content_hash]
                    existing_entry = json.loads(all_entries[existing_entry_id])
                    
                    existing_time = datetime.fromisoformat(existing_entry["timestamp"])
                    current_time = datetime.fromisoformat(entry["timestamp"])
                    
                    if current_time > existing_time:
                        # Current entry is newer, remove the old one
                        duplicates_to_remove.append(existing_entry_id)
                        content_hashes[content_hash] = entry_id
                    else:
                        # Existing entry is newer, remove current one
                        duplicates_to_remove.append(entry_id)
                else:
                    content_hashes[content_hash] = entry_id
                    
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Invalid entry during optimization: {e}")
                duplicates_to_remove.append(entry_id)
        
        # Remove duplicates
        if duplicates_to_remove:
            for entry_id in duplicates_to_remove:
                optimization_results["storage_saved_bytes"] += len(all_entries[entry_id])
            
            await self.redis.hdel(memory_key, *duplicates_to_remove)
            await self._cleanup_indexes(agent_id, duplicates_to_remove)
            
            optimization_results["duplicate_entries_removed"] = len(duplicates_to_remove)
            optimization_results["memory_compacted"] = True
        
        # Optimize indexes by removing empty entries
        await self._optimize_indexes(agent_id)
        optimization_results["indexes_optimized"] = True
        
        logger.info(f"Memory optimization completed for agent {agent_id}: {optimization_results}")
        return optimization_results
    
    async def _optimize_indexes(self, agent_id: str):
        """Optimize indexes by removing empty or expired entries"""
        
        # Optimize keyword indexes
        keyword_pattern = f"{self.index_prefix}:keywords:{agent_id}:*"
        cursor = 0
        
        while True:
            cursor, keys = await self.redis.scan(cursor, match=keyword_pattern)
            
            for key in keys:
                # Remove empty sets
                if await self.redis.scard(key) == 0:
                    await self.redis.delete(key)
            
            if cursor == 0:
                break
        
        # Optimize timestamp and cost indexes by removing entries that no longer exist
        memory_key = f"{self.memory_prefix}:entries:{agent_id}"
        existing_entries = set(await self.redis.hkeys(memory_key))
        
        # Clean timestamp index
        timestamp_index = f"{self.index_prefix}:timestamp:{agent_id}"
        indexed_entries = set(await self.redis.zrange(timestamp_index, 0, -1))
        orphaned_entries = indexed_entries - existing_entries
        if orphaned_entries:
            await self.redis.zrem(timestamp_index, *orphaned_entries)
        
        # Clean cost index
        cost_index = f"{self.index_prefix}:costs:{agent_id}"
        indexed_entries = set(await self.redis.zrange(cost_index, 0, -1))
        orphaned_entries = indexed_entries - existing_entries
        if orphaned_entries:
            await self.redis.zrem(cost_index, *orphaned_entries)