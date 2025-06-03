"""
Conflict Resolver for Monitor Legislativo v4 Desktop App
Handles data conflicts during synchronization

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import logging
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
import json
import difflib

logger = logging.getLogger(__name__)

class ConflictType(Enum):
    """Types of conflicts that can occur"""
    CREATE_CREATE = "create_create"  # Same record created both locally and remotely
    UPDATE_UPDATE = "update_update"  # Same record updated both locally and remotely
    UPDATE_DELETE = "update_delete"  # Local update vs remote delete
    DELETE_UPDATE = "delete_update"  # Local delete vs remote update
    SCHEMA_MISMATCH = "schema_mismatch"  # Data structure differences

class AutoResolutionStrategy(Enum):
    """Automatic conflict resolution strategies"""
    LATEST_WINS = "latest_wins"  # Most recent timestamp wins
    REMOTE_WINS = "remote_wins"  # Server always wins
    LOCAL_WINS = "local_wins"   # Local changes always win
    SMART_MERGE = "smart_merge"  # Attempt intelligent merge
    MANUAL_ONLY = "manual_only"  # Always require manual resolution

@dataclass
class ConflictData:
    """Represents a data conflict"""
    record_id: str
    table: str
    conflict_type: ConflictType
    local_data: Dict[str, Any]
    remote_data: Dict[str, Any]
    local_timestamp: datetime
    remote_timestamp: datetime
    field_conflicts: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class ResolutionResult:
    """Result of conflict resolution"""
    strategy: str
    resolved_data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    manual_intervention_required: bool = False
    resolution_notes: Optional[str] = None

class ConflictResolver:
    """Resolves data conflicts during synchronization"""
    
    def __init__(self):
        self.auto_strategy = AutoResolutionStrategy.SMART_MERGE
        self.field_merge_rules: Dict[str, Callable] = {}
        self.resolution_cache: Dict[str, ResolutionResult] = {}
        self.manual_resolution_callbacks: List[Callable] = []
        
        # Setup default field merge rules
        self._setup_default_merge_rules()
    
    def _setup_default_merge_rules(self) -> None:
        """Setup default rules for merging specific fields"""
        
        # String fields - take the longer/more detailed version
        def merge_text_field(local_val: str, remote_val: str, field_name: str) -> str:
            if not local_val:
                return remote_val
            if not remote_val:
                return local_val
            
            # For title/summary fields, prefer the longer version
            if field_name in ['title', 'summary', 'description']:
                return local_val if len(local_val) > len(remote_val) else remote_val
            
            # For other text fields, prefer non-empty
            return local_val or remote_val
        
        # List fields - merge and deduplicate
        def merge_list_field(local_val: List, remote_val: List, field_name: str) -> List:
            if not local_val:
                return remote_val or []
            if not remote_val:
                return local_val or []
            
            # Merge and deduplicate
            combined = list(local_val) + list(remote_val)
            return list(dict.fromkeys(combined))  # Preserve order while deduplicating
        
        # Numeric fields - take the higher value (assuming it's more recent)
        def merge_numeric_field(local_val: float, remote_val: float, field_name: str) -> float:
            # For version fields, take the higher version
            if 'version' in field_name.lower():
                return max(local_val or 0, remote_val or 0)
            
            # For count fields, take the higher count
            if 'count' in field_name.lower():
                return max(local_val or 0, remote_val or 0)
            
            # Default to remote value
            return remote_val if remote_val is not None else local_val
        
        self.field_merge_rules['text'] = merge_text_field
        self.field_merge_rules['list'] = merge_list_field
        self.field_merge_rules['numeric'] = merge_numeric_field
    
    async def resolve_conflict(self, conflict: ConflictData) -> Optional[ResolutionResult]:
        """Resolve a data conflict"""
        try:
            # Check cache first
            cache_key = self._get_cache_key(conflict)
            if cache_key in self.resolution_cache:
                cached_result = self.resolution_cache[cache_key]
                logger.info(f"Using cached resolution for conflict {conflict.record_id}")
                return cached_result
            
            # Analyze the conflict
            analysis = self._analyze_conflict(conflict)
            
            # Attempt automatic resolution
            result = await self._attempt_auto_resolution(conflict, analysis)
            
            if result and not result.manual_intervention_required:
                # Cache successful automatic resolution
                self.resolution_cache[cache_key] = result
                logger.info(f"Auto-resolved conflict for {conflict.record_id} using {result.strategy}")
                return result
            
            # Require manual resolution
            if self.manual_resolution_callbacks:
                manual_result = await self._request_manual_resolution(conflict, analysis)
                if manual_result:
                    logger.info(f"Manually resolved conflict for {conflict.record_id}")
                    return manual_result
            
            # No resolution possible
            logger.warning(f"Could not resolve conflict for {conflict.record_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error resolving conflict for {conflict.record_id}: {e}")
            return None
    
    def _analyze_conflict(self, conflict: ConflictData) -> Dict[str, Any]:
        """Analyze conflict to determine best resolution approach"""
        analysis = {
            "field_differences": [],
            "complexity_score": 0,
            "timestamp_diff_seconds": 0,
            "data_size_diff": 0,
            "structural_changes": False
        }
        
        # Calculate timestamp difference
        time_diff = abs((conflict.local_timestamp - conflict.remote_timestamp).total_seconds())
        analysis["timestamp_diff_seconds"] = time_diff
        
        # Find field differences
        local_keys = set(conflict.local_data.keys())
        remote_keys = set(conflict.remote_data.keys())
        
        # Check for structural changes
        if local_keys != remote_keys:
            analysis["structural_changes"] = True
            analysis["complexity_score"] += 2
        
        # Analyze field-by-field differences
        all_keys = local_keys.union(remote_keys)
        
        for key in all_keys:
            local_val = conflict.local_data.get(key)
            remote_val = conflict.remote_data.get(key)
            
            if local_val != remote_val:
                diff_info = {
                    "field": key,
                    "local_value": local_val,
                    "remote_value": remote_val,
                    "type": type(local_val).__name__ if local_val is not None else "None"
                }
                
                # Calculate field-level complexity
                if isinstance(local_val, (dict, list)):
                    diff_info["complexity"] = "high"
                    analysis["complexity_score"] += 2
                elif isinstance(local_val, str) and len(str(local_val)) > 100:
                    diff_info["complexity"] = "medium"
                    analysis["complexity_score"] += 1
                else:
                    diff_info["complexity"] = "low"
                
                analysis["field_differences"].append(diff_info)
        
        # Calculate data size difference
        local_size = len(json.dumps(conflict.local_data, default=str))
        remote_size = len(json.dumps(conflict.remote_data, default=str))
        analysis["data_size_diff"] = abs(local_size - remote_size)
        
        return analysis
    
    async def _attempt_auto_resolution(self, 
                                     conflict: ConflictData, 
                                     analysis: Dict[str, Any]) -> Optional[ResolutionResult]:
        """Attempt automatic conflict resolution"""
        
        if self.auto_strategy == AutoResolutionStrategy.MANUAL_ONLY:
            return ResolutionResult(
                strategy="manual_required",
                resolved_data={},
                confidence=0.0,
                manual_intervention_required=True
            )
        
        # Simple strategies first
        if self.auto_strategy == AutoResolutionStrategy.LATEST_WINS:
            return self._resolve_latest_wins(conflict)
        
        if self.auto_strategy == AutoResolutionStrategy.REMOTE_WINS:
            return ResolutionResult(
                strategy="remote_wins",
                resolved_data=conflict.remote_data,
                confidence=1.0,
                resolution_notes="Always prefer remote data"
            )
        
        if self.auto_strategy == AutoResolutionStrategy.LOCAL_WINS:
            return ResolutionResult(
                strategy="local_wins", 
                resolved_data=conflict.local_data,
                confidence=1.0,
                resolution_notes="Always prefer local data"
            )
        
        # Smart merge strategy
        if self.auto_strategy == AutoResolutionStrategy.SMART_MERGE:
            return await self._smart_merge_resolution(conflict, analysis)
        
        return None
    
    def _resolve_latest_wins(self, conflict: ConflictData) -> ResolutionResult:
        """Resolve by using the most recent timestamp"""
        if conflict.local_timestamp > conflict.remote_timestamp:
            return ResolutionResult(
                strategy="latest_wins_local",
                resolved_data=conflict.local_data,
                confidence=0.8,
                resolution_notes=f"Local data is more recent ({conflict.local_timestamp})"
            )
        else:
            return ResolutionResult(
                strategy="latest_wins_remote",
                resolved_data=conflict.remote_data,
                confidence=0.8,
                resolution_notes=f"Remote data is more recent ({conflict.remote_timestamp})"
            )
    
    async def _smart_merge_resolution(self, 
                                    conflict: ConflictData, 
                                    analysis: Dict[str, Any]) -> ResolutionResult:
        """Attempt intelligent merging of conflicting data"""
        
        # If complexity is too high, require manual resolution
        if analysis["complexity_score"] > 5:
            return ResolutionResult(
                strategy="manual_required_complex",
                resolved_data={},
                confidence=0.0,
                manual_intervention_required=True,
                resolution_notes="Conflict too complex for automatic resolution"
            )
        
        # Start with the base data (prefer local as starting point)
        merged_data = dict(conflict.local_data)
        merge_notes = []
        confidence = 1.0
        
        # Merge field by field
        for diff in analysis["field_differences"]:
            field = diff["field"]
            local_val = diff["local_value"]
            remote_val = diff["remote_value"]
            
            # Determine field type and merge strategy
            if local_val is None and remote_val is not None:
                merged_data[field] = remote_val
                merge_notes.append(f"Added missing field '{field}' from remote")
                
            elif remote_val is None and local_val is not None:
                # Keep local value (already in merged_data)
                merge_notes.append(f"Kept local field '{field}' (missing in remote)")
                
            elif isinstance(local_val, str) and isinstance(remote_val, str):
                merged_val = self.field_merge_rules['text'](local_val, remote_val, field)
                merged_data[field] = merged_val
                merge_notes.append(f"Merged text field '{field}'")
                
            elif isinstance(local_val, list) and isinstance(remote_val, list):
                merged_val = self.field_merge_rules['list'](local_val, remote_val, field)
                merged_data[field] = merged_val
                merge_notes.append(f"Merged list field '{field}'")
                
            elif isinstance(local_val, (int, float)) and isinstance(remote_val, (int, float)):
                merged_val = self.field_merge_rules['numeric'](local_val, remote_val, field)
                merged_data[field] = merged_val
                merge_notes.append(f"Merged numeric field '{field}'")
                
            else:
                # Complex merge - prefer more recent data
                if conflict.remote_timestamp > conflict.local_timestamp:
                    merged_data[field] = remote_val
                    merge_notes.append(f"Used remote value for '{field}' (more recent)")
                else:
                    # Keep local value
                    merge_notes.append(f"Used local value for '{field}' (more recent)")
                
                confidence -= 0.1  # Reduce confidence for complex merges
        
        return ResolutionResult(
            strategy="smart_merge",
            resolved_data=merged_data,
            confidence=max(0.0, confidence),
            resolution_notes="; ".join(merge_notes)
        )
    
    async def _request_manual_resolution(self, 
                                       conflict: ConflictData,
                                       analysis: Dict[str, Any]) -> Optional[ResolutionResult]:
        """Request manual resolution from user"""
        
        # Prepare conflict data for manual resolution
        manual_data = {
            "conflict": conflict,
            "analysis": analysis,
            "suggested_resolution": None
        }
        
        # Try to provide a suggested resolution
        if analysis["complexity_score"] <= 3:
            suggested = await self._smart_merge_resolution(conflict, analysis)
            if suggested and suggested.confidence > 0.5:
                manual_data["suggested_resolution"] = suggested
        
        # Call manual resolution callbacks
        for callback in self.manual_resolution_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback(manual_data)
                else:
                    result = callback(manual_data)
                
                if result:
                    return ResolutionResult(
                        strategy="manual_resolution",
                        resolved_data=result["resolved_data"],
                        confidence=1.0,
                        resolution_notes=result.get("notes", "Manually resolved")
                    )
                    
            except Exception as e:
                logger.error(f"Error in manual resolution callback: {e}")
        
        return None
    
    def _get_cache_key(self, conflict: ConflictData) -> str:
        """Generate cache key for conflict"""
        import hashlib
        
        # Create hash of conflict data
        conflict_str = f"{conflict.record_id}_{conflict.table}_{conflict.conflict_type.value}"
        conflict_str += json.dumps(conflict.local_data, sort_keys=True, default=str)
        conflict_str += json.dumps(conflict.remote_data, sort_keys=True, default=str)
        
        return hashlib.md5(conflict_str.encode()).hexdigest()
    
    def add_manual_resolution_callback(self, callback: Callable) -> None:
        """Add callback for manual conflict resolution"""
        self.manual_resolution_callbacks.append(callback)
    
    def remove_manual_resolution_callback(self, callback: Callable) -> None:
        """Remove manual resolution callback"""
        if callback in self.manual_resolution_callbacks:
            self.manual_resolution_callbacks.remove(callback)
    
    def set_auto_resolution_strategy(self, strategy: AutoResolutionStrategy) -> None:
        """Set automatic resolution strategy"""
        self.auto_strategy = strategy
        logger.info(f"Auto resolution strategy set to: {strategy.value}")
    
    def add_field_merge_rule(self, field_type: str, merge_function: Callable) -> None:
        """Add custom field merge rule"""
        self.field_merge_rules[field_type] = merge_function
    
    def get_resolution_stats(self) -> Dict[str, Any]:
        """Get conflict resolution statistics"""
        if not self.resolution_cache:
            return {
                "total_resolutions": 0,
                "strategies": {},
                "average_confidence": 0.0
            }
        
        strategies = {}
        total_confidence = 0.0
        
        for result in self.resolution_cache.values():
            strategy = result.strategy
            strategies[strategy] = strategies.get(strategy, 0) + 1
            total_confidence += result.confidence
        
        return {
            "total_resolutions": len(self.resolution_cache),
            "strategies": strategies,
            "average_confidence": total_confidence / len(self.resolution_cache)
        }
    
    def clear_resolution_cache(self) -> None:
        """Clear resolution cache"""
        self.resolution_cache.clear()
        logger.info("Conflict resolution cache cleared")

# Global conflict resolver instance
conflict_resolver = ConflictResolver()