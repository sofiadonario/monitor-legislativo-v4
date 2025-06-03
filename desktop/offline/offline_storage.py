"""
Offline Storage for Monitor Legislativo v4 Desktop App
Local data storage for offline functionality

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import sqlite3
import json
import os
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import asyncio
import aiosqlite

logger = logging.getLogger(__name__)

@dataclass
class OfflineRecord:
    """Represents a record stored offline"""
    id: str
    table: str
    data: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    synced_at: Optional[datetime] = None
    sync_version: int = 1
    is_deleted: bool = False
    local_changes: bool = False

class OfflineDatabase:
    """SQLite database for offline storage"""
    
    def __init__(self, db_path: str = "data/offline.db"):
        self.db_path = db_path
        self.connection_pool: List[aiosqlite.Connection] = []
        self.max_connections = 5
        self._lock = asyncio.Lock()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        asyncio.create_task(self._initialize_db())
    
    async def _initialize_db(self) -> None:
        """Initialize database schema"""
        async with aiosqlite.connect(self.db_path) as db:
            # Enable foreign keys
            await db.execute("PRAGMA foreign_keys = ON")
            
            # Create tables
            await db.execute("""
                CREATE TABLE IF NOT EXISTS offline_records (
                    id TEXT PRIMARY KEY,
                    table_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    synced_at TEXT,
                    sync_version INTEGER DEFAULT 1,
                    is_deleted BOOLEAN DEFAULT 0,
                    local_changes BOOLEAN DEFAULT 0
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sync_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS conflict_log (
                    id TEXT PRIMARY KEY,
                    record_id TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    conflict_type TEXT NOT NULL,
                    local_data TEXT NOT NULL,
                    remote_data TEXT NOT NULL,
                    resolution TEXT,
                    resolved_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_table_name ON offline_records(table_name)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_local_changes ON offline_records(local_changes)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sync_version ON offline_records(sync_version)")
            
            await db.commit()
            
        logger.info("Offline database initialized")
    
    async def _get_connection(self) -> aiosqlite.Connection:
        """Get database connection from pool"""
        async with self._lock:
            if self.connection_pool:
                return self.connection_pool.pop()
            else:
                return await aiosqlite.connect(self.db_path)
    
    async def _return_connection(self, conn: aiosqlite.Connection) -> None:
        """Return connection to pool"""
        async with self._lock:
            if len(self.connection_pool) < self.max_connections:
                self.connection_pool.append(conn)
            else:
                await conn.close()
    
    async def insert_record(self, record: OfflineRecord) -> bool:
        """Insert new record"""
        conn = await self._get_connection()
        
        try:
            await conn.execute("""
                INSERT OR REPLACE INTO offline_records 
                (id, table_name, data, created_at, updated_at, synced_at, 
                 sync_version, is_deleted, local_changes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.id,
                record.table,
                json.dumps(record.data),
                record.created_at.isoformat(),
                record.updated_at.isoformat(),
                record.synced_at.isoformat() if record.synced_at else None,
                record.sync_version,
                record.is_deleted,
                record.local_changes
            ))
            
            await conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error inserting record: {e}")
            return False
        finally:
            await self._return_connection(conn)
    
    async def get_record(self, record_id: str, table: str) -> Optional[OfflineRecord]:
        """Get record by ID"""
        conn = await self._get_connection()
        
        try:
            cursor = await conn.execute("""
                SELECT id, table_name, data, created_at, updated_at, synced_at,
                       sync_version, is_deleted, local_changes
                FROM offline_records 
                WHERE id = ? AND table_name = ?
            """, (record_id, table))
            
            row = await cursor.fetchone()
            if not row:
                return None
                
            return self._row_to_record(row)
            
        except Exception as e:
            logger.error(f"Error getting record: {e}")
            return None
        finally:
            await self._return_connection(conn)
    
    async def get_records(self, 
                         table: str,
                         where_clause: str = "",
                         params: tuple = (),
                         limit: Optional[int] = None) -> List[OfflineRecord]:
        """Get records with optional filtering"""
        conn = await self._get_connection()
        
        try:
            query = """
                SELECT id, table_name, data, created_at, updated_at, synced_at,
                       sync_version, is_deleted, local_changes
                FROM offline_records 
                WHERE table_name = ?
            """
            
            query_params = [table]
            
            if where_clause:
                query += f" AND {where_clause}"
                query_params.extend(params)
                
            query += " ORDER BY updated_at DESC"
            
            if limit:
                query += f" LIMIT {limit}"
            
            cursor = await conn.execute(query, query_params)
            rows = await cursor.fetchall()
            
            return [self._row_to_record(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting records: {e}")
            return []
        finally:
            await self._return_connection(conn)
    
    async def update_record(self, record: OfflineRecord) -> bool:
        """Update existing record"""
        record.updated_at = datetime.now()
        record.local_changes = True
        
        return await self.insert_record(record)
    
    async def delete_record(self, record_id: str, table: str, soft_delete: bool = True) -> bool:
        """Delete record (soft or hard delete)"""
        conn = await self._get_connection()
        
        try:
            if soft_delete:
                await conn.execute("""
                    UPDATE offline_records 
                    SET is_deleted = 1, local_changes = 1, updated_at = ?
                    WHERE id = ? AND table_name = ?
                """, (datetime.now().isoformat(), record_id, table))
            else:
                await conn.execute("""
                    DELETE FROM offline_records 
                    WHERE id = ? AND table_name = ?
                """, (record_id, table))
            
            await conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error deleting record: {e}")
            return False
        finally:
            await self._return_connection(conn)
    
    async def get_unsynced_records(self, table: Optional[str] = None) -> List[OfflineRecord]:
        """Get records that need syncing"""
        conn = await self._get_connection()
        
        try:
            query = """
                SELECT id, table_name, data, created_at, updated_at, synced_at,
                       sync_version, is_deleted, local_changes
                FROM offline_records 
                WHERE local_changes = 1
            """
            
            params = []
            if table:
                query += " AND table_name = ?"
                params.append(table)
                
            query += " ORDER BY updated_at ASC"
            
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            
            return [self._row_to_record(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting unsynced records: {e}")
            return []
        finally:
            await self._return_connection(conn)
    
    async def mark_synced(self, record_id: str, table: str, sync_version: int) -> bool:
        """Mark record as synced"""
        conn = await self._get_connection()
        
        try:
            await conn.execute("""
                UPDATE offline_records 
                SET synced_at = ?, local_changes = 0, sync_version = ?
                WHERE id = ? AND table_name = ?
            """, (datetime.now().isoformat(), sync_version, record_id, table))
            
            await conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error marking record as synced: {e}")
            return False
        finally:
            await self._return_connection(conn)
    
    async def set_metadata(self, key: str, value: Any) -> bool:
        """Set sync metadata"""
        conn = await self._get_connection()
        
        try:
            await conn.execute("""
                INSERT OR REPLACE INTO sync_metadata (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, json.dumps(value), datetime.now().isoformat()))
            
            await conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error setting metadata: {e}")
            return False
        finally:
            await self._return_connection(conn)
    
    async def get_metadata(self, key: str) -> Optional[Any]:
        """Get sync metadata"""
        conn = await self._get_connection()
        
        try:
            cursor = await conn.execute("""
                SELECT value FROM sync_metadata WHERE key = ?
            """, (key,))
            
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
            
        except Exception as e:
            logger.error(f"Error getting metadata: {e}")
            return None
        finally:
            await self._return_connection(conn)
    
    def _row_to_record(self, row) -> OfflineRecord:
        """Convert database row to OfflineRecord"""
        return OfflineRecord(
            id=row[0],
            table=row[1],
            data=json.loads(row[2]),
            created_at=datetime.fromisoformat(row[3]),
            updated_at=datetime.fromisoformat(row[4]),
            synced_at=datetime.fromisoformat(row[5]) if row[5] else None,
            sync_version=row[6],
            is_deleted=bool(row[7]),
            local_changes=bool(row[8])
        )
    
    async def close(self) -> None:
        """Close all connections"""
        async with self._lock:
            for conn in self.connection_pool:
                await conn.close()
            self.connection_pool.clear()

class OfflineFileManager:
    """Manages offline file storage"""
    
    def __init__(self, base_path: str = "data/offline_files"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # File metadata storage
        self.metadata_file = self.base_path / "file_metadata.json"
        self.metadata: Dict[str, Dict[str, Any]] = {}
        self._load_metadata()
    
    def _load_metadata(self) -> None:
        """Load file metadata"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.error(f"Error loading file metadata: {e}")
                self.metadata = {}
    
    def _save_metadata(self) -> None:
        """Save file metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving file metadata: {e}")
    
    async def store_file(self, 
                        file_id: str,
                        content: bytes,
                        original_path: str,
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Store file offline"""
        try:
            # Create subdirectory based on file hash
            file_hash = hashlib.md5(file_id.encode()).hexdigest()
            subdir = self.base_path / file_hash[:2]
            subdir.mkdir(exist_ok=True)
            
            # Store file
            file_path = subdir / f"{file_hash}.data"
            
            with open(file_path, 'wb') as f:
                f.write(content)
            
            # Store metadata
            self.metadata[file_id] = {
                "original_path": original_path,
                "stored_path": str(file_path),
                "size": len(content),
                "hash": file_hash,
                "created_at": datetime.now().isoformat(),
                "metadata": metadata or {}
            }
            
            self._save_metadata()
            
            logger.info(f"Stored file offline: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing file {file_id}: {e}")
            return False
    
    async def get_file(self, file_id: str) -> Optional[bytes]:
        """Retrieve file content"""
        if file_id not in self.metadata:
            return None
            
        try:
            stored_path = self.metadata[file_id]["stored_path"]
            
            with open(stored_path, 'rb') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Error retrieving file {file_id}: {e}")
            return None
    
    async def delete_file(self, file_id: str) -> bool:
        """Delete stored file"""
        if file_id not in self.metadata:
            return False
            
        try:
            stored_path = self.metadata[file_id]["stored_path"]
            
            # Delete file
            if os.path.exists(stored_path):
                os.remove(stored_path)
            
            # Remove metadata
            del self.metadata[file_id]
            self._save_metadata()
            
            logger.info(f"Deleted offline file: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file {file_id}: {e}")
            return False
    
    def list_files(self) -> List[Dict[str, Any]]:
        """List all stored files"""
        files = []
        
        for file_id, meta in self.metadata.items():
            files.append({
                "file_id": file_id,
                "original_path": meta["original_path"],
                "size": meta["size"],
                "created_at": meta["created_at"],
                "metadata": meta.get("metadata", {})
            })
            
        return sorted(files, key=lambda x: x["created_at"], reverse=True)
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        total_size = 0
        file_count = len(self.metadata)
        
        for meta in self.metadata.values():
            total_size += meta.get("size", 0)
        
        return {
            "file_count": file_count,
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "storage_path": str(self.base_path)
        }

class OfflineStorage:
    """Main offline storage interface"""
    
    def __init__(self, db_path: str = "data/offline.db", files_path: str = "data/offline_files"):
        self.database = OfflineDatabase(db_path)
        self.file_manager = OfflineFileManager(files_path)
    
    async def store_proposition(self, proposition: Dict[str, Any]) -> bool:
        """Store proposition offline"""
        record = OfflineRecord(
            id=str(proposition["id"]),
            table="propositions",
            data=proposition,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            local_changes=True
        )
        
        return await self.database.insert_record(record)
    
    async def get_propositions(self, 
                              limit: Optional[int] = None,
                              search_query: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get propositions from offline storage"""
        where_clause = ""
        params = ()
        
        if search_query:
            where_clause = "json_extract(data, '$.title') LIKE ? OR json_extract(data, '$.summary') LIKE ?"
            params = (f"%{search_query}%", f"%{search_query}%")
        
        records = await self.database.get_records("propositions", where_clause, params, limit)
        
        return [record.data for record in records if not record.is_deleted]
    
    async def update_proposition(self, proposition_id: str, updates: Dict[str, Any]) -> bool:
        """Update proposition offline"""
        record = await self.database.get_record(proposition_id, "propositions")
        if not record:
            return False
        
        # Merge updates
        record.data.update(updates)
        
        return await self.database.update_record(record)
    
    async def store_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """Store user preferences offline"""
        record = OfflineRecord(
            id=user_id,
            table="user_preferences",
            data=preferences,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            local_changes=True
        )
        
        return await self.database.insert_record(record)
    
    async def get_user_preferences(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user preferences from offline storage"""
        record = await self.database.get_record(user_id, "user_preferences")
        return record.data if record and not record.is_deleted else None
    
    async def store_search_history(self, user_id: str, query: str, results_count: int) -> bool:
        """Store search history offline"""
        search_id = hashlib.md5(f"{user_id}_{query}_{datetime.now().timestamp()}".encode()).hexdigest()
        
        record = OfflineRecord(
            id=search_id,
            table="search_history",
            data={
                "user_id": user_id,
                "query": query,
                "results_count": results_count,
                "timestamp": datetime.now().isoformat()
            },
            created_at=datetime.now(),
            updated_at=datetime.now(),
            local_changes=True
        )
        
        return await self.database.insert_record(record)
    
    async def get_search_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get search history from offline storage"""
        where_clause = "json_extract(data, '$.user_id') = ?"
        params = (user_id,)
        
        records = await self.database.get_records("search_history", where_clause, params, limit)
        
        return [record.data for record in records if not record.is_deleted]
    
    async def get_sync_status(self) -> Dict[str, Any]:
        """Get synchronization status"""
        unsynced_records = await self.database.get_unsynced_records()
        
        last_sync = await self.database.get_metadata("last_sync_time")
        
        return {
            "unsynced_count": len(unsynced_records),
            "unsynced_by_table": self._group_by_table(unsynced_records),
            "last_sync": last_sync,
            "database_size": await self._get_db_size(),
            "file_storage": self.file_manager.get_storage_stats()
        }
    
    def _group_by_table(self, records: List[OfflineRecord]) -> Dict[str, int]:
        """Group records by table"""
        groups = {}
        for record in records:
            table = record.table
            groups[table] = groups.get(table, 0) + 1
        return groups
    
    async def _get_db_size(self) -> int:
        """Get database file size"""
        try:
            return os.path.getsize(self.database.db_path)
        except:
            return 0
    
    async def cleanup_old_data(self, days_old: int = 30) -> Dict[str, int]:
        """Clean up old data"""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        # This is a simplified cleanup - in production, implement more sophisticated logic
        logger.info(f"Would clean up data older than {cutoff_date}")
        
        return {
            "deleted_records": 0,
            "deleted_files": 0,
            "freed_space_mb": 0
        }
    
    async def close(self) -> None:
        """Close storage connections"""
        await self.database.close()

# Global offline storage instance
offline_storage = OfflineStorage()