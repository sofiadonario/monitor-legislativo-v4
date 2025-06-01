"""
Automated Backup Manager
Handles data backup, retention, and restoration
"""

import os
import json
import shutil
import gzip
import tarfile
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import threading
import schedule
import time

logger = logging.getLogger(__name__)

@dataclass
class BackupConfig:
    """Backup configuration"""
    backup_dir: str = "data/backups"
    retention_days: int = 30
    compression: bool = True
    encryption: bool = False
    schedule_interval: str = "daily"  # daily, hourly, weekly
    schedule_time: str = "02:00"  # HH:MM for daily backups
    max_backup_size_mb: int = 1000
    include_logs: bool = True
    include_cache: bool = False
    cloud_storage: bool = False
    cloud_provider: str = "aws"  # aws, gcp, azure
    notification_webhook: Optional[str] = None

@dataclass
class BackupMetadata:
    """Backup metadata"""
    backup_id: str
    timestamp: datetime
    size_bytes: int
    compression_ratio: float
    files_count: int
    backup_type: str
    duration_seconds: float
    checksum: str
    status: str  # success, failed, partial

class BackupManager:
    """Main backup manager"""
    
    def __init__(self, config: BackupConfig = None):
        self.config = config or BackupConfig()
        self.backup_dir = Path(self.config.backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self._scheduler_thread = None
        self._running = False
        
        # Backup handlers for different data types
        self.backup_handlers: Dict[str, Callable] = {
            'database': self._backup_database,
            'files': self._backup_files,
            'logs': self._backup_logs,
            'cache': self._backup_cache,
            'config': self._backup_config
        }
    
    def create_backup(self, backup_type: str = "full") -> BackupMetadata:
        """Create a backup"""
        start_time = time.time()
        backup_id = f"{backup_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Starting {backup_type} backup: {backup_id}")
        
        try:
            backup_path = self.backup_dir / backup_id
            backup_path.mkdir(exist_ok=True)
            
            total_size = 0
            total_files = 0
            
            # Determine what to backup based on type
            if backup_type == "full":
                handlers_to_run = list(self.backup_handlers.keys())
            elif backup_type == "data":
                handlers_to_run = ['database', 'files', 'config']
            elif backup_type == "logs":
                handlers_to_run = ['logs']
            elif backup_type == "incremental":
                handlers_to_run = self._get_incremental_handlers()
            else:
                handlers_to_run = [backup_type] if backup_type in self.backup_handlers else []
            
            # Remove handlers based on config
            if not self.config.include_logs and 'logs' in handlers_to_run:
                handlers_to_run.remove('logs')
            if not self.config.include_cache and 'cache' in handlers_to_run:
                handlers_to_run.remove('cache')
            
            # Run backup handlers
            for handler_name in handlers_to_run:
                if handler_name in self.backup_handlers:
                    try:
                        handler_result = self.backup_handlers[handler_name](backup_path)
                        total_size += handler_result.get('size_bytes', 0)
                        total_files += handler_result.get('files_count', 0)
                        logger.info(f"Completed {handler_name} backup")
                    except Exception as e:
                        logger.error(f"Failed to backup {handler_name}: {e}")
            
            # Compress backup if enabled
            if self.config.compression:
                compressed_path = self._compress_backup(backup_path)
                original_size = total_size
                total_size = compressed_path.stat().st_size
                compression_ratio = original_size / total_size if total_size > 0 else 1.0
                
                # Remove uncompressed backup
                shutil.rmtree(backup_path)
                backup_path = compressed_path
            else:
                compression_ratio = 1.0
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Create metadata
            duration = time.time() - start_time
            metadata = BackupMetadata(
                backup_id=backup_id,
                timestamp=datetime.now(),
                size_bytes=total_size,
                compression_ratio=compression_ratio,
                files_count=total_files,
                backup_type=backup_type,
                duration_seconds=duration,
                checksum=checksum,
                status="success"
            )
            
            # Save metadata
            self._save_metadata(metadata)
            
            # Clean old backups
            self._cleanup_old_backups()
            
            # Send notification
            self._send_notification(metadata)
            
            logger.info(f"Backup completed: {backup_id} ({total_size} bytes, {duration:.2f}s)")
            return metadata
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            metadata = BackupMetadata(
                backup_id=backup_id,
                timestamp=datetime.now(),
                size_bytes=0,
                compression_ratio=1.0,
                files_count=0,
                backup_type=backup_type,
                duration_seconds=time.time() - start_time,
                checksum="",
                status="failed"
            )
            self._save_metadata(metadata)
            raise
    
    def _backup_database(self, backup_path: Path) -> Dict[str, Any]:
        """Backup database data"""
        db_backup_path = backup_path / "database"
        db_backup_path.mkdir(exist_ok=True)
        
        # For SQLite databases
        sqlite_files = []
        for ext in ['*.db', '*.sqlite', '*.sqlite3']:
            sqlite_files.extend(Path('.').rglob(ext))
        
        total_size = 0
        files_count = 0
        
        for db_file in sqlite_files:
            if db_file.exists():
                dest_file = db_backup_path / db_file.name
                shutil.copy2(db_file, dest_file)
                total_size += dest_file.stat().st_size
                files_count += 1
        
        # Export data as JSON for additional safety
        try:
            # This would integrate with your actual database models
            data_export = self._export_database_to_json()
            if data_export:
                export_file = db_backup_path / "data_export.json"
                with open(export_file, 'w', encoding='utf-8') as f:
                    json.dump(data_export, f, indent=2, default=str)
                total_size += export_file.stat().st_size
                files_count += 1
        except Exception as e:
            logger.warning(f"Failed to export database to JSON: {e}")
        
        return {'size_bytes': total_size, 'files_count': files_count}
    
    def _backup_files(self, backup_path: Path) -> Dict[str, Any]:
        """Backup important files"""
        files_backup_path = backup_path / "files"
        files_backup_path.mkdir(exist_ok=True)
        
        # Define important directories to backup
        important_dirs = [
            'data/exports',
            'data/reports',
            'configs',
            'resources'
        ]
        
        total_size = 0
        files_count = 0
        
        for dir_name in important_dirs:
            source_dir = Path(dir_name)
            if source_dir.exists():
                dest_dir = files_backup_path / dir_name.replace('/', '_')
                try:
                    shutil.copytree(source_dir, dest_dir, dirs_exist_ok=True)
                    
                    # Calculate size
                    for file_path in dest_dir.rglob('*'):
                        if file_path.is_file():
                            total_size += file_path.stat().st_size
                            files_count += 1
                            
                except Exception as e:
                    logger.warning(f"Failed to backup {dir_name}: {e}")
        
        return {'size_bytes': total_size, 'files_count': files_count}
    
    def _backup_logs(self, backup_path: Path) -> Dict[str, Any]:
        """Backup log files"""
        logs_backup_path = backup_path / "logs"
        logs_backup_path.mkdir(exist_ok=True)
        
        # Find log files
        log_files = []
        for ext in ['*.log', '*.log.*']:
            log_files.extend(Path('.').rglob(ext))
        
        # Also check data/logs directory
        logs_dir = Path('data/logs')
        if logs_dir.exists():
            log_files.extend(logs_dir.rglob('*'))
        
        total_size = 0
        files_count = 0
        
        for log_file in log_files:
            if log_file.is_file():
                try:
                    dest_file = logs_backup_path / log_file.name
                    
                    # Compress large log files
                    if log_file.stat().st_size > 10 * 1024 * 1024:  # 10MB
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(f"{dest_file}.gz", 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        dest_file = f"{dest_file}.gz"
                    else:
                        shutil.copy2(log_file, dest_file)
                    
                    total_size += Path(dest_file).stat().st_size
                    files_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to backup log {log_file}: {e}")
        
        return {'size_bytes': total_size, 'files_count': files_count}
    
    def _backup_cache(self, backup_path: Path) -> Dict[str, Any]:
        """Backup cache data"""
        cache_backup_path = backup_path / "cache"
        cache_backup_path.mkdir(exist_ok=True)
        
        cache_dir = Path('data/cache')
        total_size = 0
        files_count = 0
        
        if cache_dir.exists():
            try:
                shutil.copytree(cache_dir, cache_backup_path / "cache_data", dirs_exist_ok=True)
                
                for file_path in (cache_backup_path / "cache_data").rglob('*'):
                    if file_path.is_file():
                        total_size += file_path.stat().st_size
                        files_count += 1
                        
            except Exception as e:
                logger.warning(f"Failed to backup cache: {e}")
        
        return {'size_bytes': total_size, 'files_count': files_count}
    
    def _backup_config(self, backup_path: Path) -> Dict[str, Any]:
        """Backup configuration files"""
        config_backup_path = backup_path / "config"
        config_backup_path.mkdir(exist_ok=True)
        
        # Configuration files to backup
        config_files = [
            'core/config/*.py',
            '*.json',
            '*.yaml',
            '*.yml',
            'requirements.txt',
            'setup.py',
            'Dockerfile',
            'docker-compose.yml'
        ]
        
        total_size = 0
        files_count = 0
        
        for pattern in config_files:
            for file_path in Path('.').glob(pattern):
                if file_path.is_file():
                    try:
                        dest_file = config_backup_path / file_path.name
                        shutil.copy2(file_path, dest_file)
                        total_size += dest_file.stat().st_size
                        files_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to backup config {file_path}: {e}")
        
        return {'size_bytes': total_size, 'files_count': files_count}
    
    def _export_database_to_json(self) -> Optional[Dict[str, Any]]:
        """Export database data to JSON format"""
        try:
            # This is a placeholder - integrate with your actual models
            from core.models.models import LegislativeDocument
            
            # Example export structure
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'data': {
                    'documents': [],
                    'searches': [],
                    'alerts': []
                }
            }
            
            # Add actual data export logic here
            return export_data
            
        except Exception as e:
            logger.error(f"Database export failed: {e}")
            return None
    
    def _compress_backup(self, backup_path: Path) -> Path:
        """Compress backup directory"""
        compressed_path = backup_path.with_suffix('.tar.gz')
        
        with tarfile.open(compressed_path, 'w:gz') as tar:
            tar.add(backup_path, arcname=backup_path.name)
        
        return compressed_path
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of backup"""
        import hashlib
        
        if file_path.is_dir():
            # Calculate checksum of all files in directory
            hash_sha256 = hashlib.sha256()
            for file_path in sorted(file_path.rglob('*')):
                if file_path.is_file():
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_sha256.update(chunk)
        else:
            # Calculate checksum of single file
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def _save_metadata(self, metadata: BackupMetadata):
        """Save backup metadata"""
        metadata_file = self.backup_dir / f"{metadata.backup_id}_metadata.json"
        
        with open(metadata_file, 'w') as f:
            json.dump(asdict(metadata), f, indent=2, default=str)
    
    def _cleanup_old_backups(self):
        """Remove old backups based on retention policy"""
        cutoff_date = datetime.now() - timedelta(days=self.config.retention_days)
        
        for metadata_file in self.backup_dir.glob('*_metadata.json'):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                backup_date = datetime.fromisoformat(metadata['timestamp'])
                
                if backup_date < cutoff_date:
                    # Remove backup and metadata
                    backup_id = metadata['backup_id']
                    
                    # Remove compressed backup
                    backup_file = self.backup_dir / f"{backup_id}.tar.gz"
                    if backup_file.exists():
                        backup_file.unlink()
                    
                    # Remove backup directory if exists
                    backup_dir = self.backup_dir / backup_id
                    if backup_dir.exists():
                        shutil.rmtree(backup_dir)
                    
                    # Remove metadata
                    metadata_file.unlink()
                    
                    logger.info(f"Removed old backup: {backup_id}")
                    
            except Exception as e:
                logger.warning(f"Failed to process metadata file {metadata_file}: {e}")
    
    def _get_incremental_handlers(self) -> List[str]:
        """Get handlers for incremental backup"""
        # For incremental, backup only data and config (not logs)
        return ['database', 'config']
    
    def _send_notification(self, metadata: BackupMetadata):
        """Send backup notification"""
        if not self.config.notification_webhook:
            return
        
        try:
            import requests
            
            payload = {
                'backup_id': metadata.backup_id,
                'status': metadata.status,
                'size_mb': metadata.size_bytes / (1024 * 1024),
                'duration_minutes': metadata.duration_seconds / 60,
                'timestamp': metadata.timestamp.isoformat()
            }
            
            response = requests.post(
                self.config.notification_webhook,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Backup notification sent successfully")
            else:
                logger.warning(f"Backup notification failed: {response.status_code}")
                
        except Exception as e:
            logger.warning(f"Failed to send backup notification: {e}")
    
    def restore_backup(self, backup_id: str, restore_path: str = None) -> bool:
        """Restore from backup"""
        try:
            # Find backup file
            backup_file = self.backup_dir / f"{backup_id}.tar.gz"
            if not backup_file.exists():
                backup_file = self.backup_dir / backup_id
                if not backup_file.exists():
                    logger.error(f"Backup {backup_id} not found")
                    return False
            
            restore_path = restore_path or tempfile.mkdtemp(prefix='restore_')
            restore_path = Path(restore_path)
            restore_path.mkdir(parents=True, exist_ok=True)
            
            # Extract backup
            if backup_file.suffix == '.gz':
                with tarfile.open(backup_file, 'r:gz') as tar:
                    tar.extractall(restore_path)
            else:
                shutil.copytree(backup_file, restore_path / backup_id, dirs_exist_ok=True)
            
            logger.info(f"Backup {backup_id} restored to {restore_path}")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def list_backups(self) -> List[BackupMetadata]:
        """List all available backups"""
        backups = []
        
        for metadata_file in self.backup_dir.glob('*_metadata.json'):
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                
                metadata = BackupMetadata(
                    backup_id=data['backup_id'],
                    timestamp=datetime.fromisoformat(data['timestamp']),
                    size_bytes=data['size_bytes'],
                    compression_ratio=data['compression_ratio'],
                    files_count=data['files_count'],
                    backup_type=data['backup_type'],
                    duration_seconds=data['duration_seconds'],
                    checksum=data['checksum'],
                    status=data['status']
                )
                
                backups.append(metadata)
                
            except Exception as e:
                logger.warning(f"Failed to load metadata from {metadata_file}: {e}")
        
        return sorted(backups, key=lambda x: x.timestamp, reverse=True)
    
    def start_scheduler(self):
        """Start automated backup scheduler"""
        if self._running:
            logger.warning("Backup scheduler already running")
            return
        
        self._running = True
        
        # Schedule backups based on config
        if self.config.schedule_interval == "daily":
            schedule.every().day.at(self.config.schedule_time).do(
                lambda: self.create_backup("incremental")
            )
        elif self.config.schedule_interval == "hourly":
            schedule.every().hour.do(
                lambda: self.create_backup("incremental")
            )
        elif self.config.schedule_interval == "weekly":
            schedule.every().week.at(self.config.schedule_time).do(
                lambda: self.create_backup("full")
            )
        
        # Start scheduler thread
        def run_scheduler():
            while self._running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        self._scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self._scheduler_thread.start()
        
        logger.info(f"Backup scheduler started ({self.config.schedule_interval})")
    
    def stop_scheduler(self):
        """Stop automated backup scheduler"""
        self._running = False
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        
        schedule.clear()
        logger.info("Backup scheduler stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backup statistics"""
        backups = self.list_backups()
        
        if not backups:
            return {
                'total_backups': 0,
                'total_size_mb': 0,
                'latest_backup': None,
                'success_rate': 0
            }
        
        total_size = sum(b.size_bytes for b in backups)
        successful_backups = [b for b in backups if b.status == 'success']
        
        return {
            'total_backups': len(backups),
            'total_size_mb': total_size / (1024 * 1024),
            'latest_backup': backups[0].backup_id if backups else None,
            'success_rate': len(successful_backups) / len(backups) * 100,
            'retention_days': self.config.retention_days,
            'scheduler_running': self._running
        }

# Global backup manager instance
_backup_manager: Optional[BackupManager] = None

def get_backup_manager() -> BackupManager:
    """Get global backup manager instance"""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager

def init_backup_manager(config: BackupConfig = None) -> BackupManager:
    """Initialize global backup manager"""
    global _backup_manager
    _backup_manager = BackupManager(config)
    return _backup_manager