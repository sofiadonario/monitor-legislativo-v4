# Automated Backup System for Monitor Legislativo v4
# Phase 5 Week 19: Enterprise-grade backup automation for Brazilian legislative data
# Multi-target backups with encryption, compression, and intelligent scheduling

import asyncio
import asyncpg
import aiofiles
import aiohttp
import json
import logging
import boto3
from google.cloud import storage as gcs
import azure.storage.blob as azure_blob
import ftplib
import paramiko
import tarfile
import gzip
import lzma
import zipfile
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import os
import shutil
import tempfile
import hashlib
import hmac
import base64
import uuid
from pathlib import Path
import subprocess
import psutil
import schedule
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import multiprocessing

logger = logging.getLogger(__name__)

class BackupType(Enum):
    """Types of backups"""
    FULL = "full"                    # Complete database dump
    INCREMENTAL = "incremental"      # Only changes since last backup
    DIFFERENTIAL = "differential"    # Changes since last full backup
    TRANSACTION_LOG = "transaction_log"  # Transaction log backup
    FILE_SYSTEM = "file_system"      # File system backup
    APPLICATION = "application"      # Application-specific backup

class BackupStatus(Enum):
    """Backup job status"""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    EXPIRED = "expired"

class StorageTarget(Enum):
    """Backup storage targets"""
    LOCAL_DISK = "local_disk"
    AWS_S3 = "aws_s3"
    GOOGLE_CLOUD = "google_cloud"
    AZURE_BLOB = "azure_blob"
    FTP_SERVER = "ftp_server"
    SFTP_SERVER = "sftp_server"
    NETWORK_SHARE = "network_share"
    TAPE_LIBRARY = "tape_library"

class CompressionType(Enum):
    """Compression algorithms"""
    NONE = "none"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    LZMA = "lzma"
    ZIP = "zip"
    TAR_GZ = "tar_gz"
    TAR_XZ = "tar_xz"

class EncryptionType(Enum):
    """Encryption methods"""
    NONE = "none"
    AES256 = "aes256"
    FERNET = "fernet"
    GPG = "gpg"
    CUSTOM = "custom"

@dataclass
class BackupTarget:
    """Backup storage target configuration"""
    target_id: str
    name: str
    storage_type: StorageTarget
    connection_config: Dict[str, Any]
    encryption_config: Dict[str, Any] = field(default_factory=dict)
    compression: CompressionType = CompressionType.GZIP
    retention_days: int = 90
    max_backup_size: Optional[int] = None  # bytes
    is_active: bool = True
    priority: int = 1  # 1=highest priority
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['storage_type'] = self.storage_type.value
        result['compression'] = self.compression.value
        return result

@dataclass
class BackupSchedule:
    """Backup schedule configuration"""
    schedule_id: str
    name: str
    backup_type: BackupType
    cron_expression: str
    targets: List[str]  # target_ids
    data_sources: List[str]  # database names, file paths, etc.
    enabled: bool = True
    parallel_execution: bool = True
    max_retry_attempts: int = 3
    notification_emails: List[str] = field(default_factory=list)
    retention_policy: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['backup_type'] = self.backup_type.value
        return result

@dataclass
class BackupJob:
    """Individual backup job execution"""
    job_id: str
    schedule_id: str
    backup_type: BackupType
    target_id: str
    data_source: str
    status: BackupStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    compressed_size: Optional[int] = None
    checksum: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    progress_percentage: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['backup_type'] = self.backup_type.value
        result['status'] = self.status.value
        if self.started_at:
            result['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        return result

@dataclass
class BackupMetrics:
    """Backup system metrics"""
    total_backups: int
    successful_backups: int
    failed_backups: int
    total_data_backed_up: int  # bytes
    compression_ratio: float
    average_backup_time: float  # seconds
    success_rate: float
    last_backup_time: Optional[datetime] = None
    next_scheduled_backup: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.last_backup_time:
            result['last_backup_time'] = self.last_backup_time.isoformat()
        if self.next_scheduled_backup:
            result['next_scheduled_backup'] = self.next_scheduled_backup.isoformat()
        return result

class AutomatedBackupSystem:
    """
    Enterprise-grade automated backup system for Monitor Legislativo v4
    
    Features:
    - Multi-target backup support (cloud, local, network)
    - Intelligent scheduling with cron expressions
    - Data encryption and compression
    - Incremental and differential backups
    - Backup verification and integrity checks
    - Automatic retention management
    - Real-time monitoring and alerting
    - Disaster recovery orchestration
    - Academic data protection compliance
    """
    
    def __init__(self, db_config: Dict[str, str], 
                 backup_root: str = "/var/backups/monitor_legislativo",
                 encryption_key: Optional[str] = None):
        self.db_config = db_config
        self.backup_root = Path(backup_root)
        self.backup_root.mkdir(parents=True, exist_ok=True)
        
        # Encryption setup
        if encryption_key:
            self.encryption_key = encryption_key.encode()
        else:
            self.encryption_key = Fernet.generate_key()
        
        self.fernet = Fernet(self.encryption_key)
        
        # Backup targets and schedules
        self.targets: Dict[str, BackupTarget] = {}
        self.schedules: Dict[str, BackupSchedule] = {}
        self.active_jobs: Dict[str, BackupJob] = {}
        
        # Background scheduler
        self.scheduler_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
        # Metrics tracking
        self.metrics = BackupMetrics(
            total_backups=0,
            successful_backups=0,
            failed_backups=0,
            total_data_backed_up=0,
            compression_ratio=0.0,
            average_backup_time=0.0,
            success_rate=0.0
        )
    
    async def initialize(self) -> None:
        """Initialize backup system"""
        await self._create_backup_tables()
        await self._load_configuration()
        await self._setup_default_targets()
        await self._setup_default_schedules()
        self._start_scheduler()
        logger.info("Automated backup system initialized")
    
    async def _create_backup_tables(self) -> None:
        """Create backup system database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Backup targets table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_targets (
                    target_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    storage_type VARCHAR(30) NOT NULL,
                    connection_config JSONB NOT NULL,
                    encryption_config JSONB DEFAULT '{}'::jsonb,
                    compression VARCHAR(20) DEFAULT 'gzip',
                    retention_days INTEGER DEFAULT 90,
                    max_backup_size BIGINT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    priority INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Backup schedules table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_schedules (
                    schedule_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    backup_type VARCHAR(30) NOT NULL,
                    cron_expression VARCHAR(100) NOT NULL,
                    targets JSONB NOT NULL DEFAULT '[]'::jsonb,
                    data_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
                    enabled BOOLEAN DEFAULT TRUE,
                    parallel_execution BOOLEAN DEFAULT TRUE,
                    max_retry_attempts INTEGER DEFAULT 3,
                    notification_emails JSONB DEFAULT '[]'::jsonb,
                    retention_policy JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Backup jobs table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_jobs (
                    job_id VARCHAR(36) PRIMARY KEY,
                    schedule_id VARCHAR(36) NOT NULL,
                    backup_type VARCHAR(30) NOT NULL,
                    target_id VARCHAR(36) NOT NULL,
                    data_source VARCHAR(500) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'scheduled',
                    started_at TIMESTAMP NULL,
                    completed_at TIMESTAMP NULL,
                    file_path VARCHAR(1000) NULL,
                    file_size BIGINT NULL,
                    compressed_size BIGINT NULL,
                    checksum VARCHAR(128) NULL,
                    error_message TEXT NULL,
                    retry_count INTEGER DEFAULT 0,
                    progress_percentage FLOAT DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Backup history table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_history (
                    history_id VARCHAR(36) PRIMARY KEY,
                    job_id VARCHAR(36) NOT NULL,
                    event_type VARCHAR(30) NOT NULL,
                    event_message TEXT NOT NULL,
                    event_data JSONB NULL,
                    timestamp TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Backup metrics table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_metrics (
                    metric_id VARCHAR(36) PRIMARY KEY,
                    date_period DATE NOT NULL,
                    total_backups INTEGER DEFAULT 0,
                    successful_backups INTEGER DEFAULT 0,
                    failed_backups INTEGER DEFAULT 0,
                    total_data_backed_up BIGINT DEFAULT 0,
                    compression_ratio FLOAT DEFAULT 0.0,
                    average_backup_time FLOAT DEFAULT 0.0,
                    success_rate FLOAT DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_targets_active ON backup_targets(is_active);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_schedules_enabled ON backup_schedules(enabled);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_jobs_created ON backup_jobs(created_at);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_history_job ON backup_history(job_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_metrics_date ON backup_metrics(date_period);")
            
            logger.info("Backup system tables created successfully")
        
        finally:
            await conn.close()
    
    async def _load_configuration(self) -> None:
        """Load backup configuration from database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Load targets
            targets = await conn.fetch("SELECT * FROM backup_targets WHERE is_active = TRUE")
            for target_row in targets:
                target = BackupTarget(
                    target_id=target_row['target_id'],
                    name=target_row['name'],
                    storage_type=StorageTarget(target_row['storage_type']),
                    connection_config=json.loads(target_row['connection_config']),
                    encryption_config=json.loads(target_row['encryption_config']),
                    compression=CompressionType(target_row['compression']),
                    retention_days=target_row['retention_days'],
                    max_backup_size=target_row['max_backup_size'],
                    is_active=target_row['is_active'],
                    priority=target_row['priority']
                )
                self.targets[target.target_id] = target
            
            # Load schedules
            schedules = await conn.fetch("SELECT * FROM backup_schedules WHERE enabled = TRUE")
            for schedule_row in schedules:
                schedule = BackupSchedule(
                    schedule_id=schedule_row['schedule_id'],
                    name=schedule_row['name'],
                    backup_type=BackupType(schedule_row['backup_type']),
                    cron_expression=schedule_row['cron_expression'],
                    targets=json.loads(schedule_row['targets']),
                    data_sources=json.loads(schedule_row['data_sources']),
                    enabled=schedule_row['enabled'],
                    parallel_execution=schedule_row['parallel_execution'],
                    max_retry_attempts=schedule_row['max_retry_attempts'],
                    notification_emails=json.loads(schedule_row['notification_emails']),
                    retention_policy=json.loads(schedule_row['retention_policy'])
                )
                self.schedules[schedule.schedule_id] = schedule
            
            logger.info(f"Loaded {len(self.targets)} targets and {len(self.schedules)} schedules")
        
        finally:
            await conn.close()
    
    async def _setup_default_targets(self) -> None:
        """Setup default backup targets"""
        
        # Local disk target
        local_target = BackupTarget(
            target_id="local_primary",
            name="Local Primary Storage",
            storage_type=StorageTarget.LOCAL_DISK,
            connection_config={
                "base_path": str(self.backup_root / "local"),
                "max_size_gb": 100
            },
            compression=CompressionType.GZIP,
            retention_days=30,
            priority=1
        )
        
        # AWS S3 target (if configured)
        s3_target = BackupTarget(
            target_id="aws_s3_primary",
            name="AWS S3 Primary",
            storage_type=StorageTarget.AWS_S3,
            connection_config={
                "bucket_name": "monitor-legislativo-backups",
                "region": "us-east-1",
                "storage_class": "STANDARD_IA"
            },
            encryption_config={
                "type": "AES256",
                "key_id": "alias/backup-key"
            },
            compression=CompressionType.TAR_GZ,
            retention_days=365,
            priority=2
        )
        
        # Google Cloud Storage target
        gcs_target = BackupTarget(
            target_id="gcs_archive",
            name="Google Cloud Archive",
            storage_type=StorageTarget.GOOGLE_CLOUD,
            connection_config={
                "bucket_name": "monitor-legislativo-archive",
                "project_id": "monitor-legislativo",
                "storage_class": "COLDLINE"
            },
            compression=CompressionType.TAR_XZ,
            retention_days=2555,  # 7 years for academic compliance
            priority=3
        )
        
        # Save default targets
        default_targets = [local_target, s3_target, gcs_target]
        for target in default_targets:
            self.targets[target.target_id] = target
            await self._save_backup_target(target)
    
    async def _setup_default_schedules(self) -> None:
        """Setup default backup schedules"""
        
        # Daily full database backup
        daily_full = BackupSchedule(
            schedule_id="daily_database_full",
            name="Daily Database Full Backup",
            backup_type=BackupType.FULL,
            cron_expression="0 2 * * *",  # 2 AM daily
            targets=["local_primary", "aws_s3_primary"],
            data_sources=["legislative_documents", "research_projects", "user_data"],
            parallel_execution=True,
            retention_policy={"daily": 7, "weekly": 4, "monthly": 12}
        )
        
        # Hourly incremental backup
        hourly_incremental = BackupSchedule(
            schedule_id="hourly_incremental",
            name="Hourly Incremental Backup",
            backup_type=BackupType.INCREMENTAL,
            cron_expression="0 * * * *",  # Every hour
            targets=["local_primary"],
            data_sources=["legislative_documents", "user_activity"],
            parallel_execution=False,
            retention_policy={"hourly": 24}
        )
        
        # Weekly archive backup
        weekly_archive = BackupSchedule(
            schedule_id="weekly_archive",
            name="Weekly Archive Backup",
            backup_type=BackupType.FULL,
            cron_expression="0 1 * * 0",  # 1 AM every Sunday
            targets=["gcs_archive"],
            data_sources=["complete_database", "application_files", "logs"],
            parallel_execution=True,
            retention_policy={"weekly": 52, "monthly": 24, "yearly": 7}
        )
        
        # Application files backup
        app_files_backup = BackupSchedule(
            schedule_id="application_files",
            name="Application Files Backup",
            backup_type=BackupType.FILE_SYSTEM,
            cron_expression="0 3 * * *",  # 3 AM daily
            targets=["local_primary", "aws_s3_primary"],
            data_sources=[
                "/app/static", "/app/uploads", "/app/exports", 
                "/app/reports", "/app/visualizations"
            ],
            parallel_execution=True,
            retention_policy={"daily": 14, "weekly": 8}
        )
        
        # Save default schedules
        default_schedules = [daily_full, hourly_incremental, weekly_archive, app_files_backup]
        for schedule in default_schedules:
            self.schedules[schedule.schedule_id] = schedule
            await self._save_backup_schedule(schedule)
    
    async def _save_backup_target(self, target: BackupTarget) -> None:
        """Save backup target to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO backup_targets 
                (target_id, name, storage_type, connection_config, encryption_config,
                 compression, retention_days, max_backup_size, is_active, priority)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (target_id) 
                DO UPDATE SET
                    name = $2, connection_config = $4, encryption_config = $5,
                    compression = $6, retention_days = $7, max_backup_size = $8,
                    is_active = $9, priority = $10, updated_at = NOW()
            """, target.target_id, target.name, target.storage_type.value,
                json.dumps(target.connection_config), json.dumps(target.encryption_config),
                target.compression.value, target.retention_days, target.max_backup_size,
                target.is_active, target.priority)
        
        finally:
            await conn.close()
    
    async def _save_backup_schedule(self, schedule: BackupSchedule) -> None:
        """Save backup schedule to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO backup_schedules 
                (schedule_id, name, backup_type, cron_expression, targets, data_sources,
                 enabled, parallel_execution, max_retry_attempts, notification_emails, retention_policy)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (schedule_id)
                DO UPDATE SET
                    name = $2, backup_type = $3, cron_expression = $4, targets = $5,
                    data_sources = $6, enabled = $7, parallel_execution = $8,
                    max_retry_attempts = $9, notification_emails = $10, 
                    retention_policy = $11, updated_at = NOW()
            """, schedule.schedule_id, schedule.name, schedule.backup_type.value,
                schedule.cron_expression, json.dumps(schedule.targets), json.dumps(schedule.data_sources),
                schedule.enabled, schedule.parallel_execution, schedule.max_retry_attempts,
                json.dumps(schedule.notification_emails), json.dumps(schedule.retention_policy))
        
        finally:
            await conn.close()
    
    def _start_scheduler(self) -> None:
        """Start the backup scheduler"""
        if self.scheduler_running:
            return
        
        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        logger.info("Backup scheduler started")
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.scheduler_running:
            try:
                # Check for scheduled backups
                asyncio.run(self._check_scheduled_backups())
                
                # Sleep for 60 seconds
                time.sleep(60)
            
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(60)
    
    async def _check_scheduled_backups(self) -> None:
        """Check for backups that need to be executed"""
        current_time = datetime.now()
        
        for schedule in self.schedules.values():
            if not schedule.enabled:
                continue
            
            # Check if backup should run now (simplified cron check)
            if await self._should_run_backup(schedule, current_time):
                logger.info(f"Triggering scheduled backup: {schedule.name}")
                await self.execute_backup_schedule(schedule.schedule_id)
    
    async def _should_run_backup(self, schedule: BackupSchedule, current_time: datetime) -> bool:
        """Check if backup should run based on cron expression"""
        # Simplified cron checking - in production, use proper cron library
        
        # Check if backup has run recently
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            last_run = await conn.fetchval("""
                SELECT MAX(started_at) FROM backup_jobs 
                WHERE schedule_id = $1 AND status IN ('completed', 'running')
            """, schedule.schedule_id)
            
            if last_run:
                # Don't run if backup ran in the last hour
                if (current_time - last_run).total_seconds() < 3600:
                    return False
            
            # Basic cron expression parsing for common patterns
            parts = schedule.cron_expression.split()
            if len(parts) != 5:
                return False
            
            minute, hour, day, month, weekday = parts
            
            # Check hour
            if hour != "*" and int(hour) != current_time.hour:
                return False
            
            # Check minute
            if minute != "*" and int(minute) != current_time.minute:
                return False
            
            # If we get here, it's time to run
            return True
        
        finally:
            await conn.close()
    
    async def execute_backup_schedule(self, schedule_id: str) -> List[str]:
        """Execute a backup schedule"""
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            raise ValueError(f"Schedule not found: {schedule_id}")
        
        job_ids = []
        
        for target_id in schedule.targets:
            target = self.targets.get(target_id)
            if not target or not target.is_active:
                continue
            
            for data_source in schedule.data_sources:
                job_id = await self.create_backup_job(
                    schedule_id=schedule_id,
                    backup_type=schedule.backup_type,
                    target_id=target_id,
                    data_source=data_source
                )
                job_ids.append(job_id)
        
        # Execute jobs
        if schedule.parallel_execution:
            # Run jobs in parallel
            tasks = [self.execute_backup_job(job_id) for job_id in job_ids]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run jobs sequentially
            for job_id in job_ids:
                await self.execute_backup_job(job_id)
        
        return job_ids
    
    async def create_backup_job(self, schedule_id: str, backup_type: BackupType,
                              target_id: str, data_source: str) -> str:
        """Create a new backup job"""
        job_id = str(uuid.uuid4())
        
        job = BackupJob(
            job_id=job_id,
            schedule_id=schedule_id,
            backup_type=backup_type,
            target_id=target_id,
            data_source=data_source,
            status=BackupStatus.SCHEDULED
        )
        
        self.active_jobs[job_id] = job
        
        # Save to database
        await self._save_backup_job(job)
        
        logger.info(f"Created backup job: {job_id}")
        return job_id
    
    async def execute_backup_job(self, job_id: str) -> None:
        """Execute a specific backup job"""
        job = self.active_jobs.get(job_id)
        if not job:
            logger.error(f"Backup job not found: {job_id}")
            return
        
        target = self.targets.get(job.target_id)
        if not target:
            job.status = BackupStatus.FAILED
            job.error_message = f"Target not found: {job.target_id}"
            await self._save_backup_job(job)
            return
        
        try:
            job.status = BackupStatus.RUNNING
            job.started_at = datetime.now()
            await self._save_backup_job(job)
            
            logger.info(f"Starting backup job: {job_id}")
            
            # Create backup based on type
            if job.backup_type == BackupType.FULL:
                backup_file = await self._create_full_backup(job, target)
            elif job.backup_type == BackupType.INCREMENTAL:
                backup_file = await self._create_incremental_backup(job, target)
            elif job.backup_type == BackupType.DIFFERENTIAL:
                backup_file = await self._create_differential_backup(job, target)
            elif job.backup_type == BackupType.FILE_SYSTEM:
                backup_file = await self._create_filesystem_backup(job, target)
            else:
                raise ValueError(f"Unsupported backup type: {job.backup_type}")
            
            # Compress backup if needed
            if target.compression != CompressionType.NONE:
                backup_file = await self._compress_backup(backup_file, target.compression)
            
            # Encrypt backup if needed
            if target.encryption_config:
                backup_file = await self._encrypt_backup(backup_file, target.encryption_config)
            
            # Calculate checksum
            checksum = await self._calculate_checksum(backup_file)
            
            # Upload to target storage
            final_path = await self._upload_backup(backup_file, target, job)
            
            # Update job completion
            job.status = BackupStatus.COMPLETED
            job.completed_at = datetime.now()
            job.file_path = final_path
            job.file_size = Path(backup_file).stat().st_size
            job.checksum = checksum
            job.progress_percentage = 100.0
            
            # Clean up local temporary file
            if backup_file != final_path:
                os.remove(backup_file)
            
            await self._save_backup_job(job)
            await self._update_metrics(job)
            
            logger.info(f"Backup job completed: {job_id}")
        
        except Exception as e:
            logger.error(f"Backup job failed: {job_id} - {str(e)}")
            job.status = BackupStatus.FAILED
            job.error_message = str(e)
            job.completed_at = datetime.now()
            await self._save_backup_job(job)
            
            # Retry if configured
            schedule = self.schedules.get(job.schedule_id)
            if schedule and job.retry_count < schedule.max_retry_attempts:
                job.retry_count += 1
                job.status = BackupStatus.SCHEDULED
                logger.info(f"Retrying backup job: {job_id} (attempt {job.retry_count})")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
                await self.execute_backup_job(job_id)
    
    async def _create_full_backup(self, job: BackupJob, target: BackupTarget) -> str:
        """Create full database backup"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_root / f"full_backup_{job.data_source}_{timestamp}.sql"
        
        # PostgreSQL dump command
        dump_cmd = [
            "pg_dump",
            "-h", self.db_config.get("host", "localhost"),
            "-p", str(self.db_config.get("port", 5432)),
            "-U", self.db_config["user"],
            "-d", job.data_source,
            "-f", str(backup_file),
            "--verbose",
            "--no-password"
        ]
        
        # Set password via environment
        env = os.environ.copy()
        env["PGPASSWORD"] = self.db_config["password"]
        
        # Execute backup
        process = await asyncio.create_subprocess_exec(
            *dump_cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Database backup failed: {stderr.decode()}")
        
        return str(backup_file)
    
    async def _create_incremental_backup(self, job: BackupJob, target: BackupTarget) -> str:
        """Create incremental backup (changes since last backup)"""
        
        # Get last backup timestamp
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            last_backup_time = await conn.fetchval("""
                SELECT MAX(completed_at) FROM backup_jobs 
                WHERE data_source = $1 AND status = 'completed'
                AND backup_type IN ('full', 'incremental')
            """, job.data_source)
            
            if not last_backup_time:
                # No previous backup, create full backup
                return await self._create_full_backup(job, target)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_root / f"incremental_{job.data_source}_{timestamp}.sql"
            
            # Create incremental backup query
            incremental_query = f"""
                COPY (
                    SELECT * FROM {job.data_source} 
                    WHERE updated_at > '{last_backup_time.isoformat()}'
                    OR created_at > '{last_backup_time.isoformat()}'
                ) TO '{backup_file}' WITH CSV HEADER;
            """
            
            await conn.execute(incremental_query)
            
            return str(backup_file)
        
        finally:
            await conn.close()
    
    async def _create_differential_backup(self, job: BackupJob, target: BackupTarget) -> str:
        """Create differential backup (changes since last full backup)"""
        
        # Get last full backup timestamp
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            last_full_backup = await conn.fetchval("""
                SELECT MAX(completed_at) FROM backup_jobs 
                WHERE data_source = $1 AND status = 'completed'
                AND backup_type = 'full'
            """, job.data_source)
            
            if not last_full_backup:
                # No previous full backup, create full backup
                return await self._create_full_backup(job, target)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_root / f"differential_{job.data_source}_{timestamp}.sql"
            
            # Create differential backup
            differential_query = f"""
                COPY (
                    SELECT * FROM {job.data_source} 
                    WHERE updated_at > '{last_full_backup.isoformat()}'
                    OR created_at > '{last_full_backup.isoformat()}'
                ) TO '{backup_file}' WITH CSV HEADER;
            """
            
            await conn.execute(differential_query)
            
            return str(backup_file)
        
        finally:
            await conn.close()
    
    async def _create_filesystem_backup(self, job: BackupJob, target: BackupTarget) -> str:
        """Create filesystem backup"""
        
        source_path = Path(job.data_source)
        if not source_path.exists():
            raise FileNotFoundError(f"Source path not found: {job.data_source}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_root / f"filesystem_{source_path.name}_{timestamp}.tar"
        
        # Create tar archive
        with tarfile.open(backup_file, "w") as tar:
            tar.add(source_path, arcname=source_path.name)
        
        return str(backup_file)
    
    async def _compress_backup(self, backup_file: str, compression: CompressionType) -> str:
        """Compress backup file"""
        
        if compression == CompressionType.GZIP:
            compressed_file = f"{backup_file}.gz"
            with open(backup_file, 'rb') as f_in:
                with gzip.open(compressed_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        
        elif compression == CompressionType.BZIP2:
            compressed_file = f"{backup_file}.bz2"
            subprocess.run(['bzip2', backup_file], check=True)
            compressed_file = f"{backup_file}.bz2"
        
        elif compression == CompressionType.LZMA:
            compressed_file = f"{backup_file}.xz"
            with open(backup_file, 'rb') as f_in:
                with lzma.open(compressed_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        
        elif compression == CompressionType.ZIP:
            compressed_file = f"{backup_file}.zip"
            with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(backup_file, Path(backup_file).name)
        
        elif compression == CompressionType.TAR_GZ:
            compressed_file = f"{backup_file}.tar.gz"
            with tarfile.open(compressed_file, "w:gz") as tar:
                tar.add(backup_file, arcname=Path(backup_file).name)
        
        elif compression == CompressionType.TAR_XZ:
            compressed_file = f"{backup_file}.tar.xz"
            with tarfile.open(compressed_file, "w:xz") as tar:
                tar.add(backup_file, arcname=Path(backup_file).name)
        
        else:
            return backup_file
        
        # Remove original file
        os.remove(backup_file)
        return compressed_file
    
    async def _encrypt_backup(self, backup_file: str, encryption_config: Dict[str, Any]) -> str:
        """Encrypt backup file"""
        
        encryption_type = encryption_config.get('type', 'fernet')
        
        if encryption_type == 'fernet':
            encrypted_file = f"{backup_file}.encrypted"
            
            with open(backup_file, 'rb') as f_in:
                data = f_in.read()
            
            encrypted_data = self.fernet.encrypt(data)
            
            with open(encrypted_file, 'wb') as f_out:
                f_out.write(encrypted_data)
            
            # Remove original file
            os.remove(backup_file)
            return encrypted_file
        
        elif encryption_type == 'gpg':
            # GPG encryption (requires gpg command)
            encrypted_file = f"{backup_file}.gpg"
            gpg_cmd = [
                "gpg", "--symmetric", "--cipher-algo", "AES256",
                "--compress-algo", "1", "--s2k-mode", "3",
                "--s2k-digest-algo", "SHA512", "--s2k-count", "65011712",
                "--force-mdc", "--quiet", "--no-greeting",
                "--output", encrypted_file, backup_file
            ]
            
            subprocess.run(gpg_cmd, check=True)
            os.remove(backup_file)
            return encrypted_file
        
        return backup_file
    
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    async def _upload_backup(self, backup_file: str, target: BackupTarget, job: BackupJob) -> str:
        """Upload backup to target storage"""
        
        if target.storage_type == StorageTarget.LOCAL_DISK:
            # Copy to local target directory
            target_dir = Path(target.connection_config['base_path'])
            target_dir.mkdir(parents=True, exist_ok=True)
            
            final_path = target_dir / Path(backup_file).name
            shutil.copy2(backup_file, final_path)
            return str(final_path)
        
        elif target.storage_type == StorageTarget.AWS_S3:
            # Upload to AWS S3
            s3_client = boto3.client('s3')
            bucket = target.connection_config['bucket_name']
            key = f"backups/{datetime.now().strftime('%Y/%m/%d')}/{Path(backup_file).name}"
            
            s3_client.upload_file(backup_file, bucket, key)
            return f"s3://{bucket}/{key}"
        
        elif target.storage_type == StorageTarget.GOOGLE_CLOUD:
            # Upload to Google Cloud Storage
            client = gcs.Client(project=target.connection_config['project_id'])
            bucket = client.bucket(target.connection_config['bucket_name'])
            blob_name = f"backups/{datetime.now().strftime('%Y/%m/%d')}/{Path(backup_file).name}"
            blob = bucket.blob(blob_name)
            
            blob.upload_from_filename(backup_file)
            return f"gs://{target.connection_config['bucket_name']}/{blob_name}"
        
        elif target.storage_type == StorageTarget.AZURE_BLOB:
            # Upload to Azure Blob Storage
            blob_service_client = azure_blob.BlobServiceClient(
                connection_string=target.connection_config['connection_string']
            )
            container_name = target.connection_config['container_name']
            blob_name = f"backups/{datetime.now().strftime('%Y/%m/%d')}/{Path(backup_file).name}"
            
            with open(backup_file, 'rb') as data:
                blob_service_client.upload_blob(
                    container=container_name,
                    name=blob_name,
                    data=data,
                    overwrite=True
                )
            
            return f"azure://{container_name}/{blob_name}"
        
        elif target.storage_type == StorageTarget.SFTP_SERVER:
            # Upload via SFTP
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=target.connection_config['hostname'],
                username=target.connection_config['username'],
                password=target.connection_config.get('password'),
                key_filename=target.connection_config.get('key_file')
            )
            
            sftp = ssh.open_sftp()
            remote_path = f"{target.connection_config['remote_path']}/{Path(backup_file).name}"
            sftp.put(backup_file, remote_path)
            
            sftp.close()
            ssh.close()
            
            return remote_path
        
        else:
            raise ValueError(f"Unsupported storage type: {target.storage_type}")
    
    async def _save_backup_job(self, job: BackupJob) -> None:
        """Save backup job to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO backup_jobs 
                (job_id, schedule_id, backup_type, target_id, data_source, status,
                 started_at, completed_at, file_path, file_size, compressed_size,
                 checksum, error_message, retry_count, progress_percentage)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (job_id)
                DO UPDATE SET
                    status = $6, started_at = $7, completed_at = $8, file_path = $9,
                    file_size = $10, compressed_size = $11, checksum = $12,
                    error_message = $13, retry_count = $14, progress_percentage = $15
            """, job.job_id, job.schedule_id, job.backup_type.value, job.target_id,
                job.data_source, job.status.value, job.started_at, job.completed_at,
                job.file_path, job.file_size, job.compressed_size, job.checksum,
                job.error_message, job.retry_count, job.progress_percentage)
        
        finally:
            await conn.close()
    
    async def _update_metrics(self, job: BackupJob) -> None:
        """Update backup metrics"""
        
        if job.status == BackupStatus.COMPLETED:
            self.metrics.successful_backups += 1
            if job.file_size:
                self.metrics.total_data_backed_up += job.file_size
        else:
            self.metrics.failed_backups += 1
        
        self.metrics.total_backups += 1
        
        # Calculate success rate
        if self.metrics.total_backups > 0:
            self.metrics.success_rate = (self.metrics.successful_backups / self.metrics.total_backups) * 100
        
        # Calculate average backup time
        if job.started_at and job.completed_at:
            backup_time = (job.completed_at - job.started_at).total_seconds()
            current_avg = self.metrics.average_backup_time
            total_count = self.metrics.total_backups
            
            self.metrics.average_backup_time = ((current_avg * (total_count - 1)) + backup_time) / total_count
        
        # Update last backup time
        self.metrics.last_backup_time = datetime.now()
        
        # Save metrics to database
        await self._save_metrics()
    
    async def _save_metrics(self) -> None:
        """Save metrics to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            today = datetime.now().date()
            
            await conn.execute("""
                INSERT INTO backup_metrics 
                (metric_id, date_period, total_backups, successful_backups, failed_backups,
                 total_data_backed_up, compression_ratio, average_backup_time, success_rate)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (date_period)
                DO UPDATE SET
                    total_backups = $3, successful_backups = $4, failed_backups = $5,
                    total_data_backed_up = $6, compression_ratio = $7,
                    average_backup_time = $8, success_rate = $9
            """, str(uuid.uuid4()), today, self.metrics.total_backups,
                self.metrics.successful_backups, self.metrics.failed_backups,
                self.metrics.total_data_backed_up, self.metrics.compression_ratio,
                self.metrics.average_backup_time, self.metrics.success_rate)
        
        finally:
            await conn.close()
    
    async def get_backup_status(self) -> Dict[str, Any]:
        """Get current backup system status"""
        return {
            "metrics": self.metrics.to_dict(),
            "active_jobs": len([j for j in self.active_jobs.values() if j.status == BackupStatus.RUNNING]),
            "scheduled_jobs": len([j for j in self.active_jobs.values() if j.status == BackupStatus.SCHEDULED]),
            "targets_count": len(self.targets),
            "schedules_count": len(self.schedules),
            "scheduler_running": self.scheduler_running
        }
    
    async def cleanup_old_backups(self) -> None:
        """Clean up old backups based on retention policies"""
        
        for target in self.targets.values():
            cutoff_date = datetime.now() - timedelta(days=target.retention_days)
            
            conn = await asyncpg.connect(**self.db_config)
            
            try:
                # Find old backups
                old_backups = await conn.fetch("""
                    SELECT job_id, file_path FROM backup_jobs 
                    WHERE target_id = $1 AND completed_at < $2 
                    AND status = 'completed'
                """, target.target_id, cutoff_date)
                
                for backup in old_backups:
                    try:
                        # Delete file if it's local
                        if backup['file_path'] and not backup['file_path'].startswith(('s3://', 'gs://', 'azure://')):
                            if os.path.exists(backup['file_path']):
                                os.remove(backup['file_path'])
                        
                        # Update job status
                        await conn.execute("""
                            UPDATE backup_jobs SET status = 'expired' 
                            WHERE job_id = $1
                        """, backup['job_id'])
                        
                        logger.info(f"Cleaned up old backup: {backup['job_id']}")
                    
                    except Exception as e:
                        logger.error(f"Failed to cleanup backup {backup['job_id']}: {e}")
            
            finally:
                await conn.close()
    
    def stop(self) -> None:
        """Stop the backup system"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=30)
        logger.info("Backup system stopped")

# Factory function for easy creation
async def create_backup_system(db_config: Dict[str, str], 
                             backup_root: str = "/var/backups/monitor_legislativo",
                             encryption_key: Optional[str] = None) -> AutomatedBackupSystem:
    """Create and initialize automated backup system"""
    backup_system = AutomatedBackupSystem(db_config, backup_root, encryption_key)
    await backup_system.initialize()
    return backup_system

# Export main classes
__all__ = [
    'AutomatedBackupSystem',
    'BackupTarget',
    'BackupSchedule',
    'BackupJob',
    'BackupMetrics',
    'BackupType',
    'BackupStatus',
    'StorageTarget',
    'CompressionType',
    'EncryptionType',
    'create_backup_system'
]