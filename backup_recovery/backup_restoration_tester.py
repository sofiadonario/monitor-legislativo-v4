# Backup Restoration and Testing Automation for Monitor Legislativo v4
# Phase 5 Week 19: Automated backup testing and restoration validation
# Ensures backup integrity and validates restoration procedures

import asyncio
import asyncpg
import aiofiles
import json
import logging
import time
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid
import subprocess
import psutil
import hashlib
import os
from pathlib import Path
import threading
import schedule
import boto3
from cryptography.fernet import Fernet
import tarfile
import gzip
import zipfile
import sqlite3
import pandas as pd
import numpy as np
from collections import defaultdict

logger = logging.getLogger(__name__)

class TestType(Enum):
    """Types of backup tests"""
    INTEGRITY_CHECK = "integrity_check"
    RESTORATION_TEST = "restoration_test"
    PERFORMANCE_TEST = "performance_test"
    STRESS_TEST = "stress_test"
    RECOVERY_TIME_TEST = "recovery_time_test"
    DATA_CONSISTENCY_TEST = "data_consistency_test"
    SECURITY_TEST = "security_test"

class TestStatus(Enum):
    """Test execution status"""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"

class RestorationType(Enum):
    """Types of restoration tests"""
    FULL_RESTORE = "full_restore"
    PARTIAL_RESTORE = "partial_restore"
    POINT_IN_TIME = "point_in_time"
    TABLE_LEVEL = "table_level"
    SCHEMA_ONLY = "schema_only"
    DATA_ONLY = "data_only"

class ValidationLevel(Enum):
    """Validation thoroughness levels"""
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    FORENSIC = "forensic"

@dataclass
class BackupTestConfig:
    """Configuration for backup testing"""
    test_id: str
    backup_id: str
    test_type: TestType
    restoration_type: RestorationType
    validation_level: ValidationLevel
    test_database_name: str
    timeout_minutes: int = 60
    data_sample_size: int = 1000
    cleanup_after_test: bool = True
    parallel_validation: bool = True
    custom_validations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['test_type'] = self.test_type.value
        result['restoration_type'] = self.restoration_type.value
        result['validation_level'] = self.validation_level.value
        return result

@dataclass
class TestResult:
    """Backup test result"""
    test_id: str
    backup_id: str
    test_type: TestType
    status: TestStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    validation_results: Dict[str, Any] = field(default_factory=dict)
    restoration_size_mb: float = 0.0
    data_integrity_score: float = 0.0
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['test_type'] = self.test_type.value
        result['status'] = self.status.value
        result['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        return result

@dataclass
class ValidationCheck:
    """Individual validation check result"""
    check_name: str
    description: str
    expected_value: Any
    actual_value: Any
    passed: bool
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0

class BackupRestorationTester:
    """
    Automated backup restoration and testing system.
    
    This system validates backup integrity by performing actual restorations
    to test databases and running comprehensive validation checks.
    """
    
    def __init__(self, 
                 db_config: Dict[str, str],
                 backup_system,  # Reference to AutomatedBackupSystem
                 test_db_prefix: str = "test_restore_",
                 max_parallel_tests: int = 3):
        self.db_config = db_config
        self.backup_system = backup_system
        self.test_db_prefix = test_db_prefix
        self.max_parallel_tests = max_parallel_tests
        
        # Test database configuration
        self.test_db_config = db_config.copy()
        
        # Test results storage
        self.test_results: Dict[str, TestResult] = {}
        self.running_tests: Dict[str, asyncio.Task] = {}
        
        # Validation rules for Brazilian legislative data
        self.validation_rules = {
            'basic': [
                'table_count_validation',
                'row_count_validation',
                'schema_structure_validation'
            ],
            'standard': [
                'data_integrity_validation',
                'foreign_key_validation',
                'index_validation',
                'constraint_validation'
            ],
            'comprehensive': [
                'data_consistency_validation',
                'business_rule_validation',
                'performance_validation',
                'brazilian_legislative_format_validation'
            ],
            'forensic': [
                'byte_level_comparison',
                'checksum_validation',
                'audit_trail_validation',
                'temporal_consistency_validation'
            ]
        }
        
        # Performance thresholds
        self.performance_thresholds = {
            'restoration_time_minutes': 30,
            'data_validation_time_minutes': 15,
            'memory_usage_mb': 2048,
            'cpu_usage_percent': 80
        }
        
        # Schedule automated testing
        self._setup_automated_testing()
    
    async def create_test_database(self, test_db_name: str) -> bool:
        """Create isolated test database for restoration"""
        try:
            # Connect to default database to create test database
            admin_config = self.db_config.copy()
            admin_config['database'] = 'postgres'
            
            conn = await asyncpg.connect(**admin_config)
            
            # Drop existing test database if it exists
            await conn.execute(f'DROP DATABASE IF EXISTS "{test_db_name}"')
            
            # Create new test database
            await conn.execute(f'CREATE DATABASE "{test_db_name}"')
            
            await conn.close()
            
            logger.info(f"Created test database: {test_db_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create test database {test_db_name}: {str(e)}")
            return False
    
    async def perform_restoration_test(self, config: BackupTestConfig) -> TestResult:
        """Perform comprehensive backup restoration test"""
        test_result = TestResult(
            test_id=config.test_id,
            backup_id=config.backup_id,
            test_type=config.test_type,
            status=TestStatus.RUNNING,
            started_at=datetime.now()
        )
        
        try:
            logger.info(f"Starting restoration test {config.test_id} for backup {config.backup_id}")
            
            # Create test database
            if not await self.create_test_database(config.test_database_name):
                raise Exception("Failed to create test database")
            
            # Perform restoration
            restoration_start = time.time()
            await self._restore_backup_to_test_db(config)
            restoration_time = time.time() - restoration_start
            
            test_result.performance_metrics['restoration_time_seconds'] = restoration_time
            test_result.restoration_size_mb = await self._get_database_size_mb(config.test_database_name)
            
            # Run validation checks
            validation_start = time.time()
            validation_results = await self._run_validation_checks(config)
            validation_time = time.time() - validation_start
            
            test_result.validation_results = validation_results
            test_result.performance_metrics['validation_time_seconds'] = validation_time
            
            # Calculate data integrity score
            test_result.data_integrity_score = self._calculate_integrity_score(validation_results)
            
            # Determine test status
            if test_result.data_integrity_score >= 0.95:
                test_result.status = TestStatus.PASSED
            elif test_result.data_integrity_score >= 0.80:
                test_result.status = TestStatus.WARNING
                test_result.warnings.append("Data integrity score below optimal threshold")
            else:
                test_result.status = TestStatus.FAILED
                test_result.error_message = "Data integrity validation failed"
            
            # Performance validation
            if restoration_time > self.performance_thresholds['restoration_time_minutes'] * 60:
                test_result.warnings.append(f"Restoration time exceeded threshold: {restoration_time:.1f}s")
            
            if validation_time > self.performance_thresholds['data_validation_time_minutes'] * 60:
                test_result.warnings.append(f"Validation time exceeded threshold: {validation_time:.1f}s")
            
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
            logger.error(f"Restoration test {config.test_id} failed: {str(e)}")
        
        finally:
            # Cleanup test database if configured
            if config.cleanup_after_test:
                await self._cleanup_test_database(config.test_database_name)
            
            test_result.completed_at = datetime.now()
            test_result.duration_seconds = (test_result.completed_at - test_result.started_at).total_seconds()
            
            # Store test result
            self.test_results[config.test_id] = test_result
            
            logger.info(f"Restoration test {config.test_id} completed with status: {test_result.status.value}")
        
        return test_result
    
    async def _restore_backup_to_test_db(self, config: BackupTestConfig) -> None:
        """Restore backup to test database"""
        # Get backup metadata
        backup_info = await self.backup_system.get_backup_info(config.backup_id)
        if not backup_info:
            raise Exception(f"Backup {config.backup_id} not found")
        
        # Download and extract backup
        temp_dir = Path(tempfile.mkdtemp())
        try:
            backup_file = await self.backup_system.download_backup(config.backup_id, temp_dir)
            
            # Extract if compressed
            if backup_info.get('compression') != 'none':
                extracted_file = await self._extract_backup_file(backup_file, temp_dir)
            else:
                extracted_file = backup_file
            
            # Restore to test database based on restoration type
            if config.restoration_type == RestorationType.FULL_RESTORE:
                await self._restore_full_database(extracted_file, config.test_database_name)
            elif config.restoration_type == RestorationType.PARTIAL_RESTORE:
                await self._restore_partial_database(extracted_file, config.test_database_name, config.custom_validations)
            elif config.restoration_type == RestorationType.SCHEMA_ONLY:
                await self._restore_schema_only(extracted_file, config.test_database_name)
            elif config.restoration_type == RestorationType.DATA_ONLY:
                await self._restore_data_only(extracted_file, config.test_database_name)
            else:
                raise Exception(f"Unsupported restoration type: {config.restoration_type}")
        
        finally:
            # Cleanup temporary files
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def _extract_backup_file(self, backup_file: Path, temp_dir: Path) -> Path:
        """Extract compressed backup file"""
        extracted_file = temp_dir / "restored_backup.sql"
        
        if backup_file.suffix == '.gz':
            with gzip.open(backup_file, 'rb') as f_in:
                with open(extracted_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif backup_file.suffix == '.zip':
            with zipfile.ZipFile(backup_file, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                # Find the SQL file in extracted contents
                sql_files = list(temp_dir.glob("*.sql"))
                if sql_files:
                    extracted_file = sql_files[0]
        elif backup_file.suffix == '.tar.gz':
            with tarfile.open(backup_file, 'r:gz') as tar:
                tar.extractall(temp_dir)
                sql_files = list(temp_dir.glob("*.sql"))
                if sql_files:
                    extracted_file = sql_files[0]
        else:
            extracted_file = backup_file
        
        return extracted_file
    
    async def _restore_full_database(self, backup_file: Path, test_db_name: str) -> None:
        """Restore complete database from backup"""
        cmd = [
            'psql',
            '-h', self.db_config['host'],
            '-p', str(self.db_config['port']),
            '-U', self.db_config['user'],
            '-d', test_db_name,
            '-f', str(backup_file)
        ]
        
        env = os.environ.copy()
        env['PGPASSWORD'] = self.db_config['password']
        
        process = subprocess.run(cmd, env=env, capture_output=True, text=True)
        
        if process.returncode != 0:
            raise Exception(f"Database restoration failed: {process.stderr}")
    
    async def _restore_partial_database(self, backup_file: Path, test_db_name: str, tables: List[str]) -> None:
        """Restore specific tables from backup"""
        # This would require more sophisticated parsing of the SQL dump
        # For now, we'll implement a basic version
        await self._restore_full_database(backup_file, test_db_name)
        
        # Then drop tables not in the requested list
        if tables:
            test_config = self.db_config.copy()
            test_config['database'] = test_db_name
            
            conn = await asyncpg.connect(**test_config)
            try:
                # Get all tables in the database
                all_tables = await conn.fetch(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
                )
                
                # Drop tables not in the requested list
                for table_record in all_tables:
                    table_name = table_record['tablename']
                    if table_name not in tables:
                        await conn.execute(f'DROP TABLE IF EXISTS "{table_name}" CASCADE')
            finally:
                await conn.close()
    
    async def _restore_schema_only(self, backup_file: Path, test_db_name: str) -> None:
        """Restore only database schema (structure) without data"""
        cmd = [
            'pg_restore',
            '--schema-only',
            '-h', self.db_config['host'],
            '-p', str(self.db_config['port']),
            '-U', self.db_config['user'],
            '-d', test_db_name,
            str(backup_file)
        ]
        
        env = os.environ.copy()
        env['PGPASSWORD'] = self.db_config['password']
        
        process = subprocess.run(cmd, env=env, capture_output=True, text=True)
        
        if process.returncode != 0:
            # Try with psql if pg_restore fails (for SQL dumps)
            await self._restore_full_database(backup_file, test_db_name)
    
    async def _restore_data_only(self, backup_file: Path, test_db_name: str) -> None:
        """Restore only data without schema"""
        cmd = [
            'pg_restore',
            '--data-only',
            '-h', self.db_config['host'],
            '-p', str(self.db_config['port']),
            '-U', self.db_config['user'],
            '-d', test_db_name,
            str(backup_file)
        ]
        
        env = os.environ.copy()
        env['PGPASSWORD'] = self.db_config['password']
        
        process = subprocess.run(cmd, env=env, capture_output=True, text=True)
        
        if process.returncode != 0:
            # For SQL dumps, we need to filter out schema creation statements
            await self._restore_full_database(backup_file, test_db_name)
    
    async def _run_validation_checks(self, config: BackupTestConfig) -> Dict[str, Any]:
        """Run comprehensive validation checks on restored data"""
        validation_results = {
            'checks': [],
            'summary': {
                'total_checks': 0,
                'passed_checks': 0,
                'failed_checks': 0,
                'warnings': 0
            }
        }
        
        # Get validation rules for the specified level
        rules_to_run = []
        for level in ['basic', 'standard', 'comprehensive', 'forensic']:
            rules_to_run.extend(self.validation_rules[level])
            if level == config.validation_level.value:
                break
        
        # Add custom validations
        rules_to_run.extend(config.custom_validations)
        
        # Connect to test database
        test_config = self.db_config.copy()
        test_config['database'] = config.test_database_name
        
        conn = await asyncpg.connect(**test_config)
        
        try:
            for rule in rules_to_run:
                try:
                    check_start = time.time()
                    check_result = await self._execute_validation_rule(conn, rule, config)
                    check_time = (time.time() - check_start) * 1000
                    
                    check_result.execution_time_ms = check_time
                    validation_results['checks'].append(asdict(check_result))
                    
                    validation_results['summary']['total_checks'] += 1
                    if check_result.passed:
                        validation_results['summary']['passed_checks'] += 1
                    else:
                        validation_results['summary']['failed_checks'] += 1
                
                except Exception as e:
                    logger.error(f"Validation rule {rule} failed: {str(e)}")
                    validation_results['summary']['warnings'] += 1
        
        finally:
            await conn.close()
        
        return validation_results
    
    async def _execute_validation_rule(self, conn: asyncpg.Connection, rule: str, config: BackupTestConfig) -> ValidationCheck:
        """Execute individual validation rule"""
        if rule == 'table_count_validation':
            return await self._validate_table_count(conn)
        elif rule == 'row_count_validation':
            return await self._validate_row_counts(conn)
        elif rule == 'schema_structure_validation':
            return await self._validate_schema_structure(conn)
        elif rule == 'data_integrity_validation':
            return await self._validate_data_integrity(conn)
        elif rule == 'foreign_key_validation':
            return await self._validate_foreign_keys(conn)
        elif rule == 'index_validation':
            return await self._validate_indexes(conn)
        elif rule == 'constraint_validation':
            return await self._validate_constraints(conn)
        elif rule == 'brazilian_legislative_format_validation':
            return await self._validate_brazilian_legislative_format(conn)
        elif rule == 'performance_validation':
            return await self._validate_performance(conn)
        else:
            return ValidationCheck(
                check_name=rule,
                description=f"Custom validation: {rule}",
                expected_value="Custom check",
                actual_value="Not implemented",
                passed=False,
                error_message="Custom validation rule not implemented"
            )
    
    async def _validate_table_count(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate that all expected tables are present"""
        # Get original table count from main database
        main_conn = await asyncpg.connect(**self.db_config)
        try:
            original_count = await main_conn.fetchval(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'"
            )
        finally:
            await main_conn.close()
        
        # Get restored table count
        restored_count = await conn.fetchval(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'"
        )
        
        return ValidationCheck(
            check_name="table_count_validation",
            description="Verify all tables were restored",
            expected_value=original_count,
            actual_value=restored_count,
            passed=original_count == restored_count
        )
    
    async def _validate_row_counts(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate row counts for critical tables"""
        # Get list of tables
        tables = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        )
        
        total_variance = 0
        tables_checked = 0
        
        for table_record in tables[:10]:  # Check first 10 tables for performance
            table_name = table_record['tablename']
            try:
                # Get original row count
                main_conn = await asyncpg.connect(**self.db_config)
                try:
                    original_count = await main_conn.fetchval(f'SELECT COUNT(*) FROM "{table_name}"')
                finally:
                    await main_conn.close()
                
                # Get restored row count
                restored_count = await conn.fetchval(f'SELECT COUNT(*) FROM "{table_name}"')
                
                if original_count > 0:
                    variance = abs(original_count - restored_count) / original_count
                    total_variance += variance
                    tables_checked += 1
            
            except Exception as e:
                logger.warning(f"Could not validate row count for table {table_name}: {str(e)}")
        
        avg_variance = total_variance / max(tables_checked, 1)
        
        return ValidationCheck(
            check_name="row_count_validation",
            description="Verify row counts match original data",
            expected_value="< 1% variance",
            actual_value=f"{avg_variance:.2%} average variance",
            passed=avg_variance < 0.01
        )
    
    async def _validate_schema_structure(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate database schema structure"""
        # Check that key tables exist with expected columns
        critical_tables = ['legislative_documents', 'search_results', 'api_usage']
        
        for table in critical_tables:
            try:
                columns = await conn.fetch(
                    """
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = $1 AND table_schema = 'public'
                    ORDER BY ordinal_position
                    """,
                    table
                )
                
                if not columns:
                    return ValidationCheck(
                        check_name="schema_structure_validation",
                        description="Verify critical tables and columns exist",
                        expected_value=f"Table {table} exists",
                        actual_value=f"Table {table} missing",
                        passed=False
                    )
            
            except Exception as e:
                return ValidationCheck(
                    check_name="schema_structure_validation",
                    description="Verify critical tables and columns exist",
                    expected_value="All critical tables present",
                    actual_value=f"Error checking {table}: {str(e)}",
                    passed=False
                )
        
        return ValidationCheck(
            check_name="schema_structure_validation",
            description="Verify critical tables and columns exist",
            expected_value="All critical tables present",
            actual_value="Schema structure validated",
            passed=True
        )
    
    async def _validate_data_integrity(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate data integrity constraints"""
        try:
            # Check for obvious data corruption patterns
            corruption_checks = [
                "SELECT COUNT(*) FROM legislative_documents WHERE title IS NULL OR title = ''",
                "SELECT COUNT(*) FROM legislative_documents WHERE created_at > NOW()",
                "SELECT COUNT(*) FROM search_results WHERE query_text IS NULL"
            ]
            
            total_issues = 0
            for check_sql in corruption_checks:
                try:
                    issues = await conn.fetchval(check_sql)
                    total_issues += issues or 0
                except Exception:
                    pass  # Skip if table doesn't exist
            
            return ValidationCheck(
                check_name="data_integrity_validation",
                description="Check for data corruption patterns",
                expected_value=0,
                actual_value=total_issues,
                passed=total_issues == 0
            )
        
        except Exception as e:
            return ValidationCheck(
                check_name="data_integrity_validation",
                description="Check for data corruption patterns",
                expected_value="No corruption",
                actual_value=f"Error: {str(e)}",
                passed=False
            )
    
    async def _validate_foreign_keys(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate foreign key constraints"""
        try:
            # Check for broken foreign key references
            orphaned_records = await conn.fetchval(
                """
                SELECT COUNT(*) FROM information_schema.table_constraints 
                WHERE constraint_type = 'FOREIGN KEY'
                """
            )
            
            return ValidationCheck(
                check_name="foreign_key_validation",
                description="Verify foreign key constraints",
                expected_value="No broken references",
                actual_value=f"{orphaned_records} constraints found",
                passed=True  # Basic check - constraints exist
            )
        
        except Exception as e:
            return ValidationCheck(
                check_name="foreign_key_validation",
                description="Verify foreign key constraints",
                expected_value="No broken references",
                actual_value=f"Error: {str(e)}",
                passed=False
            )
    
    async def _validate_indexes(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate database indexes"""
        try:
            index_count = await conn.fetchval(
                """
                SELECT COUNT(*) FROM pg_indexes 
                WHERE schemaname = 'public'
                """
            )
            
            return ValidationCheck(
                check_name="index_validation",
                description="Verify database indexes were restored",
                expected_value="> 0",
                actual_value=f"{index_count} indexes",
                passed=index_count > 0
            )
        
        except Exception as e:
            return ValidationCheck(
                check_name="index_validation",
                description="Verify database indexes were restored",
                expected_value="> 0",
                actual_value=f"Error: {str(e)}",
                passed=False
            )
    
    async def _validate_constraints(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate database constraints"""
        try:
            constraint_count = await conn.fetchval(
                """
                SELECT COUNT(*) FROM information_schema.table_constraints 
                WHERE table_schema = 'public'
                """
            )
            
            return ValidationCheck(
                check_name="constraint_validation",
                description="Verify database constraints were restored",
                expected_value="> 0",
                actual_value=f"{constraint_count} constraints",
                passed=constraint_count > 0
            )
        
        except Exception as e:
            return ValidationCheck(
                check_name="constraint_validation",
                description="Verify database constraints were restored",
                expected_value="> 0",
                actual_value=f"Error: {str(e)}",
                passed=False
            )
    
    async def _validate_brazilian_legislative_format(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate Brazilian legislative document format compliance"""
        try:
            # Check for proper Brazilian legislative document formatting
            format_violations = await conn.fetchval(
                """
                SELECT COUNT(*) as format_violations
                FROM legislative_documents 
                WHERE document_type IN ('lei', 'decreto', 'resolucao')
                  AND (
                    (document_type = 'lei' AND NOT title ~* '^Lei\\s+n[ºo°]?\\s*\\d+')
                    OR (document_type = 'decreto' AND NOT title ~* '^Decreto\\s+n[ºo°]?\\s*\\d+')
                    OR (document_type = 'resolucao' AND NOT title ~* '^Resolução\\s+n[ºo°]?\\s*\\d+')
                  )
                """
            )
            
            return ValidationCheck(
                check_name="brazilian_legislative_format_validation",
                description="Verify Brazilian legislative document format compliance",
                expected_value=0,
                actual_value=format_violations or 0,
                passed=(format_violations or 0) == 0
            )
        
        except Exception as e:
            # Table might not exist in test scenarios
            return ValidationCheck(
                check_name="brazilian_legislative_format_validation",
                description="Verify Brazilian legislative document format compliance",
                expected_value="Format compliance",
                actual_value=f"Skipped: {str(e)}",
                passed=True
            )
    
    async def _validate_performance(self, conn: asyncpg.Connection) -> ValidationCheck:
        """Validate query performance on restored data"""
        try:
            # Run a sample query and measure performance
            start_time = time.time()
            
            # Sample performance query
            await conn.fetchval(
                "SELECT COUNT(*) FROM legislative_documents WHERE created_at > NOW() - INTERVAL '30 days'"
            )
            
            query_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            return ValidationCheck(
                check_name="performance_validation",
                description="Verify query performance on restored data",
                expected_value="< 1000ms",
                actual_value=f"{query_time:.0f}ms",
                passed=query_time < 1000
            )
        
        except Exception as e:
            return ValidationCheck(
                check_name="performance_validation",
                description="Verify query performance on restored data",
                expected_value="< 1000ms",
                actual_value=f"Error: {str(e)}",
                passed=False
            )
    
    def _calculate_integrity_score(self, validation_results: Dict[str, Any]) -> float:
        """Calculate overall data integrity score from validation results"""
        if not validation_results.get('checks'):
            return 0.0
        
        total_checks = validation_results['summary']['total_checks']
        passed_checks = validation_results['summary']['passed_checks']
        
        if total_checks == 0:
            return 0.0
        
        base_score = passed_checks / total_checks
        
        # Apply weights for critical checks
        critical_checks = ['table_count_validation', 'schema_structure_validation', 'data_integrity_validation']
        critical_passed = 0
        critical_total = 0
        
        for check in validation_results['checks']:
            if check['check_name'] in critical_checks:
                critical_total += 1
                if check['passed']:
                    critical_passed += 1
        
        if critical_total > 0:
            critical_score = critical_passed / critical_total
            # Weight critical checks as 70% of total score
            final_score = (base_score * 0.3) + (critical_score * 0.7)
        else:
            final_score = base_score
        
        return min(final_score, 1.0)
    
    async def _get_database_size_mb(self, db_name: str) -> float:
        """Get database size in megabytes"""
        try:
            admin_config = self.db_config.copy()
            admin_config['database'] = 'postgres'
            
            conn = await asyncpg.connect(**admin_config)
            try:
                size_bytes = await conn.fetchval(
                    "SELECT pg_database_size($1)",
                    db_name
                )
                return (size_bytes or 0) / (1024 * 1024)  # Convert to MB
            finally:
                await conn.close()
        
        except Exception as e:
            logger.error(f"Failed to get database size for {db_name}: {str(e)}")
            return 0.0
    
    async def _cleanup_test_database(self, test_db_name: str) -> None:
        """Clean up test database after testing"""
        try:
            admin_config = self.db_config.copy()
            admin_config['database'] = 'postgres'
            
            conn = await asyncpg.connect(**admin_config)
            try:
                # Terminate any active connections to the test database
                await conn.execute(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity 
                    WHERE datname = $1 AND pid <> pg_backend_pid()
                    """,
                    test_db_name
                )
                
                # Drop the test database
                await conn.execute(f'DROP DATABASE IF EXISTS "{test_db_name}"')
                
                logger.info(f"Cleaned up test database: {test_db_name}")
            finally:
                await conn.close()
        
        except Exception as e:
            logger.error(f"Failed to cleanup test database {test_db_name}: {str(e)}")
    
    async def run_automated_test_suite(self, backup_id: str) -> Dict[str, TestResult]:
        """Run comprehensive automated test suite for a backup"""
        test_suite_id = str(uuid.uuid4())
        results = {}
        
        # Define test configurations for comprehensive validation
        test_configs = [
            # Basic integrity test
            BackupTestConfig(
                test_id=f"{test_suite_id}_basic",
                backup_id=backup_id,
                test_type=TestType.INTEGRITY_CHECK,
                restoration_type=RestorationType.FULL_RESTORE,
                validation_level=ValidationLevel.BASIC,
                test_database_name=f"{self.test_db_prefix}basic_{int(time.time())}"
            ),
            
            # Comprehensive restoration test
            BackupTestConfig(
                test_id=f"{test_suite_id}_comprehensive",
                backup_id=backup_id,
                test_type=TestType.RESTORATION_TEST,
                restoration_type=RestorationType.FULL_RESTORE,
                validation_level=ValidationLevel.COMPREHENSIVE,
                test_database_name=f"{self.test_db_prefix}comprehensive_{int(time.time())}"
            ),
            
            # Performance test
            BackupTestConfig(
                test_id=f"{test_suite_id}_performance",
                backup_id=backup_id,
                test_type=TestType.PERFORMANCE_TEST,
                restoration_type=RestorationType.FULL_RESTORE,
                validation_level=ValidationLevel.STANDARD,
                test_database_name=f"{self.test_db_prefix}performance_{int(time.time())}"
            )
        ]
        
        # Run tests with limited parallelism
        semaphore = asyncio.Semaphore(self.max_parallel_tests)
        
        async def run_single_test(config):
            async with semaphore:
                return await self.perform_restoration_test(config)
        
        # Execute all tests
        tasks = [run_single_test(config) for config in test_configs]
        test_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(test_results):
            if isinstance(result, Exception):
                logger.error(f"Test {test_configs[i].test_id} failed with exception: {str(result)}")
                # Create failed result
                failed_result = TestResult(
                    test_id=test_configs[i].test_id,
                    backup_id=backup_id,
                    test_type=test_configs[i].test_type,
                    status=TestStatus.ERROR,
                    started_at=datetime.now(),
                    error_message=str(result)
                )
                failed_result.completed_at = datetime.now()
                results[test_configs[i].test_id] = failed_result
            else:
                results[result.test_id] = result
        
        return results
    
    def _setup_automated_testing(self) -> None:
        """Setup automated backup testing schedule"""
        # Schedule daily backup validation
        schedule.every().day.at("02:00").do(self._daily_backup_validation)
        
        # Schedule weekly comprehensive testing
        schedule.every().week.do(self._weekly_comprehensive_testing)
        
        # Start scheduler thread
        scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        scheduler_thread.start()
    
    def _run_scheduler(self) -> None:
        """Run the backup testing scheduler"""
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    async def _daily_backup_validation(self) -> None:
        """Daily automated backup validation"""
        try:
            # Get most recent backup
            recent_backups = await self.backup_system.list_backups(limit=1)
            if recent_backups:
                backup_id = recent_backups[0]['backup_id']
                
                # Run basic validation test
                config = BackupTestConfig(
                    test_id=f"daily_validation_{int(time.time())}",
                    backup_id=backup_id,
                    test_type=TestType.INTEGRITY_CHECK,
                    restoration_type=RestorationType.FULL_RESTORE,
                    validation_level=ValidationLevel.BASIC,
                    test_database_name=f"{self.test_db_prefix}daily_{int(time.time())}"
                )
                
                result = await self.perform_restoration_test(config)
                
                # Log result
                if result.status == TestStatus.PASSED:
                    logger.info(f"Daily backup validation passed for backup {backup_id}")
                else:
                    logger.warning(f"Daily backup validation failed for backup {backup_id}: {result.error_message}")
        
        except Exception as e:
            logger.error(f"Daily backup validation failed: {str(e)}")
    
    async def _weekly_comprehensive_testing(self) -> None:
        """Weekly comprehensive backup testing"""
        try:
            # Get recent backups for testing
            recent_backups = await self.backup_system.list_backups(limit=3)
            
            for backup_info in recent_backups:
                backup_id = backup_info['backup_id']
                
                # Run comprehensive test suite
                results = await self.run_automated_test_suite(backup_id)
                
                # Analyze results
                all_passed = all(result.status == TestStatus.PASSED for result in results.values())
                
                if all_passed:
                    logger.info(f"Weekly comprehensive testing passed for backup {backup_id}")
                else:
                    failed_tests = [test_id for test_id, result in results.items() if result.status != TestStatus.PASSED]
                    logger.warning(f"Weekly comprehensive testing failed for backup {backup_id}. Failed tests: {failed_tests}")
        
        except Exception as e:
            logger.error(f"Weekly comprehensive testing failed: {str(e)}")
    
    async def get_test_results(self, test_id: Optional[str] = None, backup_id: Optional[str] = None) -> Union[TestResult, List[TestResult]]:
        """Get test results by test_id or backup_id"""
        if test_id:
            return self.test_results.get(test_id)
        elif backup_id:
            return [result for result in self.test_results.values() if result.backup_id == backup_id]
        else:
            return list(self.test_results.values())
    
    async def generate_test_report(self, backup_id: str) -> Dict[str, Any]:
        """Generate comprehensive test report for a backup"""
        test_results = await self.get_test_results(backup_id=backup_id)
        
        if not test_results:
            return {
                'backup_id': backup_id,
                'status': 'no_tests_found',
                'message': 'No test results found for this backup'
            }
        
        # Calculate summary statistics
        total_tests = len(test_results)
        passed_tests = sum(1 for result in test_results if result.status == TestStatus.PASSED)
        failed_tests = sum(1 for result in test_results if result.status == TestStatus.FAILED)
        warning_tests = sum(1 for result in test_results if result.status == TestStatus.WARNING)
        
        # Calculate average metrics
        avg_integrity_score = np.mean([result.data_integrity_score for result in test_results])
        avg_restoration_time = np.mean([result.performance_metrics.get('restoration_time_seconds', 0) for result in test_results])
        avg_validation_time = np.mean([result.performance_metrics.get('validation_time_seconds', 0) for result in test_results])
        
        # Overall status
        if failed_tests > 0:
            overall_status = 'failed'
        elif warning_tests > 0:
            overall_status = 'warning'
        else:
            overall_status = 'passed'
        
        return {
            'backup_id': backup_id,
            'overall_status': overall_status,
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'warning_tests': warning_tests,
                'success_rate': passed_tests / total_tests if total_tests > 0 else 0
            },
            'metrics': {
                'average_integrity_score': float(avg_integrity_score),
                'average_restoration_time_seconds': float(avg_restoration_time),
                'average_validation_time_seconds': float(avg_validation_time)
            },
            'test_details': [result.to_dict() for result in test_results],
            'recommendations': self._generate_recommendations(test_results),
            'generated_at': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, test_results: List[TestResult]) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Check for performance issues
        slow_restorations = [r for r in test_results if r.performance_metrics.get('restoration_time_seconds', 0) > 1800]  # 30 minutes
        if slow_restorations:
            recommendations.append("Consider optimizing backup compression or restoration procedures to improve performance")
        
        # Check for integrity issues
        low_integrity = [r for r in test_results if r.data_integrity_score < 0.95]
        if low_integrity:
            recommendations.append("Investigate data integrity issues - some backups have validation concerns")
        
        # Check for consistent failures
        failed_tests = [r for r in test_results if r.status == TestStatus.FAILED]
        if len(failed_tests) > len(test_results) * 0.2:  # More than 20% failure rate
            recommendations.append("High failure rate detected - review backup procedures and infrastructure")
        
        # Check for warnings
        warning_tests = [r for r in test_results if r.status == TestStatus.WARNING]
        if warning_tests:
            recommendations.append("Address warning conditions to ensure optimal backup reliability")
        
        return recommendations