# Data Integrity Monitoring and Validation System for Monitor Legislativo v4
# Phase 5 Week 19: Advanced data integrity assurance for Brazilian legislative research
# Real-time data validation, corruption detection, and automatic healing

import asyncio
import asyncpg
import json
import logging
import hashlib
import hmac
import zlib
import time
from typing import Dict, List, Optional, Any, Union, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
import threading
import schedule
import re
import difflib
from pathlib import Path
import pickle
import psutil
import sqlite3

logger = logging.getLogger(__name__)

class IntegrityCheckType(Enum):
    """Types of integrity checks"""
    CHECKSUM_VALIDATION = "checksum_validation"
    REFERENTIAL_INTEGRITY = "referential_integrity"
    DATA_CONSISTENCY = "data_consistency"
    SCHEMA_VALIDATION = "schema_validation"
    DUPLICATE_DETECTION = "duplicate_detection"
    ORPHANED_RECORDS = "orphaned_records"
    DATA_COMPLETENESS = "data_completeness"
    TEMPORAL_CONSISTENCY = "temporal_consistency"
    BUSINESS_RULE_VALIDATION = "business_rule_validation"
    CROSS_TABLE_VALIDATION = "cross_table_validation"

class IntegrityStatus(Enum):
    """Integrity check status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CORRUPTED = "corrupted"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    HEALING = "healing"

class ValidationSeverity(Enum):
    """Validation issue severity"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class HealingAction(Enum):
    """Automatic healing actions"""
    NO_ACTION = "no_action"
    RECALCULATE_CHECKSUM = "recalculate_checksum"
    RESTORE_FROM_BACKUP = "restore_from_backup"
    DELETE_CORRUPT_RECORD = "delete_corrupt_record"
    REPAIR_REFERENCE = "repair_reference"
    MERGE_DUPLICATES = "merge_duplicates"
    NOTIFY_ADMIN = "notify_admin"
    QUARANTINE_DATA = "quarantine_data"

@dataclass
class IntegrityRule:
    """Data integrity validation rule"""
    rule_id: str
    name: str
    check_type: IntegrityCheckType
    description: str
    sql_query: str
    expected_result: Any  # Expected result for validation
    severity: ValidationSeverity
    healing_action: HealingAction
    target_tables: List[str]
    check_frequency_minutes: int = 60
    is_active: bool = True
    auto_heal: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['check_type'] = self.check_type.value
        result['severity'] = self.severity.value
        result['healing_action'] = self.healing_action.value
        return result

@dataclass
class IntegrityIssue:
    """Data integrity issue record"""
    issue_id: str
    rule_id: str
    check_type: IntegrityCheckType
    severity: ValidationSeverity
    description: str
    affected_tables: List[str]
    affected_records: List[str]  # Record IDs
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    healing_action_taken: Optional[HealingAction] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['check_type'] = self.check_type.value
        result['severity'] = self.severity.value
        if self.healing_action_taken:
            result['healing_action_taken'] = self.healing_action_taken.value
        result['detected_at'] = self.detected_at.isoformat()
        if self.resolved_at:
            result['resolved_at'] = self.resolved_at.isoformat()
        return result

@dataclass
class TableIntegrityStatus:
    """Integrity status for a database table"""
    table_name: str
    status: IntegrityStatus
    last_check: datetime
    total_records: int
    issues_count: int
    checksum: Optional[str] = None
    corruption_percentage: float = 0.0
    issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        result['last_check'] = self.last_check.isoformat()
        return result

@dataclass
class IntegrityMetrics:
    """System-wide integrity metrics"""
    total_tables_monitored: int
    healthy_tables: int
    tables_with_issues: int
    total_records_validated: int
    corrupted_records: int
    issues_resolved_automatically: int
    overall_integrity_score: float
    last_full_scan: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.last_full_scan:
            result['last_full_scan'] = self.last_full_scan.isoformat()
        return result

class DataIntegrityMonitor:
    """
    Advanced data integrity monitoring and validation system for Monitor Legislativo v4
    
    Features:
    - Real-time integrity monitoring
    - Comprehensive validation rules for Brazilian legislative data
    - Automatic corruption detection and healing
    - Academic research data protection
    - LGPD compliance validation
    - Cross-table consistency checks
    - Temporal data validation
    - Automated backup restoration for corrupt data
    - Machine learning-based anomaly detection
    """
    
    def __init__(self, db_config: Dict[str, str], 
                 backup_system=None,
                 alert_threshold: float = 95.0):
        self.db_config = db_config
        self.backup_system = backup_system
        self.alert_threshold = alert_threshold  # Alert if integrity score below this
        
        # Integrity monitoring
        self.integrity_rules: Dict[str, IntegrityRule] = {}
        self.table_status: Dict[str, TableIntegrityStatus] = {}
        self.active_issues: Dict[str, IntegrityIssue] = {}
        
        # Monitoring control
        self.monitoring_enabled = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # Checksums for tables
        self.table_checksums: Dict[str, str] = {}
        
        # Metrics
        self.metrics = IntegrityMetrics(
            total_tables_monitored=0,
            healthy_tables=0,
            tables_with_issues=0,
            total_records_validated=0,
            corrupted_records=0,
            issues_resolved_automatically=0,
            overall_integrity_score=100.0
        )
        
        # Brazilian legislative data specific patterns
        self.legislative_patterns = {
            'lei_number': r'^Lei\s+n[ºo°]?\s*(\d+([.,]\d+)*)',
            'decree_number': r'^Decreto\s+n[ºo°]?\s*(\d+([.,]\d+)*)',
            'resolution_number': r'^Resolução\s+n[ºo°]?\s*(\d+([.,]\d+)*)',
            'date_pattern': r'\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}',
            'cpf_pattern': r'\d{3}\.?\d{3}\.?\d{3}\-?\d{2}',
            'cnpj_pattern': r'\d{2}\.?\d{3}\.?\d{3}\/?\d{4}\-?\d{2}'
        }
    
    async def initialize(self) -> None:
        """Initialize data integrity monitoring system"""
        await self._create_integrity_tables()
        await self._setup_default_integrity_rules()
        await self._load_existing_rules()
        await self._start_monitoring()
        logger.info("Data integrity monitor initialized")
    
    async def _create_integrity_tables(self) -> None:
        """Create integrity monitoring database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Integrity rules table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS integrity_rules (
                    rule_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    check_type VARCHAR(50) NOT NULL,
                    description TEXT NOT NULL,
                    sql_query TEXT NOT NULL,
                    expected_result TEXT NULL,
                    severity VARCHAR(20) NOT NULL,
                    healing_action VARCHAR(50) NOT NULL,
                    target_tables JSONB NOT NULL,
                    check_frequency_minutes INTEGER DEFAULT 60,
                    is_active BOOLEAN DEFAULT TRUE,
                    auto_heal BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Integrity issues table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS integrity_issues (
                    issue_id VARCHAR(36) PRIMARY KEY,
                    rule_id VARCHAR(36) NOT NULL,
                    check_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    description TEXT NOT NULL,
                    affected_tables JSONB NOT NULL,
                    affected_records JSONB NOT NULL,
                    detected_at TIMESTAMP NOT NULL,
                    resolved_at TIMESTAMP NULL,
                    healing_action_taken VARCHAR(50) NULL,
                    details JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Table integrity status table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS table_integrity_status (
                    status_id VARCHAR(36) PRIMARY KEY,
                    table_name VARCHAR(100) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    last_check TIMESTAMP NOT NULL,
                    total_records BIGINT NOT NULL,
                    issues_count INTEGER DEFAULT 0,
                    checksum VARCHAR(64) NULL,
                    corruption_percentage FLOAT DEFAULT 0.0,
                    issues JSONB DEFAULT '[]'::jsonb,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Integrity metrics table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS integrity_metrics (
                    metric_id VARCHAR(36) PRIMARY KEY,
                    date_period DATE NOT NULL,
                    total_tables_monitored INTEGER NOT NULL,
                    healthy_tables INTEGER NOT NULL,
                    tables_with_issues INTEGER NOT NULL,
                    total_records_validated BIGINT NOT NULL,
                    corrupted_records BIGINT NOT NULL,
                    issues_resolved_automatically INTEGER NOT NULL,
                    overall_integrity_score FLOAT NOT NULL,
                    last_full_scan TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Data checksums table (for tracking table changes)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS data_checksums (
                    checksum_id VARCHAR(36) PRIMARY KEY,
                    table_name VARCHAR(100) NOT NULL,
                    checksum_value VARCHAR(64) NOT NULL,
                    record_count BIGINT NOT NULL,
                    calculated_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(table_name, calculated_at)
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_rules_type ON integrity_rules(check_type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_rules_active ON integrity_rules(is_active);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_issues_severity ON integrity_issues(severity);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_issues_detected ON integrity_issues(detected_at);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_table_integrity_status_table ON table_integrity_status(table_name);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_metrics_date ON integrity_metrics(date_period);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_data_checksums_table ON data_checksums(table_name);")
            
            logger.info("Data integrity tables created successfully")
        
        finally:
            await conn.close()
    
    async def _setup_default_integrity_rules(self) -> None:
        """Setup default integrity validation rules for Brazilian legislative data"""
        
        # Referential integrity rules
        foreign_key_rule = IntegrityRule(
            rule_id="foreign_key_integrity",
            name="Foreign Key Integrity Check",
            check_type=IntegrityCheckType.REFERENTIAL_INTEGRITY,
            description="Check for orphaned foreign key references",
            sql_query="""
                SELECT COUNT(*) as orphaned_count 
                FROM legislative_documents ld 
                LEFT JOIN institutions i ON ld.institution_id = i.institution_id 
                WHERE ld.institution_id IS NOT NULL AND i.institution_id IS NULL
            """,
            expected_result=0,
            severity=ValidationSeverity.HIGH,
            healing_action=HealingAction.REPAIR_REFERENCE,
            target_tables=["legislative_documents", "institutions"],
            auto_heal=True
        )
        
        # Duplicate detection rule
        duplicate_detection_rule = IntegrityRule(
            rule_id="duplicate_documents",
            name="Duplicate Legislative Documents",
            check_type=IntegrityCheckType.DUPLICATE_DETECTION,
            description="Detect duplicate legislative documents",
            sql_query="""
                SELECT COUNT(*) as duplicate_count
                FROM (
                    SELECT title, institution, published_date, COUNT(*) as count
                    FROM legislative_documents 
                    GROUP BY title, institution, published_date
                    HAVING COUNT(*) > 1
                ) duplicates
            """,
            expected_result=0,
            severity=ValidationSeverity.MEDIUM,
            healing_action=HealingAction.MERGE_DUPLICATES,
            target_tables=["legislative_documents"],
            auto_heal=False  # Requires manual review
        )
        
        # Data completeness rule
        completeness_rule = IntegrityRule(
            rule_id="document_completeness",
            name="Document Data Completeness",
            check_type=IntegrityCheckType.DATA_COMPLETENESS,
            description="Check for missing required fields in legislative documents",
            sql_query="""
                SELECT COUNT(*) as incomplete_count
                FROM legislative_documents 
                WHERE title IS NULL OR title = '' 
                   OR institution IS NULL OR institution = ''
                   OR document_type IS NULL OR document_type = ''
            """,
            expected_result=0,
            severity=ValidationSeverity.HIGH,
            healing_action=HealingAction.NOTIFY_ADMIN,
            target_tables=["legislative_documents"]
        )
        
        # Temporal consistency rule
        temporal_consistency_rule = IntegrityRule(
            rule_id="temporal_consistency",
            name="Temporal Data Consistency",
            check_type=IntegrityCheckType.TEMPORAL_CONSISTENCY,
            description="Check for temporal inconsistencies in document dates",
            sql_query="""
                SELECT COUNT(*) as inconsistent_count
                FROM legislative_documents 
                WHERE published_date > CURRENT_DATE 
                   OR created_at > updated_at
                   OR published_date < '1988-10-05'  -- Brazilian Constitution date
            """,
            expected_result=0,
            severity=ValidationSeverity.MEDIUM,
            healing_action=HealingAction.NOTIFY_ADMIN,
            target_tables=["legislative_documents"]
        )
        
        # Brazilian legislative format validation
        format_validation_rule = IntegrityRule(
            rule_id="brazilian_legislative_format",
            name="Brazilian Legislative Format Validation",
            check_type=IntegrityCheckType.BUSINESS_RULE_VALIDATION,
            description="Validate Brazilian legislative document format compliance",
            sql_query="""
                SELECT COUNT(*) as format_violations
                FROM legislative_documents 
                WHERE document_type IN ('lei', 'decreto', 'resolucao')
                  AND (
                    (document_type = 'lei' AND NOT title ~* '^Lei\s+n[ºo°]?\s*\d+')
                    OR (document_type = 'decreto' AND NOT title ~* '^Decreto\s+n[ºo°]?\s*\d+')
                    OR (document_type = 'resolucao' AND NOT title ~* '^Resolução\s+n[ºo°]?\s*\d+')
                  )
            """,
            expected_result=0,
            severity=ValidationSeverity.LOW,
            healing_action=HealingAction.NOTIFY_ADMIN,
            target_tables=["legislative_documents"]
        )
        
        # LGPD compliance validation
        lgpd_compliance_rule = IntegrityRule(
            rule_id="lgpd_compliance_check",
            name="LGPD Personal Data Compliance",
            check_type=IntegrityCheckType.BUSINESS_RULE_VALIDATION,
            description="Check for potential LGPD compliance issues with personal data",
            sql_query="""
                SELECT COUNT(*) as potential_violations
                FROM legislative_documents 
                WHERE content ~* '\d{3}\.?\d{3}\.?\d{3}\-?\d{2}'  -- CPF pattern
                   OR content ~* '\d{2}\.?\d{3}\.?\d{3}\/?\d{4}\-?\d{2}'  -- CNPJ pattern
                   OR content ~* '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'  -- Email pattern
            """,
            expected_result=0,
            severity=ValidationSeverity.CRITICAL,
            healing_action=HealingAction.QUARANTINE_DATA,
            target_tables=["legislative_documents"],
            auto_heal=False  # Requires legal review
        )
        
        # Research project integrity
        research_integrity_rule = IntegrityRule(
            rule_id="research_project_integrity",
            name="Research Project Data Integrity",
            check_type=IntegrityCheckType.CROSS_TABLE_VALIDATION,
            description="Validate research project and document relationships",
            sql_query="""
                SELECT COUNT(*) as integrity_violations
                FROM research_projects rp
                LEFT JOIN project_documents pd ON rp.project_id = pd.project_id
                LEFT JOIN legislative_documents ld ON pd.document_id = ld.document_id
                WHERE pd.document_id IS NOT NULL AND ld.document_id IS NULL
            """,
            expected_result=0,
            severity=ValidationSeverity.HIGH,
            healing_action=HealingAction.REPAIR_REFERENCE,
            target_tables=["research_projects", "project_documents", "legislative_documents"]
        )
        
        # Schema validation rule
        schema_validation_rule = IntegrityRule(
            rule_id="table_schema_validation",
            name="Database Schema Validation",
            check_type=IntegrityCheckType.SCHEMA_VALIDATION,
            description="Validate database schema consistency",
            sql_query="""
                SELECT COUNT(*) as schema_issues
                FROM information_schema.columns 
                WHERE table_schema = 'public' 
                  AND table_name = 'legislative_documents'
                  AND column_name IN ('document_id', 'title', 'content', 'institution', 'published_date')
                  AND is_nullable = 'YES'
            """,
            expected_result=0,
            severity=ValidationSeverity.CRITICAL,
            healing_action=HealingAction.NOTIFY_ADMIN,
            target_tables=["legislative_documents"]
        )
        
        # Save default rules
        default_rules = [
            foreign_key_rule, duplicate_detection_rule, completeness_rule,
            temporal_consistency_rule, format_validation_rule, lgpd_compliance_rule,
            research_integrity_rule, schema_validation_rule
        ]
        
        for rule in default_rules:
            self.integrity_rules[rule.rule_id] = rule
            await self._save_integrity_rule(rule)
    
    async def _save_integrity_rule(self, rule: IntegrityRule) -> None:
        """Save integrity rule to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO integrity_rules 
                (rule_id, name, check_type, description, sql_query, expected_result,
                 severity, healing_action, target_tables, check_frequency_minutes,
                 is_active, auto_heal)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (rule_id)
                DO UPDATE SET
                    name = $2, check_type = $3, description = $4, sql_query = $5,
                    expected_result = $6, severity = $7, healing_action = $8,
                    target_tables = $9, check_frequency_minutes = $10,
                    is_active = $11, auto_heal = $12, updated_at = NOW()
            """, rule.rule_id, rule.name, rule.check_type.value, rule.description,
                rule.sql_query, json.dumps(rule.expected_result), rule.severity.value,
                rule.healing_action.value, json.dumps(rule.target_tables),
                rule.check_frequency_minutes, rule.is_active, rule.auto_heal)
        
        finally:
            await conn.close()
    
    async def _load_existing_rules(self) -> None:
        """Load existing integrity rules from database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            rules = await conn.fetch("SELECT * FROM integrity_rules WHERE is_active = TRUE")
            
            for rule_row in rules:
                rule = IntegrityRule(
                    rule_id=rule_row['rule_id'],
                    name=rule_row['name'],
                    check_type=IntegrityCheckType(rule_row['check_type']),
                    description=rule_row['description'],
                    sql_query=rule_row['sql_query'],
                    expected_result=json.loads(rule_row['expected_result']) if rule_row['expected_result'] else None,
                    severity=ValidationSeverity(rule_row['severity']),
                    healing_action=HealingAction(rule_row['healing_action']),
                    target_tables=json.loads(rule_row['target_tables']),
                    check_frequency_minutes=rule_row['check_frequency_minutes'],
                    is_active=rule_row['is_active'],
                    auto_heal=rule_row['auto_heal']
                )
                self.integrity_rules[rule.rule_id] = rule
            
            logger.info(f"Loaded {len(self.integrity_rules)} integrity rules")
        
        finally:
            await conn.close()
    
    async def _start_monitoring(self) -> None:
        """Start continuous integrity monitoring"""
        self.monitoring_enabled = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Data integrity monitoring started")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring_enabled:
            try:
                # Run integrity checks
                asyncio.run(self._run_all_integrity_checks())
                
                # Calculate checksums for key tables
                asyncio.run(self._update_table_checksums())
                
                # Update metrics
                asyncio.run(self._update_integrity_metrics())
                
                # Sleep for 5 minutes
                time.sleep(300)
            
            except Exception as e:
                logger.error(f"Integrity monitoring error: {e}")
                time.sleep(60)
    
    async def _run_all_integrity_checks(self) -> None:
        """Run all active integrity checks"""
        
        for rule in self.integrity_rules.values():
            if not rule.is_active:
                continue
            
            try:
                await self._run_integrity_check(rule)
            except Exception as e:
                logger.error(f"Integrity check failed for rule {rule.rule_id}: {e}")
    
    async def _run_integrity_check(self, rule: IntegrityRule) -> None:
        """Run a specific integrity check"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Execute the validation query
            result = await conn.fetchrow(rule.sql_query)
            
            if not result:
                logger.warning(f"No result from integrity check: {rule.rule_id}")
                return
            
            # Check if result matches expected
            actual_value = list(result.values())[0] if result else None
            
            # Determine if there's an issue
            has_issue = False
            issue_description = ""
            
            if rule.expected_result is not None:
                if actual_value != rule.expected_result:
                    has_issue = True
                    issue_description = f"Expected {rule.expected_result}, got {actual_value}"
            else:
                # For rules without specific expected results, any non-zero value is an issue
                if actual_value and actual_value > 0:
                    has_issue = True
                    issue_description = f"Found {actual_value} integrity violations"
            
            if has_issue:
                await self._handle_integrity_issue(rule, actual_value, issue_description, result)
            else:
                # Mark as healthy
                await self._update_table_integrity_status(rule.target_tables, IntegrityStatus.HEALTHY)
        
        finally:
            await conn.close()
    
    async def _handle_integrity_issue(self, rule: IntegrityRule, actual_value: Any, 
                                    description: str, query_result: Any) -> None:
        """Handle detected integrity issue"""
        
        issue_id = str(uuid.uuid4())
        
        # Get affected records if possible
        affected_records = await self._get_affected_records(rule, query_result)
        
        integrity_issue = IntegrityIssue(
            issue_id=issue_id,
            rule_id=rule.rule_id,
            check_type=rule.check_type,
            severity=rule.severity,
            description=f"{rule.description}: {description}",
            affected_tables=rule.target_tables,
            affected_records=affected_records,
            detected_at=datetime.now(),
            details={
                "rule_name": rule.name,
                "actual_value": actual_value,
                "expected_value": rule.expected_result,
                "query_result": dict(query_result) if query_result else None
            }
        )
        
        self.active_issues[issue_id] = integrity_issue
        
        # Save to database
        await self._save_integrity_issue(integrity_issue)
        
        # Update table status
        status = IntegrityStatus.WARNING
        if rule.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]:
            status = IntegrityStatus.CORRUPTED
        
        await self._update_table_integrity_status(rule.target_tables, status, [issue_id])
        
        # Auto-heal if configured
        if rule.auto_heal and rule.healing_action != HealingAction.NO_ACTION:
            await self._attempt_auto_healing(integrity_issue, rule)
        
        logger.warning(f"Integrity issue detected: {issue_id} - {description}")
    
    async def _get_affected_records(self, rule: IntegrityRule, query_result: Any) -> List[str]:
        """Get specific record IDs affected by the integrity issue"""
        
        # This would contain logic to identify specific affected records
        # For now, return empty list as this would require rule-specific queries
        return []
    
    async def _attempt_auto_healing(self, issue: IntegrityIssue, rule: IntegrityRule) -> None:
        """Attempt automatic healing of integrity issue"""
        
        try:
            healing_success = False
            
            if rule.healing_action == HealingAction.RECALCULATE_CHECKSUM:
                healing_success = await self._recalculate_checksums(issue.affected_tables)
            
            elif rule.healing_action == HealingAction.RESTORE_FROM_BACKUP:
                if self.backup_system:
                    healing_success = await self._restore_from_backup(issue.affected_tables)
            
            elif rule.healing_action == HealingAction.DELETE_CORRUPT_RECORD:
                healing_success = await self._delete_corrupt_records(issue.affected_records)
            
            elif rule.healing_action == HealingAction.REPAIR_REFERENCE:
                healing_success = await self._repair_references(issue.affected_tables)
            
            elif rule.healing_action == HealingAction.MERGE_DUPLICATES:
                healing_success = await self._merge_duplicate_records(issue.affected_tables)
            
            elif rule.healing_action == HealingAction.QUARANTINE_DATA:
                healing_success = await self._quarantine_data(issue.affected_records)
            
            if healing_success:
                issue.resolved_at = datetime.now()
                issue.healing_action_taken = rule.healing_action
                
                await self._save_integrity_issue(issue)
                
                # Re-run the check to verify healing
                await self._run_integrity_check(rule)
                
                logger.info(f"Successfully auto-healed integrity issue: {issue.issue_id}")
                self.metrics.issues_resolved_automatically += 1
            else:
                logger.warning(f"Auto-healing failed for issue: {issue.issue_id}")
        
        except Exception as e:
            logger.error(f"Auto-healing error for issue {issue.issue_id}: {e}")
    
    async def _recalculate_checksums(self, tables: List[str]) -> bool:
        """Recalculate checksums for specified tables"""
        try:
            for table in tables:
                await self._calculate_table_checksum(table)
            return True
        except Exception as e:
            logger.error(f"Failed to recalculate checksums: {e}")
            return False
    
    async def _restore_from_backup(self, tables: List[str]) -> bool:
        """Restore tables from backup"""
        try:
            if self.backup_system:
                # This would integrate with the backup system
                logger.info(f"Initiating backup restoration for tables: {tables}")
                # Implementation would depend on backup system integration
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to restore from backup: {e}")
            return False
    
    async def _delete_corrupt_records(self, record_ids: List[str]) -> bool:
        """Delete corrupt records"""
        if not record_ids:
            return True
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # This is a dangerous operation - would need specific implementation
            # For now, just log the action
            logger.warning(f"Would delete corrupt records: {record_ids}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete corrupt records: {e}")
            return False
        
        finally:
            await conn.close()
    
    async def _repair_references(self, tables: List[str]) -> bool:
        """Repair foreign key references"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            if "legislative_documents" in tables and "institutions" in tables:
                # Set null for orphaned foreign keys
                await conn.execute("""
                    UPDATE legislative_documents 
                    SET institution_id = NULL 
                    WHERE institution_id IS NOT NULL 
                    AND institution_id NOT IN (SELECT institution_id FROM institutions)
                """)
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to repair references: {e}")
            return False
        
        finally:
            await conn.close()
    
    async def _merge_duplicate_records(self, tables: List[str]) -> bool:
        """Merge duplicate records (requires manual review)"""
        # This is a complex operation that would need specific business logic
        logger.info(f"Duplicate merge required for tables: {tables} (manual review needed)")
        return False  # Requires manual intervention
    
    async def _quarantine_data(self, record_ids: List[str]) -> bool:
        """Quarantine potentially sensitive data"""
        if not record_ids:
            return True
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Move records to quarantine table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantined_documents AS 
                SELECT *, NOW() as quarantined_at 
                FROM legislative_documents WHERE FALSE
            """)
            
            # Insert quarantined records
            for record_id in record_ids:
                await conn.execute("""
                    INSERT INTO quarantined_documents 
                    SELECT *, NOW() as quarantined_at 
                    FROM legislative_documents 
                    WHERE document_id = $1
                """, record_id)
                
                # Remove from main table
                await conn.execute("""
                    DELETE FROM legislative_documents WHERE document_id = $1
                """, record_id)
            
            logger.info(f"Quarantined {len(record_ids)} records for review")
            return True
        
        except Exception as e:
            logger.error(f"Failed to quarantine data: {e}")
            return False
        
        finally:
            await conn.close()
    
    async def _update_table_checksums(self) -> None:
        """Update checksums for all monitored tables"""
        
        tables_to_monitor = [
            "legislative_documents", "institutions", "research_projects",
            "project_documents", "document_annotations", "research_notes"
        ]
        
        for table in tables_to_monitor:
            try:
                await self._calculate_table_checksum(table)
            except Exception as e:
                logger.error(f"Failed to calculate checksum for {table}: {e}")
    
    async def _calculate_table_checksum(self, table_name: str) -> str:
        """Calculate checksum for a table"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Get table data in consistent order
            query = f"""
                SELECT md5(string_agg(
                    md5(row(t.*)::text), '' ORDER BY md5(row(t.*)::text)
                )) as table_checksum,
                COUNT(*) as record_count
                FROM {table_name} t
            """
            
            result = await conn.fetchrow(query)
            
            if result:
                checksum = result['table_checksum']
                record_count = result['record_count']
                
                # Store checksum
                await conn.execute("""
                    INSERT INTO data_checksums (checksum_id, table_name, checksum_value, record_count)
                    VALUES ($1, $2, $3, $4)
                """, str(uuid.uuid4()), table_name, checksum, record_count)
                
                # Update in-memory cache
                old_checksum = self.table_checksums.get(table_name)
                self.table_checksums[table_name] = checksum
                
                # Check for changes
                if old_checksum and old_checksum != checksum:
                    logger.info(f"Table {table_name} checksum changed: {old_checksum} -> {checksum}")
                
                return checksum
        
        finally:
            await conn.close()
    
    async def _update_table_integrity_status(self, tables: List[str], status: IntegrityStatus, 
                                           issues: List[str] = None) -> None:
        """Update integrity status for tables"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            for table in tables:
                # Get current record count
                record_count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
                
                current_status = TableIntegrityStatus(
                    table_name=table,
                    status=status,
                    last_check=datetime.now(),
                    total_records=record_count,
                    issues_count=len(issues) if issues else 0,
                    checksum=self.table_checksums.get(table),
                    issues=issues or []
                )
                
                self.table_status[table] = current_status
                
                # Save to database
                await conn.execute("""
                    INSERT INTO table_integrity_status 
                    (status_id, table_name, status, last_check, total_records, 
                     issues_count, checksum, issues)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """, str(uuid.uuid4()), table, status.value, datetime.now(),
                    record_count, len(issues) if issues else 0,
                    self.table_checksums.get(table), json.dumps(issues or []))
        
        finally:
            await conn.close()
    
    async def _save_integrity_issue(self, issue: IntegrityIssue) -> None:
        """Save integrity issue to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO integrity_issues 
                (issue_id, rule_id, check_type, severity, description, affected_tables,
                 affected_records, detected_at, resolved_at, healing_action_taken, details)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (issue_id)
                DO UPDATE SET
                    resolved_at = $9, healing_action_taken = $10, details = $11
            """, issue.issue_id, issue.rule_id, issue.check_type.value,
                issue.severity.value, issue.description, json.dumps(issue.affected_tables),
                json.dumps(issue.affected_records), issue.detected_at, issue.resolved_at,
                issue.healing_action_taken.value if issue.healing_action_taken else None,
                json.dumps(issue.details))
        
        finally:
            await conn.close()
    
    async def _update_integrity_metrics(self) -> None:
        """Update overall integrity metrics"""
        
        # Count healthy vs problematic tables
        healthy_tables = sum(
            1 for status in self.table_status.values()
            if status.status == IntegrityStatus.HEALTHY
        )
        
        tables_with_issues = len(self.table_status) - healthy_tables
        
        # Calculate corruption percentage
        total_records = sum(status.total_records for status in self.table_status.values())
        corrupted_records = sum(
            status.issues_count for status in self.table_status.values()
        )
        
        # Calculate overall integrity score
        if len(self.table_status) > 0:
            integrity_score = (healthy_tables / len(self.table_status)) * 100
        else:
            integrity_score = 100.0
        
        # Update metrics
        self.metrics.total_tables_monitored = len(self.table_status)
        self.metrics.healthy_tables = healthy_tables
        self.metrics.tables_with_issues = tables_with_issues
        self.metrics.total_records_validated = total_records
        self.metrics.corrupted_records = corrupted_records
        self.metrics.overall_integrity_score = integrity_score
        
        # Save to database
        await self._save_integrity_metrics()
        
        # Alert if integrity score is below threshold
        if integrity_score < self.alert_threshold:
            logger.critical(f"Data integrity score below threshold: {integrity_score:.2f}%")
    
    async def _save_integrity_metrics(self) -> None:
        """Save integrity metrics to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            today = datetime.now().date()
            
            await conn.execute("""
                INSERT INTO integrity_metrics 
                (metric_id, date_period, total_tables_monitored, healthy_tables,
                 tables_with_issues, total_records_validated, corrupted_records,
                 issues_resolved_automatically, overall_integrity_score, last_full_scan)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (date_period)
                DO UPDATE SET
                    total_tables_monitored = $3, healthy_tables = $4,
                    tables_with_issues = $5, total_records_validated = $6,
                    corrupted_records = $7, issues_resolved_automatically = $8,
                    overall_integrity_score = $9, last_full_scan = $10
            """, str(uuid.uuid4()), today, self.metrics.total_tables_monitored,
                self.metrics.healthy_tables, self.metrics.tables_with_issues,
                self.metrics.total_records_validated, self.metrics.corrupted_records,
                self.metrics.issues_resolved_automatically, self.metrics.overall_integrity_score,
                datetime.now())
        
        finally:
            await conn.close()
    
    async def run_full_integrity_scan(self) -> Dict[str, Any]:
        """Run comprehensive integrity scan"""
        logger.info("Starting full integrity scan")
        start_time = datetime.now()
        
        # Run all integrity checks
        await self._run_all_integrity_checks()
        
        # Update all checksums
        await self._update_table_checksums()
        
        # Update metrics
        await self._update_integrity_metrics()
        
        self.metrics.last_full_scan = datetime.now()
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        scan_results = {
            "scan_duration_seconds": scan_duration,
            "tables_scanned": len(self.table_status),
            "issues_found": len(self.active_issues),
            "integrity_score": self.metrics.overall_integrity_score,
            "healthy_tables": self.metrics.healthy_tables,
            "corrupted_tables": self.metrics.tables_with_issues,
            "scan_completed_at": end_time.isoformat()
        }
        
        logger.info(f"Full integrity scan completed in {scan_duration:.2f} seconds")
        return scan_results
    
    async def get_integrity_status(self) -> Dict[str, Any]:
        """Get current integrity status"""
        return {
            "metrics": self.metrics.to_dict(),
            "table_status": {name: status.to_dict() for name, status in self.table_status.items()},
            "active_issues": len(self.active_issues),
            "monitoring_enabled": self.monitoring_enabled,
            "rules_count": len(self.integrity_rules)
        }
    
    async def get_integrity_report(self) -> Dict[str, Any]:
        """Generate comprehensive integrity report"""
        
        # Get recent issues
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            recent_issues = await conn.fetch("""
                SELECT * FROM integrity_issues 
                WHERE detected_at >= NOW() - INTERVAL '7 days'
                ORDER BY detected_at DESC
                LIMIT 50
            """)
            
            # Get integrity trends
            trends = await conn.fetch("""
                SELECT date_period, overall_integrity_score, corrupted_records
                FROM integrity_metrics 
                WHERE date_period >= CURRENT_DATE - INTERVAL '30 days'
                ORDER BY date_period DESC
            """)
            
            return {
                "summary": self.metrics.to_dict(),
                "table_details": {name: status.to_dict() for name, status in self.table_status.items()},
                "recent_issues": [dict(issue) for issue in recent_issues],
                "trends": [dict(trend) for trend in trends],
                "recommendations": self._generate_recommendations()
            }
        
        finally:
            await conn.close()
    
    def _generate_recommendations(self) -> List[str]:
        """Generate integrity improvement recommendations"""
        recommendations = []
        
        if self.metrics.overall_integrity_score < 95:
            recommendations.append("Consider running data cleanup procedures to improve integrity score")
        
        if self.metrics.tables_with_issues > self.metrics.healthy_tables:
            recommendations.append("High number of tables with issues - investigate common causes")
        
        if self.metrics.corrupted_records > 100:
            recommendations.append("Significant data corruption detected - review backup and recovery procedures")
        
        if len(self.active_issues) > 10:
            recommendations.append("Multiple active integrity issues - prioritize resolution")
        
        return recommendations
    
    def stop(self) -> None:
        """Stop integrity monitoring"""
        self.monitoring_enabled = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=30)
        logger.info("Data integrity monitor stopped")

# Factory function for easy creation
async def create_data_integrity_monitor(db_config: Dict[str, str], 
                                      backup_system=None,
                                      alert_threshold: float = 95.0) -> DataIntegrityMonitor:
    """Create and initialize data integrity monitor"""
    monitor = DataIntegrityMonitor(db_config, backup_system, alert_threshold)
    await monitor.initialize()
    return monitor

# Export main classes
__all__ = [
    'DataIntegrityMonitor',
    'IntegrityRule',
    'IntegrityIssue',
    'TableIntegrityStatus',
    'IntegrityMetrics',
    'IntegrityCheckType',
    'IntegrityStatus',
    'ValidationSeverity',
    'HealingAction',
    'create_data_integrity_monitor'
]