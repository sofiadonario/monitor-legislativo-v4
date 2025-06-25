# LGPD (Lei Geral de Proteção de Dados) Compliance System for Monitor Legislativo v4
# Phase 4 Week 16: Brazilian data privacy law compliance implementation
# Ensures compliance with Brazilian data protection regulations

import asyncio
import asyncpg
import json
import logging
import hashlib
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class DataSubjectRight(Enum):
    """LGPD data subject rights"""
    ACCESS = "access"                    # Right to access personal data
    RECTIFICATION = "rectification"      # Right to correct personal data
    ERASURE = "erasure"                 # Right to delete personal data
    PORTABILITY = "portability"         # Right to data portability
    RESTRICTION = "restriction"         # Right to restrict processing
    OBJECTION = "objection"             # Right to object to processing
    CONFIRMATION = "confirmation"       # Right to confirm data processing

class LegalBasis(Enum):
    """LGPD legal basis for data processing"""
    CONSENT = "consent"                 # Art. 7º, I - Consent
    LEGAL_OBLIGATION = "legal_obligation"  # Art. 7º, II - Legal obligation
    PUBLIC_INTEREST = "public_interest"    # Art. 7º, III - Public interest
    VITAL_INTERESTS = "vital_interests"    # Art. 7º, IV - Vital interests
    LEGITIMATE_INTEREST = "legitimate_interest"  # Art. 7º, IX - Legitimate interest
    CONTRACT = "contract"               # Art. 7º, V - Contract performance
    RESEARCH = "research"              # Art. 7º, IV - Research purposes

class DataCategory(Enum):
    """Categories of personal data under LGPD"""
    IDENTIFICATION = "identification"    # CPF, RG, name, etc.
    CONTACT = "contact"                # Email, phone, address
    DEMOGRAPHIC = "demographic"        # Age, gender, location
    PROFESSIONAL = "professional"      # Job title, organization
    BEHAVIORAL = "behavioral"          # Usage patterns, preferences
    TECHNICAL = "technical"            # IP address, user agent
    SENSITIVE = "sensitive"            # Racial/ethnic origin, political opinions, etc.

@dataclass
class PersonalDataMapping:
    """Maps personal data fields in the system"""
    field_name: str
    table_name: str
    data_category: DataCategory
    legal_basis: LegalBasis
    retention_period: int  # Days
    is_sensitive: bool = False
    is_pseudonymized: bool = False
    collection_purpose: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['data_category'] = self.data_category.value
        result['legal_basis'] = self.legal_basis.value
        return result

@dataclass
class ConsentRecord:
    """Records user consent for data processing"""
    consent_id: str
    user_identifier: str  # Email or other identifier
    legal_basis: LegalBasis
    purposes: List[str]
    consent_given: bool
    consent_timestamp: datetime
    consent_method: str  # "form", "api", "implicit"
    consent_version: str
    withdrawal_timestamp: Optional[datetime] = None
    withdrawal_method: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['legal_basis'] = self.legal_basis.value
        result['consent_timestamp'] = self.consent_timestamp.isoformat()
        if self.withdrawal_timestamp:
            result['withdrawal_timestamp'] = self.withdrawal_timestamp.isoformat()
        return result

@dataclass
class DataSubjectRequest:
    """Data subject rights request"""
    request_id: str
    user_identifier: str
    request_type: DataSubjectRight
    request_details: str
    submitted_at: datetime
    processed_at: Optional[datetime] = None
    status: str = "pending"  # pending, processing, completed, rejected
    response_data: Optional[Dict[str, Any]] = None
    processor_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['request_type'] = self.request_type.value
        result['submitted_at'] = self.submitted_at.isoformat()
        if self.processed_at:
            result['processed_at'] = self.processed_at.isoformat()
        return result

@dataclass
class LGPDComplianceReport:
    """LGPD compliance assessment report"""
    report_id: str
    timestamp: datetime
    compliance_score: float  # 0-100
    personal_data_inventory: List[PersonalDataMapping]
    active_consents: int
    withdrawn_consents: int
    pending_requests: int
    violations: List[Dict[str, Any]]
    recommendations: List[str]
    retention_review_needed: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        result['personal_data_inventory'] = [pdm.to_dict() for pdm in self.personal_data_inventory]
        return result

class LGPDComplianceManager:
    """
    LGPD Compliance Management System for Monitor Legislativo v4
    
    Implements Brazilian data privacy law (LGPD) compliance including:
    - Personal data inventory and mapping
    - Consent management
    - Data subject rights processing
    - Retention policy enforcement
    - Privacy impact assessments
    - Breach notification procedures
    """
    
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        self.personal_data_mappings = []
        self.consent_records = []
        self.data_subject_requests = []
        
        # Initialize personal data mappings for Monitor Legislativo
        self._initialize_data_mappings()
    
    def _initialize_data_mappings(self) -> None:
        """Initialize personal data mappings for the application"""
        
        # User-related data (if any user accounts exist)
        self.personal_data_mappings.extend([
            PersonalDataMapping(
                field_name="email",
                table_name="users",
                data_category=DataCategory.CONTACT,
                legal_basis=LegalBasis.CONSENT,
                retention_period=1095,  # 3 years
                collection_purpose="User account management and communication"
            ),
            PersonalDataMapping(
                field_name="ip_address",
                table_name="access_logs",
                data_category=DataCategory.TECHNICAL,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                retention_period=180,  # 6 months
                collection_purpose="Security monitoring and analytics"
            ),
            PersonalDataMapping(
                field_name="user_agent",
                table_name="access_logs",
                data_category=DataCategory.TECHNICAL,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                retention_period=90,  # 3 months
                collection_purpose="Technical support and analytics"
            ),
            PersonalDataMapping(
                field_name="session_id",
                table_name="user_sessions",
                data_category=DataCategory.TECHNICAL,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                retention_period=30,  # 1 month
                collection_purpose="Session management and security"
            )
        ])
        
        # Analytics and usage data
        self.personal_data_mappings.extend([
            PersonalDataMapping(
                field_name="search_query",
                table_name="search_analytics",
                data_category=DataCategory.BEHAVIORAL,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                retention_period=365,  # 1 year
                is_pseudonymized=True,
                collection_purpose="Service improvement and research analytics"
            ),
            PersonalDataMapping(
                field_name="location_region",
                table_name="usage_analytics",
                data_category=DataCategory.DEMOGRAPHIC,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                retention_period=730,  # 2 years
                is_pseudonymized=True,
                collection_purpose="Geographic usage analysis for service optimization"
            )
        ])
    
    async def create_lgpd_tables(self) -> None:
        """Create LGPD compliance tables in database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Create consent management table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS lgpd_consent_records (
                    consent_id VARCHAR(36) PRIMARY KEY,
                    user_identifier VARCHAR(255) NOT NULL,
                    legal_basis VARCHAR(50) NOT NULL,
                    purposes JSONB NOT NULL,
                    consent_given BOOLEAN NOT NULL,
                    consent_timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                    consent_method VARCHAR(50) NOT NULL,
                    consent_version VARCHAR(20) NOT NULL,
                    withdrawal_timestamp TIMESTAMP NULL,
                    withdrawal_method VARCHAR(50) NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create data subject requests table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS lgpd_data_subject_requests (
                    request_id VARCHAR(36) PRIMARY KEY,
                    user_identifier VARCHAR(255) NOT NULL,
                    request_type VARCHAR(50) NOT NULL,
                    request_details TEXT NOT NULL,
                    submitted_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    processed_at TIMESTAMP NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    response_data JSONB NULL,
                    processor_notes TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create data processing activities log
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS lgpd_processing_activities (
                    activity_id VARCHAR(36) PRIMARY KEY,
                    activity_name VARCHAR(255) NOT NULL,
                    processing_purpose TEXT NOT NULL,
                    legal_basis VARCHAR(50) NOT NULL,
                    data_categories JSONB NOT NULL,
                    data_subjects VARCHAR(255) NOT NULL,
                    recipients TEXT NULL,
                    retention_period INTEGER NOT NULL,
                    security_measures JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create data breach incidents table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS lgpd_data_breaches (
                    breach_id VARCHAR(36) PRIMARY KEY,
                    incident_date TIMESTAMP NOT NULL,
                    detection_date TIMESTAMP NOT NULL DEFAULT NOW(),
                    breach_type VARCHAR(100) NOT NULL,
                    affected_data_types JSONB NOT NULL,
                    affected_subjects_count INTEGER NOT NULL DEFAULT 0,
                    severity_level VARCHAR(20) NOT NULL,
                    containment_actions TEXT NOT NULL,
                    notification_required BOOLEAN NOT NULL DEFAULT FALSE,
                    authority_notified_at TIMESTAMP NULL,
                    subjects_notified_at TIMESTAMP NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'investigating',
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes for performance
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_consent_user ON lgpd_consent_records(user_identifier);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_consent_timestamp ON lgpd_consent_records(consent_timestamp);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_user ON lgpd_data_subject_requests(user_identifier);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_status ON lgpd_data_subject_requests(status);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_breaches_date ON lgpd_data_breaches(incident_date);")
            
            logger.info("LGPD compliance tables created successfully")
        
        finally:
            await conn.close()
    
    async def record_consent(self, user_identifier: str, purposes: List[str], 
                           consent_method: str = "form", legal_basis: LegalBasis = LegalBasis.CONSENT) -> str:
        """Record user consent for data processing"""
        consent_id = str(uuid.uuid4())
        
        consent_record = ConsentRecord(
            consent_id=consent_id,
            user_identifier=user_identifier,
            legal_basis=legal_basis,
            purposes=purposes,
            consent_given=True,
            consent_timestamp=datetime.now(),
            consent_method=consent_method,
            consent_version="1.0"
        )
        
        conn = await asyncpg.connect(**self.db_config)
        try:
            await conn.execute("""
                INSERT INTO lgpd_consent_records 
                (consent_id, user_identifier, legal_basis, purposes, consent_given, 
                 consent_timestamp, consent_method, consent_version)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, consent_id, user_identifier, legal_basis.value, json.dumps(purposes),
                True, consent_record.consent_timestamp, consent_method, "1.0")
            
            logger.info(f"Consent recorded for user {user_identifier}: {consent_id}")
            return consent_id
        
        finally:
            await conn.close()
    
    async def withdraw_consent(self, user_identifier: str, consent_id: str, 
                             withdrawal_method: str = "form") -> bool:
        """Withdraw user consent"""
        conn = await asyncpg.connect(**self.db_config)
        try:
            result = await conn.execute("""
                UPDATE lgpd_consent_records 
                SET consent_given = FALSE, 
                    withdrawal_timestamp = $1,
                    withdrawal_method = $2,
                    updated_at = $1
                WHERE consent_id = $3 AND user_identifier = $4 AND consent_given = TRUE
            """, datetime.now(), withdrawal_method, consent_id, user_identifier)
            
            if result == "UPDATE 1":
                logger.info(f"Consent withdrawn: {consent_id} for user {user_identifier}")
                
                # Trigger data deletion if consent was the only legal basis
                await self._handle_consent_withdrawal(user_identifier, consent_id)
                return True
            else:
                logger.warning(f"Failed to withdraw consent {consent_id} for user {user_identifier}")
                return False
        
        finally:
            await conn.close()
    
    async def _handle_consent_withdrawal(self, user_identifier: str, consent_id: str) -> None:
        """Handle data processing changes after consent withdrawal"""
        # Check if user has other valid consents
        conn = await asyncpg.connect(**self.db_config)
        try:
            remaining_consents = await conn.fetch("""
                SELECT consent_id FROM lgpd_consent_records
                WHERE user_identifier = $1 AND consent_given = TRUE
            """, user_identifier)
            
            if not remaining_consents:
                # No remaining consents - schedule data deletion
                await self._schedule_data_deletion(user_identifier, "consent_withdrawal")
                logger.info(f"Scheduled data deletion for user {user_identifier} - no remaining consents")
        
        finally:
            await conn.close()
    
    async def submit_data_subject_request(self, user_identifier: str, request_type: DataSubjectRight,
                                        request_details: str) -> str:
        """Submit a data subject rights request"""
        request_id = str(uuid.uuid4())
        
        request = DataSubjectRequest(
            request_id=request_id,
            user_identifier=user_identifier,
            request_type=request_type,
            request_details=request_details,
            submitted_at=datetime.now()
        )
        
        conn = await asyncpg.connect(**self.db_config)
        try:
            await conn.execute("""
                INSERT INTO lgpd_data_subject_requests 
                (request_id, user_identifier, request_type, request_details, submitted_at)
                VALUES ($1, $2, $3, $4, $5)
            """, request_id, user_identifier, request_type.value, request_details, request.submitted_at)
            
            logger.info(f"Data subject request submitted: {request_id} - {request_type.value}")
            
            # Auto-process some request types
            if request_type in [DataSubjectRight.ACCESS, DataSubjectRight.CONFIRMATION]:
                await self._auto_process_request(request_id)
            
            return request_id
        
        finally:
            await conn.close()
    
    async def _auto_process_request(self, request_id: str) -> None:
        """Auto-process certain types of data subject requests"""
        conn = await asyncpg.connect(**self.db_config)
        try:
            # Get request details
            request_data = await conn.fetchrow("""
                SELECT user_identifier, request_type FROM lgpd_data_subject_requests
                WHERE request_id = $1
            """, request_id)
            
            if not request_data:
                return
            
            user_identifier = request_data['user_identifier']
            request_type = DataSubjectRight(request_data['request_type'])
            
            response_data = {}
            
            if request_type == DataSubjectRight.ACCESS:
                # Generate data export for access request
                response_data = await self._generate_data_export(user_identifier)
            
            elif request_type == DataSubjectRight.CONFIRMATION:
                # Confirm what data is being processed
                response_data = await self._generate_processing_confirmation(user_identifier)
            
            # Update request with response
            await conn.execute("""
                UPDATE lgpd_data_subject_requests 
                SET status = 'completed',
                    processed_at = $1,
                    response_data = $2,
                    processor_notes = 'Auto-processed',
                    updated_at = $1
                WHERE request_id = $3
            """, datetime.now(), json.dumps(response_data), request_id)
            
            logger.info(f"Auto-processed data subject request: {request_id}")
        
        finally:
            await conn.close()
    
    async def _generate_data_export(self, user_identifier: str) -> Dict[str, Any]:
        """Generate data export for access request"""
        conn = await asyncpg.connect(**self.db_config)
        export_data = {
            "user_identifier": user_identifier,
            "export_timestamp": datetime.now().isoformat(),
            "data_categories": {}
        }
        
        try:
            # Export consent records
            consents = await conn.fetch("""
                SELECT * FROM lgpd_consent_records WHERE user_identifier = $1
            """, user_identifier)
            
            export_data["data_categories"]["consent_records"] = [
                {
                    "consent_id": record['consent_id'],
                    "legal_basis": record['legal_basis'],
                    "purposes": record['purposes'],
                    "consent_given": record['consent_given'],
                    "consent_timestamp": record['consent_timestamp'].isoformat() if record['consent_timestamp'] else None,
                    "withdrawal_timestamp": record['withdrawal_timestamp'].isoformat() if record['withdrawal_timestamp'] else None
                }
                for record in consents
            ]
            
            # Export other personal data based on mappings
            for mapping in self.personal_data_mappings:
                if mapping.table_name in ["users", "access_logs", "user_sessions", "search_analytics", "usage_analytics"]:
                    try:
                        # Query each table for user data
                        if mapping.table_name == "access_logs":
                            user_data = await conn.fetch(f"""
                                SELECT {mapping.field_name} FROM {mapping.table_name} 
                                WHERE user_identifier = $1 OR ip_address = $1
                                ORDER BY timestamp DESC LIMIT 100
                            """, user_identifier)
                        else:
                            user_data = await conn.fetch(f"""
                                SELECT {mapping.field_name} FROM {mapping.table_name} 
                                WHERE user_identifier = $1 OR email = $1
                                ORDER BY created_at DESC LIMIT 100
                            """, user_identifier)
                        
                        if user_data:
                            export_data["data_categories"][mapping.table_name] = [
                                {mapping.field_name: record[mapping.field_name]}
                                for record in user_data
                            ]
                    
                    except Exception as e:
                        logger.debug(f"Could not export data from {mapping.table_name}: {e}")
            
            return export_data
        
        finally:
            await conn.close()
    
    async def _generate_processing_confirmation(self, user_identifier: str) -> Dict[str, Any]:
        """Generate processing confirmation for confirmation request"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Get active consents
            consents = await conn.fetch("""
                SELECT legal_basis, purposes, consent_timestamp FROM lgpd_consent_records
                WHERE user_identifier = $1 AND consent_given = TRUE
            """, user_identifier)
            
            confirmation_data = {
                "user_identifier": user_identifier,
                "confirmation_timestamp": datetime.now().isoformat(),
                "data_processing_confirmed": len(consents) > 0,
                "active_consents": len(consents),
                "processing_activities": []
            }
            
            # Add processing activities based on consents
            for consent in consents:
                confirmation_data["processing_activities"].append({
                    "legal_basis": consent['legal_basis'],
                    "purposes": consent['purposes'],
                    "consent_date": consent['consent_timestamp'].isoformat(),
                    "data_categories": [mapping.data_category.value for mapping in self.personal_data_mappings 
                                     if mapping.legal_basis.value == consent['legal_basis']]
                })
            
            # Add data categories being processed
            confirmation_data["data_categories_processed"] = list(set([
                mapping.data_category.value for mapping in self.personal_data_mappings
            ]))
            
            return confirmation_data
        
        finally:
            await conn.close()
    
    async def _schedule_data_deletion(self, user_identifier: str, reason: str) -> None:
        """Schedule data deletion for a user"""
        # For now, log the deletion request
        # In a full implementation, this would trigger a deletion job
        logger.info(f"Scheduled data deletion for {user_identifier} - reason: {reason}")
        
        # Could implement a deletion queue or immediate deletion here
        # For Monitor Legislativo, we might want to pseudonymize rather than delete
        # to preserve research data while protecting privacy
    
    async def process_data_deletion_request(self, user_identifier: str) -> Dict[str, Any]:
        """Process data deletion (erasure) request"""
        conn = await asyncpg.connect(**self.db_config)
        deletion_report = {
            "user_identifier": user_identifier,
            "deletion_timestamp": datetime.now().isoformat(),
            "deleted_records": {},
            "pseudonymized_records": {},
            "retained_records": {}
        }
        
        try:
            # Delete or pseudonymize data based on retention requirements
            for mapping in self.personal_data_mappings:
                try:
                    if mapping.legal_basis == LegalBasis.RESEARCH:
                        # Pseudonymize research data instead of deleting
                        if mapping.table_name in ["search_analytics", "usage_analytics"]:
                            # Replace user identifier with hash
                            user_hash = hashlib.sha256(user_identifier.encode()).hexdigest()[:16]
                            
                            result = await conn.execute(f"""
                                UPDATE {mapping.table_name} 
                                SET user_identifier = $1 
                                WHERE user_identifier = $2
                            """, f"pseudonym_{user_hash}", user_identifier)
                            
                            deletion_report["pseudonymized_records"][mapping.table_name] = result
                    
                    else:
                        # Delete non-research data
                        if mapping.table_name in ["users", "access_logs", "user_sessions"]:
                            result = await conn.execute(f"""
                                DELETE FROM {mapping.table_name} 
                                WHERE user_identifier = $1 OR email = $1
                            """, user_identifier)
                            
                            deletion_report["deleted_records"][mapping.table_name] = result
                
                except Exception as e:
                    logger.error(f"Error processing deletion for {mapping.table_name}: {e}")
                    deletion_report["retained_records"][mapping.table_name] = f"Error: {str(e)}"
            
            # Delete consent records (these should always be deletable)
            consent_result = await conn.execute("""
                DELETE FROM lgpd_consent_records WHERE user_identifier = $1
            """, user_identifier)
            deletion_report["deleted_records"]["lgpd_consent_records"] = consent_result
            
            logger.info(f"Processed data deletion request for {user_identifier}")
            return deletion_report
        
        finally:
            await conn.close()
    
    async def run_retention_policy_enforcement(self) -> Dict[str, Any]:
        """Enforce data retention policies"""
        conn = await asyncpg.connect(**self.db_config)
        enforcement_report = {
            "enforcement_timestamp": datetime.now().isoformat(),
            "deleted_records": {},
            "errors": []
        }
        
        try:
            for mapping in self.personal_data_mappings:
                try:
                    cutoff_date = datetime.now() - timedelta(days=mapping.retention_period)
                    
                    # Delete expired data based on retention period
                    if mapping.table_name == "access_logs":
                        result = await conn.execute(f"""
                            DELETE FROM {mapping.table_name} 
                            WHERE timestamp < $1
                        """, cutoff_date)
                    
                    elif mapping.table_name in ["search_analytics", "usage_analytics", "user_sessions"]:
                        result = await conn.execute(f"""
                            DELETE FROM {mapping.table_name} 
                            WHERE created_at < $1
                        """, cutoff_date)
                    
                    else:
                        continue  # Skip tables without timestamp fields
                    
                    enforcement_report["deleted_records"][mapping.table_name] = {
                        "retention_period_days": mapping.retention_period,
                        "cutoff_date": cutoff_date.isoformat(),
                        "records_deleted": result
                    }
                
                except Exception as e:
                    error_msg = f"Error enforcing retention for {mapping.table_name}: {str(e)}"
                    enforcement_report["errors"].append(error_msg)
                    logger.error(error_msg)
            
            logger.info("Data retention policy enforcement completed")
            return enforcement_report
        
        finally:
            await conn.close()
    
    async def generate_compliance_report(self) -> LGPDComplianceReport:
        """Generate comprehensive LGPD compliance report"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Count consent records
            consent_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) FILTER (WHERE consent_given = TRUE) as active_consents,
                    COUNT(*) FILTER (WHERE consent_given = FALSE) as withdrawn_consents
                FROM lgpd_consent_records
            """)
            
            active_consents = consent_stats['active_consents'] or 0
            withdrawn_consents = consent_stats['withdrawn_consents'] or 0
            
            # Count pending requests
            pending_requests = await conn.fetchval("""
                SELECT COUNT(*) FROM lgpd_data_subject_requests 
                WHERE status = 'pending'
            """) or 0
            
            # Check for violations
            violations = []
            
            # Check for overdue requests (should be processed within 15 days per LGPD)
            overdue_requests = await conn.fetch("""
                SELECT request_id, user_identifier, request_type, submitted_at
                FROM lgpd_data_subject_requests
                WHERE status = 'pending' AND submitted_at < $1
            """, datetime.now() - timedelta(days=15))
            
            for request in overdue_requests:
                violations.append({
                    "type": "overdue_request",
                    "description": f"Data subject request {request['request_id']} overdue by {(datetime.now() - request['submitted_at']).days} days",
                    "severity": "medium",
                    "request_id": request['request_id']
                })
            
            # Check for consent without clear legal basis
            unclear_consents = await conn.fetch("""
                SELECT consent_id FROM lgpd_consent_records
                WHERE legal_basis = 'consent' AND (purposes IS NULL OR purposes = '[]'::jsonb)
            """)
            
            for consent in unclear_consents:
                violations.append({
                    "type": "unclear_consent",
                    "description": f"Consent {consent['consent_id']} lacks clear purpose specification",
                    "severity": "low",
                    "consent_id": consent['consent_id']
                })
            
            # Generate recommendations
            recommendations = []
            
            if pending_requests > 0:
                recommendations.append(f"Process {pending_requests} pending data subject requests")
            
            if len(overdue_requests) > 0:
                recommendations.append(f"Urgently process {len(overdue_requests)} overdue data subject requests")
            
            if withdrawn_consents > active_consents:
                recommendations.append("Review consent collection process - high withdrawal rate detected")
            
            # Check retention review needs
            retention_review_needed = []
            for mapping in self.personal_data_mappings:
                if mapping.retention_period > 730:  # More than 2 years
                    retention_review_needed.append(f"{mapping.table_name}.{mapping.field_name} - {mapping.retention_period} days retention")
            
            if not recommendations:
                recommendations.append("LGPD compliance status is good - continue monitoring")
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(
                len(violations), pending_requests, len(overdue_requests)
            )
            
            return LGPDComplianceReport(
                report_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                compliance_score=compliance_score,
                personal_data_inventory=self.personal_data_mappings,
                active_consents=active_consents,
                withdrawn_consents=withdrawn_consents,
                pending_requests=pending_requests,
                violations=violations,
                recommendations=recommendations,
                retention_review_needed=retention_review_needed
            )
        
        finally:
            await conn.close()
    
    def _calculate_compliance_score(self, violations_count: int, pending_requests: int, overdue_requests: int) -> float:
        """Calculate LGPD compliance score (0-100)"""
        base_score = 100.0
        
        # Deduct points for violations
        base_score -= violations_count * 10  # 10 points per violation
        
        # Deduct points for pending requests
        base_score -= pending_requests * 2  # 2 points per pending request
        
        # Deduct more points for overdue requests
        base_score -= overdue_requests * 15  # 15 points per overdue request
        
        return max(0.0, base_score)

# Factory function for easy creation
async def create_lgpd_manager(db_config: Dict[str, str]) -> LGPDComplianceManager:
    """Create and initialize LGPD compliance manager"""
    manager = LGPDComplianceManager(db_config)
    await manager.create_lgpd_tables()
    return manager

# Export main classes
__all__ = [
    'LGPDComplianceManager',
    'PersonalDataMapping',
    'ConsentRecord',
    'DataSubjectRequest',
    'LGPDComplianceReport',
    'DataSubjectRight',
    'LegalBasis',
    'DataCategory',
    'create_lgpd_manager'
]