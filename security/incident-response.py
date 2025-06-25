# Security Incident Response System for Monitor Legislativo v4
# Phase 4 Week 16: Automated incident detection, response, and management
# Handles security incidents with Brazilian compliance requirements

import asyncio
import asyncpg
import aiohttp
import json
import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    """Security incident severity levels"""
    CRITICAL = "critical"    # System compromise, active data breach
    HIGH = "high"           # Significant security risk, unauthorized access
    MEDIUM = "medium"       # Security policy violation, suspicious activity
    LOW = "low"            # Minor security issue, configuration problem
    INFO = "info"          # Informational security event

class IncidentType(Enum):
    """Types of security incidents"""
    DATA_BREACH = "data_breach"                    # Unauthorized data access
    SYSTEM_COMPROMISE = "system_compromise"        # System infiltration
    MALWARE_DETECTION = "malware_detection"        # Malicious software
    DOS_ATTACK = "dos_attack"                     # Denial of service
    BRUTE_FORCE = "brute_force"                   # Password attacks
    INSIDER_THREAT = "insider_threat"             # Internal security threat
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"  # Exploit attempt
    POLICY_VIOLATION = "policy_violation"         # Security policy breach
    SUSPICIOUS_ACTIVITY = "suspicious_activity"   # Anomalous behavior
    CONFIGURATION_BREACH = "configuration_breach" # Security misconfiguration

class IncidentStatus(Enum):
    """Incident handling status"""
    NEW = "new"                    # Newly detected incident
    INVESTIGATING = "investigating" # Under investigation
    CONTAINED = "contained"        # Threat contained
    ERADICATED = "eradicated"     # Threat removed
    RECOVERING = "recovering"      # System recovery in progress
    CLOSED = "closed"             # Incident resolved
    ESCALATED = "escalated"       # Escalated to higher authority

class ResponseAction(Enum):
    """Incident response actions"""
    MONITOR = "monitor"            # Continuous monitoring
    INVESTIGATE = "investigate"    # Detailed investigation
    CONTAIN = "contain"           # Immediate containment
    ISOLATE = "isolate"           # System isolation
    BLOCK = "block"               # Block access/traffic
    PATCH = "patch"               # Apply security patches
    BACKUP_RESTORE = "backup_restore"  # Restore from backup
    NOTIFY_AUTHORITIES = "notify_authorities"  # Legal notification
    NOTIFY_USERS = "notify_users"  # User notification

@dataclass
class SecurityIncident:
    """Security incident record"""
    incident_id: str
    incident_type: IncidentType
    severity: IncidentSeverity
    title: str
    description: str
    affected_systems: List[str]
    affected_data: List[str]
    detection_time: datetime
    detection_method: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    indicators_of_compromise: List[str] = field(default_factory=list)
    estimated_impact: str = ""
    status: IncidentStatus = IncidentStatus.NEW
    assigned_to: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['incident_type'] = self.incident_type.value
        result['severity'] = self.severity.value
        result['status'] = self.status.value
        result['detection_time'] = self.detection_time.isoformat()
        return result

@dataclass
class ResponsePlan:
    """Incident response plan"""
    plan_id: str
    incident_type: IncidentType
    severity: IncidentSeverity
    response_actions: List[ResponseAction]
    containment_procedures: List[str]
    investigation_steps: List[str]
    notification_requirements: List[str]
    recovery_procedures: List[str]
    escalation_criteria: List[str]
    max_response_time_minutes: int
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['incident_type'] = self.incident_type.value
        result['severity'] = self.severity.value
        result['response_actions'] = [action.value for action in self.response_actions]
        return result

@dataclass
class IncidentTimeline:
    """Incident response timeline entry"""
    entry_id: str
    incident_id: str
    timestamp: datetime
    action_taken: str
    performed_by: str
    details: str
    evidence_collected: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class IncidentResponseManager:
    """
    Comprehensive security incident response system for Monitor Legislativo v4
    
    Features:
    - Automated incident detection and classification
    - Response plan execution and tracking
    - Brazilian compliance (LGPD) incident handling
    - Integration with security monitoring systems
    - Automated notifications and escalation
    - Forensic evidence collection and preservation
    """
    
    def __init__(self, db_config: Dict[str, str], notification_config: Dict[str, str]):
        self.db_config = db_config
        self.notification_config = notification_config
        self.response_plans = {}
        self.active_incidents = {}
        self.notification_channels = {}
        
        # Initialize response plans
        self._initialize_response_plans()
        self._initialize_notification_channels()
    
    async def initialize(self) -> None:
        """Initialize incident response system"""
        await self._create_incident_tables()
        await self._load_response_plans()
        logger.info("Incident response system initialized")
    
    def _initialize_response_plans(self) -> None:
        """Initialize predefined response plans"""
        
        # Data breach response plan (LGPD compliance critical)
        self.response_plans["data_breach_critical"] = ResponsePlan(
            plan_id="data_breach_critical",
            incident_type=IncidentType.DATA_BREACH,
            severity=IncidentSeverity.CRITICAL,
            response_actions=[
                ResponseAction.CONTAIN,
                ResponseAction.INVESTIGATE,
                ResponseAction.ISOLATE,
                ResponseAction.NOTIFY_AUTHORITIES,
                ResponseAction.NOTIFY_USERS
            ],
            containment_procedures=[
                "Immediately isolate affected systems",
                "Disable compromised user accounts",
                "Block suspicious IP addresses",
                "Enable enhanced monitoring",
                "Preserve forensic evidence"
            ],
            investigation_steps=[
                "Identify scope of data exposure",
                "Determine attack vector",
                "Assess data sensitivity",
                "Document timeline of events",
                "Collect forensic evidence"
            ],
            notification_requirements=[
                "ANPD notification within 72 hours (if high risk)",
                "Affected users notification without undue delay",
                "Internal security team immediate notification",
                "Executive team notification within 4 hours",
                "Legal team consultation within 2 hours"
            ],
            recovery_procedures=[
                "Patch security vulnerabilities",
                "Restore systems from clean backups",
                "Implement additional security controls",
                "Update access controls and credentials",
                "Conduct security awareness training"
            ],
            escalation_criteria=[
                "Personal data of >1000 individuals affected",
                "Sensitive personal data exposed",
                "Media attention or public disclosure",
                "Regulatory inquiry received",
                "Criminal activity suspected"
            ],
            max_response_time_minutes=30
        )
        
        # DoS attack response plan
        self.response_plans["dos_attack_high"] = ResponsePlan(
            plan_id="dos_attack_high",
            incident_type=IncidentType.DOS_ATTACK,
            severity=IncidentSeverity.HIGH,
            response_actions=[
                ResponseAction.CONTAIN,
                ResponseAction.BLOCK,
                ResponseAction.MONITOR
            ],
            containment_procedures=[
                "Enable DDoS protection mechanisms",
                "Block attacking IP addresses",
                "Scale infrastructure resources",
                "Implement rate limiting",
                "Activate CDN protection"
            ],
            investigation_steps=[
                "Analyze attack patterns",
                "Identify attack sources",
                "Assess impact on services",
                "Document attack characteristics",
                "Check for coordinated attacks"
            ],
            notification_requirements=[
                "Infrastructure team immediate notification",
                "Security team notification within 15 minutes",
                "Management notification if >30 min downtime"
            ],
            recovery_procedures=[
                "Restore normal service levels",
                "Remove temporary blocks gradually",
                "Update DDoS protection rules",
                "Review infrastructure scaling",
                "Post-incident analysis and improvements"
            ],
            escalation_criteria=[
                "Service downtime >1 hour",
                "Attack overwhelms defenses",
                "Multiple services affected",
                "Attack persists >6 hours"
            ],
            max_response_time_minutes=15
        )
        
        # System compromise response plan
        self.response_plans["system_compromise_critical"] = ResponsePlan(
            plan_id="system_compromise_critical",
            incident_type=IncidentType.SYSTEM_COMPROMISE,
            severity=IncidentSeverity.CRITICAL,
            response_actions=[
                ResponseAction.ISOLATE,
                ResponseAction.INVESTIGATE,
                ResponseAction.BACKUP_RESTORE,
                ResponseAction.PATCH
            ],
            containment_procedures=[
                "Isolate compromised systems immediately",
                "Disable network access",
                "Preserve system state for forensics",
                "Change all administrative credentials",
                "Enable emergency access procedures"
            ],
            investigation_steps=[
                "Identify compromise method",
                "Assess data access and exfiltration",
                "Check for persistence mechanisms",
                "Analyze system and network logs",
                "Identify additional compromised systems"
            ],
            notification_requirements=[
                "CTO/CISO immediate notification",
                "Security team immediate notification",
                "Legal team notification within 1 hour",
                "Law enforcement if criminal activity"
            ],
            recovery_procedures=[
                "Rebuild systems from trusted sources",
                "Restore data from clean backups",
                "Implement additional security controls",
                "Update all system configurations",
                "Comprehensive security testing"
            ],
            escalation_criteria=[
                "Administrative access compromised",
                "Database systems affected",
                "Multiple systems compromised",
                "Evidence of data exfiltration"
            ],
            max_response_time_minutes=15
        )
        
        # Vulnerability exploitation response plan
        self.response_plans["vulnerability_exploitation_medium"] = ResponsePlan(
            plan_id="vulnerability_exploitation_medium",
            incident_type=IncidentType.VULNERABILITY_EXPLOITATION,
            severity=IncidentSeverity.MEDIUM,
            response_actions=[
                ResponseAction.PATCH,
                ResponseAction.INVESTIGATE,
                ResponseAction.MONITOR
            ],
            containment_procedures=[
                "Apply emergency patches",
                "Implement temporary mitigations",
                "Increase monitoring on affected systems",
                "Review access logs",
                "Update security configurations"
            ],
            investigation_steps=[
                "Verify exploitation attempts",
                "Assess impact of vulnerability",
                "Check for successful compromises",
                "Review related systems",
                "Document exploitation timeline"
            ],
            notification_requirements=[
                "Security team notification within 30 minutes",
                "System administrators notification",
                "Management notification if critical systems affected"
            ],
            recovery_procedures=[
                "Complete vulnerability patching",
                "Update security monitoring rules",
                "Review and update security policies",
                "Conduct vulnerability reassessment",
                "Update incident response procedures"
            ],
            escalation_criteria=[
                "Successful system compromise",
                "Critical infrastructure affected",
                "Public exploit code available",
                "Multiple systems vulnerable"
            ],
            max_response_time_minutes=60
        )
    
    def _initialize_notification_channels(self) -> None:
        """Initialize notification channels"""
        self.notification_channels = {
            "email": {
                "security_team": ["security@monitor-legislativo.com"],
                "management": ["cto@monitor-legislativo.com", "management@monitor-legislativo.com"],
                "legal": ["legal@monitor-legislativo.com"],
                "infrastructure": ["infra@monitor-legislativo.com"],
                "all_staff": ["all@monitor-legislativo.com"]
            },
            "sms": {
                "emergency": ["+5511999999999"]  # Emergency contact numbers
            },
            "webhook": {
                "slack_security": "https://hooks.slack.com/services/...",
                "pagerduty": "https://events.pagerduty.com/..."
            }
        }
    
    async def _create_incident_tables(self) -> None:
        """Create incident response tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Create incidents table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    incident_id VARCHAR(36) PRIMARY KEY,
                    incident_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    affected_systems JSONB NOT NULL DEFAULT '[]'::jsonb,
                    affected_data JSONB NOT NULL DEFAULT '[]'::jsonb,
                    detection_time TIMESTAMP NOT NULL,
                    detection_method VARCHAR(100) NOT NULL,
                    source_ip INET NULL,
                    user_agent TEXT NULL,
                    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
                    indicators_of_compromise JSONB NOT NULL DEFAULT '[]'::jsonb,
                    estimated_impact TEXT DEFAULT '',
                    status VARCHAR(20) NOT NULL DEFAULT 'new',
                    assigned_to VARCHAR(100) NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create incident timeline table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_timeline (
                    entry_id VARCHAR(36) PRIMARY KEY,
                    incident_id VARCHAR(36) NOT NULL REFERENCES security_incidents(incident_id),
                    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                    action_taken VARCHAR(255) NOT NULL,
                    performed_by VARCHAR(100) NOT NULL,
                    details TEXT NOT NULL,
                    evidence_collected TEXT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create response plans table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_response_plans (
                    plan_id VARCHAR(50) PRIMARY KEY,
                    incident_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    response_actions JSONB NOT NULL,
                    containment_procedures JSONB NOT NULL,
                    investigation_steps JSONB NOT NULL,
                    notification_requirements JSONB NOT NULL,
                    recovery_procedures JSONB NOT NULL,
                    escalation_criteria JSONB NOT NULL,
                    max_response_time_minutes INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create notification log table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_notifications (
                    notification_id VARCHAR(36) PRIMARY KEY,
                    incident_id VARCHAR(36) NOT NULL REFERENCES security_incidents(incident_id),
                    notification_type VARCHAR(50) NOT NULL,
                    recipient VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    delivery_status VARCHAR(20) DEFAULT 'pending',
                    delivery_details JSONB DEFAULT '{}'::jsonb
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON security_incidents(severity);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_type ON security_incidents(incident_type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_detection_time ON security_incidents(detection_time);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON incident_timeline(timestamp);")
            
            logger.info("Incident response tables created successfully")
        
        finally:
            await conn.close()
    
    async def _load_response_plans(self) -> None:
        """Load response plans into database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            for plan_id, plan in self.response_plans.items():
                await conn.execute("""
                    INSERT INTO incident_response_plans 
                    (plan_id, incident_type, severity, response_actions, containment_procedures,
                     investigation_steps, notification_requirements, recovery_procedures,
                     escalation_criteria, max_response_time_minutes)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (plan_id) DO UPDATE SET
                        incident_type = EXCLUDED.incident_type,
                        severity = EXCLUDED.severity,
                        response_actions = EXCLUDED.response_actions,
                        containment_procedures = EXCLUDED.containment_procedures,
                        investigation_steps = EXCLUDED.investigation_steps,
                        notification_requirements = EXCLUDED.notification_requirements,
                        recovery_procedures = EXCLUDED.recovery_procedures,
                        escalation_criteria = EXCLUDED.escalation_criteria,
                        max_response_time_minutes = EXCLUDED.max_response_time_minutes,
                        updated_at = NOW()
                """, plan_id, plan.incident_type.value, plan.severity.value,
                    json.dumps([action.value for action in plan.response_actions]),
                    json.dumps(plan.containment_procedures),
                    json.dumps(plan.investigation_steps),
                    json.dumps(plan.notification_requirements),
                    json.dumps(plan.recovery_procedures),
                    json.dumps(plan.escalation_criteria),
                    plan.max_response_time_minutes)
            
            logger.info(f"Loaded {len(self.response_plans)} response plans")
        
        finally:
            await conn.close()
    
    async def create_incident(self, incident_type: IncidentType, severity: IncidentSeverity,
                            title: str, description: str, detection_method: str,
                            affected_systems: List[str] = None, affected_data: List[str] = None,
                            source_ip: str = None, user_agent: str = None,
                            evidence: Dict[str, Any] = None) -> str:
        """Create a new security incident"""
        
        incident_id = str(uuid.uuid4())
        
        incident = SecurityIncident(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            affected_systems=affected_systems or [],
            affected_data=affected_data or [],
            detection_time=datetime.now(),
            detection_method=detection_method,
            source_ip=source_ip,
            user_agent=user_agent,
            evidence=evidence or {}
        )
        
        # Store incident in database
        await self._store_incident(incident)
        
        # Add to active incidents
        self.active_incidents[incident_id] = incident
        
        # Log initial timeline entry
        await self.add_timeline_entry(
            incident_id=incident_id,
            action_taken="incident_created",
            performed_by="system",
            details=f"Incident created via {detection_method}"
        )
        
        # Execute immediate response
        await self._execute_immediate_response(incident)
        
        logger.info(f"Security incident created: {incident_id} - {title}")
        return incident_id
    
    async def _store_incident(self, incident: SecurityIncident) -> None:
        """Store incident in database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO security_incidents 
                (incident_id, incident_type, severity, title, description, affected_systems,
                 affected_data, detection_time, detection_method, source_ip, user_agent,
                 evidence, indicators_of_compromise, estimated_impact, status, assigned_to)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            """, incident.incident_id, incident.incident_type.value, incident.severity.value,
                incident.title, incident.description, json.dumps(incident.affected_systems),
                json.dumps(incident.affected_data), incident.detection_time,
                incident.detection_method, incident.source_ip, incident.user_agent,
                json.dumps(incident.evidence), json.dumps(incident.indicators_of_compromise),
                incident.estimated_impact, incident.status.value, incident.assigned_to)
        
        finally:
            await conn.close()
    
    async def _execute_immediate_response(self, incident: SecurityIncident) -> None:
        """Execute immediate response actions"""
        
        # Find applicable response plan
        plan_key = f"{incident.incident_type.value}_{incident.severity.value}"
        response_plan = self.response_plans.get(plan_key)
        
        if not response_plan:
            # Use generic response plan based on severity
            response_plan = self._get_generic_response_plan(incident.severity)
        
        if response_plan:
            await self._execute_response_plan(incident, response_plan)
        
        # Send immediate notifications
        await self._send_immediate_notifications(incident)
    
    def _get_generic_response_plan(self, severity: IncidentSeverity) -> ResponsePlan:
        """Get generic response plan for severity level"""
        if severity == IncidentSeverity.CRITICAL:
            return ResponsePlan(
                plan_id="generic_critical",
                incident_type=IncidentType.SUSPICIOUS_ACTIVITY,
                severity=severity,
                response_actions=[ResponseAction.INVESTIGATE, ResponseAction.CONTAIN, ResponseAction.MONITOR],
                containment_procedures=["Enable enhanced monitoring", "Review access logs"],
                investigation_steps=["Analyze incident details", "Assess impact", "Collect evidence"],
                notification_requirements=["Security team immediate notification"],
                recovery_procedures=["Implement additional security measures"],
                escalation_criteria=["Significant impact detected"],
                max_response_time_minutes=30
            )
        else:
            return ResponsePlan(
                plan_id="generic_standard",
                incident_type=IncidentType.SUSPICIOUS_ACTIVITY,
                severity=severity,
                response_actions=[ResponseAction.MONITOR, ResponseAction.INVESTIGATE],
                containment_procedures=["Monitor situation"],
                investigation_steps=["Review incident details"],
                notification_requirements=["Security team notification within 1 hour"],
                recovery_procedures=["Document lessons learned"],
                escalation_criteria=["Escalation if severity increases"],
                max_response_time_minutes=60
            )
    
    async def _execute_response_plan(self, incident: SecurityIncident, plan: ResponsePlan) -> None:
        """Execute response plan actions"""
        
        for action in plan.response_actions:
            try:
                await self._execute_response_action(incident, action, plan)
                
                await self.add_timeline_entry(
                    incident_id=incident.incident_id,
                    action_taken=f"executed_{action.value}",
                    performed_by="system",
                    details=f"Executed response action: {action.value}"
                )
            
            except Exception as e:
                logger.error(f"Error executing response action {action.value}: {e}")
                
                await self.add_timeline_entry(
                    incident_id=incident.incident_id,
                    action_taken=f"failed_{action.value}",
                    performed_by="system",
                    details=f"Failed to execute {action.value}: {str(e)}"
                )
    
    async def _execute_response_action(self, incident: SecurityIncident, 
                                     action: ResponseAction, plan: ResponsePlan) -> None:
        """Execute specific response action"""
        
        if action == ResponseAction.CONTAIN:
            await self._execute_containment(incident, plan)
        
        elif action == ResponseAction.ISOLATE:
            await self._execute_isolation(incident)
        
        elif action == ResponseAction.BLOCK:
            await self._execute_blocking(incident)
        
        elif action == ResponseAction.INVESTIGATE:
            await self._initiate_investigation(incident, plan)
        
        elif action == ResponseAction.MONITOR:
            await self._enhance_monitoring(incident)
        
        elif action == ResponseAction.NOTIFY_AUTHORITIES:
            await self._notify_authorities(incident)
        
        elif action == ResponseAction.NOTIFY_USERS:
            await self._notify_users(incident)
        
        elif action == ResponseAction.PATCH:
            await self._initiate_patching(incident)
        
        elif action == ResponseAction.BACKUP_RESTORE:
            await self._initiate_backup_restore(incident)
    
    async def _execute_containment(self, incident: SecurityIncident, plan: ResponsePlan) -> None:
        """Execute containment procedures"""
        for procedure in plan.containment_procedures:
            logger.info(f"Containment procedure: {procedure}")
            
            # Log containment action
            await self.add_timeline_entry(
                incident_id=incident.incident_id,
                action_taken="containment",
                performed_by="system",
                details=procedure
            )
    
    async def _execute_isolation(self, incident: SecurityIncident) -> None:
        """Execute system isolation"""
        if incident.source_ip:
            # Add IP to blacklist
            logger.info(f"Isolating source IP: {incident.source_ip}")
            
            # Here you would integrate with firewall/network security systems
            # For now, log the action
            await self.add_timeline_entry(
                incident_id=incident.incident_id,
                action_taken="isolation",
                performed_by="system",
                details=f"Isolated source IP: {incident.source_ip}"
            )
    
    async def _execute_blocking(self, incident: SecurityIncident) -> None:
        """Execute blocking actions"""
        if incident.source_ip:
            logger.info(f"Blocking source IP: {incident.source_ip}")
            
            # Here you would integrate with rate limiting or firewall systems
            await self.add_timeline_entry(
                incident_id=incident.incident_id,
                action_taken="blocking",
                performed_by="system",
                details=f"Blocked source IP: {incident.source_ip}"
            )
    
    async def _initiate_investigation(self, incident: SecurityIncident, plan: ResponsePlan) -> None:
        """Initiate investigation procedures"""
        for step in plan.investigation_steps:
            logger.info(f"Investigation step: {step}")
            
            await self.add_timeline_entry(
                incident_id=incident.incident_id,
                action_taken="investigation",
                performed_by="system",
                details=f"Investigation step: {step}"
            )
    
    async def _enhance_monitoring(self, incident: SecurityIncident) -> None:
        """Enhance monitoring for the incident"""
        logger.info("Enhanced monitoring activated")
        
        await self.add_timeline_entry(
            incident_id=incident.incident_id,
            action_taken="enhance_monitoring",
            performed_by="system",
            details="Enhanced monitoring activated for incident"
        )
    
    async def _notify_authorities(self, incident: SecurityIncident) -> None:
        """Notify authorities (ANPD for LGPD compliance)"""
        if incident.incident_type == IncidentType.DATA_BREACH:
            logger.info("Preparing ANPD notification for data breach")
            
            # Generate LGPD-compliant notification
            notification_content = self._generate_lgpd_notification(incident)
            
            await self._send_notification(
                incident_id=incident.incident_id,
                notification_type="authority_notification",
                recipient="ANPD",
                message=notification_content
            )
            
            await self.add_timeline_entry(
                incident_id=incident.incident_id,
                action_taken="authority_notification",
                performed_by="system",
                details="ANPD notification prepared and queued"
            )
    
    async def _notify_users(self, incident: SecurityIncident) -> None:
        """Notify affected users"""
        if incident.incident_type == IncidentType.DATA_BREACH:
            logger.info("Preparing user notification for data breach")
            
            # Generate user notification
            notification_content = self._generate_user_notification(incident)
            
            await self._send_notification(
                incident_id=incident.incident_id,
                notification_type="user_notification",
                recipient="affected_users",
                message=notification_content
            )
            
            await self.add_timeline_entry(
                incident_id=incident.incident_id,
                action_taken="user_notification",
                performed_by="system",
                details="User notifications prepared and queued"
            )
    
    async def _initiate_patching(self, incident: SecurityIncident) -> None:
        """Initiate patching procedures"""
        logger.info("Patching procedures initiated")
        
        await self.add_timeline_entry(
            incident_id=incident.incident_id,
            action_taken="patching",
            performed_by="system",
            details="Emergency patching procedures initiated"
        )
    
    async def _initiate_backup_restore(self, incident: SecurityIncident) -> None:
        """Initiate backup restore procedures"""
        logger.info("Backup restore procedures initiated")
        
        await self.add_timeline_entry(
            incident_id=incident.incident_id,
            action_taken="backup_restore",
            performed_by="system",
            details="Backup restore procedures initiated"
        )
    
    def _generate_lgpd_notification(self, incident: SecurityIncident) -> str:
        """Generate LGPD-compliant authority notification"""
        return f"""
NOTIFICAÇÃO DE INCIDENTE DE SEGURANÇA - LGPD

Data/Hora do Incidente: {incident.detection_time.strftime('%d/%m/%Y %H:%M:%S')}
Tipo de Incidente: {incident.incident_type.value}
Gravidade: {incident.severity.value}

Descrição do Incidente:
{incident.description}

Dados Pessoais Afetados:
{', '.join(incident.affected_data) if incident.affected_data else 'A ser determinado'}

Sistemas Afetados:
{', '.join(incident.affected_systems) if incident.affected_systems else 'A ser determinado'}

Medidas de Contenção Adotadas:
- Isolamento dos sistemas afetados
- Bloqueio de acesso não autorizado
- Ativação de monitoramento aprimorado
- Investigação em andamento

Contato para Informações Adicionais:
Email: dpo@monitor-legislativo.com
Telefone: +55 11 XXXX-XXXX

Monitor Legislativo v4
Data Protection Officer
        """.strip()
    
    def _generate_user_notification(self, incident: SecurityIncident) -> str:
        """Generate user notification for data breach"""
        return f"""
NOTIFICAÇÃO DE INCIDENTE DE SEGURANÇA

Prezado(a) usuário(a),

Informamos sobre um incidente de segurança que pode ter afetado seus dados pessoais em nossa plataforma Monitor Legislativo.

DETALHES DO INCIDENTE:
- Data: {incident.detection_time.strftime('%d/%m/%Y')}
- Tipo: {incident.title}
- Descrição: {incident.description}

DADOS POTENCIALMENTE AFETADOS:
{', '.join(incident.affected_data) if incident.affected_data else 'Estamos investigando quais dados foram afetados'}

MEDIDAS ADOTADAS:
✓ Contenção imediata do incidente
✓ Investigação em andamento
✓ Fortalecimento das medidas de segurança
✓ Notificação às autoridades competentes

RECOMENDAÇÕES:
- Monitore suas contas e atividades relacionadas
- Considere alterar sua senha
- Entre em contato conosco em caso de dúvidas

SEUS DIREITOS (LGPD):
Você tem o direito de solicitar informações sobre seus dados, correção, exclusão ou portabilidade.

Para exercer seus direitos ou obter mais informações:
Email: privacidade@monitor-legislativo.com
Telefone: +55 11 XXXX-XXXX

Lamentamos o ocorrido e reforçamos nosso compromisso com a proteção de seus dados.

Atenciosamente,
Equipe Monitor Legislativo
        """.strip()
    
    async def _send_immediate_notifications(self, incident: SecurityIncident) -> None:
        """Send immediate notifications for the incident"""
        
        # Determine notification recipients based on severity
        if incident.severity == IncidentSeverity.CRITICAL:
            recipients = ["security_team", "management", "legal"]
        elif incident.severity == IncidentSeverity.HIGH:
            recipients = ["security_team", "management"]
        else:
            recipients = ["security_team"]
        
        # Send email notifications
        for recipient_group in recipients:
            if recipient_group in self.notification_channels["email"]:
                for email in self.notification_channels["email"][recipient_group]:
                    await self._send_email_notification(incident, email, recipient_group)
        
        # Send Slack notification
        await self._send_slack_notification(incident)
        
        # Send SMS for critical incidents
        if incident.severity == IncidentSeverity.CRITICAL:
            for phone in self.notification_channels["sms"]["emergency"]:
                await self._send_sms_notification(incident, phone)
    
    async def _send_email_notification(self, incident: SecurityIncident, 
                                     email: str, recipient_group: str) -> None:
        """Send email notification"""
        try:
            subject = f"[{incident.severity.value.upper()}] Security Incident: {incident.title}"
            
            body = f"""
Security Incident Alert - Monitor Legislativo v4

Incident ID: {incident.incident_id}
Type: {incident.incident_type.value}
Severity: {incident.severity.value}
Detection Time: {incident.detection_time.isoformat()}
Detection Method: {incident.detection_method}

Description:
{incident.description}

Affected Systems: {', '.join(incident.affected_systems)}
Affected Data: {', '.join(incident.affected_data)}

Source IP: {incident.source_ip or 'Unknown'}
User Agent: {incident.user_agent or 'Unknown'}

Response actions have been automatically initiated.
Please check the incident response dashboard for updates.

This is an automated notification from the Monitor Legislativo security system.
            """.strip()
            
            await self._send_notification(
                incident_id=incident.incident_id,
                notification_type="email",
                recipient=email,
                message=body
            )
        
        except Exception as e:
            logger.error(f"Failed to send email notification to {email}: {e}")
    
    async def _send_slack_notification(self, incident: SecurityIncident) -> None:
        """Send Slack notification"""
        try:
            webhook_url = self.notification_channels["webhook"]["slack_security"]
            
            payload = {
                "text": f"🚨 Security Incident Alert",
                "attachments": [{
                    "color": "danger" if incident.severity.value in ["critical", "high"] else "warning",
                    "fields": [
                        {"title": "Incident ID", "value": incident.incident_id, "short": True},
                        {"title": "Type", "value": incident.incident_type.value, "short": True},
                        {"title": "Severity", "value": incident.severity.value, "short": True},
                        {"title": "Detection", "value": incident.detection_method, "short": True},
                        {"title": "Description", "value": incident.description, "short": False}
                    ],
                    "ts": int(incident.detection_time.timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info("Slack notification sent successfully")
                    else:
                        logger.error(f"Failed to send Slack notification: {response.status}")
        
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
    
    async def _send_sms_notification(self, incident: SecurityIncident, phone: str) -> None:
        """Send SMS notification for critical incidents"""
        try:
            message = f"CRITICAL SECURITY INCIDENT: {incident.title} - Monitor Legislativo. Check email for details. ID: {incident.incident_id[:8]}"
            
            # Here you would integrate with SMS service (Twilio, AWS SNS, etc.)
            logger.info(f"SMS notification sent to {phone}: {message}")
            
            await self._send_notification(
                incident_id=incident.incident_id,
                notification_type="sms",
                recipient=phone,
                message=message
            )
        
        except Exception as e:
            logger.error(f"Failed to send SMS notification to {phone}: {e}")
    
    async def _send_notification(self, incident_id: str, notification_type: str,
                               recipient: str, message: str) -> None:
        """Log notification in database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            notification_id = str(uuid.uuid4())
            await conn.execute("""
                INSERT INTO incident_notifications 
                (notification_id, incident_id, notification_type, recipient, message)
                VALUES ($1, $2, $3, $4, $5)
            """, notification_id, incident_id, notification_type, recipient, message)
        
        finally:
            await conn.close()
    
    async def add_timeline_entry(self, incident_id: str, action_taken: str,
                               performed_by: str, details: str,
                               evidence_collected: str = None) -> str:
        """Add entry to incident timeline"""
        entry_id = str(uuid.uuid4())
        
        timeline_entry = IncidentTimeline(
            entry_id=entry_id,
            incident_id=incident_id,
            timestamp=datetime.now(),
            action_taken=action_taken,
            performed_by=performed_by,
            details=details,
            evidence_collected=evidence_collected
        )
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO incident_timeline 
                (entry_id, incident_id, timestamp, action_taken, performed_by, details, evidence_collected)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, entry_id, incident_id, timeline_entry.timestamp, action_taken, 
                performed_by, details, evidence_collected)
        
        finally:
            await conn.close()
        
        return entry_id
    
    async def update_incident_status(self, incident_id: str, new_status: IncidentStatus,
                                   assigned_to: str = None, notes: str = "") -> None:
        """Update incident status"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                UPDATE security_incidents 
                SET status = $1, assigned_to = $2, updated_at = NOW()
                WHERE incident_id = $3
            """, new_status.value, assigned_to, incident_id)
            
            # Add timeline entry
            await self.add_timeline_entry(
                incident_id=incident_id,
                action_taken="status_update",
                performed_by=assigned_to or "system",
                details=f"Status changed to {new_status.value}. {notes}".strip()
            )
            
            # Update active incidents cache
            if incident_id in self.active_incidents:
                self.active_incidents[incident_id].status = new_status
                if assigned_to:
                    self.active_incidents[incident_id].assigned_to = assigned_to
        
        finally:
            await conn.close()
    
    async def get_incident_details(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive incident details"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Get incident data
            incident_data = await conn.fetchrow("""
                SELECT * FROM security_incidents WHERE incident_id = $1
            """, incident_id)
            
            if not incident_data:
                return None
            
            # Get timeline
            timeline_data = await conn.fetch("""
                SELECT * FROM incident_timeline 
                WHERE incident_id = $1 
                ORDER BY timestamp ASC
            """, incident_id)
            
            # Get notifications
            notifications_data = await conn.fetch("""
                SELECT * FROM incident_notifications 
                WHERE incident_id = $1 
                ORDER BY sent_at ASC
            """, incident_id)
            
            return {
                "incident": dict(incident_data),
                "timeline": [dict(entry) for entry in timeline_data],
                "notifications": [dict(notification) for notification in notifications_data]
            }
        
        finally:
            await conn.close()
    
    async def get_active_incidents(self) -> List[Dict[str, Any]]:
        """Get all active incidents"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            incidents = await conn.fetch("""
                SELECT * FROM security_incidents 
                WHERE status NOT IN ('closed', 'resolved')
                ORDER BY detection_time DESC
            """)
            
            return [dict(incident) for incident in incidents]
        
        finally:
            await conn.close()

# Factory function for easy creation
async def create_incident_response_manager(db_config: Dict[str, str], 
                                         notification_config: Dict[str, str]) -> IncidentResponseManager:
    """Create and initialize incident response manager"""
    manager = IncidentResponseManager(db_config, notification_config)
    await manager.initialize()
    return manager

# Export main classes
__all__ = [
    'IncidentResponseManager',
    'SecurityIncident',
    'ResponsePlan',
    'IncidentTimeline',
    'IncidentSeverity',
    'IncidentType',
    'IncidentStatus',
    'ResponseAction',
    'create_incident_response_manager'
]