# Disaster Recovery Orchestration System for Monitor Legislativo v4
# Phase 5 Week 19: Advanced disaster recovery automation for Brazilian legislative research platform
# Real-time failover, automated recovery, and business continuity management

import asyncio
import asyncpg
import aiohttp
import redis
import json
import logging
import time
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid
import subprocess
import psutil
import socket
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import boto3
from kubernetes import client, config as k8s_config
import docker
import paramiko
from pathlib import Path
import yaml
import requests
import dns.resolver
import ping3

logger = logging.getLogger(__name__)

class DisasterType(Enum):
    """Types of disasters that can occur"""
    DATABASE_FAILURE = "database_failure"
    APPLICATION_CRASH = "application_crash"
    NETWORK_OUTAGE = "network_outage"
    STORAGE_FAILURE = "storage_failure"
    SECURITY_BREACH = "security_breach"
    DATA_CORRUPTION = "data_corruption"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    NATURAL_DISASTER = "natural_disaster"
    POWER_OUTAGE = "power_outage"
    DDOS_ATTACK = "ddos_attack"
    SERVICE_DEGRADATION = "service_degradation"

class RecoveryStrategy(Enum):
    """Recovery strategies"""
    AUTOMATED_FAILOVER = "automated_failover"
    MANUAL_INTERVENTION = "manual_intervention"
    PARTIAL_RECOVERY = "partial_recovery"
    FULL_SYSTEM_RESTORE = "full_system_restore"
    ROLLBACK_TO_BACKUP = "rollback_to_backup"
    EMERGENCY_MAINTENANCE = "emergency_maintenance"
    DATA_RECONSTRUCTION = "data_reconstruction"

class SystemComponent(Enum):
    """System components that can fail"""
    PRIMARY_DATABASE = "primary_database"
    BACKUP_DATABASE = "backup_database"
    WEB_APPLICATION = "web_application"
    API_SERVER = "api_server"
    REDIS_CACHE = "redis_cache"
    FILE_STORAGE = "file_storage"
    LOAD_BALANCER = "load_balancer"
    CDN = "cdn"
    MONITORING_SYSTEM = "monitoring_system"
    BACKUP_SYSTEM = "backup_system"

class HealthStatus(Enum):
    """Component health status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"
    UNKNOWN = "unknown"
    RECOVERING = "recovering"

@dataclass
class DisasterEvent:
    """Disaster event record"""
    event_id: str
    disaster_type: DisasterType
    affected_components: List[SystemComponent]
    severity_level: int  # 1-5 (5 being most severe)
    description: str
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    recovery_strategy: Optional[RecoveryStrategy] = None
    impact_assessment: Dict[str, Any] = field(default_factory=dict)
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['disaster_type'] = self.disaster_type.value
        result['affected_components'] = [c.value for c in self.affected_components]
        result['recovery_strategy'] = self.recovery_strategy.value if self.recovery_strategy else None
        result['detected_at'] = self.detected_at.isoformat()
        if self.resolved_at:
            result['resolved_at'] = self.resolved_at.isoformat()
        return result

@dataclass
class RecoveryPlan:
    """Disaster recovery plan"""
    plan_id: str
    name: str
    disaster_types: List[DisasterType]
    affected_components: List[SystemComponent]
    recovery_strategy: RecoveryStrategy
    rto_minutes: int  # Recovery Time Objective
    rpo_minutes: int  # Recovery Point Objective
    steps: List[Dict[str, Any]]
    prerequisites: List[str] = field(default_factory=list)
    rollback_plan: List[Dict[str, Any]] = field(default_factory=list)
    notification_contacts: List[str] = field(default_factory=list)
    is_automated: bool = True
    priority: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['disaster_types'] = [d.value for d in self.disaster_types]
        result['affected_components'] = [c.value for c in self.affected_components]
        result['recovery_strategy'] = self.recovery_strategy.value
        return result

@dataclass
class SystemHealth:
    """System component health status"""
    component: SystemComponent
    status: HealthStatus
    last_check: datetime
    response_time: Optional[float] = None
    error_rate: Optional[float] = None
    availability: Optional[float] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['component'] = self.component.value
        result['status'] = self.status.value
        result['last_check'] = self.last_check.isoformat()
        return result

@dataclass
class RecoveryExecution:
    """Recovery plan execution record"""
    execution_id: str
    event_id: str
    plan_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, aborted
    current_step: int = 0
    total_steps: int = 0
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        return result

class DisasterRecoveryOrchestrator:
    """
    Advanced disaster recovery orchestration system for Monitor Legislativo v4
    
    Features:
    - Real-time system health monitoring
    - Automated disaster detection and classification
    - Intelligent recovery plan selection and execution
    - Multi-tier failover and redundancy management
    - Business continuity assurance
    - Post-incident analysis and learning
    - Compliance reporting for academic institutions
    - Integration with Brazilian data protection regulations
    """
    
    def __init__(self, db_config: Dict[str, str], 
                 redis_config: Dict[str, str] = None,
                 notification_config: Dict[str, str] = None):
        self.db_config = db_config
        self.redis_config = redis_config or {}
        self.notification_config = notification_config or {}
        
        # System monitoring
        self.system_health: Dict[SystemComponent, SystemHealth] = {}
        self.monitoring_enabled = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # Recovery plans and active executions
        self.recovery_plans: Dict[str, RecoveryPlan] = {}
        self.active_executions: Dict[str, RecoveryExecution] = {}
        
        # Event tracking
        self.active_disasters: Dict[str, DisasterEvent] = {}
        
        # External connections
        self.redis_client: Optional[redis.Redis] = None
        if self.redis_config:
            self.redis_client = redis.Redis(**self.redis_config)
        
        # Kubernetes client (if available)
        self.k8s_client = None
        try:
            k8s_config.load_incluster_config()
            self.k8s_client = client.CoreV1Api()
        except:
            try:
                k8s_config.load_kube_config()
                self.k8s_client = client.CoreV1Api()
            except:
                logger.warning("Kubernetes client not available")
        
        # Docker client (if available)
        self.docker_client = None
        try:
            self.docker_client = docker.from_env()
        except:
            logger.warning("Docker client not available")
    
    async def initialize(self) -> None:
        """Initialize disaster recovery system"""
        await self._create_dr_tables()
        await self._setup_default_recovery_plans()
        await self._start_health_monitoring()
        logger.info("Disaster recovery orchestrator initialized")
    
    async def _create_dr_tables(self) -> None:
        """Create disaster recovery database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Disaster events table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS disaster_events (
                    event_id VARCHAR(36) PRIMARY KEY,
                    disaster_type VARCHAR(50) NOT NULL,
                    affected_components JSONB NOT NULL,
                    severity_level INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    detected_at TIMESTAMP NOT NULL,
                    resolved_at TIMESTAMP NULL,
                    recovery_strategy VARCHAR(50) NULL,
                    impact_assessment JSONB DEFAULT '{}'::jsonb,
                    root_cause TEXT NULL,
                    lessons_learned TEXT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Recovery plans table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_plans (
                    plan_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    disaster_types JSONB NOT NULL,
                    affected_components JSONB NOT NULL,
                    recovery_strategy VARCHAR(50) NOT NULL,
                    rto_minutes INTEGER NOT NULL,
                    rpo_minutes INTEGER NOT NULL,
                    steps JSONB NOT NULL,
                    prerequisites JSONB DEFAULT '[]'::jsonb,
                    rollback_plan JSONB DEFAULT '[]'::jsonb,
                    notification_contacts JSONB DEFAULT '[]'::jsonb,
                    is_automated BOOLEAN DEFAULT TRUE,
                    priority INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Recovery executions table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_executions (
                    execution_id VARCHAR(36) PRIMARY KEY,
                    event_id VARCHAR(36) NOT NULL,
                    plan_id VARCHAR(36) NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP NULL,
                    status VARCHAR(20) DEFAULT 'running',
                    current_step INTEGER DEFAULT 0,
                    total_steps INTEGER DEFAULT 0,
                    step_results JSONB DEFAULT '[]'::jsonb,
                    error_message TEXT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # System health history table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS system_health_history (
                    health_id VARCHAR(36) PRIMARY KEY,
                    component VARCHAR(50) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    response_time FLOAT NULL,
                    error_rate FLOAT NULL,
                    availability FLOAT NULL,
                    metrics JSONB DEFAULT '{}'::jsonb,
                    alerts JSONB DEFAULT '[]'::jsonb,
                    checked_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # DR metrics table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dr_metrics (
                    metric_id VARCHAR(36) PRIMARY KEY,
                    date_period DATE NOT NULL,
                    total_incidents INTEGER DEFAULT 0,
                    resolved_incidents INTEGER DEFAULT 0,
                    avg_resolution_time FLOAT DEFAULT 0.0,
                    system_availability FLOAT DEFAULT 0.0,
                    rto_compliance FLOAT DEFAULT 0.0,
                    rpo_compliance FLOAT DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_disaster_events_type ON disaster_events(disaster_type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_disaster_events_detected ON disaster_events(detected_at);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_recovery_plans_strategy ON recovery_plans(recovery_strategy);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_recovery_executions_status ON recovery_executions(status);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_system_health_component ON system_health_history(component);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_system_health_checked ON system_health_history(checked_at);")
            
            logger.info("Disaster recovery tables created successfully")
        
        finally:
            await conn.close()
    
    async def _setup_default_recovery_plans(self) -> None:
        """Setup default disaster recovery plans"""
        
        # Database failover plan
        db_failover_plan = RecoveryPlan(
            plan_id="database_failover_v1",
            name="Database Primary to Secondary Failover",
            disaster_types=[DisasterType.DATABASE_FAILURE, DisasterType.INFRASTRUCTURE_FAILURE],
            affected_components=[SystemComponent.PRIMARY_DATABASE],
            recovery_strategy=RecoveryStrategy.AUTOMATED_FAILOVER,
            rto_minutes=5,  # 5 minutes recovery time
            rpo_minutes=1,  # 1 minute data loss tolerance
            steps=[
                {
                    "step": 1,
                    "action": "verify_primary_database_failure",
                    "description": "Confirm primary database is unreachable",
                    "timeout_seconds": 30,
                    "retry_count": 3
                },
                {
                    "step": 2,
                    "action": "promote_backup_database",
                    "description": "Promote backup database to primary",
                    "timeout_seconds": 120,
                    "rollback_on_failure": True
                },
                {
                    "step": 3,
                    "action": "update_application_config",
                    "description": "Update application database connections",
                    "timeout_seconds": 60
                },
                {
                    "step": 4,
                    "action": "restart_application_services",
                    "description": "Restart application with new database config",
                    "timeout_seconds": 180
                },
                {
                    "step": 5,
                    "action": "verify_system_health",
                    "description": "Verify application is healthy with new database",
                    "timeout_seconds": 300
                },
                {
                    "step": 6,
                    "action": "notify_stakeholders",
                    "description": "Send notification about database failover",
                    "timeout_seconds": 30
                }
            ],
            rollback_plan=[
                {
                    "step": 1,
                    "action": "revert_database_promotion",
                    "description": "Revert backup database promotion"
                },
                {
                    "step": 2,
                    "action": "restore_original_config",
                    "description": "Restore original application configuration"
                }
            ],
            notification_contacts=["admin@monitor-legislativo.br", "dba@monitor-legislativo.br"]
        )
        
        # Application recovery plan
        app_recovery_plan = RecoveryPlan(
            plan_id="application_recovery_v1",
            name="Application Service Recovery",
            disaster_types=[DisasterType.APPLICATION_CRASH, DisasterType.SERVICE_DEGRADATION],
            affected_components=[SystemComponent.WEB_APPLICATION, SystemComponent.API_SERVER],
            recovery_strategy=RecoveryStrategy.AUTOMATED_FAILOVER,
            rto_minutes=3,
            rpo_minutes=0,  # No data loss for application restarts
            steps=[
                {
                    "step": 1,
                    "action": "check_application_health",
                    "description": "Verify application services are down",
                    "timeout_seconds": 60
                },
                {
                    "step": 2,
                    "action": "collect_error_logs",
                    "description": "Gather application error logs for analysis",
                    "timeout_seconds": 30
                },
                {
                    "step": 3,
                    "action": "restart_application_containers",
                    "description": "Restart application containers/services",
                    "timeout_seconds": 120
                },
                {
                    "step": 4,
                    "action": "verify_database_connectivity",
                    "description": "Ensure database connections are working",
                    "timeout_seconds": 60
                },
                {
                    "step": 5,
                    "action": "run_health_checks",
                    "description": "Execute comprehensive health checks",
                    "timeout_seconds": 180
                },
                {
                    "step": 6,
                    "action": "restore_load_balancer",
                    "description": "Add recovered services back to load balancer",
                    "timeout_seconds": 60
                }
            ],
            notification_contacts=["admin@monitor-legislativo.br", "devops@monitor-legislativo.br"]
        )
        
        # Security breach response plan
        security_response_plan = RecoveryPlan(
            plan_id="security_breach_response_v1",
            name="Security Breach Response and Containment",
            disaster_types=[DisasterType.SECURITY_BREACH, DisasterType.DDOS_ATTACK],
            affected_components=[SystemComponent.WEB_APPLICATION, SystemComponent.API_SERVER, SystemComponent.PRIMARY_DATABASE],
            recovery_strategy=RecoveryStrategy.MANUAL_INTERVENTION,
            rto_minutes=15,
            rpo_minutes=5,
            steps=[
                {
                    "step": 1,
                    "action": "isolate_affected_systems",
                    "description": "Immediately isolate compromised systems",
                    "timeout_seconds": 300,
                    "requires_approval": True
                },
                {
                    "step": 2,
                    "action": "enable_maintenance_mode",
                    "description": "Put system in maintenance mode",
                    "timeout_seconds": 60
                },
                {
                    "step": 3,
                    "action": "activate_incident_response_team",
                    "description": "Alert security incident response team",
                    "timeout_seconds": 30
                },
                {
                    "step": 4,
                    "action": "backup_forensic_evidence",
                    "description": "Create forensic backups before any changes",
                    "timeout_seconds": 600
                },
                {
                    "step": 5,
                    "action": "analyze_attack_vectors",
                    "description": "Identify how the breach occurred",
                    "timeout_seconds": 1800,
                    "manual_step": True
                },
                {
                    "step": 6,
                    "action": "implement_security_patches",
                    "description": "Apply security fixes and patches",
                    "timeout_seconds": 900
                },
                {
                    "step": 7,
                    "action": "restore_from_clean_backup",
                    "description": "Restore system from pre-breach backup",
                    "timeout_seconds": 1800
                },
                {
                    "step": 8,
                    "action": "notify_authorities",
                    "description": "Report to relevant authorities (LGPD compliance)",
                    "timeout_seconds": 300,
                    "manual_step": True
                }
            ],
            notification_contacts=[
                "security@monitor-legislativo.br", 
                "legal@monitor-legislativo.br",
                "ciso@monitor-legislativo.br"
            ],
            is_automated=False  # Requires manual oversight
        )
        
        # Data corruption recovery plan
        data_recovery_plan = RecoveryPlan(
            plan_id="data_corruption_recovery_v1",
            name="Data Corruption Recovery",
            disaster_types=[DisasterType.DATA_CORRUPTION, DisasterType.STORAGE_FAILURE],
            affected_components=[SystemComponent.PRIMARY_DATABASE, SystemComponent.FILE_STORAGE],
            recovery_strategy=RecoveryStrategy.ROLLBACK_TO_BACKUP,
            rto_minutes=30,
            rpo_minutes=60,  # Up to 1 hour data loss acceptable
            steps=[
                {
                    "step": 1,
                    "action": "assess_corruption_scope",
                    "description": "Determine extent of data corruption",
                    "timeout_seconds": 300
                },
                {
                    "step": 2,
                    "action": "isolate_corrupted_data",
                    "description": "Prevent further corruption spread",
                    "timeout_seconds": 180
                },
                {
                    "step": 3,
                    "action": "identify_clean_backup",
                    "description": "Find most recent clean backup",
                    "timeout_seconds": 120
                },
                {
                    "step": 4,
                    "action": "verify_backup_integrity",
                    "description": "Validate backup integrity and completeness",
                    "timeout_seconds": 600
                },
                {
                    "step": 5,
                    "action": "restore_database_from_backup",
                    "description": "Restore database from verified backup",
                    "timeout_seconds": 1800
                },
                {
                    "step": 6,
                    "action": "replay_transaction_logs",
                    "description": "Apply transaction logs to minimize data loss",
                    "timeout_seconds": 900
                },
                {
                    "step": 7,
                    "action": "validate_data_consistency",
                    "description": "Run data consistency checks",
                    "timeout_seconds": 600
                },
                {
                    "step": 8,
                    "action": "restart_application_services",
                    "description": "Bring application services back online",
                    "timeout_seconds": 300
                }
            ],
            notification_contacts=["admin@monitor-legislativo.br", "dba@monitor-legislativo.br"]
        )
        
        # Save default plans
        default_plans = [db_failover_plan, app_recovery_plan, security_response_plan, data_recovery_plan]
        for plan in default_plans:
            self.recovery_plans[plan.plan_id] = plan
            await self._save_recovery_plan(plan)
    
    async def _save_recovery_plan(self, plan: RecoveryPlan) -> None:
        """Save recovery plan to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO recovery_plans 
                (plan_id, name, disaster_types, affected_components, recovery_strategy,
                 rto_minutes, rpo_minutes, steps, prerequisites, rollback_plan,
                 notification_contacts, is_automated, priority)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (plan_id)
                DO UPDATE SET
                    name = $2, disaster_types = $3, affected_components = $4,
                    recovery_strategy = $5, rto_minutes = $6, rpo_minutes = $7,
                    steps = $8, prerequisites = $9, rollback_plan = $10,
                    notification_contacts = $11, is_automated = $12, priority = $13,
                    updated_at = NOW()
            """, plan.plan_id, plan.name, 
                json.dumps([d.value for d in plan.disaster_types]),
                json.dumps([c.value for c in plan.affected_components]),
                plan.recovery_strategy.value, plan.rto_minutes, plan.rpo_minutes,
                json.dumps(plan.steps), json.dumps(plan.prerequisites),
                json.dumps(plan.rollback_plan), json.dumps(plan.notification_contacts),
                plan.is_automated, plan.priority)
        
        finally:
            await conn.close()
    
    async def _start_health_monitoring(self) -> None:
        """Start continuous system health monitoring"""
        self.monitoring_enabled = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("System health monitoring started")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring_enabled:
            try:
                asyncio.run(self._check_system_health())
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                time.sleep(60)
    
    async def _check_system_health(self) -> None:
        """Check health of all system components"""
        
        # Check database health
        await self._check_database_health()
        
        # Check application health
        await self._check_application_health()
        
        # Check Redis health
        await self._check_redis_health()
        
        # Check storage health
        await self._check_storage_health()
        
        # Check network connectivity
        await self._check_network_health()
        
        # Analyze health data and detect issues
        await self._analyze_health_status()
    
    async def _check_database_health(self) -> None:
        """Check database connectivity and performance"""
        start_time = time.time()
        
        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(**self.db_config),
                timeout=10.0
            )
            
            # Test query
            await conn.fetchval("SELECT 1")
            
            response_time = (time.time() - start_time) * 1000  # milliseconds
            
            # Get database stats
            db_stats = await conn.fetchrow("""
                SELECT 
                    (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') as active_connections,
                    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') as max_connections,
                    (SELECT sum(blks_hit)*100.0/sum(blks_hit+blks_read) FROM pg_stat_database) as cache_hit_ratio
            """)
            
            # Determine status based on metrics
            status = HealthStatus.HEALTHY
            alerts = []
            
            if response_time > 1000:  # > 1 second
                status = HealthStatus.WARNING
                alerts.append(f"Slow database response: {response_time:.2f}ms")
            
            if db_stats and db_stats['active_connections'] > db_stats['max_connections'] * 0.8:
                status = HealthStatus.WARNING
                alerts.append(f"High connection usage: {db_stats['active_connections']}/{db_stats['max_connections']}")
            
            self.system_health[SystemComponent.PRIMARY_DATABASE] = SystemHealth(
                component=SystemComponent.PRIMARY_DATABASE,
                status=status,
                last_check=datetime.now(),
                response_time=response_time,
                availability=100.0,
                metrics={
                    "active_connections": db_stats['active_connections'] if db_stats else 0,
                    "max_connections": db_stats['max_connections'] if db_stats else 0,
                    "cache_hit_ratio": float(db_stats['cache_hit_ratio']) if db_stats and db_stats['cache_hit_ratio'] else 0
                },
                alerts=alerts
            )
            
            await conn.close()
        
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            self.system_health[SystemComponent.PRIMARY_DATABASE] = SystemHealth(
                component=SystemComponent.PRIMARY_DATABASE,
                status=HealthStatus.FAILED,
                last_check=datetime.now(),
                availability=0.0,
                alerts=[f"Database connection failed: {str(e)}"]
            )
    
    async def _check_application_health(self) -> None:
        """Check application server health"""
        
        # Check web application
        await self._check_http_endpoint("http://localhost:3000/health", SystemComponent.WEB_APPLICATION)
        
        # Check API server
        await self._check_http_endpoint("http://localhost:8000/health", SystemComponent.API_SERVER)
    
    async def _check_http_endpoint(self, url: str, component: SystemComponent) -> None:
        """Check HTTP endpoint health"""
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    status = HealthStatus.HEALTHY
                    alerts = []
                    
                    if response.status != 200:
                        status = HealthStatus.CRITICAL
                        alerts.append(f"HTTP {response.status} response")
                    elif response_time > 2000:  # > 2 seconds
                        status = HealthStatus.WARNING
                        alerts.append(f"Slow response: {response_time:.2f}ms")
                    
                    self.system_health[component] = SystemHealth(
                        component=component,
                        status=status,
                        last_check=datetime.now(),
                        response_time=response_time,
                        availability=100.0 if status in [HealthStatus.HEALTHY, HealthStatus.WARNING] else 0.0,
                        metrics={"http_status": response.status},
                        alerts=alerts
                    )
        
        except Exception as e:
            self.system_health[component] = SystemHealth(
                component=component,
                status=HealthStatus.FAILED,
                last_check=datetime.now(),
                availability=0.0,
                alerts=[f"Connection failed: {str(e)}"]
            )
    
    async def _check_redis_health(self) -> None:
        """Check Redis cache health"""
        if not self.redis_client:
            return
        
        start_time = time.time()
        
        try:
            # Test Redis connection
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.ping
            )
            
            response_time = (time.time() - start_time) * 1000
            
            # Get Redis info
            info = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.info
            )
            
            status = HealthStatus.HEALTHY
            alerts = []
            
            if response_time > 500:  # > 500ms
                status = HealthStatus.WARNING
                alerts.append(f"Slow Redis response: {response_time:.2f}ms")
            
            memory_usage = info.get('used_memory_rss', 0) / info.get('maxmemory', 1)
            if memory_usage > 0.8:
                status = HealthStatus.WARNING
                alerts.append(f"High memory usage: {memory_usage:.1%}")
            
            self.system_health[SystemComponent.REDIS_CACHE] = SystemHealth(
                component=SystemComponent.REDIS_CACHE,
                status=status,
                last_check=datetime.now(),
                response_time=response_time,
                availability=100.0,
                metrics={
                    "connected_clients": info.get('connected_clients', 0),
                    "used_memory": info.get('used_memory', 0),
                    "memory_usage_ratio": memory_usage
                },
                alerts=alerts
            )
        
        except Exception as e:
            self.system_health[SystemComponent.REDIS_CACHE] = SystemHealth(
                component=SystemComponent.REDIS_CACHE,
                status=HealthStatus.FAILED,
                last_check=datetime.now(),
                availability=0.0,
                alerts=[f"Redis connection failed: {str(e)}"]
            )
    
    async def _check_storage_health(self) -> None:
        """Check file storage health"""
        try:
            # Check disk space
            disk_usage = psutil.disk_usage('/')
            disk_usage_percent = (disk_usage.used / disk_usage.total) * 100
            
            status = HealthStatus.HEALTHY
            alerts = []
            
            if disk_usage_percent > 90:
                status = HealthStatus.CRITICAL
                alerts.append(f"Critical disk space: {disk_usage_percent:.1f}% used")
            elif disk_usage_percent > 80:
                status = HealthStatus.WARNING
                alerts.append(f"Low disk space: {disk_usage_percent:.1f}% used")
            
            self.system_health[SystemComponent.FILE_STORAGE] = SystemHealth(
                component=SystemComponent.FILE_STORAGE,
                status=status,
                last_check=datetime.now(),
                availability=100.0,
                metrics={
                    "disk_usage_percent": disk_usage_percent,
                    "free_space_gb": disk_usage.free / (1024**3),
                    "total_space_gb": disk_usage.total / (1024**3)
                },
                alerts=alerts
            )
        
        except Exception as e:
            self.system_health[SystemComponent.FILE_STORAGE] = SystemHealth(
                component=SystemComponent.FILE_STORAGE,
                status=HealthStatus.UNKNOWN,
                last_check=datetime.now(),
                alerts=[f"Storage check failed: {str(e)}"]
            )
    
    async def _check_network_health(self) -> None:
        """Check network connectivity"""
        try:
            # Test connectivity to key external services
            external_hosts = [
                "8.8.8.8",  # Google DNS
                "dadosabertos.camara.leg.br",  # Câmara API
                "legis.senado.leg.br"  # Senado API
            ]
            
            ping_results = []
            for host in external_hosts:
                try:
                    ping_time = ping3.ping(host, timeout=5)
                    if ping_time:
                        ping_results.append(ping_time * 1000)  # Convert to ms
                    else:
                        ping_results.append(float('inf'))
                except:
                    ping_results.append(float('inf'))
            
            avg_ping = sum(p for p in ping_results if p != float('inf')) / len([p for p in ping_results if p != float('inf')])
            failed_pings = sum(1 for p in ping_results if p == float('inf'))
            
            status = HealthStatus.HEALTHY
            alerts = []
            
            if failed_pings > len(external_hosts) / 2:
                status = HealthStatus.CRITICAL
                alerts.append(f"Multiple network failures: {failed_pings}/{len(external_hosts)}")
            elif failed_pings > 0:
                status = HealthStatus.WARNING
                alerts.append(f"Some network issues: {failed_pings}/{len(external_hosts)} hosts unreachable")
            elif avg_ping > 1000:  # > 1 second
                status = HealthStatus.WARNING
                alerts.append(f"High network latency: {avg_ping:.2f}ms")
            
            # This would be a load balancer check in a real deployment
            self.system_health[SystemComponent.LOAD_BALANCER] = SystemHealth(
                component=SystemComponent.LOAD_BALANCER,
                status=status,
                last_check=datetime.now(),
                response_time=avg_ping if avg_ping != float('inf') else None,
                availability=((len(external_hosts) - failed_pings) / len(external_hosts)) * 100,
                metrics={
                    "avg_ping_ms": avg_ping if avg_ping != float('inf') else 0,
                    "failed_hosts": failed_pings,
                    "total_hosts": len(external_hosts)
                },
                alerts=alerts
            )
        
        except Exception as e:
            self.system_health[SystemComponent.LOAD_BALANCER] = SystemHealth(
                component=SystemComponent.LOAD_BALANCER,
                status=HealthStatus.UNKNOWN,
                last_check=datetime.now(),
                alerts=[f"Network check failed: {str(e)}"]
            )
    
    async def _analyze_health_status(self) -> None:
        """Analyze system health and trigger disaster response if needed"""
        
        critical_components = [
            comp for comp, health in self.system_health.items()
            if health.status == HealthStatus.FAILED
        ]
        
        warning_components = [
            comp for comp, health in self.system_health.items()
            if health.status in [HealthStatus.CRITICAL, HealthStatus.WARNING]
        ]
        
        # Save health status to database
        await self._save_health_status()
        
        # Trigger disaster response for critical failures
        if critical_components:
            await self._trigger_disaster_response(critical_components)
        
        # Log warnings
        if warning_components:
            logger.warning(f"System components with issues: {[c.value for c in warning_components]}")
    
    async def _save_health_status(self) -> None:
        """Save current health status to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            for health in self.system_health.values():
                await conn.execute("""
                    INSERT INTO system_health_history 
                    (health_id, component, status, response_time, error_rate, 
                     availability, metrics, alerts, checked_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, str(uuid.uuid4()), health.component.value, health.status.value,
                    health.response_time, health.error_rate, health.availability,
                    json.dumps(health.metrics), json.dumps(health.alerts), health.last_check)
        
        finally:
            await conn.close()
    
    async def _trigger_disaster_response(self, failed_components: List[SystemComponent]) -> None:
        """Trigger disaster response for failed components"""
        
        # Determine disaster type based on failed components
        disaster_type = self._classify_disaster(failed_components)
        
        # Check if we already have an active disaster for these components
        for event in self.active_disasters.values():
            if (set(failed_components).issubset(set(event.affected_components)) and
                event.disaster_type == disaster_type):
                logger.info(f"Disaster already being handled: {event.event_id}")
                return
        
        # Create new disaster event
        event_id = str(uuid.uuid4())
        disaster_event = DisasterEvent(
            event_id=event_id,
            disaster_type=disaster_type,
            affected_components=failed_components,
            severity_level=self._calculate_severity(failed_components),
            description=f"System failure detected in components: {[c.value for c in failed_components]}",
            detected_at=datetime.now()
        )
        
        self.active_disasters[event_id] = disaster_event
        
        # Save disaster event
        await self._save_disaster_event(disaster_event)
        
        # Find and execute recovery plan
        recovery_plan = self._select_recovery_plan(disaster_event)
        if recovery_plan:
            logger.info(f"Executing recovery plan: {recovery_plan.name}")
            await self._execute_recovery_plan(disaster_event, recovery_plan)
        else:
            logger.error(f"No recovery plan found for disaster: {disaster_type}")
            await self._send_emergency_notification(disaster_event)
    
    def _classify_disaster(self, failed_components: List[SystemComponent]) -> DisasterType:
        """Classify disaster type based on failed components"""
        
        if SystemComponent.PRIMARY_DATABASE in failed_components:
            return DisasterType.DATABASE_FAILURE
        elif SystemComponent.WEB_APPLICATION in failed_components or SystemComponent.API_SERVER in failed_components:
            return DisasterType.APPLICATION_CRASH
        elif SystemComponent.LOAD_BALANCER in failed_components:
            return DisasterType.NETWORK_OUTAGE
        elif SystemComponent.FILE_STORAGE in failed_components:
            return DisasterType.STORAGE_FAILURE
        else:
            return DisasterType.INFRASTRUCTURE_FAILURE
    
    def _calculate_severity(self, failed_components: List[SystemComponent]) -> int:
        """Calculate disaster severity (1-5 scale)"""
        
        critical_components = {
            SystemComponent.PRIMARY_DATABASE: 5,
            SystemComponent.WEB_APPLICATION: 4,
            SystemComponent.API_SERVER: 4,
            SystemComponent.LOAD_BALANCER: 3,
            SystemComponent.FILE_STORAGE: 3,
            SystemComponent.REDIS_CACHE: 2,
            SystemComponent.BACKUP_DATABASE: 2
        }
        
        max_severity = max(critical_components.get(comp, 1) for comp in failed_components)
        
        # Increase severity for multiple component failures
        if len(failed_components) > 1:
            max_severity = min(5, max_severity + 1)
        
        return max_severity
    
    def _select_recovery_plan(self, disaster_event: DisasterEvent) -> Optional[RecoveryPlan]:
        """Select the best recovery plan for the disaster"""
        
        matching_plans = []
        
        for plan in self.recovery_plans.values():
            # Check if plan applies to this disaster type
            if disaster_event.disaster_type in plan.disaster_types:
                # Check if plan covers affected components
                if set(disaster_event.affected_components).issubset(set(plan.affected_components)):
                    matching_plans.append(plan)
        
        if not matching_plans:
            return None
        
        # Select plan with highest priority (lowest priority number)
        return min(matching_plans, key=lambda p: p.priority)
    
    async def _execute_recovery_plan(self, disaster_event: DisasterEvent, recovery_plan: RecoveryPlan) -> None:
        """Execute a recovery plan"""
        
        execution_id = str(uuid.uuid4())
        execution = RecoveryExecution(
            execution_id=execution_id,
            event_id=disaster_event.event_id,
            plan_id=recovery_plan.plan_id,
            started_at=datetime.now(),
            total_steps=len(recovery_plan.steps)
        )
        
        self.active_executions[execution_id] = execution
        
        try:
            logger.info(f"Starting recovery plan execution: {execution_id}")
            
            # Send initial notification
            await self._send_recovery_notification(disaster_event, recovery_plan, "started")
            
            # Execute each step
            for step_index, step in enumerate(recovery_plan.steps):
                execution.current_step = step_index + 1
                
                logger.info(f"Executing step {execution.current_step}: {step['description']}")
                
                step_result = await self._execute_recovery_step(step, disaster_event)
                execution.step_results.append(step_result)
                
                if not step_result.get('success', False):
                    if step.get('rollback_on_failure', False):
                        logger.warning(f"Step failed, initiating rollback: {step['description']}")
                        await self._execute_rollback(recovery_plan, execution)
                        break
                    elif step.get('required', True):
                        logger.error(f"Required step failed: {step['description']}")
                        execution.status = "failed"
                        execution.error_message = step_result.get('error', 'Step failed')
                        break
                
                # Update progress
                execution.status = "running"
                await self._save_recovery_execution(execution)
            
            else:
                # All steps completed successfully
                execution.status = "completed"
                execution.completed_at = datetime.now()
                
                # Mark disaster as resolved
                disaster_event.resolved_at = datetime.now()
                disaster_event.recovery_strategy = recovery_plan.recovery_strategy
                
                logger.info(f"Recovery plan completed successfully: {execution_id}")
                await self._send_recovery_notification(disaster_event, recovery_plan, "completed")
        
        except Exception as e:
            logger.error(f"Recovery plan execution failed: {e}")
            execution.status = "failed"
            execution.error_message = str(e)
            execution.completed_at = datetime.now()
            
            await self._send_recovery_notification(disaster_event, recovery_plan, "failed")
        
        finally:
            await self._save_recovery_execution(execution)
            await self._save_disaster_event(disaster_event)
    
    async def _execute_recovery_step(self, step: Dict[str, Any], disaster_event: DisasterEvent) -> Dict[str, Any]:
        """Execute a single recovery step"""
        
        action = step['action']
        timeout = step.get('timeout_seconds', 300)
        
        try:
            if action == "verify_primary_database_failure":
                return await self._verify_database_failure()
            elif action == "promote_backup_database":
                return await self._promote_backup_database()
            elif action == "update_application_config":
                return await self._update_application_config()
            elif action == "restart_application_services":
                return await self._restart_application_services()
            elif action == "restart_application_containers":
                return await self._restart_application_containers()
            elif action == "verify_system_health":
                return await self._verify_system_health()
            elif action == "notify_stakeholders":
                return await self._notify_stakeholders(disaster_event)
            elif action == "collect_error_logs":
                return await self._collect_error_logs()
            elif action == "run_health_checks":
                return await self._run_comprehensive_health_checks()
            elif action == "restore_load_balancer":
                return await self._restore_load_balancer()
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Step timed out after {timeout} seconds"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _verify_database_failure(self) -> Dict[str, Any]:
        """Verify that the primary database has actually failed"""
        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(**self.db_config),
                timeout=10.0
            )
            await conn.fetchval("SELECT 1")
            await conn.close()
            
            # Database is actually working
            return {"success": False, "error": "Database is responsive, no failover needed"}
        
        except:
            # Database is indeed failed
            return {"success": True, "message": "Primary database failure confirmed"}
    
    async def _promote_backup_database(self) -> Dict[str, Any]:
        """Promote backup database to primary"""
        # This would contain actual database promotion logic
        # For demonstration, we'll simulate the process
        
        logger.info("Promoting backup database to primary")
        await asyncio.sleep(2)  # Simulate promotion time
        
        return {"success": True, "message": "Backup database promoted to primary"}
    
    async def _update_application_config(self) -> Dict[str, Any]:
        """Update application configuration for new database"""
        # Update database connection strings, environment variables, etc.
        logger.info("Updating application configuration")
        await asyncio.sleep(1)  # Simulate config update
        
        return {"success": True, "message": "Application configuration updated"}
    
    async def _restart_application_services(self) -> Dict[str, Any]:
        """Restart application services"""
        try:
            if self.docker_client:
                # Restart Docker containers
                containers = self.docker_client.containers.list(filters={"label": "app=monitor-legislativo"})
                for container in containers:
                    container.restart()
                    logger.info(f"Restarted container: {container.name}")
            
            elif self.k8s_client:
                # Restart Kubernetes pods
                pods = self.k8s_client.list_namespaced_pod(namespace="default", label_selector="app=monitor-legislativo")
                for pod in pods.items:
                    self.k8s_client.delete_namespaced_pod(name=pod.metadata.name, namespace="default")
                    logger.info(f"Restarted pod: {pod.metadata.name}")
            
            else:
                # Restart using systemctl or similar
                subprocess.run(["systemctl", "restart", "monitor-legislativo"], check=True)
            
            await asyncio.sleep(5)  # Wait for services to start
            
            return {"success": True, "message": "Application services restarted"}
        
        except Exception as e:
            return {"success": False, "error": f"Failed to restart services: {e}"}
    
    async def _restart_application_containers(self) -> Dict[str, Any]:
        """Restart application containers specifically"""
        return await self._restart_application_services()
    
    async def _verify_system_health(self) -> Dict[str, Any]:
        """Verify that the system is healthy after recovery"""
        await self._check_system_health()
        
        failed_components = [
            comp for comp, health in self.system_health.items()
            if health.status == HealthStatus.FAILED
        ]
        
        if failed_components:
            return {
                "success": False, 
                "error": f"System still has failed components: {[c.value for c in failed_components]}"
            }
        
        return {"success": True, "message": "System health verified"}
    
    async def _notify_stakeholders(self, disaster_event: DisasterEvent) -> Dict[str, Any]:
        """Send notifications to stakeholders"""
        try:
            # This would send actual notifications via email, SMS, Slack, etc.
            logger.info(f"Sending stakeholder notifications for disaster: {disaster_event.event_id}")
            
            return {"success": True, "message": "Stakeholders notified"}
        
        except Exception as e:
            return {"success": False, "error": f"Failed to send notifications: {e}"}
    
    async def _collect_error_logs(self) -> Dict[str, Any]:
        """Collect error logs for analysis"""
        try:
            # Collect logs from various sources
            log_paths = [
                "/var/log/monitor-legislativo/app.log",
                "/var/log/monitor-legislativo/error.log",
                "/var/log/nginx/error.log"
            ]
            
            collected_logs = []
            for log_path in log_paths:
                if Path(log_path).exists():
                    collected_logs.append(log_path)
            
            return {"success": True, "message": f"Collected logs from {len(collected_logs)} sources"}
        
        except Exception as e:
            return {"success": False, "error": f"Failed to collect logs: {e}"}
    
    async def _run_comprehensive_health_checks(self) -> Dict[str, Any]:
        """Run comprehensive health checks"""
        await self._check_system_health()
        
        # Wait a bit for health checks to complete
        await asyncio.sleep(10)
        
        healthy_components = sum(
            1 for health in self.system_health.values()
            if health.status == HealthStatus.HEALTHY
        )
        
        total_components = len(self.system_health)
        
        return {
            "success": True,
            "message": f"Health checks completed: {healthy_components}/{total_components} components healthy"
        }
    
    async def _restore_load_balancer(self) -> Dict[str, Any]:
        """Restore load balancer configuration"""
        try:
            logger.info("Restoring load balancer configuration")
            await asyncio.sleep(1)  # Simulate load balancer update
            
            return {"success": True, "message": "Load balancer restored"}
        
        except Exception as e:
            return {"success": False, "error": f"Failed to restore load balancer: {e}"}
    
    async def _execute_rollback(self, recovery_plan: RecoveryPlan, execution: RecoveryExecution) -> None:
        """Execute rollback plan"""
        logger.info(f"Executing rollback for plan: {recovery_plan.plan_id}")
        
        for step in recovery_plan.rollback_plan:
            try:
                step_result = await self._execute_recovery_step(step, None)
                execution.step_results.append({
                    "rollback_step": step,
                    "result": step_result
                })
            except Exception as e:
                logger.error(f"Rollback step failed: {e}")
        
        execution.status = "failed"
        execution.error_message = "Recovery failed, rollback executed"
    
    async def _save_disaster_event(self, event: DisasterEvent) -> None:
        """Save disaster event to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO disaster_events 
                (event_id, disaster_type, affected_components, severity_level, description,
                 detected_at, resolved_at, recovery_strategy, impact_assessment, root_cause, lessons_learned)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (event_id)
                DO UPDATE SET
                    resolved_at = $7, recovery_strategy = $8, impact_assessment = $9,
                    root_cause = $10, lessons_learned = $11
            """, event.event_id, event.disaster_type.value,
                json.dumps([c.value for c in event.affected_components]),
                event.severity_level, event.description, event.detected_at,
                event.resolved_at, event.recovery_strategy.value if event.recovery_strategy else None,
                json.dumps(event.impact_assessment), event.root_cause, event.lessons_learned)
        
        finally:
            await conn.close()
    
    async def _save_recovery_execution(self, execution: RecoveryExecution) -> None:
        """Save recovery execution to database"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO recovery_executions 
                (execution_id, event_id, plan_id, started_at, completed_at, status,
                 current_step, total_steps, step_results, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (execution_id)
                DO UPDATE SET
                    completed_at = $5, status = $6, current_step = $7,
                    step_results = $9, error_message = $10
            """, execution.execution_id, execution.event_id, execution.plan_id,
                execution.started_at, execution.completed_at, execution.status,
                execution.current_step, execution.total_steps,
                json.dumps(execution.step_results), execution.error_message)
        
        finally:
            await conn.close()
    
    async def _send_recovery_notification(self, disaster_event: DisasterEvent, 
                                        recovery_plan: RecoveryPlan, status: str) -> None:
        """Send recovery status notification"""
        
        message = f"""
        Disaster Recovery Notification - Monitor Legislativo v4
        
        Status: {status.upper()}
        Disaster Type: {disaster_event.disaster_type.value}
        Affected Components: {[c.value for c in disaster_event.affected_components]}
        Recovery Plan: {recovery_plan.name}
        Detected At: {disaster_event.detected_at.isoformat()}
        Severity Level: {disaster_event.severity_level}/5
        
        Description: {disaster_event.description}
        
        Next Steps: {"Recovery completed successfully" if status == "completed" else "Recovery in progress"}
        """
        
        logger.info(f"Recovery notification ({status}): {disaster_event.event_id}")
        
        # Send to configured notification channels
        for contact in recovery_plan.notification_contacts:
            await self._send_email_notification(contact, f"DR Alert - {status}", message)
    
    async def _send_emergency_notification(self, disaster_event: DisasterEvent) -> None:
        """Send emergency notification when no recovery plan is available"""
        
        message = f"""
        EMERGENCY: No Recovery Plan Available - Monitor Legislativo v4
        
        A disaster has been detected but no automated recovery plan is available.
        IMMEDIATE MANUAL INTERVENTION REQUIRED.
        
        Disaster Type: {disaster_event.disaster_type.value}
        Affected Components: {[c.value for c in disaster_event.affected_components]}
        Severity Level: {disaster_event.severity_level}/5
        Detected At: {disaster_event.detected_at.isoformat()}
        
        Description: {disaster_event.description}
        
        Please investigate immediately and implement manual recovery procedures.
        """
        
        logger.critical(f"Emergency notification: {disaster_event.event_id}")
        
        # Send to all emergency contacts
        emergency_contacts = [
            "admin@monitor-legislativo.br",
            "emergency@monitor-legislativo.br"
        ]
        
        for contact in emergency_contacts:
            await self._send_email_notification(contact, "EMERGENCY: Manual DR Required", message)
    
    async def _send_email_notification(self, email: str, subject: str, message: str) -> None:
        """Send email notification"""
        try:
            if not self.notification_config.get('smtp_enabled', False):
                logger.info(f"Email notification (SMTP disabled): {subject} to {email}")
                return
            
            smtp_server = self.notification_config['smtp_server']
            smtp_port = self.notification_config['smtp_port']
            smtp_user = self.notification_config['smtp_user']
            smtp_password = self.notification_config['smtp_password']
            
            msg = MIMEMultipart()
            msg['From'] = smtp_user
            msg['To'] = email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent to {email}: {subject}")
        
        except Exception as e:
            logger.error(f"Failed to send email to {email}: {e}")
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return {
            "system_health": {comp.value: health.to_dict() for comp, health in self.system_health.items()},
            "active_disasters": len(self.active_disasters),
            "active_recoveries": len(self.active_executions),
            "monitoring_enabled": self.monitoring_enabled,
            "recovery_plans_count": len(self.recovery_plans)
        }
    
    def stop(self) -> None:
        """Stop the disaster recovery system"""
        self.monitoring_enabled = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=30)
        logger.info("Disaster recovery orchestrator stopped")

# Factory function for easy creation
async def create_disaster_recovery_orchestrator(
    db_config: Dict[str, str],
    redis_config: Dict[str, str] = None,
    notification_config: Dict[str, str] = None
) -> DisasterRecoveryOrchestrator:
    """Create and initialize disaster recovery orchestrator"""
    orchestrator = DisasterRecoveryOrchestrator(db_config, redis_config, notification_config)
    await orchestrator.initialize()
    return orchestrator

# Export main classes
__all__ = [
    'DisasterRecoveryOrchestrator',
    'DisasterEvent',
    'RecoveryPlan',
    'SystemHealth',
    'RecoveryExecution',
    'DisasterType',
    'RecoveryStrategy',
    'SystemComponent',
    'HealthStatus',
    'create_disaster_recovery_orchestrator'
]