"""
Zero Trust Security Model Implementation
Monitor Legislativo v4

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas  
Financing: MackPesquisa - Instituto de Pesquisa Mackenzie
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from functools import wraps
import ipaddress
import re

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Trust levels for zero trust evaluation"""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


class RiskLevel(Enum):
    """Risk assessment levels"""
    MINIMAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class DeviceFingerprint:
    """Device identification and characteristics"""
    user_agent: str
    screen_resolution: str
    timezone: str
    language: str
    platform: str
    plugins: List[str]
    canvas_fingerprint: str
    webgl_fingerprint: str
    audio_fingerprint: str
    
    def generate_hash(self) -> str:
        """Generate unique device hash"""
        data = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class NetworkContext:
    """Network and location context"""
    ip_address: str
    country: str
    city: str
    isp: str
    is_vpn: bool
    is_tor: bool
    is_proxy: bool
    asn: str
    threat_intelligence: Dict[str, Any]


@dataclass
class BehaviorPattern:
    """User behavior analysis"""
    login_times: List[datetime]
    access_patterns: Dict[str, int]
    typing_patterns: Dict[str, float]
    mouse_movements: List[Dict[str, Any]]
    session_duration: timedelta
    feature_usage: Dict[str, int]
    geographical_consistency: bool


@dataclass
class SecurityEvent:
    """Security event for analysis"""
    timestamp: datetime
    event_type: str
    user_id: str
    ip_address: str
    device_fingerprint: str
    risk_score: float
    trust_score: float
    context: Dict[str, Any]


class ZeroTrustEngine:
    """Core zero trust security engine"""
    
    def __init__(self):
        self.trust_cache: Dict[str, TrustLevel] = {}
        self.risk_cache: Dict[str, RiskLevel] = {}
        self.device_registry: Dict[str, DeviceFingerprint] = {}
        self.behavior_baselines: Dict[str, BehaviorPattern] = {}
        self.security_events: List[SecurityEvent] = []
        self.blocked_ips: Set[str] = set()
        self.suspicious_patterns: Dict[str, Any] = {}
        
        # Attribution
        self.project_attribution = {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
    
    async def evaluate_trust(self, user_id: str, request_context: Dict[str, Any]) -> TrustLevel:
        """Evaluate trust level for user request"""
        try:
            # Extract context
            device_fp = self._extract_device_fingerprint(request_context)
            network_ctx = await self._analyze_network_context(request_context)
            behavior = await self._analyze_behavior(user_id, request_context)
            
            # Calculate trust components
            device_trust = await self._evaluate_device_trust(device_fp)
            network_trust = await self._evaluate_network_trust(network_ctx)
            behavior_trust = await self._evaluate_behavior_trust(behavior)
            historical_trust = await self._get_historical_trust(user_id)
            
            # Weighted trust calculation
            trust_score = (
                device_trust * 0.25 +
                network_trust * 0.20 +
                behavior_trust * 0.35 +
                historical_trust * 0.20
            )
            
            # Map to trust level
            if trust_score >= 0.9:
                return TrustLevel.VERIFIED
            elif trust_score >= 0.7:
                return TrustLevel.HIGH
            elif trust_score >= 0.5:
                return TrustLevel.MEDIUM
            elif trust_score >= 0.3:
                return TrustLevel.LOW
            else:
                return TrustLevel.UNKNOWN
                
        except Exception as e:
            logger.error(f"Trust evaluation failed: {e}")
            return TrustLevel.UNKNOWN
    
    async def assess_risk(self, user_id: str, resource: str, action: str, context: Dict[str, Any]) -> RiskLevel:
        """Assess risk level for specific action"""
        try:
            # Risk factors
            user_risk = await self._assess_user_risk(user_id)
            resource_risk = await self._assess_resource_risk(resource)
            action_risk = await self._assess_action_risk(action)
            context_risk = await self._assess_context_risk(context)
            temporal_risk = await self._assess_temporal_risk(context)
            
            # Aggregate risk score
            risk_score = max(user_risk, resource_risk, action_risk, context_risk, temporal_risk)
            
            # Map to risk level
            if risk_score >= 0.8:
                return RiskLevel.CRITICAL
            elif risk_score >= 0.6:
                return RiskLevel.HIGH
            elif risk_score >= 0.4:
                return RiskLevel.MEDIUM
            elif risk_score >= 0.2:
                return RiskLevel.LOW
            else:
                return RiskLevel.MINIMAL
                
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            return RiskLevel.HIGH
    
    def _extract_device_fingerprint(self, context: Dict[str, Any]) -> DeviceFingerprint:
        """Extract device fingerprint from request context"""
        headers = context.get('headers', {})
        fingerprint_data = context.get('fingerprint', {})
        
        return DeviceFingerprint(
            user_agent=headers.get('user-agent', ''),
            screen_resolution=fingerprint_data.get('screen_resolution', ''),
            timezone=fingerprint_data.get('timezone', ''),
            language=fingerprint_data.get('language', ''),
            platform=fingerprint_data.get('platform', ''),
            plugins=fingerprint_data.get('plugins', []),
            canvas_fingerprint=fingerprint_data.get('canvas', ''),
            webgl_fingerprint=fingerprint_data.get('webgl', ''),
            audio_fingerprint=fingerprint_data.get('audio', '')
        )
    
    async def _analyze_network_context(self, context: Dict[str, Any]) -> NetworkContext:
        """Analyze network and geographical context"""
        ip = context.get('ip_address', '')
        
        # Mock geolocation and threat intelligence
        # In production, integrate with MaxMind, IPinfo, etc.
        return NetworkContext(
            ip_address=ip,
            country=context.get('country', 'Unknown'),
            city=context.get('city', 'Unknown'),
            isp=context.get('isp', 'Unknown'),
            is_vpn=context.get('is_vpn', False),
            is_tor=context.get('is_tor', False),
            is_proxy=context.get('is_proxy', False),
            asn=context.get('asn', ''),
            threat_intelligence=context.get('threat_intel', {})
        )
    
    async def _analyze_behavior(self, user_id: str, context: Dict[str, Any]) -> BehaviorPattern:
        """Analyze user behavior patterns"""
        # Mock behavior analysis
        # In production, implement ML-based behavior analysis
        return BehaviorPattern(
            login_times=[datetime.now()],
            access_patterns={},
            typing_patterns={},
            mouse_movements=[],
            session_duration=timedelta(minutes=30),
            feature_usage={},
            geographical_consistency=True
        )
    
    async def _evaluate_device_trust(self, device_fp: DeviceFingerprint) -> float:
        """Evaluate device trustworthiness"""
        device_hash = device_fp.generate_hash()
        
        # Check if device is known
        if device_hash in self.device_registry:
            return 0.8  # Known device
        
        # Analyze device characteristics
        trust_score = 0.5  # Base score for unknown device
        
        # Check for suspicious characteristics
        if not device_fp.user_agent or len(device_fp.user_agent) < 10:
            trust_score -= 0.2
        
        if not device_fp.canvas_fingerprint:
            trust_score -= 0.1
            
        return max(0.0, min(1.0, trust_score))
    
    async def _evaluate_network_trust(self, network_ctx: NetworkContext) -> float:
        """Evaluate network trustworthiness"""
        trust_score = 1.0
        
        # Check for anonymization services
        if network_ctx.is_tor:
            trust_score -= 0.5
        if network_ctx.is_vpn:
            trust_score -= 0.2
        if network_ctx.is_proxy:
            trust_score -= 0.3
        
        # Check threat intelligence
        threat_score = network_ctx.threat_intelligence.get('risk_score', 0)
        trust_score -= threat_score * 0.4
        
        # Check if IP is blocked
        if network_ctx.ip_address in self.blocked_ips:
            trust_score = 0.0
        
        return max(0.0, min(1.0, trust_score))
    
    async def _evaluate_behavior_trust(self, behavior: BehaviorPattern) -> float:
        """Evaluate behavioral trustworthiness"""
        # Mock implementation
        # In production, implement sophisticated behavior analysis
        return 0.7
    
    async def _get_historical_trust(self, user_id: str) -> float:
        """Get historical trust score for user"""
        return self.trust_cache.get(user_id, 0.5)
    
    async def _assess_user_risk(self, user_id: str) -> float:
        """Assess user-specific risk factors"""
        # Check user history, privileges, recent activities
        return 0.1  # Mock low risk
    
    async def _assess_resource_risk(self, resource: str) -> float:
        """Assess resource sensitivity"""
        sensitive_resources = [
            'admin', 'config', 'users', 'database', 'api_keys'
        ]
        
        if any(sensitive in resource.lower() for sensitive in sensitive_resources):
            return 0.7
        return 0.2
    
    async def _assess_action_risk(self, action: str) -> float:
        """Assess action risk level"""
        high_risk_actions = ['delete', 'modify', 'export', 'admin']
        medium_risk_actions = ['create', 'update', 'upload']
        
        action_lower = action.lower()
        if any(risk_action in action_lower for risk_action in high_risk_actions):
            return 0.8
        elif any(risk_action in action_lower for risk_action in medium_risk_actions):
            return 0.5
        return 0.1
    
    async def _assess_context_risk(self, context: Dict[str, Any]) -> float:
        """Assess contextual risk factors"""
        risk_score = 0.0
        
        # Time-based risk
        hour = datetime.now().hour
        if hour < 6 or hour > 22:  # Outside business hours
            risk_score += 0.2
        
        # Location risk
        if context.get('unusual_location', False):
            risk_score += 0.3
        
        return min(1.0, risk_score)
    
    async def _assess_temporal_risk(self, context: Dict[str, Any]) -> float:
        """Assess temporal anomalies"""
        # Check for rapid successive requests, unusual timing patterns
        return 0.1  # Mock low temporal risk


class AccessController:
    """Zero trust access control"""
    
    def __init__(self, zero_trust_engine: ZeroTrustEngine):
        self.zt_engine = zero_trust_engine
        self.access_policies: Dict[str, Dict[str, Any]] = {}
        
    async def authorize_request(self, user_id: str, resource: str, action: str, context: Dict[str, Any]) -> bool:
        """Authorize request based on zero trust principles"""
        try:
            # Evaluate trust and risk
            trust_level = await self.zt_engine.evaluate_trust(user_id, context)
            risk_level = await self.zt_engine.assess_risk(user_id, resource, action, context)
            
            # Apply access policy
            required_trust = self._get_required_trust_level(resource, action)
            max_allowed_risk = self._get_max_allowed_risk(resource, action)
            
            # Make authorization decision
            trust_sufficient = trust_level.value >= required_trust.value
            risk_acceptable = risk_level.value <= max_allowed_risk.value
            
            authorized = trust_sufficient and risk_acceptable
            
            # Log decision
            await self._log_access_decision(
                user_id, resource, action, trust_level, risk_level, authorized, context
            )
            
            return authorized
            
        except Exception as e:
            logger.error(f"Authorization failed: {e}")
            return False
    
    def _get_required_trust_level(self, resource: str, action: str) -> TrustLevel:
        """Get required trust level for resource/action"""
        # Administrative actions require high trust
        if 'admin' in resource.lower() or 'admin' in action.lower():
            return TrustLevel.VERIFIED
        
        # Sensitive data requires medium-high trust
        if any(sensitive in resource.lower() for sensitive in ['config', 'users', 'database']):
            return TrustLevel.HIGH
        
        # Write operations require medium trust
        if action.lower() in ['create', 'update', 'delete', 'modify']:
            return TrustLevel.MEDIUM
        
        # Read operations require basic trust
        return TrustLevel.LOW
    
    def _get_max_allowed_risk(self, resource: str, action: str) -> RiskLevel:
        """Get maximum allowed risk for resource/action"""
        # Critical operations have low risk tolerance
        if 'admin' in resource.lower() or action.lower() in ['delete', 'modify']:
            return RiskLevel.LOW
        
        # Sensitive resources have medium risk tolerance
        if any(sensitive in resource.lower() for sensitive in ['config', 'users']):
            return RiskLevel.MEDIUM
        
        # Regular operations have higher risk tolerance
        return RiskLevel.HIGH
    
    async def _log_access_decision(self, user_id: str, resource: str, action: str, 
                                 trust_level: TrustLevel, risk_level: RiskLevel, 
                                 authorized: bool, context: Dict[str, Any]):
        """Log access control decision"""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type='access_control',
            user_id=user_id,
            ip_address=context.get('ip_address', ''),
            device_fingerprint=context.get('device_fingerprint', ''),
            risk_score=risk_level.value / 4.0,
            trust_score=trust_level.value / 4.0,
            context={
                'resource': resource,
                'action': action,
                'authorized': authorized,
                'trust_level': trust_level.name,
                'risk_level': risk_level.name
            }
        )
        
        self.zt_engine.security_events.append(event)
        
        logger.info(f"Access decision: user={user_id}, resource={resource}, "
                   f"action={action}, trust={trust_level.name}, risk={risk_level.name}, "
                   f"authorized={authorized}")


def zero_trust_required(trust_level: TrustLevel = TrustLevel.MEDIUM, 
                       max_risk: RiskLevel = RiskLevel.MEDIUM):
    """Decorator for zero trust access control"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request context (implementation depends on framework)
            context = kwargs.get('context', {})
            user_id = context.get('user_id', '')
            
            # Get zero trust engine instance
            zt_engine = ZeroTrustEngine()
            access_controller = AccessController(zt_engine)
            
            # Authorize request
            authorized = await access_controller.authorize_request(
                user_id, func.__name__, 'execute', context
            )
            
            if not authorized:
                raise PermissionError("Zero trust authorization failed")
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


class ContinuousMonitoring:
    """Continuous security monitoring for zero trust"""
    
    def __init__(self, zt_engine: ZeroTrustEngine):
        self.zt_engine = zt_engine
        self.monitoring_active = True
        
    async def start_monitoring(self):
        """Start continuous monitoring"""
        while self.monitoring_active:
            try:
                await self._analyze_security_events()
                await self._update_trust_scores()
                await self._detect_anomalies()
                await asyncio.sleep(60)  # Monitor every minute
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _analyze_security_events(self):
        """Analyze recent security events"""
        recent_events = [
            event for event in self.zt_engine.security_events
            if (datetime.now() - event.timestamp).total_seconds() < 3600
        ]
        
        # Detect patterns in recent events
        await self._detect_attack_patterns(recent_events)
    
    async def _update_trust_scores(self):
        """Update trust scores based on recent behavior"""
        # Implementation for dynamic trust score updates
        pass
    
    async def _detect_anomalies(self):
        """Detect behavioral and access anomalies"""
        # Implementation for anomaly detection
        pass
    
    async def _detect_attack_patterns(self, events: List[SecurityEvent]):
        """Detect potential attack patterns"""
        # Group events by user and IP
        user_events = {}
        ip_events = {}
        
        for event in events:
            user_events.setdefault(event.user_id, []).append(event)
            ip_events.setdefault(event.ip_address, []).append(event)
        
        # Detect suspicious patterns
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) > 100:  # Too many events
                logger.warning(f"Suspicious activity from user {user_id}")
        
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) > 50:  # Too many events from single IP
                logger.warning(f"Suspicious activity from IP {ip}")
                self.zt_engine.blocked_ips.add(ip)