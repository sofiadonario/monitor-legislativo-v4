"""
Unit Tests for Zero Trust Security Model
Monitor Legislativo v4

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas
Financing: MackPesquisa - Instituto de Pesquisa Mackenzie
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from core.security.zero_trust import (
    ZeroTrustEngine,
    AccessController,
    TrustLevel,
    RiskLevel,
    DeviceFingerprint,
    NetworkContext,
    BehaviorPattern,
    SecurityEvent,
    ContinuousMonitoring,
    zero_trust_required
)


class TestDeviceFingerprint:
    """Test device fingerprinting functionality"""
    
    def test_device_fingerprint_creation(self):
        """Test device fingerprint creation"""
        fp = DeviceFingerprint(
            user_agent="Mozilla/5.0 Test",
            screen_resolution="1920x1080",
            timezone="UTC",
            language="en-US",
            platform="Linux",
            plugins=["plugin1", "plugin2"],
            canvas_fingerprint="canvas123",
            webgl_fingerprint="webgl456",
            audio_fingerprint="audio789"
        )
        
        assert fp.user_agent == "Mozilla/5.0 Test"
        assert fp.screen_resolution == "1920x1080"
        assert len(fp.plugins) == 2
    
    def test_device_fingerprint_hash(self):
        """Test device fingerprint hash generation"""
        fp1 = DeviceFingerprint(
            user_agent="Mozilla/5.0 Test",
            screen_resolution="1920x1080",
            timezone="UTC",
            language="en-US",
            platform="Linux",
            plugins=["plugin1"],
            canvas_fingerprint="canvas123",
            webgl_fingerprint="webgl456",
            audio_fingerprint="audio789"
        )
        
        fp2 = DeviceFingerprint(
            user_agent="Mozilla/5.0 Test",
            screen_resolution="1920x1080",
            timezone="UTC",
            language="en-US",
            platform="Linux",
            plugins=["plugin1"],
            canvas_fingerprint="canvas123",
            webgl_fingerprint="webgl456",
            audio_fingerprint="audio789"
        )
        
        # Same fingerprints should generate same hash
        assert fp1.generate_hash() == fp2.generate_hash()
        
        # Different fingerprints should generate different hashes
        fp2.user_agent = "Different Agent"
        assert fp1.generate_hash() != fp2.generate_hash()


class TestZeroTrustEngine:
    """Test zero trust engine functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.zt_engine = ZeroTrustEngine()
    
    @pytest.mark.asyncio
    async def test_evaluate_trust_unknown_device(self):
        """Test trust evaluation for unknown device"""
        context = {
            'headers': {'user-agent': 'Test Agent'},
            'fingerprint': {
                'screen_resolution': '1920x1080',
                'timezone': 'UTC',
                'language': 'en-US',
                'platform': 'Linux'
            },
            'ip_address': '192.168.1.1',
            'country': 'US'
        }
        
        trust_level = await self.zt_engine.evaluate_trust('user123', context)
        assert isinstance(trust_level, TrustLevel)
        assert trust_level in [TrustLevel.UNKNOWN, TrustLevel.LOW, TrustLevel.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_assess_risk_admin_action(self):
        """Test risk assessment for administrative actions"""
        context = {
            'ip_address': '192.168.1.1',
            'unusual_location': False
        }
        
        risk_level = await self.zt_engine.assess_risk(
            'user123', 'admin_panel', 'delete', context
        )
        
        assert isinstance(risk_level, RiskLevel)
        # Admin delete should be high risk
        assert risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_assess_risk_read_action(self):
        """Test risk assessment for read actions"""
        context = {
            'ip_address': '192.168.1.1',
            'unusual_location': False
        }
        
        risk_level = await self.zt_engine.assess_risk(
            'user123', 'documents', 'read', context
        )
        
        assert isinstance(risk_level, RiskLevel)
        # Read operations should be lower risk
        assert risk_level in [RiskLevel.MINIMAL, RiskLevel.LOW, RiskLevel.MEDIUM]
    
    def test_extract_device_fingerprint(self):
        """Test device fingerprint extraction"""
        context = {
            'headers': {'user-agent': 'Test Agent'},
            'fingerprint': {
                'screen_resolution': '1920x1080',
                'timezone': 'UTC',
                'language': 'en-US',
                'platform': 'Linux',
                'plugins': ['plugin1', 'plugin2']
            }
        }
        
        fp = self.zt_engine._extract_device_fingerprint(context)
        assert isinstance(fp, DeviceFingerprint)
        assert fp.user_agent == 'Test Agent'
        assert fp.screen_resolution == '1920x1080'
        assert len(fp.plugins) == 2
    
    @pytest.mark.asyncio
    async def test_evaluate_device_trust_suspicious(self):
        """Test device trust evaluation for suspicious device"""
        # Empty user agent should reduce trust
        fp = DeviceFingerprint(
            user_agent="",
            screen_resolution="1920x1080",
            timezone="UTC",
            language="en-US",
            platform="Linux",
            plugins=[],
            canvas_fingerprint="",
            webgl_fingerprint="",
            audio_fingerprint=""
        )
        
        trust_score = await self.zt_engine._evaluate_device_trust(fp)
        assert 0.0 <= trust_score <= 1.0
        assert trust_score < 0.5  # Should be low trust
    
    @pytest.mark.asyncio
    async def test_evaluate_network_trust_tor(self):
        """Test network trust evaluation for Tor connection"""
        network_ctx = NetworkContext(
            ip_address="192.168.1.1",
            country="US",
            city="New York",
            isp="Test ISP",
            is_vpn=False,
            is_tor=True,  # Tor should reduce trust
            is_proxy=False,
            asn="AS12345",
            threat_intelligence={'risk_score': 0.0}
        )
        
        trust_score = await self.zt_engine._evaluate_network_trust(network_ctx)
        assert 0.0 <= trust_score <= 1.0
        assert trust_score < 0.8  # Tor should reduce trust


class TestAccessController:
    """Test access control functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.zt_engine = ZeroTrustEngine()
        self.access_controller = AccessController(self.zt_engine)
    
    @pytest.mark.asyncio
    async def test_authorize_request_success(self):
        """Test successful authorization"""
        context = {
            'headers': {'user-agent': 'Test Agent'},
            'fingerprint': {
                'screen_resolution': '1920x1080',
                'platform': 'Linux'
            },
            'ip_address': '192.168.1.1'
        }
        
        # Mock high trust and low risk
        with patch.object(self.zt_engine, 'evaluate_trust', return_value=TrustLevel.HIGH):
            with patch.object(self.zt_engine, 'assess_risk', return_value=RiskLevel.LOW):
                authorized = await self.access_controller.authorize_request(
                    'user123', 'documents', 'read', context
                )
                assert authorized is True
    
    @pytest.mark.asyncio
    async def test_authorize_request_insufficient_trust(self):
        """Test authorization failure due to insufficient trust"""
        context = {
            'headers': {'user-agent': 'Test Agent'},
            'ip_address': '192.168.1.1'
        }
        
        # Mock low trust for admin action requiring high trust
        with patch.object(self.zt_engine, 'evaluate_trust', return_value=TrustLevel.LOW):
            with patch.object(self.zt_engine, 'assess_risk', return_value=RiskLevel.LOW):
                authorized = await self.access_controller.authorize_request(
                    'user123', 'admin_panel', 'delete', context
                )
                assert authorized is False
    
    @pytest.mark.asyncio
    async def test_authorize_request_high_risk(self):
        """Test authorization failure due to high risk"""
        context = {
            'headers': {'user-agent': 'Test Agent'},
            'ip_address': '192.168.1.1'
        }
        
        # Mock high trust but critical risk
        with patch.object(self.zt_engine, 'evaluate_trust', return_value=TrustLevel.VERIFIED):
            with patch.object(self.zt_engine, 'assess_risk', return_value=RiskLevel.CRITICAL):
                authorized = await self.access_controller.authorize_request(
                    'user123', 'documents', 'read', context
                )
                assert authorized is False
    
    def test_get_required_trust_level(self):
        """Test required trust level calculation"""
        # Admin operations should require verified trust
        trust_level = self.access_controller._get_required_trust_level('admin_panel', 'configure')
        assert trust_level == TrustLevel.VERIFIED
        
        # Write operations should require medium trust
        trust_level = self.access_controller._get_required_trust_level('documents', 'create')
        assert trust_level == TrustLevel.MEDIUM
        
        # Read operations should require low trust
        trust_level = self.access_controller._get_required_trust_level('documents', 'read')
        assert trust_level == TrustLevel.LOW
    
    def test_get_max_allowed_risk(self):
        """Test maximum allowed risk calculation"""
        # Admin operations should have low risk tolerance
        max_risk = self.access_controller._get_max_allowed_risk('admin_panel', 'delete')
        assert max_risk == RiskLevel.LOW
        
        # Regular operations should have higher risk tolerance
        max_risk = self.access_controller._get_max_allowed_risk('documents', 'read')
        assert max_risk == RiskLevel.HIGH


class TestContinuousMonitoring:
    """Test continuous monitoring functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.zt_engine = ZeroTrustEngine()
        self.monitoring = ContinuousMonitoring(self.zt_engine)
    
    @pytest.mark.asyncio
    async def test_detect_attack_patterns_user_flood(self):
        """Test detection of user flooding attack"""
        # Create many events for single user
        events = []
        for i in range(150):
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type='login_attempt',
                user_id='attacker_user',
                ip_address=f'192.168.1.{i % 10}',
                device_fingerprint='fp123',
                risk_score=0.5,
                trust_score=0.3,
                context={}
            )
            events.append(event)
        
        # Should detect suspicious pattern
        with patch('core.security.zero_trust.logger') as mock_logger:
            await self.monitoring._detect_attack_patterns(events)
            mock_logger.warning.assert_called()
    
    @pytest.mark.asyncio
    async def test_detect_attack_patterns_ip_flood(self):
        """Test detection of IP flooding attack"""
        # Create many events from single IP
        events = []
        for i in range(60):
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type='api_request',
                user_id=f'user_{i}',
                ip_address='192.168.1.100',
                device_fingerprint=f'fp{i}',
                risk_score=0.3,
                trust_score=0.7,
                context={}
            )
            events.append(event)
        
        # Should detect suspicious pattern and block IP
        await self.monitoring._detect_attack_patterns(events)
        assert '192.168.1.100' in self.zt_engine.blocked_ips


class TestZeroTrustDecorator:
    """Test zero trust decorator functionality"""
    
    @pytest.mark.asyncio
    async def test_zero_trust_decorator_success(self):
        """Test zero trust decorator with successful authorization"""
        
        @zero_trust_required(trust_level=TrustLevel.MEDIUM, max_risk=RiskLevel.MEDIUM)
        async def protected_function(context=None):
            return "success"
        
        context = {
            'user_id': 'user123',
            'headers': {'user-agent': 'Test Agent'},
            'ip_address': '192.168.1.1'
        }
        
        # Mock authorization success
        with patch('core.security.zero_trust.AccessController.authorize_request', return_value=True):
            result = await protected_function(context=context)
            assert result == "success"
    
    @pytest.mark.asyncio
    async def test_zero_trust_decorator_failure(self):
        """Test zero trust decorator with authorization failure"""
        
        @zero_trust_required(trust_level=TrustLevel.HIGH, max_risk=RiskLevel.LOW)
        async def protected_function(context=None):
            return "success"
        
        context = {
            'user_id': 'user123',
            'headers': {'user-agent': 'Test Agent'},
            'ip_address': '192.168.1.1'
        }
        
        # Mock authorization failure
        with patch('core.security.zero_trust.AccessController.authorize_request', return_value=False):
            with pytest.raises(PermissionError, match="Zero trust authorization failed"):
                await protected_function(context=context)


class TestSecurityEvent:
    """Test security event functionality"""
    
    def test_security_event_creation(self):
        """Test security event creation"""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type='login',
            user_id='user123',
            ip_address='192.168.1.1',
            device_fingerprint='fp123',
            risk_score=0.3,
            trust_score=0.8,
            context={'action': 'login', 'resource': 'dashboard'}
        )
        
        assert event.user_id == 'user123'
        assert event.event_type == 'login'
        assert 0.0 <= event.risk_score <= 1.0
        assert 0.0 <= event.trust_score <= 1.0
        assert 'action' in event.context


if __name__ == '__main__':
    pytest.main([__file__])