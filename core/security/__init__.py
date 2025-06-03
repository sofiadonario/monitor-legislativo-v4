"""
Security Module - Monitor Legislativo v4

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas
Financing: MackPesquisa - Instituto de Pesquisa Mackenzie
"""

from .zero_trust import (
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

__all__ = [
    'ZeroTrustEngine',
    'AccessController', 
    'TrustLevel',
    'RiskLevel',
    'DeviceFingerprint',
    'NetworkContext',
    'BehaviorPattern',
    'SecurityEvent',
    'ContinuousMonitoring',
    'zero_trust_required'
]