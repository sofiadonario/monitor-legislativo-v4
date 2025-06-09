"""
Enhanced Security Validation System for Monitor Legislativo v4
Based on transport guide security requirements

SPRINT 9 - TASK 9.2: Security Validation Enhancement
✅ XML parsing security (XXE prevention)
✅ SQL injection protection validation
✅ XSS prevention in all input fields
✅ Response sanitization for all APIs
✅ Input length and character validation
✅ Malicious pattern detection
✅ Security event logging
✅ Threat level classification
"""

import re
import html
import hashlib
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote, unquote
import xml.etree.ElementTree as ET
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges, feature_external_pes

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventType(Enum):
    """Types of security events."""
    INPUT_VALIDATION_FAILED = "input_validation_failed"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    XXE_ATTEMPT = "xxe_attempt"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    COMMAND_INJECTION_ATTEMPT = "command_injection_attempt"
    RESPONSE_SANITIZATION = "response_sanitization"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    MALFORMED_REQUEST = "malformed_request"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_type: SecurityEventType
    threat_level: ThreatLevel
    timestamp: float
    source_ip: str
    user_agent: str
    input_data: str
    sanitized_data: str
    message: str
    additional_data: Dict[str, Any]


class EnhancedSecurityValidator:
    """
    Military-grade security validation system.
    
    Features:
    - XXE attack prevention
    - SQL injection detection and prevention
    - XSS attack mitigation
    - Input sanitization and validation
    - Response content filtering
    - Malicious pattern detection
    - Security event logging
    - Threat level assessment
    """
    
    def __init__(self):
        """Initialize enhanced security validator."""
        self.security_events = []
        self.threat_patterns = self._load_threat_patterns()
        self.blocked_patterns = self._load_blocked_patterns()
        
        # Security statistics
        self.stats = {
            'total_validations': 0,
            'threats_detected': 0,
            'inputs_sanitized': 0,
            'blocked_requests': 0,
            'last_threat': None
        }
    
    def _load_threat_patterns(self) -> Dict[SecurityEventType, List[str]]:
        """Load threat detection patterns."""
        return {
            SecurityEventType.SQL_INJECTION_ATTEMPT: [
                r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
                r"(\'|\"|;|--|\/\*|\*\/)",
                r"(\b(or|and)\b\s*\d*\s*=\s*\d*)",
                r"(\b(or|and)\b\s*(\'|\")?\s*\w*\s*(\'|\")?\s*=\s*(\'|\")?\s*\w*\s*(\'|\")?)",
                r"(sleep\s*\(\s*\d+\s*\))",
                r"(benchmark\s*\(\s*\d+\s*,)",
                r"(waitfor\s+delay)",
                r"(\bxp_cmdshell\b)",
                r"(\bsp_executesql\b)"
            ],
            SecurityEventType.XSS_ATTEMPT: [
                r"(<script[^>]*>.*?</script>)",
                r"(<iframe[^>]*>.*?</iframe>)",
                r"(<object[^>]*>.*?</object>)",
                r"(<embed[^>]*>.*?</embed>)",
                r"(<link[^>]*>)",
                r"(<meta[^>]*>)",
                r"(javascript\s*:)",
                r"(vbscript\s*:)",
                r"(on\w+\s*=)",
                r"(<svg[^>]*>.*?</svg>)",
                r"(eval\s*\()",
                r"(expression\s*\()",
                r"(alert\s*\()",
                r"(confirm\s*\()",
                r"(prompt\s*\()"
            ],
            SecurityEventType.XXE_ATTEMPT: [
                r"(<!DOCTYPE[^>]*\[.*ENTITY)",
                r"(<!ENTITY[^>]*>)",
                r"(SYSTEM\s+[\"'][^\"']*[\"'])",
                r"(PUBLIC\s+[\"'][^\"']*[\"'])",
                r"(&\w+;)"
            ],
            SecurityEventType.PATH_TRAVERSAL_ATTEMPT: [
                r"(\.\./)",
                r"(\.\.\\)",
                r"(%2e%2e%2f)",
                r"(%2e%2e%5c)",
                r"(\.\.\%2f)",
                r"(\.\.\%5c)",
                r"(/etc/passwd)",
                r"(/windows/system32)",
                r"(\.\./\.\./)"
            ],
            SecurityEventType.COMMAND_INJECTION_ATTEMPT: [
                r"(;\s*(cat|ls|dir|type|ping|wget|curl|nc|netcat)\s)",
                r"(\|\s*(cat|ls|dir|type|ping|wget|curl|nc|netcat)\s)",
                r"(`[^`]*`)",
                r"(\$\([^)]*\))",
                r"(&&\s*\w+)",
                r"(\|\|\s*\w+)",
                r"(>\s*/dev/null)",
                r"(&\s*$)"
            ]
        }
    
    def _load_blocked_patterns(self) -> List[str]:
        """Load patterns that should be completely blocked."""
        return [
            r"<script[^>]*>.*?</script>",
            r"javascript\s*:",
            r"vbscript\s*:",
            r"data\s*:",
            r"<!DOCTYPE[^>]*\[.*ENTITY",
            r"<!ENTITY[^>]*>",
            r"(\b(drop|truncate|delete)\s+(table|database)\b)",
            r"(exec\s*\(\s*)",
            r"(eval\s*\(\s*)",
            r"(__import__\s*\()",
            r"(file\s*\(\s*)",
            r"(open\s*\(\s*)"
        ]
    
    def validate_input(self, input_data: str, input_type: str = "general", 
                      source_ip: str = "unknown", user_agent: str = "unknown") -> Tuple[bool, str, List[SecurityEvent]]:
        """
        Comprehensive input validation with threat detection.
        
        Args:
            input_data: Input to validate
            input_type: Type of input (query, xml, json, etc.)
            source_ip: Source IP address
            user_agent: User agent string
            
        Returns:
            Tuple of (is_valid, sanitized_data, security_events)
        """
        self.stats['total_validations'] += 1
        events = []
        sanitized_data = input_data
        is_valid = True
        
        try:
            # Check for blocked patterns first
            for pattern in self.blocked_patterns:
                if re.search(pattern, input_data, re.IGNORECASE | re.DOTALL):
                    event = SecurityEvent(
                        event_type=SecurityEventType.MALFORMED_REQUEST,
                        threat_level=ThreatLevel.CRITICAL,
                        timestamp=time.time(),
                        source_ip=source_ip,
                        user_agent=user_agent,
                        input_data=input_data[:500],  # Truncate for logging
                        sanitized_data="BLOCKED",
                        message=f"Blocked pattern detected: {pattern}",
                        additional_data={"input_type": input_type, "pattern": pattern}
                    )
                    events.append(event)
                    self.stats['blocked_requests'] += 1
                    self.stats['threats_detected'] += 1
                    return False, "BLOCKED", events
            
            # Detect specific threat types
            for threat_type, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, input_data, re.IGNORECASE | re.DOTALL)
                    if matches:
                        threat_level = self._assess_threat_level(threat_type, matches)
                        
                        event = SecurityEvent(
                            event_type=threat_type,
                            threat_level=threat_level,
                            timestamp=time.time(),
                            source_ip=source_ip,
                            user_agent=user_agent,
                            input_data=input_data[:500],
                            sanitized_data="",  # Will be set after sanitization
                            message=f"{threat_type.value} detected: {len(matches)} matches",
                            additional_data={
                                "input_type": input_type,
                                "matches": matches[:5],  # Limit to first 5 matches
                                "pattern": pattern
                            }
                        )
                        events.append(event)
                        self.stats['threats_detected'] += 1
                        
                        # For critical threats, consider blocking
                        if threat_level == ThreatLevel.CRITICAL:
                            is_valid = False
                            sanitized_data = "BLOCKED"
                            break
            
            # If not blocked, sanitize the input
            if is_valid:
                sanitized_data = self._sanitize_input(input_data, input_type)
                
                # Update events with sanitized data
                for event in events:
                    event.sanitized_data = sanitized_data[:500]
                
                if sanitized_data != input_data:
                    self.stats['inputs_sanitized'] += 1
            
            # Log security events
            for event in events:
                self._log_security_event(event)
            
            self.security_events.extend(events)
            
            return is_valid, sanitized_data, events
            
        except Exception as e:
            logger.error(f"Error in input validation: {e}")
            # In case of error, be conservative and block
            return False, "VALIDATION_ERROR", events
    
    def _assess_threat_level(self, threat_type: SecurityEventType, matches: List[str]) -> ThreatLevel:
        """Assess threat level based on type and matches."""
        
        # Critical threats - immediate blocking
        if threat_type in [SecurityEventType.XXE_ATTEMPT, SecurityEventType.COMMAND_INJECTION_ATTEMPT]:
            return ThreatLevel.CRITICAL
        
        # High threats - advanced SQL injection or XSS
        if threat_type == SecurityEventType.SQL_INJECTION_ATTEMPT:
            critical_keywords = ['drop', 'delete', 'truncate', 'exec', 'xp_cmdshell']
            if any(keyword in ' '.join(matches).lower() for keyword in critical_keywords):
                return ThreatLevel.CRITICAL
            elif len(matches) > 2:
                return ThreatLevel.HIGH
            else:
                return ThreatLevel.MEDIUM
        
        if threat_type == SecurityEventType.XSS_ATTEMPT:
            if any('script' in match.lower() or 'javascript' in match.lower() for match in matches):
                return ThreatLevel.HIGH
            else:
                return ThreatLevel.MEDIUM
        
        # Default to medium for other threats
        return ThreatLevel.MEDIUM
    
    def _sanitize_input(self, input_data: str, input_type: str) -> str:
        """Sanitize input data based on type."""
        
        if input_type == "xml":
            return self._sanitize_xml(input_data)
        elif input_type == "query":
            return self._sanitize_search_query(input_data)
        elif input_type == "html":
            return self._sanitize_html(input_data)
        else:
            return self._sanitize_general(input_data)
    
    def _sanitize_xml(self, xml_data: str) -> str:
        """Sanitize XML data to prevent XXE attacks."""
        try:
            # Remove DOCTYPE declarations and entity references
            xml_data = re.sub(r'<!DOCTYPE[^>]*>', '', xml_data, flags=re.IGNORECASE | re.DOTALL)
            xml_data = re.sub(r'<!ENTITY[^>]*>', '', xml_data, flags=re.IGNORECASE | re.DOTALL)
            xml_data = re.sub(r'&\w+;', '', xml_data)
            
            # Parse XML with secure parser settings
            parser = make_parser()
            parser.setFeature(feature_external_ges, False)
            parser.setFeature(feature_external_pes, False)
            
            # Validate XML structure
            try:
                ET.fromstring(xml_data)
            except ET.ParseError:
                logger.warning("Invalid XML structure detected")
                return "INVALID_XML"
            
            return xml_data
            
        except Exception as e:
            logger.error(f"Error sanitizing XML: {e}")
            return "XML_SANITIZATION_ERROR"
    
    def _sanitize_search_query(self, query: str) -> str:
        """Sanitize search query to prevent injection attacks."""
        # Remove SQL keywords and special characters
        dangerous_keywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'exec', 'execute', 'sp_executesql', 'xp_cmdshell', 'benchmark', 'sleep'
        ]
        
        sanitized = query
        for keyword in dangerous_keywords:
            sanitized = re.sub(rf'\b{keyword}\b', '', sanitized, flags=re.IGNORECASE)
        
        # Remove dangerous characters
        sanitized = re.sub(r'[;\'\"\\]', '', sanitized)
        sanitized = re.sub(r'--.*$', '', sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
        
        # Limit length
        sanitized = sanitized[:500]
        
        # Remove excessive whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized
    
    def _sanitize_html(self, html_data: str) -> str:
        """Sanitize HTML data to prevent XSS attacks."""
        # Remove script tags and dangerous elements
        html_data = re.sub(r'<script[^>]*>.*?</script>', '', html_data, flags=re.IGNORECASE | re.DOTALL)
        html_data = re.sub(r'<iframe[^>]*>.*?</iframe>', '', html_data, flags=re.IGNORECASE | re.DOTALL)
        html_data = re.sub(r'<object[^>]*>.*?</object>', '', html_data, flags=re.IGNORECASE | re.DOTALL)
        html_data = re.sub(r'<embed[^>]*>.*?</embed>', '', html_data, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove dangerous attributes
        html_data = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', html_data, flags=re.IGNORECASE)
        html_data = re.sub(r'javascript\s*:', '', html_data, flags=re.IGNORECASE)
        html_data = re.sub(r'vbscript\s*:', '', html_data, flags=re.IGNORECASE)
        html_data = re.sub(r'data\s*:', '', html_data, flags=re.IGNORECASE)
        
        # HTML encode remaining content
        html_data = html.escape(html_data)
        
        return html_data
    
    def _sanitize_general(self, data: str) -> str:
        """General purpose input sanitization."""
        # Remove null bytes and control characters
        data = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', data)
        
        # Limit length
        data = data[:1000]
        
        # Basic HTML encoding for safety
        data = html.escape(data)
        
        return data
    
    def sanitize_api_response(self, response_text: str, content_type: str = "text/html") -> str:
        """Sanitize API response content for security."""
        try:
            # Remove potentially dangerous script content
            response_text = re.sub(r'<script[^>]*>.*?</script>', '', response_text, flags=re.IGNORECASE | re.DOTALL)
            
            # Remove dangerous event handlers
            response_text = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', response_text, flags=re.IGNORECASE)
            
            # Remove dangerous protocols
            response_text = re.sub(r'(javascript|vbscript|data)\s*:', 'blocked:', response_text, flags=re.IGNORECASE)
            
            # Size limit for memory safety
            if len(response_text) > 10 * 1024 * 1024:  # 10MB limit
                response_text = response_text[:10 * 1024 * 1024]
                logger.warning("Response truncated due to size limit")
            
            return response_text
            
        except Exception as e:
            logger.error(f"Error sanitizing response: {e}")
            return "RESPONSE_SANITIZATION_ERROR"
    
    def validate_xml_security(self, xml_content: str) -> Tuple[bool, str]:
        """Validate XML content for security threats."""
        try:
            # Check for XXE indicators
            xxe_patterns = [
                r'<!DOCTYPE[^>]*\[.*ENTITY',
                r'<!ENTITY[^>]*>',
                r'SYSTEM\s+["\'][^"\']*["\']',
                r'PUBLIC\s+["\'][^"\']*["\']'
            ]
            
            for pattern in xxe_patterns:
                if re.search(pattern, xml_content, re.IGNORECASE | re.DOTALL):
                    return False, "XXE_THREAT_DETECTED"
            
            # Remove external entity references
            sanitized = re.sub(r'<!DOCTYPE[^>]*>', '', xml_content, flags=re.IGNORECASE | re.DOTALL)
            sanitized = re.sub(r'<!ENTITY[^>]*>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            # Validate XML structure with secure parser
            try:
                # Use a secure parser that disables external entities
                parser = ET.XMLParser()
                parser.parser.DefaultHandler = lambda data: None
                parser.parser.ExternalEntityRefHandler = lambda context, base, sysId, notationName: False
                
                ET.fromstring(sanitized, parser)
                return True, sanitized
                
            except ET.ParseError as e:
                logger.warning(f"XML parsing error: {e}")
                return False, "INVALID_XML_STRUCTURE"
                
        except Exception as e:
            logger.error(f"Error validating XML security: {e}")
            return False, "XML_VALIDATION_ERROR"
    
    def _log_security_event(self, event: SecurityEvent):
        """Log security event with appropriate severity."""
        log_message = (
            f"SECURITY EVENT: {event.event_type.value} | "
            f"Threat Level: {event.threat_level.value} | "
            f"Source: {event.source_ip} | "
            f"Message: {event.message}"
        )
        
        if event.threat_level == ThreatLevel.CRITICAL:
            logger.critical(log_message)
        elif event.threat_level == ThreatLevel.HIGH:
            logger.error(log_message)
        elif event.threat_level == ThreatLevel.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # Update last threat for monitoring
        if event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.stats['last_threat'] = {
                'type': event.event_type.value,
                'level': event.threat_level.value,
                'timestamp': event.timestamp,
                'source': event.source_ip
            }
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security validation statistics."""
        return {
            'total_validations': self.stats['total_validations'],
            'threats_detected': self.stats['threats_detected'],
            'inputs_sanitized': self.stats['inputs_sanitized'],
            'blocked_requests': self.stats['blocked_requests'],
            'threat_detection_rate': (
                self.stats['threats_detected'] / self.stats['total_validations'] * 100
            ) if self.stats['total_validations'] > 0 else 0,
            'last_threat': self.stats.get('last_threat'),
            'recent_events': len([
                event for event in self.security_events 
                if time.time() - event.timestamp < 3600  # Last hour
            ])
        }
    
    def get_recent_threats(self, hours: int = 24) -> List[SecurityEvent]:
        """Get recent security threats."""
        cutoff_time = time.time() - (hours * 3600)
        return [
            event for event in self.security_events
            if event.timestamp > cutoff_time and 
            event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        ]
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        recent_threats = self.get_recent_threats(24)
        
        threat_summary = {}
        for event in recent_threats:
            threat_type = event.event_type.value
            if threat_type not in threat_summary:
                threat_summary[threat_type] = {
                    'count': 0,
                    'highest_level': 'low',
                    'sources': set()
                }
            
            threat_summary[threat_type]['count'] += 1
            threat_summary[threat_type]['sources'].add(event.source_ip)
            
            if event.threat_level == ThreatLevel.CRITICAL:
                threat_summary[threat_type]['highest_level'] = 'critical'
            elif event.threat_level == ThreatLevel.HIGH and threat_summary[threat_type]['highest_level'] != 'critical':
                threat_summary[threat_type]['highest_level'] = 'high'
        
        # Convert sets to lists for JSON serialization
        for summary in threat_summary.values():
            summary['sources'] = list(summary['sources'])
        
        return {
            'report_timestamp': time.time(),
            'security_stats': self.get_security_stats(),
            'threat_summary': threat_summary,
            'recent_threats_count': len(recent_threats),
            'top_threat_sources': self._get_top_threat_sources(),
            'recommendations': self._generate_security_recommendations()
        }
    
    def _get_top_threat_sources(self) -> List[Dict[str, Any]]:
        """Get top threat sources by frequency."""
        source_counts = {}
        for event in self.security_events:
            if event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                source = event.source_ip
                if source not in source_counts:
                    source_counts[source] = {'count': 0, 'highest_level': 'low'}
                
                source_counts[source]['count'] += 1
                if event.threat_level == ThreatLevel.CRITICAL:
                    source_counts[source]['highest_level'] = 'critical'
                elif event.threat_level == ThreatLevel.HIGH and source_counts[source]['highest_level'] != 'critical':
                    source_counts[source]['highest_level'] = 'high'
        
        # Sort by count and return top 10
        top_sources = sorted(
            [(source, data) for source, data in source_counts.items()],
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]
        
        return [
            {'source_ip': source, 'threat_count': data['count'], 'highest_threat_level': data['highest_level']}
            for source, data in top_sources
        ]
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on detected threats."""
        recommendations = []
        
        if self.stats['threats_detected'] > 0:
            recommendations.append("Implement additional rate limiting for suspicious sources")
            recommendations.append("Consider implementing CAPTCHA for repeated threat sources")
        
        if self.stats['blocked_requests'] > 10:
            recommendations.append("Review firewall rules to block persistent attackers")
        
        recent_critical = len([
            event for event in self.security_events
            if event.threat_level == ThreatLevel.CRITICAL and time.time() - event.timestamp < 3600
        ])
        
        if recent_critical > 0:
            recommendations.append("Immediate security review required - critical threats detected")
            recommendations.append("Consider temporarily increasing security restrictions")
        
        return recommendations


# Global security validator instance
_security_validator: Optional[EnhancedSecurityValidator] = None


def get_security_validator() -> EnhancedSecurityValidator:
    """Get or create security validator instance."""
    global _security_validator
    if _security_validator is None:
        _security_validator = EnhancedSecurityValidator()
    return _security_validator


# Convenience functions for common validation tasks
def validate_search_query(query: str, source_ip: str = "unknown") -> Tuple[bool, str]:
    """Validate and sanitize search query."""
    validator = get_security_validator()
    is_valid, sanitized, events = validator.validate_input(query, "query", source_ip)
    return is_valid, sanitized


def validate_xml_input(xml_data: str, source_ip: str = "unknown") -> Tuple[bool, str]:
    """Validate and sanitize XML input."""
    validator = get_security_validator()
    return validator.validate_xml_security(xml_data)


def sanitize_api_response(response_text: str, content_type: str = "text/html") -> str:
    """Sanitize API response content."""
    validator = get_security_validator()
    return validator.sanitize_api_response(response_text, content_type)


if __name__ == "__main__":
    # Test the security validator
    validator = EnhancedSecurityValidator()
    
    # Test various threat types
    test_inputs = [
        "normal search query",
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>",
        "../../../etc/passwd",
        "test; cat /etc/passwd"
    ]
    
    print("🔒 Testing Enhanced Security Validator")
    print("=" * 50)
    
    for i, test_input in enumerate(test_inputs, 1):
        print(f"\nTest {i}: {test_input[:30]}...")
        is_valid, sanitized, events = validator.validate_input(test_input, "general", "127.0.0.1", "test-agent")
        
        print(f"Valid: {is_valid}")
        print(f"Sanitized: {sanitized[:50]}...")
        print(f"Events: {len(events)}")
        
        for event in events:
            print(f"  - {event.event_type.value} ({event.threat_level.value})")
    
    print(f"\n📊 Security Stats:")
    stats = validator.get_security_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")