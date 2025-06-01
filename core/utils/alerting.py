"""
Alerting System for Monitor Legislativo
Automated alerts for system health and performance issues
"""

import smtplib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

from .monitoring import metrics_collector
from .circuit_breaker import circuit_manager


@dataclass
class AlertRule:
    """Configuration for an alert rule"""
    name: str
    condition: Callable
    severity: str  # "critical", "warning", "info"
    cooldown_minutes: int = 60
    enabled: bool = True
    last_triggered: Optional[datetime] = None


@dataclass
class Alert:
    """Represents an alert"""
    rule_name: str
    severity: str
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    source: Optional[str] = None


class AlertManager:
    """Manages alerts and notifications"""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.logger = logging.getLogger("AlertManager")
        self.config_path = config_path or Path("configs/alert_config.json")
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: List[Alert] = []
        self.notification_handlers = []
        
        # Load configuration
        self._load_config()
        
        # Set up default rules
        self._setup_default_rules()
    
    def _load_config(self):
        """Load alerting configuration"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.email_config = config.get("email", {})
                    self.webhook_config = config.get("webhook", {})
            else:
                # Create default config
                default_config = {
                    "email": {
                        "enabled": False,
                        "smtp_server": "smtp.gmail.com",
                        "smtp_port": 587,
                        "username": "",
                        "password": "",
                        "recipients": []
                    },
                    "webhook": {
                        "enabled": False,
                        "url": "",
                        "headers": {}
                    }
                }
                
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
                
                self.email_config = default_config["email"]
                self.webhook_config = default_config["webhook"]
                
        except Exception as e:
            self.logger.error(f"Failed to load alert config: {e}")
            self.email_config = {"enabled": False}
            self.webhook_config = {"enabled": False}
    
    def _setup_default_rules(self):
        """Set up default alerting rules"""
        
        # Critical: Multiple sources down
        self.add_rule(AlertRule(
            name="multiple_sources_down",
            condition=lambda: self._check_multiple_sources_down(),
            severity="critical",
            cooldown_minutes=30
        ))
        
        # Critical: System-wide failure
        self.add_rule(AlertRule(
            name="system_wide_failure",
            condition=lambda: self._check_system_wide_failure(),
            severity="critical",
            cooldown_minutes=15
        ))
        
        # Warning: Source degraded
        self.add_rule(AlertRule(
            name="source_degraded",
            condition=lambda: self._check_degraded_sources(),
            severity="warning",
            cooldown_minutes=60
        ))
        
        # Warning: High response times
        self.add_rule(AlertRule(
            name="high_response_times",
            condition=lambda: self._check_high_response_times(),
            severity="warning",
            cooldown_minutes=30
        ))
        
        # Warning: Circuit breakers open
        self.add_rule(AlertRule(
            name="circuit_breakers_open",
            condition=lambda: self._check_open_circuit_breakers(),
            severity="warning",
            cooldown_minutes=45
        ))
        
        # Info: Low success rate
        self.add_rule(AlertRule(
            name="low_success_rate",
            condition=lambda: self._check_low_success_rate(),
            severity="info",
            cooldown_minutes=120
        ))
    
    def add_rule(self, rule: AlertRule):
        """Add an alerting rule"""
        self.rules[rule.name] = rule
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """Remove an alerting rule"""
        if rule_name in self.rules:
            del self.rules[rule_name]
            self.logger.info(f"Removed alert rule: {rule_name}")
    
    def check_all_rules(self) -> List[Alert]:
        """Check all alert rules and trigger notifications"""
        new_alerts = []
        
        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue
            
            # Check cooldown
            if rule.last_triggered:
                time_since_last = datetime.now() - rule.last_triggered
                if time_since_last.total_seconds() < rule.cooldown_minutes * 60:
                    continue
            
            try:
                # Check condition
                result = rule.condition()
                
                if result:
                    alert = self._create_alert_from_rule(rule, result)
                    new_alerts.append(alert)
                    rule.last_triggered = datetime.now()
                    
                    # Send notifications
                    self._send_notifications(alert)
                    
            except Exception as e:
                self.logger.error(f"Error checking rule {rule_name}: {e}")
        
        # Add to active alerts
        self.active_alerts.extend(new_alerts)
        
        # Clean up old alerts (older than 24 hours)
        cutoff = datetime.now() - timedelta(hours=24)
        self.active_alerts = [a for a in self.active_alerts if a.timestamp >= cutoff]
        
        return new_alerts
    
    def _create_alert_from_rule(self, rule: AlertRule, condition_result: Any) -> Alert:
        """Create alert from rule and condition result"""
        
        if isinstance(condition_result, dict):
            message = condition_result.get("message", f"Alert triggered: {rule.name}")
            details = condition_result.get("details", {})
            source = condition_result.get("source")
        else:
            message = f"Alert triggered: {rule.name}"
            details = {"result": str(condition_result)}
            source = None
        
        return Alert(
            rule_name=rule.name,
            severity=rule.severity,
            message=message,
            details=details,
            timestamp=datetime.now(),
            source=source
        )
    
    def _send_notifications(self, alert: Alert):
        """Send notifications for an alert"""
        try:
            # Email notification
            if self.email_config.get("enabled", False):
                self._send_email_notification(alert)
            
            # Webhook notification
            if self.webhook_config.get("enabled", False):
                self._send_webhook_notification(alert)
            
            # Log notification
            severity_emoji = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}
            emoji = severity_emoji.get(alert.severity, "📢")
            
            self.logger.warning(f"{emoji} ALERT [{alert.severity.upper()}]: {alert.message}")
            
        except Exception as e:
            self.logger.error(f"Failed to send notifications for alert: {e}")
    
    def _send_email_notification(self, alert: Alert):
        """Send email notification"""
        try:
            if not self.email_config.get("recipients"):
                return
            
            msg = MIMEMultipart()
            msg['From'] = self.email_config['username']
            msg['To'] = ', '.join(self.email_config['recipients'])
            msg['Subject'] = f"[Monitor Legislativo] {alert.severity.upper()}: {alert.message}"
            
            # Create email body
            body = f"""
Monitor Legislativo Alert

Severity: {alert.severity.upper()}
Timestamp: {alert.timestamp.isoformat()}
Source: {alert.source or 'System'}
Message: {alert.message}

Details:
{json.dumps(alert.details, indent=2)}

---
Monitor Legislativo v4.0
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email notification sent for alert: {alert.rule_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
    
    def _send_webhook_notification(self, alert: Alert):
        """Send webhook notification"""
        try:
            import requests
            
            payload = {
                "alert": {
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "message": alert.message,
                    "details": alert.details,
                    "timestamp": alert.timestamp.isoformat(),
                    "source": alert.source
                },
                "system": "Monitor Legislativo v4.0"
            }
            
            headers = self.webhook_config.get("headers", {})
            headers["Content-Type"] = "application/json"
            
            response = requests.post(
                self.webhook_config["url"],
                json=payload,
                headers=headers,
                timeout=10
            )
            
            response.raise_for_status()
            self.logger.info(f"Webhook notification sent for alert: {alert.rule_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
    
    # Alert condition checks
    
    def _check_multiple_sources_down(self) -> Optional[Dict[str, Any]]:
        """Check if multiple sources are down"""
        try:
            dashboard_data = metrics_collector.get_dashboard_data()
            down_sources = dashboard_data["summary"]["down_sources"]
            
            if down_sources >= 3:
                return {
                    "message": f"{down_sources} data sources are currently down",
                    "details": {
                        "down_sources": down_sources,
                        "total_sources": dashboard_data["summary"]["total_sources"]
                    }
                }
        except Exception:
            pass
        return None
    
    def _check_system_wide_failure(self) -> Optional[Dict[str, Any]]:
        """Check for system-wide failure"""
        try:
            dashboard_data = metrics_collector.get_dashboard_data()
            summary = dashboard_data["summary"]
            
            # System-wide failure if >70% of sources are down
            failure_rate = summary["down_sources"] / summary["total_sources"]
            
            if failure_rate > 0.7:
                return {
                    "message": "System-wide failure detected - most sources are down",
                    "details": {
                        "failure_rate": round(failure_rate * 100, 2),
                        "down_sources": summary["down_sources"],
                        "total_sources": summary["total_sources"]
                    }
                }
        except Exception:
            pass
        return None
    
    def _check_degraded_sources(self) -> Optional[Dict[str, Any]]:
        """Check for degraded sources"""
        try:
            dashboard_data = metrics_collector.get_dashboard_data()
            degraded_sources = []
            
            for source, health in dashboard_data["sources"].items():
                if health["current_status"] == "degraded":
                    degraded_sources.append({
                        "source": source,
                        "success_rate": health["success_rate"]
                    })
            
            if len(degraded_sources) >= 2:
                return {
                    "message": f"{len(degraded_sources)} sources are degraded",
                    "details": {"degraded_sources": degraded_sources}
                }
        except Exception:
            pass
        return None
    
    def _check_high_response_times(self) -> Optional[Dict[str, Any]]:
        """Check for high response times"""
        try:
            dashboard_data = metrics_collector.get_dashboard_data()
            slow_sources = []
            
            for source, health in dashboard_data["sources"].items():
                if health["avg_response_time"] > 15:  # >15 seconds
                    slow_sources.append({
                        "source": source,
                        "avg_response_time": health["avg_response_time"]
                    })
            
            if len(slow_sources) >= 2:
                return {
                    "message": f"{len(slow_sources)} sources have high response times",
                    "details": {"slow_sources": slow_sources}
                }
        except Exception:
            pass
        return None
    
    def _check_open_circuit_breakers(self) -> Optional[Dict[str, Any]]:
        """Check for open circuit breakers"""
        try:
            circuit_stats = circuit_manager.get_all_stats()
            open_breakers = []
            
            for name, stats in circuit_stats.items():
                if stats["state"] == "open":
                    open_breakers.append({
                        "name": name,
                        "failure_count": stats["failure_count"]
                    })
            
            if len(open_breakers) >= 1:
                return {
                    "message": f"{len(open_breakers)} circuit breakers are open",
                    "details": {"open_breakers": open_breakers}
                }
        except Exception:
            pass
        return None
    
    def _check_low_success_rate(self) -> Optional[Dict[str, Any]]:
        """Check for overall low success rate"""
        try:
            dashboard_data = metrics_collector.get_dashboard_data()
            recent_activity = dashboard_data["recent_activity"]
            
            success_rate = recent_activity["success_rate_last_hour"]
            
            if success_rate < 50:  # <50% success rate
                return {
                    "message": f"Low system success rate: {success_rate}%",
                    "details": {
                        "success_rate": success_rate,
                        "failed_calls": recent_activity["failed_calls_last_hour"],
                        "total_calls": recent_activity["total_calls_last_hour"]
                    }
                }
        except Exception:
            pass
        return None
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return self.active_alerts
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alert status"""
        critical_count = sum(1 for a in self.active_alerts if a.severity == "critical")
        warning_count = sum(1 for a in self.active_alerts if a.severity == "warning")
        info_count = sum(1 for a in self.active_alerts if a.severity == "info")
        
        return {
            "total_alerts": len(self.active_alerts),
            "critical_alerts": critical_count,
            "warning_alerts": warning_count,
            "info_alerts": info_count,
            "alert_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled)
        }


# Global alert manager instance
alert_manager = AlertManager()