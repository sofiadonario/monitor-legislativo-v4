#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Monitoring Service
Provides continuous monitoring and alerting for transport legislation
"""

import json
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .lexml_integration import LexMLIntegration


class LexMLMonitor:
    """
    Monitor service for tracking new and updated transport legislation
    """
    
    def __init__(self, config_file: str = "configs/lexml_monitor_config.json"):
        self.config = self._load_config(config_file)
        self.integration = LexMLIntegration(self.config.get('output_dir', 'data/lexml_monitor'))
        
        # State tracking
        self.state_file = Path(self.config.get('state_file', 'data/lexml_monitor/monitor_state.json'))
        self.state = self._load_state()
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def _load_config(self, config_file: str) -> Dict:
        """Load monitor configuration"""
        config_path = Path(config_file)
        
        if not config_path.exists():
            # Create default config
            default_config = {
                "output_dir": "data/lexml_monitor",
                "state_file": "data/lexml_monitor/monitor_state.json",
                "check_interval_hours": 24,
                "alert_recipients": [],
                "priority_terms": [
                    "Rota 2030",
                    "CONTRAN",
                    "ANTT",
                    "combustível sustentável",
                    "descarbonização"
                ],
                "notification_settings": {
                    "email_enabled": False,
                    "webhook_enabled": False,
                    "webhook_url": ""
                }
            }
            
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config
        
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def _load_state(self) -> Dict:
        """Load monitor state"""
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                return json.load(f)
        
        return {
            'last_check': None,
            'known_documents': {},
            'alert_history': []
        }
    
    def _save_state(self):
        """Save monitor state"""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def check_for_updates(self) -> Dict:
        """
        Check for new or updated legislation
        Returns dict with new and updated documents
        """
        self.logger.info("Starting legislation update check...")
        
        # Search all terms
        current_results = self.integration.search_all_terms()
        
        # Analyze changes
        new_documents = []
        updated_documents = []
        priority_alerts = []
        
        for result in current_results:
            doc_id = result.get('urn', result.get('url', ''))
            if not doc_id:
                continue
            
            # Create document hash for change detection
            doc_hash = self._create_document_hash(result)
            
            if doc_id not in self.state['known_documents']:
                # New document
                new_documents.append(result)
                self.state['known_documents'][doc_id] = {
                    'hash': doc_hash,
                    'first_seen': datetime.now().isoformat(),
                    'last_updated': datetime.now().isoformat()
                }
                
                # Check if it contains priority terms
                if self._contains_priority_terms(result):
                    priority_alerts.append(result)
            
            elif self.state['known_documents'][doc_id]['hash'] != doc_hash:
                # Updated document
                updated_documents.append(result)
                self.state['known_documents'][doc_id]['hash'] = doc_hash
                self.state['known_documents'][doc_id]['last_updated'] = datetime.now().isoformat()
        
        # Update last check time
        self.state['last_check'] = datetime.now().isoformat()
        self._save_state()
        
        # Create update summary
        update_summary = {
            'check_time': datetime.now().isoformat(),
            'total_documents': len(current_results),
            'new_documents': len(new_documents),
            'updated_documents': len(updated_documents),
            'priority_alerts': len(priority_alerts),
            'new_docs': new_documents,
            'updated_docs': updated_documents,
            'priority_docs': priority_alerts
        }
        
        # Send notifications if configured
        if new_documents or updated_documents:
            self._send_notifications(update_summary)
        
        return update_summary
    
    def _create_document_hash(self, document: Dict) -> str:
        """Create hash of document content for change detection"""
        content = json.dumps({
            'title': document.get('title', ''),
            'description': document.get('description', ''),
            'subjects': document.get('subjects', ''),
            'document_date': document.get('document_date', '')
        }, sort_keys=True)
        
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _contains_priority_terms(self, document: Dict) -> bool:
        """Check if document contains priority terms"""
        text_fields = [
            document.get('title', ''),
            document.get('description', ''),
            document.get('subjects', '')
        ]
        
        full_text = ' '.join(text_fields).lower()
        
        for term in self.config.get('priority_terms', []):
            if term.lower() in full_text:
                return True
        
        return False
    
    def _send_notifications(self, update_summary: Dict):
        """Send notifications about updates"""
        # Log updates
        self.logger.info(f"Found {update_summary['new_documents']} new documents")
        self.logger.info(f"Found {update_summary['updated_documents']} updated documents")
        
        if update_summary['priority_alerts']:
            self.logger.warning(f"PRIORITY ALERT: {update_summary['priority_alerts']} documents contain priority terms")
        
        # Add to alert history
        self.state['alert_history'].append({
            'timestamp': update_summary['check_time'],
            'new_count': update_summary['new_documents'],
            'updated_count': update_summary['updated_documents'],
            'priority_count': update_summary['priority_alerts']
        })
        
        # Keep only last 100 alerts
        self.state['alert_history'] = self.state['alert_history'][-100:]
        self._save_state()
        
        # Send email if configured
        if self.config['notification_settings'].get('email_enabled'):
            self._send_email_notification(update_summary)
        
        # Send webhook if configured
        if self.config['notification_settings'].get('webhook_enabled'):
            self._send_webhook_notification(update_summary)
    
    def _send_email_notification(self, update_summary: Dict):
        """Send email notification (placeholder - requires SMTP config)"""
        self.logger.info("Email notifications not fully implemented")
    
    def _send_webhook_notification(self, update_summary: Dict):
        """Send webhook notification"""
        webhook_url = self.config['notification_settings'].get('webhook_url')
        if not webhook_url:
            return
        
        try:
            import requests
            
            payload = {
                'type': 'lexml_update',
                'timestamp': update_summary['check_time'],
                'summary': {
                    'new_documents': update_summary['new_documents'],
                    'updated_documents': update_summary['updated_documents'],
                    'priority_alerts': update_summary['priority_alerts']
                }
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                self.logger.info("Webhook notification sent successfully")
            else:
                self.logger.error(f"Webhook notification failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error sending webhook notification: {e}")
    
    def generate_report(self, days: int = 7) -> str:
        """Generate activity report for the last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_alerts = [
            alert for alert in self.state.get('alert_history', [])
            if datetime.fromisoformat(alert['timestamp']) > cutoff_date
        ]
        
        report = {
            'report_date': datetime.now().isoformat(),
            'period_days': days,
            'total_alerts': len(recent_alerts),
            'total_new_documents': sum(a['new_count'] for a in recent_alerts),
            'total_updated_documents': sum(a['updated_count'] for a in recent_alerts),
            'total_priority_alerts': sum(a['priority_count'] for a in recent_alerts),
            'alerts_by_day': {}
        }
        
        # Group by day
        for alert in recent_alerts:
            day = alert['timestamp'][:10]
            if day not in report['alerts_by_day']:
                report['alerts_by_day'][day] = {
                    'new': 0,
                    'updated': 0,
                    'priority': 0
                }
            
            report['alerts_by_day'][day]['new'] += alert['new_count']
            report['alerts_by_day'][day]['updated'] += alert['updated_count']
            report['alerts_by_day'][day]['priority'] += alert['priority_count']
        
        # Save report
        report_file = Path(self.integration.output_dir) / f"monitor_report_{datetime.now().strftime('%Y%m%d')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Generated report: {report_file}")
        return str(report_file)
    
    def run_continuous_monitoring(self):
        """Run continuous monitoring loop"""
        check_interval = self.config.get('check_interval_hours', 24) * 3600
        
        self.logger.info(f"Starting continuous monitoring (interval: {check_interval/3600} hours)")
        
        while True:
            try:
                # Check for updates
                updates = self.check_for_updates()
                
                # Generate daily report
                if datetime.now().hour == 9:  # 9 AM
                    self.generate_report()
                
                # Sleep until next check
                self.logger.info(f"Next check in {check_interval/3600} hours")
                time.sleep(check_interval)
            
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                # Wait before retrying
                time.sleep(300)  # 5 minutes


def main():
    """Run the monitor"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    monitor = LexMLMonitor()
    
    # Run single check
    print("Running legislation update check...")
    updates = monitor.check_for_updates()
    
    print(f"\nUpdate Summary:")
    print(f"- New documents: {updates['new_documents']}")
    print(f"- Updated documents: {updates['updated_documents']}")
    print(f"- Priority alerts: {updates['priority_alerts']}")
    
    if updates['priority_docs']:
        print("\nPRIORITY DOCUMENTS:")
        for doc in updates['priority_docs'][:5]:  # Show first 5
            print(f"- {doc.get('title', 'No title')}")
            print(f"  URL: {doc.get('url', 'No URL')}")
    
    # Optionally start continuous monitoring
    # monitor.run_continuous_monitoring()


if __name__ == "__main__":
    main()