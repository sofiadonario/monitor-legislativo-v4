"""Real-time document monitoring and notification service."""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor

from core.api.api_service import APIService
from core.utils.cache_manager import CacheManager
from core.auth.models import User
from core.models.models import Alert, AlertStatus, Document


class MonitoringEvent(Enum):
    """Types of monitoring events."""
    NEW_DOCUMENT = "new_document"
    DOCUMENT_UPDATED = "document_updated"
    DOCUMENT_STATUS_CHANGED = "document_status_changed"
    KEYWORD_MATCH = "keyword_match"
    DEADLINE_APPROACHING = "deadline_approaching"
    BULK_UPDATE = "bulk_update"


@dataclass
class MonitoringRule:
    """Rule for document monitoring."""
    id: str
    user_id: int
    name: str
    keywords: List[str]
    sources: List[str]
    document_types: List[str]
    date_range: Optional[Dict[str, str]]
    enabled: bool = True
    created_at: str = ""
    last_triggered: Optional[str] = None
    trigger_count: int = 0
    
    def matches_document(self, document: Dict[str, Any]) -> bool:
        """Check if document matches this monitoring rule."""
        # Check sources
        if self.sources and document.get('source') not in self.sources:
            return False
        
        # Check document types
        if self.document_types and document.get('document_type') not in self.document_types:
            return False
        
        # Check date range
        if self.date_range:
            doc_date = document.get('published_date')
            if doc_date:
                if self.date_range.get('start') and doc_date < self.date_range['start']:
                    return False
                if self.date_range.get('end') and doc_date > self.date_range['end']:
                    return False
        
        # Check keywords
        if self.keywords:
            content = ' '.join([
                document.get('title', ''),
                document.get('content', ''),
                ' '.join(document.get('keywords', []))
            ]).lower()
            
            for keyword in self.keywords:
                if keyword.lower() in content:
                    return True
            return False
        
        return True


@dataclass
class MonitoringNotification:
    """Notification for monitoring events."""
    id: str
    rule_id: str
    user_id: int
    event_type: MonitoringEvent
    document_id: int
    title: str
    message: str
    timestamp: str
    read: bool = False
    metadata: Dict[str, Any] = None


class RealTimeMonitoringService:
    """Service for real-time document monitoring."""
    
    def __init__(self):
        self.api_service = APIService()
        self.cache_manager = CacheManager()
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.monitoring_rules: Dict[str, MonitoringRule] = {}
        self.active_monitors: Set[str] = set()
        self.document_cache: Dict[str, str] = {}  # doc_id -> hash
        self.notification_queue: List[MonitoringNotification] = []
        
        # Configuration
        self.check_interval = 300  # 5 minutes
        self.max_notifications_per_user = 100
        self.notification_batch_size = 10
        
        # Event handlers
        self.event_handlers: Dict[MonitoringEvent, List[Callable]] = {
            MonitoringEvent.NEW_DOCUMENT: [],
            MonitoringEvent.DOCUMENT_UPDATED: [],
            MonitoringEvent.DOCUMENT_STATUS_CHANGED: [],
            MonitoringEvent.KEYWORD_MATCH: [],
            MonitoringEvent.DEADLINE_APPROACHING: [],
            MonitoringEvent.BULK_UPDATE: []
        }
        
        # Async tasks
        self.monitoring_task: Optional[asyncio.Task] = None
        self.notification_task: Optional[asyncio.Task] = None
    
    async def start_monitoring(self):
        """Start the real-time monitoring service."""
        if self.monitoring_task and not self.monitoring_task.done():
            self.logger.warning("Monitoring already started")
            return
        
        self.logger.info("Starting real-time monitoring service")
        
        # Load existing rules
        await self._load_monitoring_rules()
        
        # Start monitoring tasks
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        self.notification_task = asyncio.create_task(self._notification_loop())
        
        self.logger.info("Real-time monitoring service started")
    
    async def stop_monitoring(self):
        """Stop the real-time monitoring service."""
        self.logger.info("Stopping real-time monitoring service")
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.notification_task:
            self.notification_task.cancel()
            try:
                await self.notification_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Real-time monitoring service stopped")
    
    def add_monitoring_rule(self, rule: MonitoringRule) -> str:
        """Add a new monitoring rule."""
        if not rule.id:
            rule.id = self._generate_rule_id(rule)
        
        rule.created_at = datetime.now().isoformat()
        self.monitoring_rules[rule.id] = rule
        
        if rule.enabled:
            self.active_monitors.add(rule.id)
        
        # Persist rule
        self._save_monitoring_rule(rule)
        
        self.logger.info(f"Added monitoring rule: {rule.id}")
        return rule.id
    
    def update_monitoring_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing monitoring rule."""
        if rule_id not in self.monitoring_rules:
            return False
        
        rule = self.monitoring_rules[rule_id]
        
        # Update fields
        for field, value in updates.items():
            if hasattr(rule, field):
                setattr(rule, field, value)
        
        # Update active status
        if rule.enabled:
            self.active_monitors.add(rule_id)
        else:
            self.active_monitors.discard(rule_id)
        
        # Persist changes
        self._save_monitoring_rule(rule)
        
        self.logger.info(f"Updated monitoring rule: {rule_id}")
        return True
    
    def remove_monitoring_rule(self, rule_id: str) -> bool:
        """Remove a monitoring rule."""
        if rule_id not in self.monitoring_rules:
            return False
        
        del self.monitoring_rules[rule_id]
        self.active_monitors.discard(rule_id)
        
        # Remove from storage
        self._delete_monitoring_rule(rule_id)
        
        self.logger.info(f"Removed monitoring rule: {rule_id}")
        return True
    
    def get_user_rules(self, user_id: int) -> List[MonitoringRule]:
        """Get all monitoring rules for a user."""
        return [rule for rule in self.monitoring_rules.values() if rule.user_id == user_id]
    
    def get_user_notifications(self, user_id: int, limit: int = 50) -> List[MonitoringNotification]:
        """Get notifications for a user."""
        user_notifications = [
            notif for notif in self.notification_queue 
            if notif.user_id == user_id
        ]
        return sorted(user_notifications, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    def mark_notification_read(self, notification_id: str) -> bool:
        """Mark a notification as read."""
        for notif in self.notification_queue:
            if notif.id == notification_id:
                notif.read = True
                return True
        return False
    
    def add_event_handler(self, event_type: MonitoringEvent, handler: Callable):
        """Add an event handler for monitoring events."""
        self.event_handlers[event_type].append(handler)
    
    def remove_event_handler(self, event_type: MonitoringEvent, handler: Callable):
        """Remove an event handler."""
        if handler in self.event_handlers[event_type]:
            self.event_handlers[event_type].remove(handler)
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while True:
            try:
                await self._check_for_new_documents()
                await self._check_for_document_updates()
                await self._check_for_approaching_deadlines()
                
                # Wait for next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _notification_loop(self):
        """Notification processing loop."""
        while True:
            try:
                if self.notification_queue:
                    # Process notifications in batches
                    batch = self.notification_queue[:self.notification_batch_size]
                    self.notification_queue = self.notification_queue[self.notification_batch_size:]
                    
                    for notification in batch:
                        await self._send_notification(notification)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in notification loop: {e}")
                await asyncio.sleep(30)
    
    async def _check_for_new_documents(self):
        """Check for new documents."""
        try:
            # Get recent documents from all sources
            sources = ['camara', 'senado', 'planalto']
            
            with ThreadPoolExecutor(max_workers=3) as executor:
                tasks = []
                for source in sources:
                    task = asyncio.get_event_loop().run_in_executor(
                        executor, self._fetch_recent_documents, source
                    )
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for source, result in zip(sources, results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error fetching from {source}: {result}")
                    continue
                
                if result:
                    await self._process_new_documents(result, source)
                    
        except Exception as e:
            self.logger.error(f"Error checking for new documents: {e}")
    
    def _fetch_recent_documents(self, source: str) -> List[Dict[str, Any]]:
        """Fetch recent documents from a source."""
        try:
            # Calculate date range (last 24 hours)
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=1)
            
            # Fetch documents
            params = {
                'data_inicio': start_date.isoformat(),
                'data_fim': end_date.isoformat(),
                'limite': 100
            }
            
            if source == 'camara':
                return self.api_service.search_camara_documents(**params)
            elif source == 'senado':
                return self.api_service.search_senado_documents(**params)
            elif source == 'planalto':
                return self.api_service.search_planalto_documents(**params)
            
        except Exception as e:
            self.logger.error(f"Error fetching from {source}: {e}")
            return []
    
    async def _process_new_documents(self, documents: List[Dict[str, Any]], source: str):
        """Process newly fetched documents."""
        for doc in documents:
            doc_id = str(doc.get('id', ''))
            doc_hash = self._calculate_document_hash(doc)
            
            # Check if document is new
            if doc_id not in self.document_cache:
                self.document_cache[doc_id] = doc_hash
                await self._handle_new_document(doc, source)
            elif self.document_cache[doc_id] != doc_hash:
                # Document was updated
                self.document_cache[doc_id] = doc_hash
                await self._handle_document_update(doc, source)
    
    async def _handle_new_document(self, document: Dict[str, Any], source: str):
        """Handle a new document."""
        # Check against all active monitoring rules
        for rule_id in self.active_monitors:
            rule = self.monitoring_rules[rule_id]
            
            if rule.matches_document(document):
                await self._trigger_monitoring_event(
                    MonitoringEvent.NEW_DOCUMENT,
                    rule,
                    document
                )
    
    async def _handle_document_update(self, document: Dict[str, Any], source: str):
        """Handle a document update."""
        # Check against all active monitoring rules
        for rule_id in self.active_monitors:
            rule = self.monitoring_rules[rule_id]
            
            if rule.matches_document(document):
                await self._trigger_monitoring_event(
                    MonitoringEvent.DOCUMENT_UPDATED,
                    rule,
                    document
                )
    
    async def _check_for_document_updates(self):
        """Check for updates to existing documents."""
        # This would check specific documents that users are monitoring
        # For now, this is handled in _check_for_new_documents
        pass
    
    async def _check_for_approaching_deadlines(self):
        """Check for approaching deadlines in documents."""
        # This would analyze document content for deadline mentions
        # and notify users when deadlines are approaching
        try:
            deadline_keywords = [
                'prazo', 'vencimento', 'data limite', 'até', 'vigência'
            ]
            
            # Check recent documents for deadline mentions
            # This is a simplified implementation
            
        except Exception as e:
            self.logger.error(f"Error checking deadlines: {e}")
    
    async def _trigger_monitoring_event(self, event_type: MonitoringEvent, 
                                      rule: MonitoringRule, document: Dict[str, Any]):
        """Trigger a monitoring event."""
        try:
            # Update rule statistics
            rule.last_triggered = datetime.now().isoformat()
            rule.trigger_count += 1
            
            # Create notification
            notification = self._create_notification(event_type, rule, document)
            self.notification_queue.append(notification)
            
            # Trigger event handlers
            for handler in self.event_handlers[event_type]:
                try:
                    await handler(event_type, rule, document)
                except Exception as e:
                    self.logger.error(f"Error in event handler: {e}")
            
            self.logger.info(f"Triggered {event_type.value} for rule {rule.id}")
            
        except Exception as e:
            self.logger.error(f"Error triggering event: {e}")
    
    def _create_notification(self, event_type: MonitoringEvent, 
                           rule: MonitoringRule, document: Dict[str, Any]) -> MonitoringNotification:
        """Create a notification for a monitoring event."""
        doc_title = document.get('title', 'Documento sem título')
        
        if event_type == MonitoringEvent.NEW_DOCUMENT:
            title = f"Novo documento: {rule.name}"
            message = f"Novo documento encontrado que corresponde à sua regra '{rule.name}': {doc_title}"
        elif event_type == MonitoringEvent.DOCUMENT_UPDATED:
            title = f"Documento atualizado: {rule.name}"
            message = f"Documento atualizado que corresponde à sua regra '{rule.name}': {doc_title}"
        elif event_type == MonitoringEvent.KEYWORD_MATCH:
            title = f"Palavra-chave encontrada: {rule.name}"
            message = f"Documento contém palavras-chave da regra '{rule.name}': {doc_title}"
        else:
            title = f"Evento de monitoramento: {rule.name}"
            message = f"Evento detectado para a regra '{rule.name}': {doc_title}"
        
        return MonitoringNotification(
            id=self._generate_notification_id(),
            rule_id=rule.id,
            user_id=rule.user_id,
            event_type=event_type,
            document_id=document.get('id', 0),
            title=title,
            message=message,
            timestamp=datetime.now().isoformat(),
            metadata={
                'document_source': document.get('source'),
                'document_type': document.get('document_type'),
                'document_url': document.get('url')
            }
        )
    
    async def _send_notification(self, notification: MonitoringNotification):
        """Send a notification to the user."""
        try:
            # This would integrate with notification systems
            # For now, just log the notification
            self.logger.info(f"Notification sent to user {notification.user_id}: {notification.title}")
            
            # Here you would:
            # 1. Send email notification
            # 2. Send push notification
            # 3. Update database with notification
            # 4. Send WebSocket message for real-time updates
            
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")
    
    def _calculate_document_hash(self, document: Dict[str, Any]) -> str:
        """Calculate hash for document to detect changes."""
        # Use relevant fields for change detection
        content = json.dumps({
            'title': document.get('title', ''),
            'content': document.get('content', ''),
            'status': document.get('status', ''),
            'last_modified': document.get('last_modified', '')
        }, sort_keys=True)
        
        return hashlib.md5(content.encode()).hexdigest()
    
    def _generate_rule_id(self, rule: MonitoringRule) -> str:
        """Generate unique ID for monitoring rule."""
        content = f"{rule.user_id}_{rule.name}_{datetime.now().isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _generate_notification_id(self) -> str:
        """Generate unique ID for notification."""
        content = f"notification_{datetime.now().isoformat()}_{id(self)}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    async def _load_monitoring_rules(self):
        """Load monitoring rules from storage."""
        # This would load from database
        # For now, create some example rules
        pass
    
    def _save_monitoring_rule(self, rule: MonitoringRule):
        """Save monitoring rule to storage."""
        # This would save to database
        pass
    
    def _delete_monitoring_rule(self, rule_id: str):
        """Delete monitoring rule from storage."""
        # This would delete from database
        pass