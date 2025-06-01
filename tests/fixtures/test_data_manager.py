"""Test data management system for consistent test data across test suites."""

import json
import yaml
import csv
from pathlib import Path
from datetime import datetime, date, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import random


@dataclass
class TestDocument:
    """Test document data structure."""
    id: int
    title: str
    content: str
    source: str
    document_type: str
    published_date: str
    url: str
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TestUser:
    """Test user data structure."""
    id: int
    username: str
    email: str
    password: str
    role: str
    first_name: str = ""
    last_name: str = ""
    created_at: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TestAlert:
    """Test alert data structure."""
    id: int
    title: str
    message: str
    alert_type: str
    status: str
    created_at: str
    user_id: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class TestDataManager:
    """Manages test data creation, loading, and cleanup."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize test data manager."""
        self.data_dir = data_dir or Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        
        # Data storage
        self._documents: List[TestDocument] = []
        self._users: List[TestUser] = []
        self._alerts: List[TestAlert] = []
        
        # Load existing data
        self._load_existing_data()
    
    def _load_existing_data(self):
        """Load existing test data from files."""
        try:
            # Load documents
            docs_file = self.data_dir / "documents.json"
            if docs_file.exists():
                with open(docs_file, 'r', encoding='utf-8') as f:
                    docs_data = json.load(f)
                    self._documents = [TestDocument(**doc) for doc in docs_data]
            
            # Load users
            users_file = self.data_dir / "users.json"
            if users_file.exists():
                with open(users_file, 'r', encoding='utf-8') as f:
                    users_data = json.load(f)
                    self._users = [TestUser(**user) for user in users_data]
            
            # Load alerts
            alerts_file = self.data_dir / "alerts.json"
            if alerts_file.exists():
                with open(alerts_file, 'r', encoding='utf-8') as f:
                    alerts_data = json.load(f)
                    self._alerts = [TestAlert(**alert) for alert in alerts_data]
        
        except Exception as e:
            print(f"Warning: Could not load existing test data: {e}")
    
    def generate_sample_documents(self, count: int = 50) -> List[TestDocument]:
        """Generate sample documents for testing."""
        document_types = ['LEI', 'DECRETO', 'PORTARIA', 'RESOLUCAO', 'INSTRUCAO_NORMATIVA']
        sources = ['Camara', 'Senado', 'Planalto', 'Ministerio']
        
        # Brazilian legislative topics
        topics = [
            'proteção de dados pessoais',
            'educação digital',
            'saúde pública',
            'meio ambiente',
            'direitos do consumidor',
            'tecnologia e inovação',
            'segurança pública',
            'economia digital',
            'infraestrutura',
            'desenvolvimento sustentável'
        ]
        
        documents = []
        base_date = date.today() - timedelta(days=365)
        
        for i in range(count):
            doc_id = len(self._documents) + i + 1
            topic = random.choice(topics)
            doc_type = random.choice(document_types)
            source = random.choice(sources)
            
            # Generate publication date
            pub_date = base_date + timedelta(days=random.randint(0, 365))
            
            document = TestDocument(
                id=doc_id,
                title=f"{doc_type.replace('_', ' ').title()} sobre {topic}",
                content=f"Este documento trata de regulamentações relacionadas a {topic}. "
                       f"Estabelece diretrizes importantes para a implementação de políticas "
                       f"públicas na área de {topic.split()[0]}. " * 3,
                source=source,
                document_type=doc_type,
                published_date=pub_date.isoformat(),
                url=f"https://www.{source.lower()}.gov.br/documento/{doc_id}",
                metadata={
                    'topic': topic,
                    'word_count': random.randint(500, 2000),
                    'importance': random.choice(['baixa', 'media', 'alta']),
                    'status': random.choice(['ativo', 'revogado', 'suspenso'])
                }
            )
            documents.append(document)
        
        self._documents.extend(documents)
        return documents
    
    def generate_sample_users(self, count: int = 20) -> List[TestUser]:
        """Generate sample users for testing."""
        roles = ['user', 'admin', 'moderator', 'analyst']
        
        first_names = [
            'João', 'Maria', 'José', 'Ana', 'Carlos', 'Fernanda',
            'Pedro', 'Julia', 'Lucas', 'Camila', 'Rafael', 'Beatriz'
        ]
        last_names = [
            'Silva', 'Santos', 'Oliveira', 'Souza', 'Rodrigues', 'Ferreira',
            'Alves', 'Pereira', 'Lima', 'Gomes', 'Costa', 'Ribeiro'
        ]
        
        users = []
        base_date = datetime.now() - timedelta(days=180)
        
        for i in range(count):
            user_id = len(self._users) + i + 1
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            
            # Generate creation date
            created_date = base_date + timedelta(days=random.randint(0, 180))
            
            user = TestUser(
                id=user_id,
                username=f"{first_name.lower()}.{last_name.lower()}{user_id}",
                email=f"{first_name.lower()}.{last_name.lower()}@email.com",
                password="testpassword123",
                role=random.choice(roles),
                first_name=first_name,
                last_name=last_name,
                created_at=created_date.isoformat()
            )
            users.append(user)
        
        self._users.extend(users)
        return users
    
    def generate_sample_alerts(self, count: int = 30) -> List[TestAlert]:
        """Generate sample alerts for testing."""
        alert_types = ['DOCUMENT_MATCH', 'KEYWORD_ALERT', 'STATUS_CHANGE', 'DEADLINE_REMINDER']
        statuses = ['ACTIVE', 'PENDING', 'RESOLVED', 'DISMISSED']
        
        alert_templates = [
            {
                'title': 'Nova Lei sobre {}',
                'message': 'Foi publicada uma nova lei relacionada a {}'
            },
            {
                'title': 'Alteração em Decreto',
                'message': 'O decreto sobre {} foi alterado'
            },
            {
                'title': 'Prazo de Consulta Pública',
                'message': 'Consulta pública sobre {} encerrará em breve'
            }
        ]
        
        topics = [
            'proteção de dados',
            'educação',
            'saúde',
            'meio ambiente',
            'tecnologia'
        ]
        
        alerts = []
        base_date = datetime.now() - timedelta(days=30)
        
        for i in range(count):
            alert_id = len(self._alerts) + i + 1
            template = random.choice(alert_templates)
            topic = random.choice(topics)
            
            # Ensure we have users to assign alerts to
            if not self._users:
                self.generate_sample_users(5)
            
            user_id = random.choice(self._users).id
            created_date = base_date + timedelta(days=random.randint(0, 30))
            
            alert = TestAlert(
                id=alert_id,
                title=template['title'].format(topic),
                message=template['message'].format(topic),
                alert_type=random.choice(alert_types),
                status=random.choice(statuses),
                created_at=created_date.isoformat(),
                user_id=user_id
            )
            alerts.append(alert)
        
        self._alerts.extend(alerts)
        return alerts
    
    def get_documents(self, 
                     count: Optional[int] = None, 
                     document_type: Optional[str] = None,
                     source: Optional[str] = None) -> List[TestDocument]:
        """Get documents with optional filtering."""
        documents = self._documents.copy()
        
        # Apply filters
        if document_type:
            documents = [doc for doc in documents if doc.document_type == document_type]
        
        if source:
            documents = [doc for doc in documents if doc.source == source]
        
        # Limit count
        if count:
            documents = documents[:count]
        
        return documents
    
    def get_users(self, 
                  count: Optional[int] = None, 
                  role: Optional[str] = None) -> List[TestUser]:
        """Get users with optional filtering."""
        users = self._users.copy()
        
        # Apply filters
        if role:
            users = [user for user in users if user.role == role]
        
        # Limit count
        if count:
            users = users[:count]
        
        return users
    
    def get_alerts(self, 
                   count: Optional[int] = None, 
                   status: Optional[str] = None,
                   user_id: Optional[int] = None) -> List[TestAlert]:
        """Get alerts with optional filtering."""
        alerts = self._alerts.copy()
        
        # Apply filters
        if status:
            alerts = [alert for alert in alerts if alert.status == status]
        
        if user_id:
            alerts = [alert for alert in alerts if alert.user_id == user_id]
        
        # Limit count
        if count:
            alerts = alerts[:count]
        
        return alerts
    
    def save_to_files(self):
        """Save test data to files for persistence."""
        # Save documents
        docs_file = self.data_dir / "documents.json"
        with open(docs_file, 'w', encoding='utf-8') as f:
            json.dump([doc.to_dict() for doc in self._documents], f, indent=2, ensure_ascii=False)
        
        # Save users
        users_file = self.data_dir / "users.json"
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump([user.to_dict() for user in self._users], f, indent=2, ensure_ascii=False)
        
        # Save alerts
        alerts_file = self.data_dir / "alerts.json"
        with open(alerts_file, 'w', encoding='utf-8') as f:
            json.dump([alert.to_dict() for alert in self._alerts], f, indent=2, ensure_ascii=False)
    
    def export_to_csv(self, data_type: str, filename: Optional[str] = None):
        """Export data to CSV format."""
        if filename is None:
            filename = f"{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = self.data_dir / filename
        
        if data_type == 'documents':
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if self._documents:
                    writer = csv.DictWriter(f, fieldnames=self._documents[0].to_dict().keys())
                    writer.writeheader()
                    for doc in self._documents:
                        writer.writerow(doc.to_dict())
        
        elif data_type == 'users':
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if self._users:
                    writer = csv.DictWriter(f, fieldnames=self._users[0].to_dict().keys())
                    writer.writeheader()
                    for user in self._users:
                        writer.writerow(user.to_dict())
        
        elif data_type == 'alerts':
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if self._alerts:
                    writer = csv.DictWriter(f, fieldnames=self._alerts[0].to_dict().keys())
                    writer.writeheader()
                    for alert in self._alerts:
                        writer.writerow(alert.to_dict())
    
    def clear_all_data(self):
        """Clear all test data."""
        self._documents.clear()
        self._users.clear()
        self._alerts.clear()
    
    def reset_to_defaults(self):
        """Reset to default test dataset."""
        self.clear_all_data()
        self.generate_sample_documents(50)
        self.generate_sample_users(20)
        self.generate_sample_alerts(30)
        self.save_to_files()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about current test data."""
        return {
            'total_documents': len(self._documents),
            'total_users': len(self._users),
            'total_alerts': len(self._alerts),
            'document_types': len(set(doc.document_type for doc in self._documents)),
            'sources': len(set(doc.source for doc in self._documents)),
            'user_roles': len(set(user.role for user in self._users)),
            'alert_statuses': len(set(alert.status for alert in self._alerts))
        }


# Global test data manager instance
test_data_manager = TestDataManager()


def setup_test_data():
    """Setup default test data if not exists."""
    stats = test_data_manager.get_statistics()
    
    if stats['total_documents'] == 0:
        test_data_manager.generate_sample_documents(50)
    
    if stats['total_users'] == 0:
        test_data_manager.generate_sample_users(20)
    
    if stats['total_alerts'] == 0:
        test_data_manager.generate_sample_alerts(30)
    
    test_data_manager.save_to_files()


def get_test_documents(**kwargs) -> List[TestDocument]:
    """Get test documents with optional filtering."""
    return test_data_manager.get_documents(**kwargs)


def get_test_users(**kwargs) -> List[TestUser]:
    """Get test users with optional filtering."""
    return test_data_manager.get_users(**kwargs)


def get_test_alerts(**kwargs) -> List[TestAlert]:
    """Get test alerts with optional filtering."""
    return test_data_manager.get_alerts(**kwargs)


def cleanup_test_data():
    """Cleanup test data after tests."""
    test_data_manager.clear_all_data()


# Initialize test data on import
if not test_data_manager.get_statistics()['total_documents']:
    setup_test_data()