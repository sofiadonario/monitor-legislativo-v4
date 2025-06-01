"""
Test factories for creating test data
Uses Factory Boy for consistent test data generation
"""

import factory
from factory import fuzzy
from datetime import datetime, timedelta
import random
from typing import List

from core.auth.models import User, Role, Permission
from core.models.models import Document, Alert, SearchQuery, ExportRequest


class UserFactory(factory.Factory):
    """Factory for creating test users"""
    
    class Meta:
        model = User
    
    username = factory.Sequence(lambda n: f'user{n}')
    email = factory.LazyAttribute(lambda obj: f'{obj.username}@example.com')
    full_name = factory.Faker('name', locale='pt_BR')
    department = factory.Faker('random_element', elements=['IT', 'Legal', 'Admin', 'Research'])
    
    is_active = True
    is_verified = factory.Faker('boolean', chance_of_getting_true=75)
    
    created_at = factory.Faker('date_time_between', start_date='-1y', end_date='now')
    last_login_at = factory.LazyAttribute(
        lambda obj: obj.created_at + timedelta(days=random.randint(1, 30))
    )
    
    @factory.post_generation
    def password(obj, create, extracted, **kwargs):
        """Set password after user creation"""
        if extracted:
            obj.set_password(extracted)
        else:
            obj.set_password('defaultpass123')
    
    @factory.post_generation
    def roles(obj, create, extracted, **kwargs):
        """Add roles to user"""
        if extracted:
            for role in extracted:
                obj.roles.append(role)


class AdminFactory(UserFactory):
    """Factory for creating admin users"""
    
    username = factory.Sequence(lambda n: f'admin{n}')
    department = 'IT'
    is_verified = True
    
    @factory.post_generation
    def make_admin(obj, create, extracted, **kwargs):
        """Ensure user has admin role"""
        # In real usage, would query for admin role
        pass


class RoleFactory(factory.Factory):
    """Factory for creating roles"""
    
    class Meta:
        model = Role
    
    name = factory.Faker('random_element', elements=['admin', 'manager', 'user', 'viewer'])
    description = factory.LazyAttribute(lambda obj: f'Description for {obj.name} role')
    created_at = factory.Faker('date_time_between', start_date='-1y', end_date='now')


class PermissionFactory(factory.Factory):
    """Factory for creating permissions"""
    
    class Meta:
        model = Permission
    
    name = factory.LazyAttribute(lambda obj: f'{obj.resource}:{obj.action}')
    resource = factory.Faker('random_element', elements=['document', 'user', 'alert', 'export'])
    action = factory.Faker('random_element', elements=['read', 'write', 'delete', 'export'])
    description = factory.LazyAttribute(lambda obj: f'Can {obj.action} {obj.resource}')


class DocumentFactory(factory.Factory):
    """Factory for creating test documents"""
    
    class Meta:
        model = Document
    
    title = factory.Faker('sentence', nb_words=8, locale='pt_BR')
    content = factory.Faker('text', max_nb_chars=1000, locale='pt_BR')
    summary = factory.Faker('text', max_nb_chars=200, locale='pt_BR')
    
    type = factory.Faker('random_element', elements=[
        'projeto_lei', 'decreto', 'portaria', 'resolucao', 'medida_provisoria'
    ])
    source = factory.Faker('random_element', elements=['camara', 'senado', 'planalto'])
    status = factory.Faker('random_element', elements=[
        'tramitando', 'aprovado', 'rejeitado', 'arquivado'
    ])
    
    document_number = factory.Sequence(lambda n: str(1000 + n))
    document_year = factory.Faker('random_int', min=2020, max=2025)
    
    url = factory.LazyAttribute(
        lambda obj: f'https://{obj.source}.gov.br/documento/{obj.document_number}/{obj.document_year}'
    )
    
    created_at = factory.Faker('date_time_between', start_date='-1y', end_date='now')
    updated_at = factory.LazyAttribute(
        lambda obj: obj.created_at + timedelta(days=random.randint(0, 30))
    )
    
    metadata = factory.LazyFunction(lambda: {
        'authors': [f'Autor {i}' for i in range(random.randint(1, 3))],
        'keywords': random.sample(['saúde', 'educação', 'economia', 'segurança', 'meio ambiente'], 3),
        'pages': random.randint(1, 50)
    })


class AlertFactory(factory.Factory):
    """Factory for creating test alerts"""
    
    class Meta:
        model = Alert
    
    name = factory.Faker('sentence', nb_words=4, locale='pt_BR')
    description = factory.Faker('text', max_nb_chars=200, locale='pt_BR')
    query = factory.Faker('words', nb=3, locale='pt_BR')
    
    active = factory.Faker('boolean', chance_of_getting_true=80)
    
    filters = factory.LazyFunction(lambda: {
        'type': random.sample(['projeto_lei', 'decreto', 'portaria'], 2),
        'source': random.sample(['camara', 'senado', 'planalto'], 1),
        'date_range': 'last_30_days'
    })
    
    created_at = factory.Faker('date_time_between', start_date='-6m', end_date='now')
    last_triggered = factory.LazyAttribute(
        lambda obj: obj.created_at + timedelta(days=random.randint(1, 7)) if obj.active else None
    )
    trigger_count = factory.LazyAttribute(
        lambda obj: random.randint(0, 50) if obj.active else 0
    )


class SearchQueryFactory(factory.Factory):
    """Factory for creating test search queries"""
    
    class Meta:
        model = SearchQuery
    
    query = factory.Faker('words', nb=3, locale='pt_BR')
    filters = factory.LazyFunction(lambda: {
        'type': random.choice(['projeto_lei', 'decreto', 'all']),
        'source': random.choice(['camara', 'senado', 'all']),
        'date_range': random.choice(['last_7_days', 'last_30_days', 'last_year'])
    })
    
    results_count = factory.Faker('random_int', min=0, max=500)
    execution_time = factory.Faker('pyfloat', positive=True, min_value=0.1, max_value=5.0)
    
    created_at = factory.Faker('date_time_between', start_date='-30d', end_date='now')


class ExportRequestFactory(factory.Factory):
    """Factory for creating test export requests"""
    
    class Meta:
        model = ExportRequest
    
    format = factory.Faker('random_element', elements=['csv', 'json', 'excel', 'pdf'])
    query = factory.Faker('words', nb=3, locale='pt_BR')
    
    status = factory.Faker('random_element', elements=[
        'pending', 'processing', 'completed', 'failed'
    ])
    
    filters = factory.LazyFunction(lambda: {
        'type': 'all',
        'source': 'all',
        'date_range': 'last_30_days'
    })
    
    created_at = factory.Faker('date_time_between', start_date='-7d', end_date='now')
    completed_at = factory.LazyAttribute(
        lambda obj: obj.created_at + timedelta(minutes=random.randint(1, 30))
        if obj.status in ['completed', 'failed'] else None
    )
    
    records_count = factory.LazyAttribute(
        lambda obj: random.randint(10, 1000) if obj.status == 'completed' else 0
    )
    file_size = factory.LazyAttribute(
        lambda obj: random.randint(1024, 50*1024*1024) if obj.status == 'completed' else 0
    )
    file_path = factory.LazyAttribute(
        lambda obj: f'exports/export_{obj.created_at.strftime("%Y%m%d_%H%M%S")}.{obj.format}'
        if obj.status == 'completed' else None
    )


# Batch factories for creating multiple objects

class BatchUserFactory:
    """Create multiple users with different roles"""
    
    @staticmethod
    def create_users(session, count: int = 10) -> List[User]:
        """Create a batch of users with mixed roles"""
        users = []
        
        # Create admin users (10%)
        admin_count = max(1, count // 10)
        for i in range(admin_count):
            user = AdminFactory()
            users.append(user)
        
        # Create regular users (90%)
        for i in range(count - admin_count):
            user = UserFactory()
            users.append(user)
        
        # Add to session if provided
        if session:
            session.add_all(users)
            session.commit()
        
        return users


class BatchDocumentFactory:
    """Create multiple documents with realistic distribution"""
    
    @staticmethod
    def create_documents(session, count: int = 100) -> List[Document]:
        """Create a batch of documents"""
        documents = []
        
        # Distribution of document types
        type_distribution = {
            'projeto_lei': 0.4,
            'decreto': 0.2,
            'portaria': 0.2,
            'resolucao': 0.1,
            'medida_provisoria': 0.1
        }
        
        for doc_type, percentage in type_distribution.items():
            doc_count = int(count * percentage)
            for i in range(doc_count):
                doc = DocumentFactory(type=doc_type)
                documents.append(doc)
        
        # Shuffle to mix types
        random.shuffle(documents)
        
        if session:
            session.add_all(documents)
            session.commit()
        
        return documents


# Test data generators

def generate_search_response(query: str, count: int = 10) -> dict:
    """Generate a realistic search response"""
    documents = []
    
    for i in range(count):
        doc = DocumentFactory()
        documents.append({
            'id': str(i + 1),
            'title': doc.title,
            'summary': doc.summary,
            'type': doc.type,
            'source': doc.source,
            'status': doc.status,
            'url': doc.url,
            'created_at': doc.created_at.isoformat(),
            'relevance_score': random.uniform(0.5, 1.0)
        })
    
    return {
        'query': query,
        'total_count': count,
        'results': documents,
        'facets': {
            'type': {
                'projeto_lei': random.randint(0, count),
                'decreto': random.randint(0, count),
                'portaria': random.randint(0, count)
            },
            'source': {
                'camara': random.randint(0, count),
                'senado': random.randint(0, count),
                'planalto': random.randint(0, count)
            }
        }
    }


def generate_api_error_response(status_code: int = 500, message: str = None) -> dict:
    """Generate an API error response"""
    error_messages = {
        400: "Bad request - Invalid parameters",
        401: "Unauthorized - Authentication required",
        403: "Forbidden - Insufficient permissions",
        404: "Not found - Resource does not exist",
        429: "Too many requests - Rate limit exceeded",
        500: "Internal server error",
        503: "Service unavailable"
    }
    
    return {
        'error': {
            'code': status_code,
            'message': message or error_messages.get(status_code, 'Unknown error'),
            'timestamp': datetime.utcnow().isoformat()
        }
    }