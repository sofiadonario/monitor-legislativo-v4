"""Unit tests for data models."""

import pytest
from datetime import datetime, date
from unittest.mock import patch

from core.models.models import (
    Document, Alert, User, SearchQuery, 
    DocumentType, AlertStatus, UserRole
)


class TestDocument:
    """Test suite for Document model."""

    def test_document_creation(self):
        """Test document creation with required fields."""
        doc = Document(
            title="Test Document",
            content="Test content",
            source="Test Source",
            url="http://test.com",
            document_type=DocumentType.LEI,
            published_date=date.today()
        )
        
        assert doc.title == "Test Document"
        assert doc.content == "Test content"
        assert doc.source == "Test Source"
        assert doc.document_type == DocumentType.LEI
        assert doc.published_date == date.today()

    def test_document_repr(self):
        """Test document string representation."""
        doc = Document(
            title="Test Document",
            content="Test content",
            source="Test Source",
            url="http://test.com",
            document_type=DocumentType.LEI,
            published_date=date.today()
        )
        
        repr_str = repr(doc)
        assert "Test Document" in repr_str
        assert "Test Source" in repr_str

    def test_document_validation_title_required(self):
        """Test that title is required."""
        with pytest.raises(ValueError):
            Document(
                title="",
                content="Test content",
                source="Test Source",
                url="http://test.com",
                document_type=DocumentType.LEI,
                published_date=date.today()
            )

    def test_document_validation_url_format(self):
        """Test URL format validation."""
        with pytest.raises(ValueError):
            Document(
                title="Test",
                content="Test content",
                source="Test Source",
                url="invalid-url",
                document_type=DocumentType.LEI,
                published_date=date.today()
            )

    def test_document_summary_generation(self):
        """Test automatic summary generation for long content."""
        long_content = "A" * 1000
        doc = Document(
            title="Test Document",
            content=long_content,
            source="Test Source",
            url="http://test.com",
            document_type=DocumentType.LEI,
            published_date=date.today()
        )
        
        summary = doc.generate_summary()
        assert len(summary) < len(long_content)
        assert summary.endswith("...")

    def test_document_keywords_extraction(self):
        """Test keyword extraction from content."""
        doc = Document(
            title="Lei de Proteção de Dados",
            content="Esta lei trata da proteção de dados pessoais e privacidade",
            source="Diário Oficial",
            url="http://test.com",
            document_type=DocumentType.LEI,
            published_date=date.today()
        )
        
        keywords = doc.extract_keywords()
        assert "proteção" in keywords
        assert "dados" in keywords
        assert "privacidade" in keywords

    def test_document_is_recent(self):
        """Test recent document detection."""
        recent_doc = Document(
            title="Recent Document",
            content="Content",
            source="Source",
            url="http://test.com",
            document_type=DocumentType.LEI,
            published_date=date.today()
        )
        
        assert recent_doc.is_recent()

    def test_document_to_dict(self):
        """Test document serialization to dictionary."""
        doc = Document(
            title="Test Document",
            content="Test content",
            source="Test Source",
            url="http://test.com",
            document_type=DocumentType.LEI,
            published_date=date.today()
        )
        
        doc_dict = doc.to_dict()
        assert doc_dict['title'] == "Test Document"
        assert doc_dict['content'] == "Test content"
        assert doc_dict['document_type'] == DocumentType.LEI.value


class TestAlert:
    """Test suite for Alert model."""

    def test_alert_creation(self):
        """Test alert creation with required fields."""
        alert = Alert(
            title="Test Alert",
            message="Test message",
            alert_type="INFO",
            status=AlertStatus.PENDING,
            created_at=datetime.now()
        )
        
        assert alert.title == "Test Alert"
        assert alert.message == "Test message"
        assert alert.alert_type == "INFO"
        assert alert.status == AlertStatus.PENDING

    def test_alert_activation(self):
        """Test alert activation."""
        alert = Alert(
            title="Test Alert",
            message="Test message",
            alert_type="INFO",
            status=AlertStatus.PENDING,
            created_at=datetime.now()
        )
        
        alert.activate()
        assert alert.status == AlertStatus.ACTIVE
        assert alert.activated_at is not None

    def test_alert_deactivation(self):
        """Test alert deactivation."""
        alert = Alert(
            title="Test Alert",
            message="Test message",
            alert_type="INFO",
            status=AlertStatus.ACTIVE,
            created_at=datetime.now()
        )
        
        alert.deactivate()
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None

    def test_alert_priority_calculation(self):
        """Test alert priority calculation."""
        high_priority_alert = Alert(
            title="URGENT: Critical Issue",
            message="Critical system failure",
            alert_type="ERROR",
            status=AlertStatus.PENDING,
            created_at=datetime.now()
        )
        
        priority = high_priority_alert.calculate_priority()
        assert priority > 5  # High priority

    def test_alert_expiration_check(self):
        """Test alert expiration checking."""
        old_alert = Alert(
            title="Old Alert",
            message="Old message",
            alert_type="INFO",
            status=AlertStatus.ACTIVE,
            created_at=datetime(2023, 1, 1)
        )
        
        assert old_alert.is_expired()

    def test_alert_notification_format(self):
        """Test alert notification formatting."""
        alert = Alert(
            title="Test Alert",
            message="Test message with details",
            alert_type="WARNING",
            status=AlertStatus.ACTIVE,
            created_at=datetime.now()
        )
        
        notification = alert.format_notification()
        assert "Test Alert" in notification
        assert "WARNING" in notification
        assert "Test message with details" in notification


class TestUser:
    """Test suite for User model."""

    def test_user_creation(self):
        """Test user creation with required fields."""
        user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            created_at=datetime.now()
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER

    def test_user_password_hashing(self):
        """Test password hashing functionality."""
        user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            created_at=datetime.now()
        )
        
        user.set_password("testpassword123")
        assert user.password_hash is not None
        assert user.password_hash != "testpassword123"

    def test_user_password_verification(self):
        """Test password verification."""
        user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            created_at=datetime.now()
        )
        
        user.set_password("testpassword123")
        assert user.check_password("testpassword123")
        assert not user.check_password("wrongpassword")

    def test_user_email_validation(self):
        """Test email format validation."""
        with pytest.raises(ValueError):
            User(
                username="testuser",
                email="invalid-email",
                role=UserRole.USER,
                created_at=datetime.now()
            )

    def test_user_permissions_check(self):
        """Test user permissions checking."""
        admin_user = User(
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            created_at=datetime.now()
        )
        
        regular_user = User(
            username="user",
            email="user@example.com",
            role=UserRole.USER,
            created_at=datetime.now()
        )
        
        assert admin_user.has_permission("admin_access")
        assert not regular_user.has_permission("admin_access")

    def test_user_activity_tracking(self):
        """Test user activity tracking."""
        user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            created_at=datetime.now()
        )
        
        user.update_last_activity()
        assert user.last_activity is not None

    def test_user_profile_completion(self):
        """Test user profile completion check."""
        incomplete_user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            created_at=datetime.now()
        )
        
        complete_user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            first_name="Test",
            last_name="User",
            created_at=datetime.now()
        )
        
        assert not incomplete_user.is_profile_complete()
        assert complete_user.is_profile_complete()


class TestSearchQuery:
    """Test suite for SearchQuery model."""

    def test_search_query_creation(self):
        """Test search query creation."""
        query = SearchQuery(
            query_text="lei proteção dados",
            filters={"document_type": "LEI"},
            user_id=1,
            created_at=datetime.now()
        )
        
        assert query.query_text == "lei proteção dados"
        assert query.filters == {"document_type": "LEI"}
        assert query.user_id == 1

    def test_search_query_validation(self):
        """Test search query validation."""
        with pytest.raises(ValueError):
            SearchQuery(
                query_text="",  # Empty query
                filters={},
                user_id=1,
                created_at=datetime.now()
            )

    def test_search_query_normalization(self):
        """Test search query text normalization."""
        query = SearchQuery(
            query_text="  LEI proteção   DADOS  ",
            filters={},
            user_id=1,
            created_at=datetime.now()
        )
        
        normalized = query.normalize_query()
        assert normalized == "lei proteção dados"

    def test_search_query_complexity_scoring(self):
        """Test search query complexity scoring."""
        simple_query = SearchQuery(
            query_text="lei",
            filters={},
            user_id=1,
            created_at=datetime.now()
        )
        
        complex_query = SearchQuery(
            query_text="lei proteção dados pessoais privacidade",
            filters={"document_type": "LEI", "date_range": "2024"},
            user_id=1,
            created_at=datetime.now()
        )
        
        assert complex_query.calculate_complexity() > simple_query.calculate_complexity()

    def test_search_query_suggestion_generation(self):
        """Test search query suggestion generation."""
        query = SearchQuery(
            query_text="lei protecao",  # Typo
            filters={},
            user_id=1,
            created_at=datetime.now()
        )
        
        suggestions = query.generate_suggestions()
        assert "lei proteção" in suggestions

    def test_search_query_history_tracking(self):
        """Test search query history tracking."""
        query = SearchQuery(
            query_text="lei proteção dados",
            filters={},
            user_id=1,
            created_at=datetime.now()
        )
        
        query.mark_as_executed()
        assert query.executed_at is not None
        assert query.execution_count == 1