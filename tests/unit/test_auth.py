"""
Unit tests for authentication and authorization
Critical path tests for JWT, login, and RBAC
"""

import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from core.auth.jwt_manager import JWTManager, create_access_token, verify_token
from core.auth.models import User, Role, Permission
from core.auth.decorators import require_auth, require_role, require_permission


class TestJWTManager:
    """Test JWT token management"""
    
    @pytest.fixture
    def jwt_manager(self, app):
        """Create JWT manager instance"""
        manager = JWTManager()
        manager.init_app(app)
        return manager
    
    def test_create_access_token(self, jwt_manager):
        """Test access token creation"""
        user_id = "123"
        token = jwt_manager.create_access_token(user_id)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode token
        payload = jwt.decode(
            token, 
            jwt_manager.secret_key, 
            algorithms=[jwt_manager.algorithm]
        )
        
        assert payload['sub'] == user_id
        assert payload['type'] == 'access'
        assert 'iat' in payload
        assert 'exp' in payload
    
    def test_create_access_token_with_claims(self, jwt_manager):
        """Test access token with additional claims"""
        user_id = "123"
        additional_claims = {
            'roles': ['admin', 'user'],
            'permissions': ['document:read', 'document:write']
        }
        
        token = jwt_manager.create_access_token(user_id, additional_claims)
        payload = jwt.decode(
            token,
            jwt_manager.secret_key,
            algorithms=[jwt_manager.algorithm]
        )
        
        assert payload['roles'] == ['admin', 'user']
        assert payload['permissions'] == ['document:read', 'document:write']
    
    def test_verify_valid_token(self, jwt_manager):
        """Test verification of valid token"""
        user_id = "123"
        token = jwt_manager.create_access_token(user_id)
        
        is_valid, payload = jwt_manager.verify_token(token)
        
        assert is_valid is True
        assert payload['sub'] == user_id
    
    def test_verify_expired_token(self, jwt_manager):
        """Test verification of expired token"""
        # Create token with past expiration
        now = datetime.utcnow()
        payload = {
            'sub': '123',
            'iat': now - timedelta(hours=2),
            'exp': now - timedelta(hours=1),
            'type': 'access'
        }
        
        expired_token = jwt.encode(
            payload,
            jwt_manager.secret_key,
            algorithm=jwt_manager.algorithm
        )
        
        is_valid, payload = jwt_manager.verify_token(expired_token)
        
        assert is_valid is False
        assert payload is None
    
    def test_verify_invalid_token(self, jwt_manager):
        """Test verification of invalid token"""
        invalid_token = "invalid.token.here"
        
        is_valid, payload = jwt_manager.verify_token(invalid_token)
        
        assert is_valid is False
        assert payload is None
    
    def test_refresh_access_token(self, jwt_manager):
        """Test refreshing access token"""
        user_id = "123"
        refresh_token = jwt_manager.create_refresh_token(user_id)
        
        new_access_token = jwt_manager.refresh_access_token(refresh_token)
        
        assert new_access_token is not None
        
        # Verify new token
        is_valid, payload = jwt_manager.verify_token(new_access_token)
        assert is_valid is True
        assert payload['sub'] == user_id


class TestUserModel:
    """Test User model and authentication"""
    
    def test_set_password(self):
        """Test password hashing"""
        user = User(username="testuser", email="test@example.com")
        password = "SecurePass123!"
        
        user.set_password(password)
        
        assert user.password_hash is not None
        assert user.password_hash != password  # Should be hashed
    
    def test_check_password_correct(self):
        """Test checking correct password"""
        user = User(username="testuser", email="test@example.com")
        password = "SecurePass123!"
        
        user.set_password(password)
        
        assert user.check_password(password) is True
    
    def test_check_password_incorrect(self):
        """Test checking incorrect password"""
        user = User(username="testuser", email="test@example.com")
        user.set_password("SecurePass123!")
        
        assert user.check_password("WrongPassword") is False
    
    def test_has_role(self, seed_roles_permissions):
        """Test role checking"""
        user = User(username="testuser", email="test@example.com")
        admin_role = seed_roles_permissions['admin']
        user.roles.append(admin_role)
        
        assert user.has_role('admin') is True
        assert user.has_role('user') is False
    
    def test_has_permission(self, seed_roles_permissions):
        """Test permission checking"""
        user = User(username="testuser", email="test@example.com")
        user_role = seed_roles_permissions['user']
        user.roles.append(user_role)
        
        assert user.has_permission('document:read') is True
        assert user.has_permission('admin:access') is False
    
    def test_get_permissions(self, seed_roles_permissions):
        """Test getting all user permissions"""
        user = User(username="testuser", email="test@example.com")
        user_role = seed_roles_permissions['user']
        user.roles.append(user_role)
        
        permissions = user.get_permissions()
        
        assert 'document:read' in permissions
        assert 'document:export' in permissions
        assert len(permissions) == 2
    
    def test_is_locked(self):
        """Test account locking"""
        user = User(username="testuser", email="test@example.com")
        
        # Not locked by default
        assert user.is_locked() is False
        
        # Lock account
        user.locked_until = datetime.utcnow() + timedelta(hours=1)
        assert user.is_locked() is True
        
        # Expired lock
        user.locked_until = datetime.utcnow() - timedelta(hours=1)
        assert user.is_locked() is False


class TestAuthDecorators:
    """Test authentication decorators"""
    
    @pytest.fixture
    def mock_request(self):
        """Mock Flask request"""
        with patch('core.auth.decorators.request') as mock_req:
            mock_req.headers = {}
            yield mock_req
    
    @pytest.fixture
    def mock_g(self):
        """Mock Flask g object"""
        with patch('core.auth.decorators.g') as mock_g_obj:
            yield mock_g_obj
    
    def test_require_auth_no_token(self, mock_request):
        """Test require_auth with no token"""
        mock_request.headers = {}
        
        @require_auth
        def protected_route():
            return "Success"
        
        response, status = protected_route()
        
        assert status == 401
        assert response.json['error'] == 'Authentication required'
    
    def test_require_auth_valid_token(self, mock_request, mock_g, test_user):
        """Test require_auth with valid token"""
        token = create_access_token(str(test_user.id))
        mock_request.headers = {'Authorization': f'Bearer {token}'}
        
        with patch('core.auth.decorators.get_session') as mock_session:
            mock_session.return_value.query.return_value.filter_by.return_value.first.return_value = test_user
            
            @require_auth
            def protected_route():
                return "Success"
            
            result = protected_route()
            
            assert result == "Success"
            assert mock_g.current_user == test_user
    
    def test_require_role_authorized(self, mock_request, mock_g, admin_user):
        """Test require_role with authorized user"""
        mock_g.current_user = admin_user
        
        @require_role('admin')
        def admin_route():
            return "Admin access granted"
        
        # Mock require_auth to pass
        with patch('core.auth.decorators.require_auth', lambda f: f):
            result = admin_route()
            assert result == "Admin access granted"
    
    def test_require_role_unauthorized(self, mock_request, mock_g, test_user):
        """Test require_role with unauthorized user"""
        mock_g.current_user = test_user
        
        @require_role('admin')
        def admin_route():
            return "Admin access granted"
        
        # Mock require_auth to pass
        with patch('core.auth.decorators.require_auth', lambda f: f):
            response, status = admin_route()
            
            assert status == 403
            assert response.json['error'] == 'Insufficient permissions'
    
    def test_require_permission_authorized(self, mock_request, mock_g, test_user):
        """Test require_permission with authorized user"""
        mock_g.current_user = test_user
        
        @require_permission('document:read')
        def read_documents():
            return "Documents"
        
        with patch('core.auth.decorators.require_auth', lambda f: f):
            result = read_documents()
            assert result == "Documents"
    
    def test_require_permission_unauthorized(self, mock_request, mock_g, test_user):
        """Test require_permission with unauthorized user"""
        mock_g.current_user = test_user
        
        @require_permission('admin:access')
        def admin_panel():
            return "Admin panel"
        
        with patch('core.auth.decorators.require_auth', lambda f: f):
            response, status = admin_panel()
            
            assert status == 403
            assert 'admin:access' in response.json['message']


@pytest.mark.auth
class TestAuthenticationFlow:
    """Test complete authentication flow"""
    
    def test_login_success(self, client, test_user):
        """Test successful login"""
        response = client.post('/api/auth/login', json={
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['user']['email'] == 'test@example.com'
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post('/api/auth/login', json={
            'email': 'wrong@example.com',
            'password': 'wrongpass'
        })
        
        assert response.status_code == 401
        assert response.get_json()['error'] == 'Invalid credentials'
    
    def test_login_locked_account(self, client, test_user):
        """Test login with locked account"""
        test_user.locked_until = datetime.utcnow() + timedelta(hours=1)
        
        response = client.post('/api/auth/login', json={
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        
        assert response.status_code == 403
        assert 'locked' in response.get_json()['error'].lower()
    
    def test_protected_endpoint_with_token(self, client, auth_headers):
        """Test accessing protected endpoint with valid token"""
        response = client.get('/api/v1/documents', headers=auth_headers)
        
        assert response.status_code == 200
    
    def test_protected_endpoint_without_token(self, client):
        """Test accessing protected endpoint without token"""
        response = client.get('/api/v1/documents')
        
        # Should work but with limited results (optional auth)
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('authenticated') is False