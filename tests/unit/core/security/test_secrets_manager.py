"""Unit tests for SecretsManager."""

import pytest
import json
import os
from unittest.mock import patch, mock_open, Mock
from pathlib import Path
from core.security.secrets_manager import (
    SecretsManager,
    VaultSecretsManager,
    get_secrets_manager,
    get_api_key,
    get_database_password
)


class TestSecretsManager:
    """Test cases for SecretsManager."""
    
    def test_init_with_master_key(self):
        """Test initialization with master key."""
        manager = SecretsManager(master_key='test-master-key')
        assert manager.master_key == 'test-master-key'
        assert manager._fernet is not None
    
    def test_init_without_master_key(self):
        """Test initialization fails without master key."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                SecretsManager()
            assert "Master key not provided" in str(exc_info.value)
    
    @patch.dict(os.environ, {'MASTER_KEY': 'env-master-key'})
    def test_init_with_env_master_key(self):
        """Test initialization with environment master key."""
        manager = SecretsManager()
        assert manager.master_key == 'env-master-key'
    
    def test_create_fernet(self):
        """Test Fernet cipher creation."""
        manager = SecretsManager(master_key='test-key')
        fernet = manager._create_fernet('test-key')
        assert fernet is not None
        
        # Test encryption/decryption works
        test_data = b'test data'
        encrypted = fernet.encrypt(test_data)
        decrypted = fernet.decrypt(encrypted)
        assert decrypted == test_data
    
    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_secrets_file_not_exists(self, mock_file, mock_exists):
        """Test loading secrets when file doesn't exist."""
        mock_exists.return_value = False
        
        manager = SecretsManager(master_key='test-key')
        secrets = manager._load_secrets()
        
        assert secrets == {}
        mock_file.assert_not_called()
    
    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_secrets_success(self, mock_file, mock_exists):
        """Test successful secrets loading."""
        mock_exists.return_value = True
        
        # Create test encrypted data
        manager = SecretsManager(master_key='test-key')
        test_secrets = {'api_key': 'secret-value'}
        encrypted_data = manager._fernet.encrypt(json.dumps(test_secrets).encode())
        
        mock_file.return_value.read.return_value = encrypted_data
        
        secrets = manager._load_secrets()
        
        assert secrets == test_secrets
        mock_file.assert_called_once()
    
    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_secrets_decryption_error(self, mock_file, mock_exists):
        """Test loading secrets with decryption error."""
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = b'invalid encrypted data'
        
        manager = SecretsManager(master_key='test-key')
        secrets = manager._load_secrets()
        
        assert secrets == {}
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.chmod')
    def test_save_secrets(self, mock_chmod, mock_file, mock_mkdir):
        """Test saving secrets."""
        manager = SecretsManager(master_key='test-key')
        test_secrets = {'api_key': 'secret-value'}
        
        manager._save_secrets(test_secrets)
        
        mock_mkdir.assert_called_once()
        mock_file.assert_called_once()
        mock_chmod.assert_called_once_with(manager._secrets_file, 0o600)
        
        # Verify data was encrypted
        write_call = mock_file.return_value.write.call_args[0][0]
        assert isinstance(write_call, bytes)
        assert write_call != json.dumps(test_secrets).encode()
    
    @patch.dict(os.environ, {'TEST_SECRET': 'env-value'})
    def test_get_secret_from_env(self):
        """Test getting secret from environment variable."""
        manager = SecretsManager(master_key='test-key')
        
        result = manager.get_secret('TEST_SECRET')
        assert result == 'env-value'
    
    @patch('core.security.secrets_manager.SecretsManager._load_secrets')
    def test_get_secret_from_file(self, mock_load):
        """Test getting secret from encrypted file."""
        mock_load.return_value = {'file_secret': 'file-value'}
        
        manager = SecretsManager(master_key='test-key')
        result = manager.get_secret('file_secret')
        
        assert result == 'file-value'
        assert 'file_secret' in manager._cache
    
    def test_get_secret_default(self):
        """Test getting secret with default value."""
        manager = SecretsManager(master_key='test-key')
        
        result = manager.get_secret('nonexistent', default='default-value')
        assert result == 'default-value'
    
    @patch('core.security.secrets_manager.SecretsManager._save_secrets')
    @patch('core.security.secrets_manager.SecretsManager._load_secrets')
    def test_set_secret(self, mock_load, mock_save):
        """Test setting a secret."""
        mock_load.return_value = {}
        
        manager = SecretsManager(master_key='test-key')
        manager.set_secret('new_secret', 'new-value')
        
        mock_save.assert_called_once_with({'new_secret': 'new-value'})
        assert manager._cache['new_secret'] == 'new-value'
    
    @patch('core.security.secrets_manager.SecretsManager._save_secrets')
    @patch('core.security.secrets_manager.SecretsManager._load_secrets')
    def test_delete_secret_exists(self, mock_load, mock_save):
        """Test deleting existing secret."""
        mock_load.return_value = {'existing_secret': 'value'}
        
        manager = SecretsManager(master_key='test-key')
        result = manager.delete_secret('existing_secret')
        
        assert result is True
        mock_save.assert_called_once_with({})
    
    @patch('core.security.secrets_manager.SecretsManager._load_secrets')
    def test_delete_secret_not_exists(self, mock_load):
        """Test deleting non-existent secret."""
        mock_load.return_value = {}
        
        manager = SecretsManager(master_key='test-key')
        result = manager.delete_secret('nonexistent')
        
        assert result is False
    
    @patch('core.security.secrets_manager.SecretsManager._load_secrets')
    def test_list_secrets(self, mock_load):
        """Test listing all secret keys."""
        mock_load.return_value = {'secret1': 'value1', 'secret2': 'value2'}
        
        manager = SecretsManager(master_key='test-key')
        keys = manager.list_secrets()
        
        assert set(keys) == {'secret1', 'secret2'}
    
    @patch('core.security.secrets_manager.SecretsManager._save_secrets')
    @patch('core.security.secrets_manager.SecretsManager._load_secrets')
    def test_rotate_master_key(self, mock_load, mock_save):
        """Test master key rotation."""
        mock_load.return_value = {'secret': 'value'}
        
        manager = SecretsManager(master_key='old-key')
        old_fernet = manager._fernet
        
        manager.rotate_master_key('new-key')
        
        assert manager.master_key == 'new-key'
        assert manager._fernet != old_fernet
        assert manager._cache == {}
        mock_save.assert_called_once_with({'secret': 'value'})


class TestVaultSecretsManager:
    """Test cases for VaultSecretsManager."""
    
    @patch('core.security.secrets_manager.hvac')
    def test_init_with_vault(self, mock_hvac):
        """Test initialization with Vault client."""
        mock_client = Mock()
        mock_client.is_authenticated.return_value = True
        mock_hvac.Client.return_value = mock_client
        
        manager = VaultSecretsManager('http://vault:8200', 'vault-token')
        
        assert manager.vault_url == 'http://vault:8200'
        assert manager.vault_token == 'vault-token'
        assert manager.client == mock_client
    
    @patch('core.security.secrets_manager.hvac')
    def test_init_vault_auth_failure(self, mock_hvac):
        """Test initialization with Vault auth failure."""
        mock_client = Mock()
        mock_client.is_authenticated.return_value = False
        mock_hvac.Client.return_value = mock_client
        
        with pytest.raises(ValueError) as exc_info:
            VaultSecretsManager('http://vault:8200', 'invalid-token')
        
        assert "Vault authentication failed" in str(exc_info.value)
    
    def test_init_without_hvac(self):
        """Test initialization without hvac library."""
        with patch('core.security.secrets_manager.hvac', side_effect=ImportError):
            manager = VaultSecretsManager('http://vault:8200', 'token')
            assert manager.client is None
    
    def test_get_secret_from_vault(self):
        """Test getting secret from Vault."""
        mock_client = Mock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {'data': {'value': 'vault-secret'}}
        }
        
        manager = VaultSecretsManager('http://vault:8200', 'token')
        manager.client = mock_client
        
        result = manager.get_secret('test_key')
        
        assert result == 'vault-secret'
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            mount_point='secret',
            path='legislativo/test_key'
        )
    
    def test_get_secret_vault_fallback(self):
        """Test fallback to file storage when Vault fails."""
        mock_client = Mock()
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("Vault error")
        
        manager = VaultSecretsManager('http://vault:8200', 'token')
        manager.client = mock_client
        
        with patch.object(SecretsManager, 'get_secret', return_value='file-secret') as mock_super:
            result = manager.get_secret('test_key')
            
            assert result == 'file-secret'
            mock_super.assert_called_once_with('test_key', None)
    
    def test_set_secret_to_vault(self):
        """Test setting secret in Vault."""
        mock_client = Mock()
        
        manager = VaultSecretsManager('http://vault:8200', 'token')
        manager.client = mock_client
        
        manager.set_secret('test_key', 'vault-value')
        
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
            mount_point='secret',
            path='legislativo/test_key',
            secret={'value': 'vault-value'}
        )
    
    def test_set_secret_vault_fallback(self):
        """Test fallback to file storage when Vault set fails."""
        mock_client = Mock()
        mock_client.secrets.kv.v2.create_or_update_secret.side_effect = Exception("Vault error")
        
        manager = VaultSecretsManager('http://vault:8200', 'token')
        manager.client = mock_client
        
        with patch.object(SecretsManager, 'set_secret') as mock_super:
            manager.set_secret('test_key', 'value')
            mock_super.assert_called_once_with('test_key', 'value')


class TestUtilityFunctions:
    """Test utility functions."""
    
    @patch('core.security.secrets_manager.get_secrets_manager')
    def test_get_api_key(self, mock_get_manager):
        """Test get_api_key utility function."""
        mock_manager = Mock()
        mock_manager.get_secret.return_value = 'test-api-key'
        mock_get_manager.return_value = mock_manager
        
        result = get_api_key('camara')
        
        assert result == 'test-api-key'
        mock_manager.get_secret.assert_called_once_with('CAMARA_API_KEY')
    
    @patch('core.security.secrets_manager.get_secrets_manager')
    def test_get_database_password(self, mock_get_manager):
        """Test get_database_password utility function."""
        mock_manager = Mock()
        mock_manager.get_secret.return_value = 'db-password'
        mock_get_manager.return_value = mock_manager
        
        result = get_database_password()
        
        assert result == 'db-password'
        mock_manager.get_secret.assert_called_once_with('DATABASE_PASSWORD')
    
    @patch.dict(os.environ, {'VAULT_URL': 'http://vault:8200', 'VAULT_TOKEN': 'token'})
    def test_get_secrets_manager_vault(self):
        """Test get_secrets_manager returns VaultSecretsManager."""
        with patch('core.security.secrets_manager.VaultSecretsManager') as mock_vault:
            get_secrets_manager()
            mock_vault.assert_called_once_with('http://vault:8200', 'token')
    
    @patch.dict(os.environ, {}, clear=True)
    def test_get_secrets_manager_file(self):
        """Test get_secrets_manager returns SecretsManager."""
        with patch('core.security.secrets_manager.SecretsManager') as mock_file:
            get_secrets_manager()
            mock_file.assert_called_once_with()
    
    @patch('core.security.secrets_manager.get_secrets_manager')
    def test_rotate_all_api_keys(self, mock_get_manager):
        """Test rotate_all_api_keys function."""
        mock_manager = Mock()
        mock_get_manager.return_value = mock_manager
        
        from core.security.secrets_manager import rotate_all_api_keys
        rotate_all_api_keys()
        
        # Should call set_secret for each service
        expected_services = ['camara', 'senado', 'planalto', 'anatel', 'aneel', 'anvisa']
        assert mock_manager.set_secret.call_count == len(expected_services)
        
        # Verify keys were set for each service
        call_args = [call[0][0] for call in mock_manager.set_secret.call_args_list]
        for service in expected_services:
            expected_key = f'{service.upper()}_API_KEY'
            assert expected_key in call_args


class TestSecurityFeatures:
    """Test security-specific features."""
    
    def test_master_key_strength_validation(self):
        """Test that weak master keys are handled appropriately."""
        # Very short key should still work (validation could be added)
        manager = SecretsManager(master_key='short')
        assert manager is not None
        
        # Empty key should fail in initialization
        with pytest.raises(ValueError):
            SecretsManager(master_key='')
    
    def test_file_permissions(self):
        """Test that secrets file has correct permissions."""
        with patch('os.chmod') as mock_chmod:
            with patch('builtins.open', mock_open()):
                with patch('pathlib.Path.mkdir'):
                    manager = SecretsManager(master_key='test-key')
                    manager._save_secrets({'test': 'value'})
                    
                    # Verify restrictive permissions were set
                    mock_chmod.assert_called_with(manager._secrets_file, 0o600)
    
    def test_cache_isolation(self):
        """Test that cache doesn't leak between instances."""
        manager1 = SecretsManager(master_key='key1')
        manager2 = SecretsManager(master_key='key2')
        
        manager1._cache['secret'] = 'value1'
        manager2._cache['secret'] = 'value2'
        
        assert manager1._cache['secret'] != manager2._cache['secret']
    
    def test_encryption_strength(self):
        """Test that encryption is properly applied."""
        manager = SecretsManager(master_key='test-key')
        
        # Test that same data encrypted twice produces different ciphertext
        data = 'sensitive data'
        encrypted1 = manager._fernet.encrypt(data.encode())
        encrypted2 = manager._fernet.encrypt(data.encode())
        
        assert encrypted1 != encrypted2  # Fernet includes random IV
        assert manager._fernet.decrypt(encrypted1).decode() == data
        assert manager._fernet.decrypt(encrypted2).decode() == data