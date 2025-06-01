"""Secure secrets management for the Legislative Monitoring System."""

import os
import json
import base64
from typing import Any, Dict, Optional
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)


class SecretsManager:
    """Manages application secrets with encryption at rest."""
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialize secrets manager with master key.
        
        Args:
            master_key: Master encryption key. If not provided, uses environment variable.
        """
        self.master_key = master_key or os.getenv('MASTER_KEY')
        if not self.master_key:
            raise ValueError("Master key not provided. Set MASTER_KEY environment variable.")
        
        self._fernet = self._create_fernet(self.master_key)
        self._secrets_file = Path('data/.secrets.enc')
        self._cache: Dict[str, Any] = {}
    
    def _create_fernet(self, master_key: str) -> Fernet:
        """Create Fernet cipher from master key."""
        # Derive a proper key from the master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'legislativo-salt',  # In production, use a random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return Fernet(key)
    
    def _load_secrets(self) -> Dict[str, Any]:
        """Load and decrypt secrets from file."""
        if not self._secrets_file.exists():
            return {}
        
        try:
            with open(self._secrets_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Failed to load secrets: {e}")
            return {}
    
    def _save_secrets(self, secrets: Dict[str, Any]) -> None:
        """Encrypt and save secrets to file."""
        self._secrets_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            data = json.dumps(secrets).encode()
            encrypted_data = self._fernet.encrypt(data)
            
            with open(self._secrets_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(self._secrets_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save secrets: {e}")
            raise
    
    def get_secret(self, key: str, default: Optional[Any] = None) -> Optional[Any]:
        """Get a secret value.
        
        Args:
            key: Secret key
            default: Default value if secret not found
            
        Returns:
            Secret value or default
        """
        # Check cache first
        if key in self._cache:
            return self._cache[key]
        
        # Check environment variable
        env_value = os.getenv(key)
        if env_value:
            self._cache[key] = env_value
            return env_value
        
        # Load from encrypted file
        secrets = self._load_secrets()
        value = secrets.get(key, default)
        
        if value:
            self._cache[key] = value
        
        return value
    
    def set_secret(self, key: str, value: Any) -> None:
        """Set a secret value.
        
        Args:
            key: Secret key
            value: Secret value
        """
        secrets = self._load_secrets()
        secrets[key] = value
        self._save_secrets(secrets)
        
        # Update cache
        self._cache[key] = value
        
        logger.info(f"Secret '{key}' updated successfully")
    
    def delete_secret(self, key: str) -> bool:
        """Delete a secret.
        
        Args:
            key: Secret key
            
        Returns:
            True if deleted, False if not found
        """
        secrets = self._load_secrets()
        
        if key in secrets:
            del secrets[key]
            self._save_secrets(secrets)
            
            # Remove from cache
            self._cache.pop(key, None)
            
            logger.info(f"Secret '{key}' deleted successfully")
            return True
        
        return False
    
    def list_secrets(self) -> list[str]:
        """List all secret keys (not values)."""
        secrets = self._load_secrets()
        return list(secrets.keys())
    
    def rotate_master_key(self, new_master_key: str) -> None:
        """Rotate the master encryption key.
        
        Args:
            new_master_key: New master key
        """
        # Load all secrets with current key
        secrets = self._load_secrets()
        
        # Create new cipher
        self._fernet = self._create_fernet(new_master_key)
        self.master_key = new_master_key
        
        # Re-encrypt with new key
        self._save_secrets(secrets)
        
        # Clear cache
        self._cache.clear()
        
        logger.info("Master key rotated successfully")


class VaultSecretsManager(SecretsManager):
    """Enhanced secrets manager with HashiCorp Vault integration."""
    
    def __init__(self, vault_url: str, vault_token: str):
        """Initialize with Vault connection.
        
        Args:
            vault_url: Vault server URL
            vault_token: Vault authentication token
        """
        super().__init__()
        self.vault_url = vault_url
        self.vault_token = vault_token
        
        # Import hvac only if using Vault
        try:
            import hvac
            self.client = hvac.Client(url=vault_url, token=vault_token)
            if not self.client.is_authenticated():
                raise ValueError("Vault authentication failed")
        except ImportError:
            logger.warning("hvac library not installed. Using file-based secrets.")
            self.client = None
    
    def get_secret(self, key: str, default: Optional[Any] = None) -> Optional[Any]:
        """Get secret from Vault or fall back to file storage."""
        if self.client:
            try:
                response = self.client.secrets.kv.v2.read_secret_version(
                    mount_point='secret',
                    path=f'legislativo/{key}'
                )
                return response['data']['data'].get('value', default)
            except Exception as e:
                logger.warning(f"Failed to get secret from Vault: {e}")
        
        # Fall back to parent implementation
        return super().get_secret(key, default)
    
    def set_secret(self, key: str, value: Any) -> None:
        """Set secret in Vault."""
        if self.client:
            try:
                self.client.secrets.kv.v2.create_or_update_secret(
                    mount_point='secret',
                    path=f'legislativo/{key}',
                    secret={'value': value}
                )
                logger.info(f"Secret '{key}' stored in Vault")
                return
            except Exception as e:
                logger.warning(f"Failed to set secret in Vault: {e}")
        
        # Fall back to parent implementation
        super().set_secret(key, value)


def get_secrets_manager() -> SecretsManager:
    """Get the appropriate secrets manager instance."""
    vault_url = os.getenv('VAULT_URL')
    vault_token = os.getenv('VAULT_TOKEN')
    
    if vault_url and vault_token:
        logger.info("Using Vault secrets manager")
        return VaultSecretsManager(vault_url, vault_token)
    else:
        logger.info("Using file-based secrets manager")
        return SecretsManager()


# Utility functions
def get_api_key(service: str) -> Optional[str]:
    """Get API key for a specific service."""
    manager = get_secrets_manager()
    return manager.get_secret(f'{service.upper()}_API_KEY')


def get_database_password() -> Optional[str]:
    """Get database password."""
    manager = get_secrets_manager()
    return manager.get_secret('DATABASE_PASSWORD')


def rotate_all_api_keys() -> None:
    """Rotate all API keys."""
    manager = get_secrets_manager()
    services = ['camara', 'senado', 'planalto', 'anatel', 'aneel', 'anvisa']
    
    for service in services:
        key_name = f'{service.upper()}_API_KEY'
        # In production, this would request new keys from each service
        new_key = f"new-{service}-key-{os.urandom(8).hex()}"
        manager.set_secret(key_name, new_key)
        logger.info(f"Rotated API key for {service}")