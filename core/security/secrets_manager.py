"""Secure secrets management for the Legislative Monitoring System."""

import os
import json
import base64
import secrets
from typing import Any, Dict, Optional
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

from core.security.key_rotation_service import get_key_rotation_service

logger = logging.getLogger(__name__)


class SecretsManager:
    """Manages application secrets with encryption at rest."""
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialize secrets manager with master key.
        
        Args:
            master_key: Master encryption key. If not provided, uses key rotation service.
        """
        self._secrets_file = Path('data/.secrets.enc')
        self._salt_file = Path('data/.salt')
        self._cache: Dict[str, Any] = {}
        
        # Get key rotation service
        self._key_rotation_service = get_key_rotation_service()
        
        if master_key:
            # Legacy mode: explicit master key provided
            self.master_key = master_key
            self._use_key_rotation = False
        else:
            # New mode: use key rotation service
            self._use_key_rotation = True
            # Get or generate master key from rotation service
            master_key_id = self._key_rotation_service.get_active_key_id('master')
            if not master_key_id:
                # Generate initial master key
                master_key_id, _ = self._key_rotation_service.generate_key('master')
                logger.info("Generated initial master key via rotation service")
            
            # Get key material
            key_material = self._key_rotation_service.get_key(master_key_id)
            if not key_material:
                raise ValueError("Failed to get master key from rotation service")
            
            self.master_key = key_material.decode('utf-8')
            self._master_key_id = master_key_id
        
        self._fernet = self._create_fernet(self.master_key)
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create a new cryptographically secure one."""
        if self._salt_file.exists():
            try:
                with open(self._salt_file, 'rb') as f:
                    salt = f.read()
                if len(salt) == 32:  # Verify salt is correct length
                    return salt
                logger.warning("Invalid salt length found, generating new salt")
            except Exception as e:
                logger.error(f"Failed to read salt file: {e}")
        
        # Generate cryptographically secure random salt
        salt = secrets.token_bytes(32)
        
        # Ensure directory exists with proper permissions
        self._salt_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Save salt with restrictive permissions
        try:
            with open(self._salt_file, 'wb') as f:
                f.write(salt)
            os.chmod(self._salt_file, 0o600)
            logger.info("New cryptographic salt generated and stored securely")
        except Exception as e:
            logger.error(f"Failed to save salt: {e}")
            raise
        
        return salt

    def _create_fernet(self, master_key: str) -> Fernet:
        """Create Fernet cipher from master key with secure salt."""
        salt = self._get_or_create_salt()
        
        # Use 600,000 iterations (2024 OWASP recommendation)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # Increased from 100k to meet 2024 standards
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
    
    def _validate_secret_input(self, key: str, value: Any) -> None:
        """Validate secret key and value inputs."""
        if not key or not isinstance(key, str):
            raise ValueError("Secret key must be a non-empty string")
        
        if len(key) > 255:
            raise ValueError("Secret key must be 255 characters or less")
        
        # Validate key format (alphanumeric + underscores only)
        if not key.replace('_', '').replace('-', '').isalnum():
            raise ValueError("Secret key must contain only alphanumeric characters, underscores, and hyphens")
        
        if value is None:
            raise ValueError("Secret value cannot be None")
        
        # Serialize to check size
        try:
            serialized = json.dumps(value)
            if len(serialized.encode('utf-8')) > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError("Secret value too large (max 10MB)")
        except (TypeError, ValueError) as e:
            raise ValueError(f"Secret value must be JSON serializable: {e}")

    def set_secret(self, key: str, value: Any) -> None:
        """Set a secret value with validation.
        
        Args:
            key: Secret key (alphanumeric + underscores/hyphens, max 255 chars)
            value: Secret value (JSON serializable, max 10MB)
            
        Raises:
            ValueError: If key or value validation fails
        """
        self._validate_secret_input(key, value)
        
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
    
    def _validate_master_key_strength(self, key: str) -> None:
        """Validate master key meets security requirements."""
        if not key or not isinstance(key, str):
            raise ValueError("Master key must be a non-empty string")
        
        if len(key) < 32:
            raise ValueError("Master key must be at least 32 characters long")
        
        # Check for basic complexity
        has_upper = any(c.isupper() for c in key)
        has_lower = any(c.islower() for c in key)
        has_digit = any(c.isdigit() for c in key)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in key)
        
        complexity_count = sum([has_upper, has_lower, has_digit, has_special])
        if complexity_count < 3:
            raise ValueError("Master key must contain at least 3 of: uppercase, lowercase, digits, special characters")

    def rotate_master_key(self, new_master_key: str) -> None:
        """Rotate the master encryption key with validation.
        
        Args:
            new_master_key: New master key (min 32 chars, complex)
            
        Raises:
            ValueError: If new master key doesn't meet security requirements
        """
        self._validate_master_key_strength(new_master_key)
        
        # Load all secrets with current key
        secrets = self._load_secrets()
        
        # Generate new salt for the new key
        old_salt_file = self._salt_file
        backup_salt_file = self._salt_file.with_suffix('.backup')
        
        try:
            # Backup current salt
            if old_salt_file.exists():
                old_salt_file.rename(backup_salt_file)
            
            # Create new cipher with new key and new salt
            self._fernet = self._create_fernet(new_master_key)
            self.master_key = new_master_key
            
            # Re-encrypt with new key
            self._save_secrets(secrets)
            
            # Remove backup salt after successful rotation
            if backup_salt_file.exists():
                backup_salt_file.unlink()
            
            # Clear cache
            self._cache.clear()
            
            logger.info("Master key rotated successfully with new salt")
            
        except Exception as e:
            # Restore old salt on failure
            if backup_salt_file.exists():
                backup_salt_file.rename(old_salt_file)
            logger.error(f"Master key rotation failed: {e}")
            raise


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