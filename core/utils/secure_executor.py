"""Secure command execution utilities to prevent injection attacks."""

import shlex
import subprocess
import logging
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class CommandExecutionError(Exception):
    """Raised when command execution fails."""
    pass


class SecureExecutor:
    """Secure command executor with validation and sanitization."""
    
    # Whitelist of allowed commands
    ALLOWED_COMMANDS = {
        'ls', 'cat', 'grep', 'find', 'echo', 'pwd', 'date',
        'python', 'python3', 'pip', 'pip3',
        'git', 'docker', 'docker-compose',
    }
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        ';', '|', '&', '`', '$', '(', ')', '{', '}',
        '>', '<', '>>', '<<', '||', '&&',
        '\n', '\r', '\x00',
    ]
    
    @staticmethod
    def validate_command(command: str) -> None:
        """Validate command for security issues.
        
        Args:
            command: Command to validate
            
        Raises:
            CommandExecutionError: If command contains dangerous patterns
        """
        # Check for dangerous patterns
        for pattern in SecureExecutor.DANGEROUS_PATTERNS:
            if pattern in command:
                raise CommandExecutionError(
                    f"Command contains dangerous pattern: {pattern}"
                )
        
        # Extract base command
        try:
            parts = shlex.split(command)
            if not parts:
                raise CommandExecutionError("Empty command")
            
            base_command = Path(parts[0]).name
            
            # Check if command is in whitelist
            if base_command not in SecureExecutor.ALLOWED_COMMANDS:
                raise CommandExecutionError(
                    f"Command '{base_command}' is not in allowed list"
                )
        except ValueError as e:
            raise CommandExecutionError(f"Invalid command format: {e}")
    
    @staticmethod
    def sanitize_argument(arg: str) -> str:
        """Sanitize a single command argument.
        
        Args:
            arg: Argument to sanitize
            
        Returns:
            Sanitized argument
        """
        # Remove any potentially dangerous characters
        sanitized = arg
        for pattern in SecureExecutor.DANGEROUS_PATTERNS:
            sanitized = sanitized.replace(pattern, '')
        
        # Escape special characters
        return shlex.quote(sanitized)
    
    @staticmethod
    def execute_command(
        command: List[str],
        timeout: Optional[int] = 30,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        capture_output: bool = True
    ) -> Tuple[int, str, str]:
        """Execute a command safely.
        
        Args:
            command: Command and arguments as list
            timeout: Command timeout in seconds
            cwd: Working directory
            env: Environment variables
            capture_output: Whether to capture output
            
        Returns:
            Tuple of (return_code, stdout, stderr)
            
        Raises:
            CommandExecutionError: If command execution fails
        """
        if not command:
            raise CommandExecutionError("Empty command list")
        
        # Validate base command
        base_command = Path(command[0]).name
        if base_command not in SecureExecutor.ALLOWED_COMMANDS:
            raise CommandExecutionError(
                f"Command '{base_command}' is not in allowed list"
            )
        
        # Log command execution (without sensitive data)
        logger.info(f"Executing command: {base_command}")
        
        try:
            # Use subprocess.run with specific arguments for security
            result = subprocess.run(
                command,
                timeout=timeout,
                cwd=cwd,
                env=env,
                capture_output=capture_output,
                text=True,
                shell=False,  # Never use shell=True
                check=False
            )
            
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            raise CommandExecutionError(f"Command timed out after {timeout} seconds")
        except Exception as e:
            raise CommandExecutionError(f"Command execution failed: {e}")
    
    @staticmethod
    def execute_safe(
        command_template: str,
        arguments: Dict[str, str],
        **kwargs
    ) -> Tuple[int, str, str]:
        """Execute a command with template and sanitized arguments.
        
        Args:
            command_template: Command template with placeholders
            arguments: Arguments to substitute
            **kwargs: Additional arguments for execute_command
            
        Returns:
            Tuple of (return_code, stdout, stderr)
            
        Example:
            execute_safe("grep {pattern} {file}", {"pattern": "test", "file": "data.txt"})
        """
        # Build command with sanitized arguments
        command_parts = command_template.split()
        final_command = []
        
        for part in command_parts:
            if part.startswith('{') and part.endswith('}'):
                key = part[1:-1]
                if key in arguments:
                    final_command.append(SecureExecutor.sanitize_argument(arguments[key]))
                else:
                    raise CommandExecutionError(f"Missing argument: {key}")
            else:
                final_command.append(part)
        
        return SecureExecutor.execute_command(final_command, **kwargs)


class GitOperations:
    """Secure Git operations."""
    
    @staticmethod
    def get_status() -> Tuple[int, str, str]:
        """Get git status safely."""
        return SecureExecutor.execute_command(['git', 'status', '--porcelain'])
    
    @staticmethod
    def get_log(limit: int = 10) -> Tuple[int, str, str]:
        """Get git log safely."""
        return SecureExecutor.execute_command([
            'git', 'log', f'--max-count={limit}', '--oneline'
        ])
    
    @staticmethod
    def add_file(filepath: str) -> Tuple[int, str, str]:
        """Add file to git safely."""
        # Validate file path
        safe_path = SecureExecutor.sanitize_argument(filepath)
        return SecureExecutor.execute_command(['git', 'add', safe_path])


class DockerOperations:
    """Secure Docker operations."""
    
    @staticmethod
    def list_containers() -> Tuple[int, str, str]:
        """List Docker containers safely."""
        return SecureExecutor.execute_command(['docker', 'ps', '-a'])
    
    @staticmethod
    def get_logs(container: str, tail: int = 100) -> Tuple[int, str, str]:
        """Get Docker container logs safely."""
        safe_container = SecureExecutor.sanitize_argument(container)
        return SecureExecutor.execute_command([
            'docker', 'logs', f'--tail={tail}', safe_container
        ])
    
    @staticmethod
    def execute_in_container(
        container: str,
        command: List[str]
    ) -> Tuple[int, str, str]:
        """Execute command in Docker container safely."""
        safe_container = SecureExecutor.sanitize_argument(container)
        
        # Build docker exec command
        docker_command = ['docker', 'exec', safe_container] + command
        
        return SecureExecutor.execute_command(docker_command)