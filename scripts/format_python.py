#!/usr/bin/env python3
"""
Python Code Formatting and Linting Automation Script
Applies comprehensive formatting and linting to the entire Python codebase.

This script:
1. Runs isort to organize imports
2. Runs black to format code style
3. Runs ruff to check for linting issues and apply fixes
4. Generates a formatting report

Usage:
    python scripts/format_python.py [--dry-run] [--path PATH]
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple


class PythonFormatter:
    """Comprehensive Python code formatter and linter."""

    def __init__(self, project_root: Path, dry_run: bool = False):
        """Initialize the formatter.
        
        Args:
            project_root: Root directory of the project
            dry_run: If True, show what would be done without making changes
        """
        self.project_root = project_root
        self.dry_run = dry_run
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.fixes_applied: List[str] = []

    def find_python_files(self, path: Optional[Path] = None) -> List[Path]:
        """Find all Python files in the specified path or project root.
        
        Args:
            path: Specific path to search, defaults to project root
            
        Returns:
            List of Python file paths
        """
        search_path = path or self.project_root
        
        # Directories to exclude
        exclude_dirs = {
            "legacy", "archive", "cache", "logs", "temp_venv", "check_env",
            "lexml_env", "reload_env", "node_modules", ".git", ".ruff_cache",
            ".mypy_cache", "__pycache__", ".pytest_cache", "htmlcov",
            ".coverage", "build", "dist", ".venv", "venv", ".tox", ".nox"
        }
        
        python_files = []
        
        for py_file in search_path.rglob("*.py"):
            # Skip files in excluded directories
            if any(excluded in py_file.parts for excluded in exclude_dirs):
                continue
                
            # Skip temporary and backup files
            if any(py_file.name.endswith(suffix) for suffix in ['.tmp', '.bak', '.orig', '.backup']):
                continue
                
            python_files.append(py_file)
        
        return sorted(python_files)

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> Tuple[bool, str, str]:
        """Run a shell command and return success status and output.
        
        Args:
            cmd: Command and arguments as list
            cwd: Working directory for the command
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            if self.dry_run:
                print(f"[DRY RUN] Would run: {' '.join(cmd)}")
                return True, "", ""
            
            result = subprocess.run(
                cmd,
                cwd=cwd or self.project_root,
                capture_output=True,
                text=True,
                check=False
            )
            
            success = result.returncode == 0
            return success, result.stdout, result.stderr
            
        except FileNotFoundError:
            error_msg = f"Command not found: {cmd[0]}"
            self.errors.append(error_msg)
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Error running {cmd[0]}: {e}"
            self.errors.append(error_msg)
            return False, "", error_msg

    def format_with_isort(self, files: List[Path]) -> bool:
        """Format imports using isort.
        
        Args:
            files: List of Python files to format
            
        Returns:
            True if successful, False otherwise
        """
        print("🔧 Formatting imports with isort...")
        
        if not files:
            print("   No Python files found")
            return True
        
        cmd = [
            "python", "-m", "isort",
            "--profile", "black",
            "--check-only" if self.dry_run else "--diff",
            "--color"
        ] + [str(f) for f in files]
        
        success, stdout, stderr = self.run_command(cmd)
        
        if success:
            if stdout.strip():
                print(f"   ✅ isort completed")
                if not self.dry_run:
                    self.fixes_applied.append("isort: Import organization applied")
            else:
                print("   ✅ All imports already properly formatted")
        else:
            error_msg = f"isort failed: {stderr}"
            print(f"   ❌ {error_msg}")
            self.errors.append(error_msg)
        
        return success

    def format_with_black(self, files: List[Path]) -> bool:
        """Format code using Black.
        
        Args:
            files: List of Python files to format
            
        Returns:
            True if successful, False otherwise
        """
        print("🎨 Formatting code with Black...")
        
        if not files:
            print("   No Python files found")
            return True
        
        cmd = [
            "python", "-m", "black",
            "--line-length", "88",
            "--check" if self.dry_run else "--diff",
            "--color"
        ] + [str(f) for f in files]
        
        success, stdout, stderr = self.run_command(cmd)
        
        if success:
            if stdout.strip():
                print(f"   ✅ Black formatting completed")
                if not self.dry_run:
                    self.fixes_applied.append("black: Code style formatting applied")
            else:
                print("   ✅ All code already properly formatted")
        else:
            error_msg = f"Black failed: {stderr}"
            print(f"   ❌ {error_msg}")
            self.errors.append(error_msg)
        
        return success

    def lint_with_ruff(self, files: List[Path]) -> bool:
        """Lint and fix code using Ruff.
        
        Args:
            files: List of Python files to lint
            
        Returns:
            True if successful, False otherwise
        """
        print("🔍 Linting and fixing with Ruff...")
        
        if not files:
            print("   No Python files found")
            return True
        
        # First run ruff check with fixes
        cmd = [
            "python", "-m", "ruff", "check",
            "--fix" if not self.dry_run else "--show-fixes",
            "--show-source",
        ] + [str(f) for f in files]
        
        success, stdout, stderr = self.run_command(cmd)
        
        if stdout.strip():
            print(f"   📋 Ruff output:\n{stdout}")
            
        if success:
            print("   ✅ Ruff linting completed successfully")
            if not self.dry_run and stdout.strip():
                self.fixes_applied.append("ruff: Linting issues fixed")
        else:
            if "would fix" in stderr or "would fix" in stdout:
                print("   ⚠️  Ruff found fixable issues (dry run mode)")
                self.warnings.append("Ruff found fixable issues")
            else:
                error_msg = f"Ruff linting failed: {stderr}"
                print(f"   ❌ {error_msg}")
                self.errors.append(error_msg)
        
        # Then run ruff format
        print("🎨 Formatting with Ruff...")
        
        format_cmd = [
            "python", "-m", "ruff", "format",
            "--check" if self.dry_run else "--diff"
        ] + [str(f) for f in files]
        
        format_success, format_stdout, format_stderr = self.run_command(format_cmd)
        
        if format_success:
            if format_stdout.strip():
                print(f"   ✅ Ruff formatting completed")
                if not self.dry_run:
                    self.fixes_applied.append("ruff format: Code formatting applied")
            else:
                print("   ✅ All code already properly formatted")
        else:
            error_msg = f"Ruff format failed: {format_stderr}"
            print(f"   ❌ {error_msg}")
            self.errors.append(error_msg)
        
        return success and format_success

    def check_dependencies(self) -> bool:
        """Check if required tools are available.
        
        Returns:
            True if all dependencies are available
        """
        print("🔍 Checking dependencies...")
        
        tools = ["isort", "black", "ruff"]
        missing_tools = []
        
        for tool in tools:
            success, _, _ = self.run_command(["python", "-m", tool, "--version"])
            if success:
                print(f"   ✅ {tool} is available")
            else:
                print(f"   ❌ {tool} is not available")
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"\n❌ Missing tools: {', '.join(missing_tools)}")
            print("Install them with: pip install " + " ".join(missing_tools))
            return False
        
        return True

    def format_all(self, specific_path: Optional[Path] = None) -> bool:
        """Run all formatting and linting tools.
        
        Args:
            specific_path: Specific path to format, None for entire project
            
        Returns:
            True if all operations succeeded
        """
        print("🚀 Starting Python code formatting and linting...")
        print(f"📁 Project root: {self.project_root}")
        
        if self.dry_run:
            print("🔍 Running in DRY RUN mode - no changes will be made")
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Find Python files
        files = self.find_python_files(specific_path)
        print(f"📋 Found {len(files)} Python files")
        
        if not files:
            print("ℹ️  No Python files found to format")
            return True
        
        # Show some example files
        if len(files) <= 5:
            for file in files:
                print(f"   📄 {file.relative_to(self.project_root)}")
        else:
            for file in files[:3]:
                print(f"   📄 {file.relative_to(self.project_root)}")
            print(f"   ... and {len(files) - 3} more files")
        
        print()
        
        # Run formatting tools
        success = True
        
        # 1. Format imports with isort
        if not self.format_with_isort(files):
            success = False
        
        print()
        
        # 2. Format code with Black
        if not self.format_with_black(files):
            success = False
        
        print()
        
        # 3. Lint with Ruff
        if not self.lint_with_ruff(files):
            success = False
        
        return success

    def print_summary(self):
        """Print a summary of the formatting session."""
        print("\n" + "="*60)
        print("📊 FORMATTING SUMMARY")
        print("="*60)
        
        if self.fixes_applied:
            print(f"✅ Fixes applied ({len(self.fixes_applied)}):")
            for fix in self.fixes_applied:
                print(f"   • {fix}")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
        
        if not self.fixes_applied and not self.warnings and not self.errors:
            print("🎉 All Python code is already properly formatted!")
        
        print("\n💡 Next steps:")
        if self.dry_run and (self.warnings or self.fixes_applied):
            print("   • Run without --dry-run to apply changes")
        print("   • Run pre-commit install to enable automatic formatting")
        print("   • Consider running the R and SQL formatting scripts as well")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Format and lint Python code in the Monitor Legislativo v4 project"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--path",
        type=Path,
        help="Specific path to format (default: entire project)"
    )
    
    args = parser.parse_args()
    
    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    
    # Validate project root
    if not (project_root / "pyproject.toml").exists():
        print("❌ Could not find pyproject.toml. Make sure you're running from the project root.")
        sys.exit(1)
    
    # Create formatter and run
    formatter = PythonFormatter(project_root, args.dry_run)
    
    try:
        success = formatter.format_all(args.path)
        formatter.print_summary()
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Formatting interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()