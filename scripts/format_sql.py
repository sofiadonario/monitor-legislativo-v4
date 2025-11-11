#!/usr/bin/env python3
"""
SQL Code Formatting and Linting Automation Script
Applies comprehensive formatting and linting to the entire SQL codebase.

This script:
1. Uses sqlfluff to format and lint SQL code for PostgreSQL
2. Validates SQL syntax and style conventions
3. Generates a formatting report

Usage:
    python scripts/format_sql.py [--dry-run] [--path PATH]
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple


class SQLFormatter:
    """Comprehensive SQL code formatter and linter using SQLFluff."""

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
        self.files_processed = 0
        self.total_files = 0

    def find_sql_files(self, path: Optional[Path] = None) -> List[Path]:
        """Find all SQL files in the specified path or project root.
        
        Args:
            path: Specific path to search, defaults to project root
            
        Returns:
            List of SQL file paths
        """
        search_path = path or self.project_root
        
        # Directories to exclude
        exclude_dirs = {
            "legacy", "archive", "cache", "logs", "temp_venv", "check_env",
            "lexml_env", "reload_env", "node_modules", ".git", ".ruff_cache",
            ".mypy_cache", "__pycache__", ".pytest_cache", "htmlcov",
            "build", "dist", ".venv", "venv", ".tox", ".nox"
        }
        
        sql_files = []
        
        # Search for SQL files
        for sql_file in search_path.rglob("*.sql"):
            # Skip files in excluded directories
            if any(excluded in sql_file.parts for excluded in exclude_dirs):
                continue
                
            # Skip temporary and backup files
            if any(sql_file.name.endswith(suffix) for suffix in ['.tmp', '.bak', '.orig', '.backup']):
                continue
                
            sql_files.append(sql_file)
        
        # Also search for .SQL files (case insensitive)
        for sql_file in search_path.rglob("*.SQL"):
            if sql_file not in sql_files:
                # Apply same exclusion logic
                if any(excluded in sql_file.parts for excluded in exclude_dirs):
                    continue
                if any(sql_file.name.endswith(suffix) for suffix in ['.tmp', '.bak', '.orig', '.backup']):
                    continue
                sql_files.append(sql_file)
        
        self.total_files = len(sql_files)
        return sorted(sql_files)

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> Tuple[bool, str, str]:
        """Run a shell command and return success status and output.
        
        Args:
            cmd: Command and arguments as list
            cwd: Working directory for the command
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            if self.dry_run and "fix" in " ".join(cmd):
                # Replace fix with lint for dry-run mode
                cmd = [c.replace("fix", "lint") for c in cmd]
                print(f"[DRY RUN] Would run: {' '.join(cmd)}")
            
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
            error_msg = f"Command not found: {cmd[0]} (try: pip install sqlfluff)"
            self.errors.append(error_msg)
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Error running {cmd[0]}: {e}"
            self.errors.append(error_msg)
            return False, "", error_msg

    def lint_sql_files(self, files: List[Path]) -> bool:
        """Lint SQL files using SQLFluff.
        
        Args:
            files: List of SQL files to lint
            
        Returns:
            True if successful, False otherwise
        """
        print("🔍 Linting SQL files with SQLFluff...")
        
        if not files:
            print("   No SQL files found")
            return True
        
        success = True
        total_violations = 0
        files_with_violations = 0
        
        for sql_file in files:
            self.files_processed += 1
            relative_path = sql_file.relative_to(self.project_root)
            
            print(f"   [{self.files_processed}/{self.total_files}] Linting: {relative_path}")
            
            cmd = [
                "sqlfluff", "lint",
                "--dialect", "postgres",
                "--format", "human",
                str(sql_file)
            ]
            
            file_success, stdout, stderr = self.run_command(cmd)
            
            if stdout.strip():
                # Count violations
                lines = stdout.split('\n')
                violations = [line for line in lines if 'L0' in line or 'L1' in line or 'L2' in line]
                
                if violations:
                    files_with_violations += 1
                    file_violations = len(violations)
                    total_violations += file_violations
                    
                    print(f"      ⚠️  Found {file_violations} violations")
                    
                    # Show first few violations
                    for violation in violations[:3]:
                        if violation.strip():
                            print(f"         • {violation.strip()}")
                    
                    if len(violations) > 3:
                        print(f"         ... and {len(violations) - 3} more violations")
                else:
                    print(f"      ✅ No violations found")
            else:
                print(f"      ✅ No violations found")
            
            if not file_success and stderr:
                error_msg = f"SQLFluff lint failed for {relative_path}: {stderr}"
                self.errors.append(error_msg)
                success = False
        
        if total_violations > 0:
            warning_msg = f"Found {total_violations} violations in {files_with_violations} files"
            print(f"   ⚠️  {warning_msg}")
            self.warnings.append(f"sqlfluff lint: {warning_msg}")
        else:
            print("   ✅ All SQL files passed linting")
        
        return success

    def format_sql_files(self, files: List[Path]) -> bool:
        """Format SQL files using SQLFluff.
        
        Args:
            files: List of SQL files to format
            
        Returns:
            True if successful, False otherwise
        """
        print("🎨 Formatting SQL files with SQLFluff...")
        
        if not files:
            print("   No SQL files found")
            return True
        
        success = True
        formatted_files = 0
        
        for sql_file in files:
            relative_path = sql_file.relative_to(self.project_root)
            
            if self.dry_run:
                # In dry-run mode, just check what would be formatted
                cmd = [
                    "sqlfluff", "format",
                    "--dialect", "postgres",
                    "--check",
                    str(sql_file)
                ]
                
                file_success, stdout, stderr = self.run_command(cmd)
                
                if not file_success:
                    formatted_files += 1
                    print(f"      Would format: {relative_path}")
                
            else:
                # Actually format the file
                print(f"      Formatting: {relative_path}")
                
                cmd = [
                    "sqlfluff", "fix",
                    "--dialect", "postgres",
                    "--force",
                    str(sql_file)
                ]
                
                file_success, stdout, stderr = self.run_command(cmd)
                
                if file_success:
                    if "Fixed" in stdout:
                        formatted_files += 1
                        print(f"         ✅ Formatted")
                    else:
                        print(f"         Already formatted")
                else:
                    error_msg = f"Failed to format {relative_path}: {stderr}"
                    self.errors.append(error_msg)
                    print(f"         ❌ {error_msg}")
                    success = False
        
        if formatted_files > 0:
            if self.dry_run:
                print(f"   📋 Would format {formatted_files} files")
                self.warnings.append(f"sqlfluff: Would format {formatted_files} files")
            else:
                print(f"   ✅ Formatted {formatted_files} files")
                self.fixes_applied.append(f"sqlfluff: Formatted {formatted_files} files")
        else:
            print("   ✅ All SQL files already properly formatted")
        
        return success

    def check_dependencies(self) -> bool:
        """Check if SQLFluff is available.
        
        Returns:
            True if SQLFluff is available
        """
        print("🔍 Checking SQLFluff availability...")
        
        success, stdout, stderr = self.run_command(["sqlfluff", "--version"])
        
        if success:
            version = stdout.strip()
            print(f"   ✅ SQLFluff is available: {version}")
            return True
        else:
            print("   ❌ SQLFluff is not available")
            print("   Install with: pip install sqlfluff")
            return False

    def validate_config(self) -> bool:
        """Validate SQLFluff configuration.
        
        Returns:
            True if configuration is valid
        """
        config_file = self.project_root / ".sqlfluff"
        
        if not config_file.exists():
            self.warnings.append("No .sqlfluff configuration file found")
            print("   ⚠️  No .sqlfluff configuration file found")
            return True  # Not critical
        
        print(f"   ✅ Found configuration file: {config_file}")
        return True

    def format_all(self, specific_path: Optional[Path] = None) -> bool:
        """Run all SQL formatting and linting tools.
        
        Args:
            specific_path: Specific path to format, None for entire project
            
        Returns:
            True if all operations succeeded
        """
        print("🚀 Starting SQL code formatting and linting...")
        print(f"📁 Project root: {self.project_root}")
        
        if self.dry_run:
            print("🔍 Running in DRY RUN mode - no changes will be made")
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Validate configuration
        self.validate_config()
        
        # Find SQL files
        files = self.find_sql_files(specific_path)
        print(f"📋 Found {len(files)} SQL files")
        
        if not files:
            print("ℹ️  No SQL files found to format")
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
        
        # Run SQL tools
        success = True
        
        # 1. Lint SQL files
        if not self.lint_sql_files(files):
            success = False
        
        print()
        
        # 2. Format SQL files
        if not self.format_sql_files(files):
            success = False
        
        return success

    def print_summary(self):
        """Print a summary of the formatting session."""
        print("\n" + "="*60)
        print("📊 SQL FORMATTING SUMMARY")
        print("="*60)
        
        print(f"📈 Files processed: {self.files_processed}/{self.total_files}")
        
        if self.fixes_applied:
            print(f"\n✅ Fixes applied ({len(self.fixes_applied)}):")
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
            print("🎉 All SQL code is already properly formatted!")
        
        print("\n💡 Next steps:")
        if self.dry_run and (self.warnings or self.fixes_applied):
            print("   • Run without --dry-run to apply changes")
        print("   • Run pre-commit install to enable automatic formatting")
        print("   • Review .sqlfluff configuration if needed")
        print("   • Consider integrating SQL linting in your IDE")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Format and lint SQL code in the Monitor Legislativo v4 project"
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
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    
    # Validate project root
    if not (project_root / ".sqlfluff").exists():
        print("❌ Could not find .sqlfluff config. Make sure you're running from the project root.")
        print("   A basic .sqlfluff file will be created...")
        
        # Create basic config
        basic_config = """[sqlfluff]
dialect = postgres
templater = jinja
sql_file_exts = .sql,.SQL
output_line_length = 120
"""
        with open(project_root / ".sqlfluff", "w") as f:
            f.write(basic_config)
        print("   ✅ Created basic .sqlfluff configuration")
    
    # Create formatter and run
    formatter = SQLFormatter(project_root, args.dry_run)
    
    try:
        success = formatter.format_all(args.path)
        formatter.print_summary()
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  SQL formatting interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()