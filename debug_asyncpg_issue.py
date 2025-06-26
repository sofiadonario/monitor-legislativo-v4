#!/usr/bin/env python3
"""
Comprehensive AsyncPG Version Debugging Script
Railway Platform Issue Diagnosis

This script will help identify exactly what's happening with asyncpg versions
and provide definitive proof of the runtime environment vs build environment mismatch.
"""

import os
import sys
import subprocess
import importlib
import urllib.parse
import asyncio
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_separator(title):
    """Print a separator with title"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_subsection(title):
    """Print a subsection separator"""
    print(f"\n--- {title} ---")

def run_command(cmd, description):
    """Run a command and capture output"""
    print_subsection(description)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"Command: {cmd}")
        print(f"Return code: {result.returncode}")
        if result.stdout:
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def check_python_environment():
    """Check Python environment details"""
    print_separator("PYTHON ENVIRONMENT")
    
    print(f"Python executable: {sys.executable}")
    print(f"Python version: {sys.version}")
    print(f"Python path: {sys.path}")
    
    # Check if we're in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Running in virtual environment")
        print(f"Virtual env prefix: {sys.prefix}")
    else:
        print("❌ Not in virtual environment")
    
    # Check site-packages
    import site
    print(f"Site packages: {site.getsitepackages()}")

def check_package_versions():
    """Check all relevant package versions"""
    print_separator("PACKAGE VERSIONS")
    
    packages_to_check = [
        'asyncpg',
        'sqlalchemy', 
        'psycopg2',
        'psycopg2-binary',
        'aiopg',
        'fastapi',
        'uvicorn',
        'pydantic'
    ]
    
    for package in packages_to_check:
        try:
            module = importlib.import_module(package)
            version = getattr(module, '__version__', 'Unknown')
            print(f"✅ {package}: {version}")
        except ImportError:
            print(f"❌ {package}: Not installed")
        except Exception as e:
            print(f"⚠️  {package}: Error - {e}")

def check_asyncpg_details():
    """Check asyncpg specific details"""
    print_separator("ASYNCPG DETAILED ANALYSIS")
    
    try:
        import asyncpg
        print(f"AsyncPG version: {asyncpg.__version__}")
        print(f"AsyncPG file location: {asyncpg.__file__}")
        
        # Check for critical components
        print_subsection("AsyncPG Components")
        critical_components = [
            'Connection', 'Pool', 'connect', 'create_pool'
        ]
        
        for component in critical_components:
            if hasattr(asyncpg, component):
                print(f"✅ {component}: Available")
            else:
                print(f"❌ {component}: Missing")
        
        # Check for auth-related components
        print_subsection("Authentication Components")
        try:
            from asyncpg.protocol import protocol
            print("✅ Protocol module available")
            
            # Check for SCRAM-SHA-256 support
            if hasattr(protocol, 'AuthenticationSASL'):
                print("✅ SASL authentication available")
            else:
                print("❌ SASL authentication missing")
                
        except ImportError as e:
            print(f"❌ Protocol module import failed: {e}")
        
    except ImportError as e:
        print(f"❌ AsyncPG import failed: {e}")

def check_pip_dependencies():
    """Check pip dependencies and conflicts"""
    print_separator("PIP DEPENDENCY ANALYSIS")
    
    # Check installed packages
    run_command("pip list", "All installed packages")
    
    # Check for asyncpg specifically
    run_command("pip show asyncpg", "AsyncPG package details")
    
    # Check for dependency conflicts
    run_command("pip check", "Dependency conflict check")

def check_database_url():
    """Check database URL configuration"""
    print_separator("DATABASE CONFIGURATION")
    
    db_url = os.getenv('DATABASE_URL', '')
    if not db_url:
        print("❌ DATABASE_URL not set")
        return
    
    print("✅ DATABASE_URL is set")
    
    # Parse URL safely
    try:
        parsed = urllib.parse.urlparse(db_url)
        print(f"Scheme: {parsed.scheme}")
        print(f"Host: {parsed.hostname}")
        print(f"Port: {parsed.port}")
        print(f"Database: {parsed.path.lstrip('/')}")
        print(f"Username: {parsed.username}")
        print(f"Password: {'*' * len(parsed.password) if parsed.password else 'None'}")
        
        # Check for Supabase
        if 'supabase.co' in db_url:
            print("✅ Supabase connection detected")
            if 'pooler.supabase.com' in db_url:
                print("✅ Using Supabase pooler")
            else:
                print("⚠️  Using direct Supabase connection")
        
    except Exception as e:
        print(f"❌ Failed to parse DATABASE_URL: {e}")

async def test_asyncpg_connection():
    """Test asyncpg connection directly"""
    print_separator("ASYNCPG CONNECTION TEST")
    
    db_url = os.getenv('DATABASE_URL', '')
    if not db_url:
        print("❌ Cannot test connection - DATABASE_URL not set")
        return False
    
    # Convert to asyncpg format
    if db_url.startswith('postgresql://'):
        asyncpg_url = db_url.replace('postgresql://', 'postgresql://', 1)
    else:
        asyncpg_url = db_url
    
    print(f"Testing connection to: {urllib.parse.urlparse(asyncpg_url).hostname}")
    
    try:
        import asyncpg
        
        # Test with different timeout values
        for timeout in [10, 30, 60]:
            print(f"\nTrying connection with {timeout}s timeout...")
            try:
                conn = await asyncio.wait_for(
                    asyncpg.connect(asyncpg_url), 
                    timeout=timeout
                )
                
                # Test basic query
                result = await conn.fetchval("SELECT 1")
                print(f"✅ Connection successful! Query result: {result}")
                
                # Test more complex query
                version = await conn.fetchval("SELECT version()")
                print(f"✅ PostgreSQL version: {version}")
                
                await conn.close()
                return True
                
            except asyncio.TimeoutError:
                print(f"❌ Connection timed out after {timeout}s")
                continue
            except Exception as e:
                print(f"❌ Connection failed: {e}")
                print(f"Error type: {type(e).__name__}")
                
                # Check for specific error patterns
                error_str = str(e).lower()
                if 'nonetype' in error_str and 'group' in error_str:
                    print("🔍 FOUND THE ISSUE: This is the exact error from Railway!")
                    print("🔍 This confirms asyncpg version incompatibility")
                    return False
                elif 'network' in error_str or 'unreachable' in error_str:
                    print("🔍 Network connectivity issue")
                elif 'authentication' in error_str:
                    print("🔍 Authentication issue")
                elif 'ssl' in error_str:
                    print("🔍 SSL configuration issue")
                
                continue
    
    except ImportError as e:
        print(f"❌ Cannot import asyncpg: {e}")
        return False
    
    print("❌ All connection attempts failed")
    return False

def check_railway_environment():
    """Check Railway-specific environment variables"""
    print_separator("RAILWAY ENVIRONMENT")
    
    railway_vars = [
        'RAILWAY_ENVIRONMENT', 'RAILWAY_DEPLOYMENT_ID', 'RAILWAY_REPLICA_ID',
        'RAILWAY_SERVICE_ID', 'RAILWAY_PROJECT_ID'
    ]
    
    for var in railway_vars:
        value = os.getenv(var)
        if value:
            print(f"✅ {var}: {value}")
        else:
            print(f"❌ {var}: Not set")
    
    # Check if we're running on Railway
    if os.getenv('RAILWAY_ENVIRONMENT'):
        print("✅ Running on Railway platform")
    else:
        print("❌ Not running on Railway (local environment)")

def generate_report():
    """Generate a comprehensive report"""
    print_separator("DIAGNOSIS REPORT")
    
    now = datetime.now().isoformat()
    print(f"Report generated: {now}")
    
    # Check asyncpg version
    try:
        import asyncpg
        asyncpg_version = asyncpg.__version__
        print(f"AsyncPG version: {asyncpg_version}")
        
        # Parse version
        version_parts = asyncpg_version.split('.')
        major, minor = int(version_parts[0]), int(version_parts[1])
        
        if major > 0 or (major == 0 and minor >= 26):
            print("✅ AsyncPG version is compatible with Supabase SCRAM-SHA-256")
        else:
            print("❌ AsyncPG version is TOO OLD for Supabase SCRAM-SHA-256")
            print("❌ This is likely the root cause of the authentication error")
    except ImportError:
        print("❌ AsyncPG not available")
    
    # Environment summary
    is_railway = bool(os.getenv('RAILWAY_ENVIRONMENT'))
    has_db_url = bool(os.getenv('DATABASE_URL'))
    
    print(f"Environment: {'Railway' if is_railway else 'Local'}")
    print(f"Database URL configured: {has_db_url}")
    
    # Recommendations
    print_subsection("RECOMMENDATIONS")
    
    if not is_railway:
        print("1. Test this script locally first")
        print("2. If it works locally, the issue is Railway-specific")
        print("3. Deploy with enhanced Dockerfile to Railway")
    else:
        print("1. Check Railway logs for asyncpg version output")
        print("2. If version is < 0.26.0, file Railway support ticket")
        print("3. Try adding explicit pip install in Railway build command")

async def main():
    """Main diagnostic function"""
    print_separator("ASYNCPG RAILWAY DEBUGGING SESSION")
    print("This script will help identify the exact cause of the asyncpg authentication issue")
    
    # Run all checks
    check_python_environment()
    check_package_versions()
    check_asyncpg_details()
    check_pip_dependencies()
    check_database_url()
    check_railway_environment()
    
    # Test connection
    connection_works = await test_asyncpg_connection()
    
    # Generate report
    generate_report()
    
    print_separator("DEBUGGING SESSION COMPLETE")
    
    if connection_works:
        print("✅ CONNECTION SUCCESSFUL - Issue may be Railway-specific")
    else:
        print("❌ CONNECTION FAILED - Issue reproduced locally")

if __name__ == "__main__":
    asyncio.run(main()) 