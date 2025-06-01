#!/usr/bin/env python3
"""
Monitor Legislativo v4 - Main Launcher
Simple, clean launcher for all application modes
"""

import sys
import os
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def clear_cache():
    """Clear Python cache files"""
    print("🧹 Clearing cache...")
    
    cache_dirs = [
        project_root / "__pycache__",
        project_root / "core" / "__pycache__",
        project_root / "core" / "api" / "__pycache__",
        project_root / "core" / "utils" / "__pycache__",
        project_root / "web" / "__pycache__",
        project_root / "desktop" / "__pycache__",
    ]
    
    cleared = 0
    errors = 0
    
    for cache_dir in cache_dirs:
        if cache_dir.exists():
            try:
                import shutil
                shutil.rmtree(cache_dir)
                cleared += 1
            except PermissionError:
                # Try to delete individual files instead
                try:
                    for file in cache_dir.glob("*.pyc"):
                        try:
                            file.unlink()
                        except:
                            pass
                except:
                    errors += 1
            except Exception as e:
                print(f"⚠️  Could not clear {cache_dir}: {e}")
                errors += 1
    
    # Also try to clear .pyc files in the project
    try:
        for pyc_file in project_root.rglob("*.pyc"):
            try:
                pyc_file.unlink()
                cleared += 1
            except:
                pass
    except:
        pass
    
    if errors > 0:
        print(f"✅ Cache partially cleared ({cleared} items removed, {errors} errors)")
    else:
        print("✅ Cache cleared")

def check_dependencies():
    """Check if required dependencies are installed"""
    required = ["aiohttp", "beautifulsoup4", "lxml", "requests", "pydantic"]
    missing = []
    
    for pkg in required:
        try:
            __import__(pkg.replace('-', '_'))
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print(f"Install with: pip install {' '.join(missing)}")
        return False
    
    print("✅ All dependencies found")
    return True

def launch_desktop():
    """Launch desktop application"""
    print("🖥️  Starting Desktop Application...")
    
    try:
        from desktop.main import main as desktop_main
        desktop_main()
    except ImportError as e:
        if "PySide6" in str(e) or "PyQt5" in str(e):
            print("❌ GUI library not found. Install with:")
            print("   pip install PySide6")
        else:
            print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Desktop launch failed: {e}")

def launch_web():
    """Launch web application"""
    print("🌐 Starting Web Application...")
    
    try:
        from web.main import main as web_main
        web_main()
    except Exception as e:
        print(f"❌ Web launch failed: {e}")

def run_tests():
    """Run API tests"""
    print("🧪 Running API Tests...")
    
    try:
        import asyncio
        from core.api.api_service import APIService
        from core.config.config import APIConfig
        
        async def test_apis():
            config = APIConfig()
            api_service = APIService(config)
            
            # Test a simple search
            results = await api_service.search_all(
                query="energia",
                filters={"start_date": "2024-01-01", "end_date": "2024-12-31"},
                sources=["camara", "senado"]
            )
            
            print(f"✅ Test completed. Found {sum(len(r.propositions) for r in results)} total results")
            
            for result in results:
                print(f"  {result.source}: {result.total_count} results")
        
        asyncio.run(test_apis())
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

def show_status():
    """Show system status"""
    print("📊 System Status")
    print("=" * 50)
    
    # Python version
    print(f"Python: {sys.version}")
    
    # Dependencies
    check_dependencies()
    
    # Project structure
    print(f"Project root: {project_root}")
    print(f"Core modules: {len(list((project_root / 'core').rglob('*.py')))} files")

def main():
    """Main launcher interface"""
    print("🚀 Monitor Legislativo v4 - Launcher")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode in ['desktop', 'gui']:
            clear_cache()
            launch_desktop()
        elif mode in ['web', 'server']:
            clear_cache()
            launch_web()
        elif mode in ['test', 'tests']:
            run_tests()
        elif mode in ['status', 'info']:
            show_status()
        elif mode in ['clean', 'clear']:
            clear_cache()
        else:
            print(f"❌ Unknown mode: {mode}")
            print("Available modes: desktop, web, test, status, clean")
    else:
        # Interactive mode
        print("Choose launch mode:")
        print("1. Desktop Application")
        print("2. Web Application") 
        print("3. Run Tests")
        print("4. Show Status")
        print("5. Clear Cache")
        print("6. Exit")
        
        try:
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == '1':
                clear_cache()
                launch_desktop()
            elif choice == '2':
                clear_cache()
                launch_web()
            elif choice == '3':
                run_tests()
            elif choice == '4':
                show_status()
            elif choice == '5':
                clear_cache()
            elif choice == '6':
                print("👋 Goodbye!")
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")

if __name__ == "__main__":
    main()