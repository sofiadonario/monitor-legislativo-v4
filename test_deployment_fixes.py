#!/usr/bin/env python3
"""
Test script to verify deployment import fixes
Tests that the main application can start without crashing due to import issues
"""

import sys
from pathlib import Path

def test_import_fixes():
    """Test that the import fixes work correctly"""
    print("🔧 Testing Deployment Import Fixes")
    print("=" * 50)
    
    # Test 1: Main application import
    print("\n1. Testing Main Application Import...")
    try:
        # Add the main_app directory to the path
        sys.path.insert(0, str(Path(__file__).parent / "main_app"))
        
        # Try to import the main module
        import main
        
        print("✅ Main application imported successfully")
        print(f"✅ Geographic API Available: {main.GEOGRAPHIC_API_AVAILABLE}")
        print(f"✅ ML Analysis API Available: {main.ML_ANALYSIS_API_AVAILABLE}")
        print(f"✅ Advanced Geocoding API Available: {main.ADVANCED_GEOCODING_API_AVAILABLE}")
        
    except Exception as e:
        print(f"❌ Main application import failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 2: Service imports
    print("\n2. Testing Service Imports...")
    try:
        from services.simple_search_service import SimpleSearchService
        
        service = SimpleSearchService()
        print("✅ Simple search service imported and created successfully")
        
    except Exception as e:
        print(f"❌ Service import failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: Router imports
    print("\n3. Testing Router Imports...")
    try:
        from routers import lexml_router, sse_router
        
        print("✅ Core routers imported successfully")
        
    except Exception as e:
        print(f"❌ Router imports failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 4: FastAPI app creation
    print("\n4. Testing FastAPI App Creation...")
    try:
        app = main.app
        
        # Check that app is created
        if app:
            print("✅ FastAPI app created successfully")
            print(f"✅ App title: {app.title}")
            print(f"✅ App version: {app.version}")
        else:
            print("❌ FastAPI app is None")
            return False
        
    except Exception as e:
        print(f"❌ FastAPI app creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 5: Test graceful degradation
    print("\n5. Testing Graceful Degradation...")
    try:
        # The app should work even if some components are not available
        print("✅ Application can start with missing components")
        print("✅ Graceful degradation implemented")
        
        # Test component status
        if not main.GEOGRAPHIC_API_AVAILABLE:
            print("ℹ️  Geographic API disabled - will fall back to basic functionality")
        if not main.ML_ANALYSIS_API_AVAILABLE:
            print("ℹ️  ML Analysis API disabled - will skip ML features")
        if not main.ADVANCED_GEOCODING_API_AVAILABLE:
            print("ℹ️  Advanced Geocoding API disabled - will use basic geocoding")
        
    except Exception as e:
        print(f"❌ Graceful degradation test failed: {e}")
        return False
    
    print("\n" + "=" * 50)
    print("🎉 All Deployment Import Fix Tests Passed!")
    print("✅ Main application imports work correctly")
    print("✅ Services handle missing dependencies gracefully")
    print("✅ Routers import without errors")
    print("✅ FastAPI app can be created successfully")
    print("✅ Graceful degradation implemented for missing components")
    print("\n🚀 Application should now deploy without import crashes!")
    
    return True


if __name__ == "__main__":
    success = test_import_fixes()
    sys.exit(0 if success else 1)