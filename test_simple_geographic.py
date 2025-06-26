#!/usr/bin/env python3
"""
Simple test for geographic functionality without external dependencies
"""

import asyncio
import sys
from pathlib import Path

# Add the core directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "core"))

async def test_simple_geographic():
    """Simple geographic test without API dependencies"""
    print("🇧🇷 Testing Simple Geographic Integration")
    print("=" * 50)
    
    # Test geographic service directly
    try:
        from geographic import GeographicService
        print("✅ Geographic service imported")
        
        service = GeographicService()
        await service.initialize()
        print("✅ Geographic service initialized")
        
        # Test municipality search
        municipalities = await service.search_municipalities("São Paulo", limit=3)
        print(f"✅ Found {len(municipalities)} municipalities for São Paulo")
        
        # Test document analysis
        scope = await service.analyze_document_geography(
            "Lei de São Paulo",
            "Esta lei se aplica ao município de São Paulo",
            "municipal"
        )
        print(f"✅ Document analysis: {scope.scope_type} (confidence: {scope.confidence:.2f})")
        
        # Test statistics
        stats = await service.get_statistics()
        print(f"✅ Statistics: {stats['total_municipalities']} municipalities loaded")
        
        print("\n🎉 Simple geographic integration working!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_simple_geographic())
    sys.exit(0 if success else 1)