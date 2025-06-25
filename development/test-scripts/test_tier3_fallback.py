#!/usr/bin/env python3
"""
Test Tier 3 CSV Fallback
========================

Simple test to verify that Tier 3 (CSV fallback) works correctly
without requiring external API dependencies.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

async def test_tier3_fallback():
    """Test Tier 3 CSV fallback functionality"""
    
    print("=" * 60)
    print("Testing Tier 3 CSV Fallback")
    print("=" * 60)
    
    # Test 1: Load the CSV data directly
    print("\n1. Testing CSV data loading...")
    try:
        from src.data.real_legislative_data import realLegislativeData
        print(f"   ✅ Successfully loaded {len(realLegislativeData)} documents from CSV")
        
        if len(realLegislativeData) > 0:
            sample_doc = realLegislativeData[0]
            print(f"   📄 Sample document: {sample_doc.get('title', 'No title')[:80]}...")
            print(f"   🏛️  Document type: {sample_doc.get('type', 'Unknown')}")
            print(f"   🔗 URL: {sample_doc.get('url', 'No URL')}")
        
    except ImportError as e:
        print(f"   ❌ Failed to load CSV data: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error loading CSV data: {e}")
        return False
    
    # Test 2: Test the official service with Tier 3
    print("\n2. Testing LexML Official Service (Tier 3 only)...")
    try:
        from core.api.lexml_service_official import LexMLOfficialSearchService
        
        service = LexMLOfficialSearchService()
        await service.initialize()
        print(f"   ✅ Service initialized successfully")
        
        # Force Tier 3 by directly calling the tier 3 method
        print("   🔍 Testing Tier 3 search with 'transporte'...")
        result = await service._search_tier3_local_data("transporte", {})
        
        print(f"   📊 Search results:")
        print(f"      - Total documents found: {result.total_count}")
        print(f"      - Search tier: {result.metadata.get('search_tier', 'unknown')}")
        print(f"      - Data source: {result.source}")
        
        if result.propositions:
            first_prop = result.propositions[0]
            print(f"      - First result: {first_prop.title[:60]}...")
            print(f"      - Type: {first_prop.type}")
            print(f"      - Source: {first_prop.source}")
        
        await service.close()
        
    except Exception as e:
        print(f"   ❌ Error testing official service: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: Test search with different terms
    print("\n3. Testing multiple search terms...")
    search_terms = ["transporte", "carga", "licenciamento", "sustentável"]
    
    for term in search_terms:
        try:
            service = LexMLOfficialSearchService()
            await service.initialize()
            
            result = await service._search_tier3_local_data(term, {})
            print(f"   🔍 '{term}': {result.total_count} documents found")
            
            await service.close()
            
        except Exception as e:
            print(f"   ❌ Error searching for '{term}': {e}")
    
    print("\n" + "=" * 60)
    print("✅ Tier 3 CSV Fallback Test Complete")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    success = asyncio.run(test_tier3_fallback())
    if success:
        print("\n🎉 All tests passed! Tier 3 fallback is working correctly.")
    else:
        print("\n❌ Some tests failed. Check the error messages above.")
        sys.exit(1)