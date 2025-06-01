#!/usr/bin/env python3
"""Test script to debug why searches return 0 results"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.api.lexml_service_official import LexMLOfficialSearchService

async def test_search():
    """Test the search functionality"""
    service = LexMLOfficialSearchService()
    
    # Test initialization
    print("1. Testing initialization...")
    await service.initialize()
    print(f"   - Initialized: {service.initialized}")
    print(f"   - Vocabulary available: {service.vocabulary_manager is not None}")
    
    # Test direct Tier 3 search
    print("\n2. Testing Tier 3 (local data) directly...")
    try:
        result = await service._search_tier3_local_data("transporte", {})
        print(f"   - Documents found: {result.total_count}")
        print(f"   - Search tier: {result.metadata.get('search_tier')}")
        if result.propositions:
            print(f"   - First document: {result.propositions[0].title[:100]}...")
    except Exception as e:
        print(f"   - ERROR: {e}")
        import traceback
        traceback.print_exc()
    
    # Test full search
    print("\n3. Testing full search flow...")
    try:
        result = await service.search("transporte", {})
        print(f"   - Documents found: {result.total_count}")
        print(f"   - Search tier: {result.metadata.get('search_tier')}")
        print(f"   - Performance metrics: {service.get_performance_metrics()}")
    except Exception as e:
        print(f"   - ERROR: {e}")
        import traceback
        traceback.print_exc()
    
    await service.close()

if __name__ == "__main__":
    asyncio.run(test_search())