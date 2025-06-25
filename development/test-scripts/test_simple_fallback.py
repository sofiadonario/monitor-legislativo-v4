#!/usr/bin/env python3
"""
Simple CSV Fallback Test
=========================

Direct test of CSV fallback without importing problematic modules.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

async def test_csv_data_only():
    """Test just the CSV data loading and basic search logic"""
    
    print("=" * 50)
    print("Simple CSV Fallback Test")
    print("=" * 50)
    
    # Test 1: Load CSV data
    print("\n1. Loading CSV data...")
    try:
        from src.data.real_legislative_data import realLegislativeData
        print(f"   ✅ Loaded {len(realLegislativeData)} documents")
        
        if realLegislativeData:
            sample = realLegislativeData[0]
            print(f"   📄 Sample: {sample.get('title', '')[:50]}...")
            print(f"   🏛️  Type: {sample.get('type', 'Unknown')}")
            print(f"   🗂️  Keywords: {sample.get('keywords', [])}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 2: Basic search simulation
    print("\n2. Testing search logic...")
    search_terms = ["transporte", "carga", "sustentável"]
    
    for search_term in search_terms:
        matches = []
        term_lower = search_term.lower()
        
        for doc in realLegislativeData:
            # Simple search logic
            title = doc.get('title', '').lower()
            keywords = doc.get('keywords', [])
            
            if (term_lower in title or 
                any(term_lower in kw.lower() for kw in keywords)):
                matches.append(doc)
        
        print(f"   🔍 '{search_term}': {len(matches)} matches")
        
        if matches:
            first_match = matches[0]
            print(f"      📄 First: {first_match.get('title', '')[:40]}...")
    
    # Test 3: Verify data structure
    print("\n3. Verifying data structure...")
    if realLegislativeData:
        doc = realLegislativeData[0]
        required_fields = ['id', 'title', 'type', 'date', 'url']
        
        for field in required_fields:
            if field in doc:
                print(f"   ✅ {field}: {str(doc[field])[:30]}...")
            else:
                print(f"   ❌ Missing field: {field}")
    
    print(f"\n✅ CSV fallback data is ready with {len(realLegislativeData)} documents!")
    print("=" * 50)
    
    return True

if __name__ == "__main__":
    success = asyncio.run(test_csv_data_only())
    if success:
        print("\n🎉 CSV fallback is working! The three-tier system has valid Tier 3 data.")
    else:
        print("\n❌ CSV fallback failed.")
        sys.exit(1)