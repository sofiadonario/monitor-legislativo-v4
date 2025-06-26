#!/usr/bin/env python3
"""
Test script for geographic integration
Verifies that Brazilian municipality data loads and geographic analysis works
"""

import asyncio
import sys
from pathlib import Path

# Add the core directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "core"))

from geographic import BrazilianGeographicDataLoader, GeographicService


async def test_geographic_integration():
    """Test the geographic integration components"""
    print("🇧🇷 Testing Monitor Legislativo v4 Geographic Integration")
    print("=" * 60)
    
    # Test 1: Data Loader
    print("\n1. Testing Brazilian Geographic Data Loader...")
    loader = BrazilianGeographicDataLoader()
    
    try:
        municipalities = await loader.load_municipalities()
        print(f"✅ Loaded {len(municipalities)} municipalities")
        
        # Show sample municipalities
        print("\nSample municipalities:")
        for i, municipality in enumerate(municipalities[:5]):
            print(f"  {i+1}. {municipality.name}, {municipality.state} ({municipality.ibge_code})")
            if municipality.coordinates:
                lat, lon = municipality.coordinates
                print(f"     Coordinates: {lat:.4f}, {lon:.4f}")
        
    except Exception as e:
        print(f"❌ Failed to load municipalities: {e}")
        return False
    
    # Test 2: Geographic Service
    print("\n2. Testing Geographic Service...")
    service = GeographicService(loader)
    
    try:
        await service.initialize()
        print("✅ Geographic service initialized")
        
        # Test municipality search
        sao_paulo = await service.get_municipality_by_name("São Paulo", "SP")
        if sao_paulo:
            print(f"✅ Found São Paulo: {sao_paulo.ibge_code}")
        else:
            print("❌ Could not find São Paulo")
        
        # Test state municipalities
        sp_municipalities = await service.get_municipalities_by_state("SP")
        print(f"✅ Found {len(sp_municipalities)} municipalities in São Paulo state")
        
    except Exception as e:
        print(f"❌ Geographic service failed: {e}")
        return False
    
    # Test 3: Document Geographic Analysis
    print("\n3. Testing Document Geographic Analysis...")
    
    # Sample legislative document about São Paulo
    sample_document = {
        'title': 'Lei Municipal de São Paulo sobre Transporte Público',
        'content': '''Esta lei estabelece diretrizes para o transporte público 
                     no município de São Paulo, Estado de São Paulo, visando 
                     melhorar a mobilidade urbana na região metropolitana.''',
        'source': 'camara'
    }
    
    try:
        geographic_scope = await service.analyze_document_geography(
            sample_document['title'],
            sample_document['content'],
            sample_document['source']
        )
        
        print(f"✅ Document analysis completed")
        print(f"   Scope Type: {geographic_scope.scope_type}")
        print(f"   Confidence: {geographic_scope.confidence:.2f}")
        print(f"   Municipalities: {len(geographic_scope.municipalities)}")
        print(f"   States: {geographic_scope.states}")
        print(f"   Regions: [r.value for r in geographic_scope.regions]")
        
        if geographic_scope.municipalities:
            print("   Detected municipalities:")
            for municipality in geographic_scope.municipalities:
                print(f"     - {municipality.name}, {municipality.state}")
        
    except Exception as e:
        print(f"❌ Document analysis failed: {e}")
        return False
    
    # Test 4: Statistics
    print("\n4. Testing Statistics...")
    try:
        stats = await service.get_statistics()
        print("✅ Statistics generated:")
        print(f"   Total municipalities: {stats['total_municipalities']}")
        print(f"   With coordinates: {stats['municipalities_with_coordinates']}")
        print(f"   São Paulo state: {stats.get('municipalities_sp', 0)}")
        print(f"   Rio de Janeiro state: {stats.get('municipalities_rj', 0)}")
        
    except Exception as e:
        print(f"❌ Statistics failed: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 All geographic integration tests passed!")
    print("✅ Brazilian municipality data loading works")
    print("✅ Geographic service initialization works") 
    print("✅ Document geographic analysis works")
    print("✅ Statistics generation works")
    
    return True


if __name__ == "__main__":
    success = asyncio.run(test_geographic_integration())
    sys.exit(0 if success else 1)