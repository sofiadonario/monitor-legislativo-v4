#!/usr/bin/env python3
"""
Test script for geographic API endpoints
Tests the FastAPI integration of geographic services
"""

import asyncio
import sys
import json
from pathlib import Path

# Add the core directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "core"))
sys.path.insert(0, str(Path(__file__).parent / "main_app"))

async def test_geographic_api():
    """Test the geographic API integration"""
    print("🌍 Testing Monitor Legislativo v4 Geographic API")
    print("=" * 60)
    
    # Test 1: Import and initialize API components
    print("\n1. Testing API Component Import...")
    try:
        from api.geographic import get_geographic_service
        print("✅ Geographic API components imported successfully")
        
        # Initialize the service
        service = await get_geographic_service()
        print("✅ Geographic service dependency injection works")
        
    except Exception as e:
        print(f"❌ API component import failed: {e}")
        return False
    
    # Test 2: Test Municipality Search
    print("\n2. Testing Municipality Search...")
    try:
        municipalities = await service.search_municipalities(
            query="São Paulo",
            limit=5
        )
        
        print(f"✅ Found {len(municipalities)} municipalities for 'São Paulo'")
        if municipalities:
            print(f"   First result: {municipalities[0].name}, {municipalities[0].state}")
        
    except Exception as e:
        print(f"❌ Municipality search failed: {e}")
        return False
    
    # Test 3: Test State Municipality Lookup
    print("\n3. Testing State Municipality Lookup...")
    try:
        sp_municipalities = await service.get_municipalities_by_state("SP")
        print(f"✅ Found {len(sp_municipalities)} municipalities in São Paulo state")
        
    except Exception as e:
        print(f"❌ State municipality lookup failed: {e}")
        return False
    
    # Test 4: Test Document Analysis
    print("\n4. Testing Document Geographic Analysis...")
    try:
        sample_document = {
            'title': 'Lei Municipal de São Paulo sobre Transporte',
            'content': 'Esta lei se aplica ao município de São Paulo e região metropolitana.',
            'source': 'camara'
        }
        
        geographic_scope = await service.analyze_document_geography(
            sample_document['title'],
            sample_document['content'],
            sample_document['source']
        )
        
        print(f"✅ Document analysis completed:")
        print(f"   Scope Type: {geographic_scope.scope_type}")
        print(f"   Confidence: {geographic_scope.confidence:.2f}")
        print(f"   Municipalities: {len(geographic_scope.municipalities)}")
        print(f"   States: {len(geographic_scope.states)}")
        
    except Exception as e:
        print(f"❌ Document analysis failed: {e}")
        return False
    
    # Test 5: Test API Response Models
    print("\n5. Testing API Response Models...")
    try:
        from api.geographic import MunicipalityResponse, GeographicScopeResponse
        
        # Test municipality response model
        if municipalities:
            municipality = municipalities[0]
            response_data = MunicipalityResponse(
                name=municipality.name,
                state=municipality.state,
                state_name=municipality.state_name,
                region=municipality.region.value,
                ibge_code=municipality.ibge_code,
                latitude=municipality.latitude,
                longitude=municipality.longitude,
                population=municipality.population,
                area_km2=municipality.area_km2
            )
            print(f"✅ Municipality response model works: {response_data.name}")
        
        # Test geographic scope response model
        scope_response = GeographicScopeResponse(
            municipalities=[],
            states=geographic_scope.states,
            regions=[r.value for r in geographic_scope.regions],
            scope_type=geographic_scope.scope_type,
            confidence=geographic_scope.confidence
        )
        print(f"✅ Geographic scope response model works: {scope_response.scope_type}")
        
    except Exception as e:
        print(f"❌ API response models failed: {e}")
        return False
    
    # Test 6: Test Statistics
    print("\n6. Testing Geographic Statistics...")
    try:
        stats = await service.get_statistics()
        print(f"✅ Statistics generated:")
        print(f"   Total municipalities: {stats.get('total_municipalities', 0)}")
        print(f"   Service initialized: {stats.get('service_initialized', False)}")
        print(f"   Cache size: {stats.get('cache_size', 0)}")
        
    except Exception as e:
        print(f"❌ Statistics failed: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 All geographic API tests passed!")
    print("✅ API component import and initialization works")
    print("✅ Municipality search functionality works")
    print("✅ State municipality lookup works")
    print("✅ Document geographic analysis works")
    print("✅ API response models work correctly")
    print("✅ Statistics generation works")
    print("\n🚀 Geographic API is ready for FastAPI integration!")
    
    return True


if __name__ == "__main__":
    success = asyncio.run(test_geographic_api())
    sys.exit(0 if success else 1)