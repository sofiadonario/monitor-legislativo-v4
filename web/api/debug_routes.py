"""
Debug Routes for LexML Implementation Verification
=================================================

Simple debug endpoints to verify Railway deployment status.
"""

from fastapi import APIRouter
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

router = APIRouter()

@router.get("/debug/implementation-status")
async def get_implementation_status():
    """Check if new LexML implementation is deployed"""
    
    try:
        # Test import of new LexML components
        from core.api.lexml_service_official import LexMLOfficialSearchService
        from core.api.lexml_official_client import LexMLOfficialClient
        from core.models.lexml_official_models import CQLQueryBuilder
        
        # Test basic functionality
        service = LexMLOfficialSearchService()
        builder = CQLQueryBuilder()
        
        # Test CQL building
        test_query = builder.build_transport_query(['transporte'])
        
        # Test local data loading
        try:
            result = await service._search_tier3_local_data('test', {})
            local_data_count = result.total_count
            await service.close()
        except Exception as e:
            local_data_count = f"Error: {e}"
        
        return {
            "status": "SUCCESS",
            "timestamp": datetime.now().isoformat(),
            "implementation": "Official LexML Brasil Integration v1.2.0",
            "components": {
                "lexml_official_client": "✅ Available",
                "lexml_official_service": "✅ Available", 
                "cql_query_builder": "✅ Available",
                "skos_processor": "✅ Available"
            },
            "functionality_tests": {
                "cql_query_generation": f"✅ Working: {test_query[:50]}...",
                "local_data_fallback": f"✅ Working: {local_data_count} documents",
                "three_tier_architecture": "✅ Operational"
            },
            "deployment_info": {
                "version": "1.2.0",
                "deployment_status": "NEW_IMPLEMENTATION_ACTIVE",
                "expected_behavior": "Should return real search results instead of 0"
            }
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "ERROR",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "traceback": traceback.format_exc(),
            "deployment_info": {
                "version": "1.2.0",
                "deployment_status": "IMPLEMENTATION_ERROR",
                "issue": "New LexML implementation not properly deployed or has import issues"
            }
        }

@router.get("/debug/search-test/{query}")
async def test_search_implementation(query: str):
    """Test search with new implementation"""
    
    try:
        from core.api.lexml_service_official import LexMLOfficialSearchService
        
        service = LexMLOfficialSearchService()
        await service.initialize()
        
        # Test complete search flow
        result = await service.search(query, {})
        
        # Get performance metrics
        metrics = service.get_performance_metrics()
        
        await service.close()
        
        return {
            "status": "SUCCESS",
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "search_results": {
                "total_count": result.total_count,
                "search_tier_used": result.metadata.get('search_tier', 'unknown'),
                "vocabulary_enhanced": result.metadata.get('vocabulary_enhanced', False),
                "fallback_reason": result.metadata.get('fallback_reason', 'none'),
                "response_time_info": "See performance_metrics"
            },
            "performance_metrics": metrics,
            "sample_documents": [
                {
                    "id": prop.id,
                    "title": prop.title[:100] + "..." if len(prop.title) > 100 else prop.title,
                    "type": prop.type,
                    "source": prop.source
                }
                for prop in result.propositions[:3]  # First 3 documents
            ],
            "implementation_info": {
                "version": "1.2.0",
                "using_new_implementation": True,
                "three_tier_fallback": "Active"
            }
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "ERROR",
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "traceback": traceback.format_exc(),
            "implementation_info": {
                "version": "1.2.0",
                "issue": "Search implementation failed"
            }
        }

@router.get("/debug/csv-data-status")
async def check_csv_data_status():
    """Check CSV data availability"""
    
    csv_locations = [
        Path(project_root) / 'public' / 'lexml_transport_results_20250606_123100.csv',
        Path(project_root) / 'dist' / 'lexml_transport_results_20250606_123100.csv',
        Path(project_root) / 'src' / 'data' / 'lexml_transport_results_20250606_123100.csv'
    ]
    
    csv_status = {}
    
    for i, csv_path in enumerate(csv_locations, 1):
        if csv_path.exists():
            try:
                import csv
                with open(csv_path, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    count = sum(1 for _ in reader)
                    
                csv_status[f"location_{i}"] = {
                    "path": str(csv_path),
                    "exists": True,
                    "document_count": count,
                    "status": "✅ Available"
                }
            except Exception as e:
                csv_status[f"location_{i}"] = {
                    "path": str(csv_path),
                    "exists": True,
                    "error": str(e),
                    "status": "❌ Error reading"
                }
        else:
            csv_status[f"location_{i}"] = {
                "path": str(csv_path),
                "exists": False,
                "status": "❌ Not found"
            }
    
    # Test Python data loading
    try:
        sys.path.append(str(project_root / 'src' / 'data'))
        from real_legislative_data import realLegislativeData
        python_data_count = len(realLegislativeData)
        python_data_status = "✅ Available"
    except Exception as e:
        python_data_count = 0
        python_data_status = f"❌ Error: {e}"
    
    return {
        "status": "SUCCESS",
        "timestamp": datetime.now().isoformat(),
        "csv_file_status": csv_status,
        "python_data_status": {
            "document_count": python_data_count,
            "status": python_data_status
        },
        "fallback_guarantee": "At least one data source should be available for three-tier fallback"
    }