"""
Simple Search Test Endpoint
===========================

Direct test of CSV data loading and search functionality.
Bypasses complex three-tier architecture for debugging.
"""

from fastapi import APIRouter
from datetime import datetime
import csv
import sys
from pathlib import Path
from typing import List, Dict, Any

router = APIRouter()

@router.get("/simple-search-test/{query}")
async def simple_search_test(query: str):
    """Direct test of CSV search functionality"""
    
    try:
        # Find CSV file
        csv_paths = [
            Path('/app/public/lexml_transport_results_20250606_123100.csv'),  # Railway path
            Path(__file__).parent.parent.parent / 'public' / 'lexml_transport_results_20250606_123100.csv',
            Path(__file__).parent.parent.parent / 'dist' / 'lexml_transport_results_20250606_123100.csv',
        ]
        
        csv_file = None
        for path in csv_paths:
            if path.exists():
                csv_file = path
                break
        
        if not csv_file:
            return {
                "status": "ERROR",
                "error": "CSV file not found",
                "attempted_paths": [str(p) for p in csv_paths]
            }
        
        # Load CSV data
        documents = []
        with open(csv_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                documents.append({
                    'id': row['urn'],
                    'title': row['title'],
                    'url': row['url'],
                    'search_term': row['search_term']
                })
        
        # Search documents
        query_lower = query.lower()
        matches = []
        for doc in documents:
            if (query_lower in doc['title'].lower() or 
                query_lower in doc['search_term'].lower()):
                matches.append(doc)
        
        return {
            "status": "SUCCESS",
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "csv_file_used": str(csv_file),
            "total_documents_in_csv": len(documents),
            "matching_documents": len(matches),
            "sample_matches": matches[:5],  # First 5 matches
            "search_working": len(matches) > 0
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "ERROR",
            "query": query,
            "error": str(e),
            "traceback": traceback.format_exc()
        }

@router.get("/test-python-data-loading")
async def test_python_data_loading():
    """Test Python data loading functionality"""
    
    try:
        # Try to import the Python data
        sys.path.append('/app/src/data')
        sys.path.append(str(Path(__file__).parent.parent.parent / 'src' / 'data'))
        
        from real_legislative_data import realLegislativeData
        
        return {
            "status": "SUCCESS",
            "timestamp": datetime.now().isoformat(),
            "python_data_loaded": True,
            "document_count": len(realLegislativeData),
            "sample_document": realLegislativeData[0] if realLegislativeData else None,
            "data_structure_keys": list(realLegislativeData[0].keys()) if realLegislativeData else []
        }
        
    except Exception as e:
        import traceback
        return {
            "status": "ERROR",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "python_paths": sys.path[-5:]  # Last 5 paths added
        }