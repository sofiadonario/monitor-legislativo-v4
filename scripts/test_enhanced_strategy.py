#!/usr/bin/env python3
"""
Test script for the enhanced LexML strategy
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_enhanced_strategy import LexMLFinalStrategy, load_search_terms
import pandas as pd

def test_basic_functionality():
    """Test basic functionality with a single search term"""
    print("=== Testing Enhanced LexML Strategy ===")
    
    # Initialize strategy
    strategy = LexMLFinalStrategy()
    print("✓ Strategy initialized successfully")
    
    # Test with a single term
    print("\n--- Testing single search term ---")
    test_term = "transporte de carga"
    results = strategy.search_documents(test_term, max_results=5)
    
    print(f"Search term: '{test_term}'")
    print(f"Results found: {len(results)}")
    
    if results:
        df = pd.DataFrame(results)
        print(f"Columns: {list(df.columns)}")
        print("\nFirst result:")
        for key, value in results[0].items():
            if value:  # Only show non-empty values
                print(f"  {key}: {value}")
        
        # Save test results
        test_output = 'test_enhanced_results.csv'
        df.to_csv(test_output, index=False, encoding='utf-8')
        print(f"\n✓ Test results saved to: {test_output}")
        return True
    else:
        print("❌ No results found")
        return False

def test_search_terms_loading():
    """Test loading search terms from file"""
    print("\n--- Testing search terms loading ---")
    
    terms_file = 'termos_busca.txt'
    terms = load_search_terms(terms_file)
    
    print(f"Terms loaded: {len(terms)}")
    if terms:
        print("First 10 terms:")
        for i, term in enumerate(terms[:10]):
            print(f"  {i+1}. {term}")
        return True
    else:
        print("❌ No terms loaded")
        return False

if __name__ == "__main__":
    success1 = test_basic_functionality()
    success2 = test_search_terms_loading()
    
    if success1 and success2:
        print("\n✓ All tests passed! Enhanced strategy is ready.")
    else:
        print("\n❌ Some tests failed. Check the output above.")