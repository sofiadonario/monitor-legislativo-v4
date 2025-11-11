#!/usr/bin/env python3
"""
Run priority LexML data collection with top terms only
"""

import sys
import os
import time
import pandas as pd
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_enhanced_strategy import LexMLFinalStrategy

def run_priority_collection():
    """
    Run data collection for priority terms only
    """
    print("=== Starting Priority LexML Collection ===")
    
    # Initialize strategy
    strategy = LexMLFinalStrategy()
    
    # Priority terms for testing
    priority_terms = [
        "transporte de carga",
        "transporte rodoviário de carga", 
        "veículos pesados",
        "caminhão",
        "gás natural veicular",
        "biometano",
        "diesel",
        "biodiesel",
        "eficiência energética",
        "emissões"
    ]
    
    print(f"Processing {len(priority_terms)} priority terms")
    
    # Collection parameters
    max_results_per_term = 30  # Moderate number for testing
    all_results = []
    
    # Progress tracking
    start_time = datetime.now()
    
    for i, term in enumerate(priority_terms):
        try:
            print(f"\n[{i+1}/{len(priority_terms)}] Processing: '{term}'")
            
            # Search for documents
            results = strategy.search_documents(
                search_term=term,
                max_results=max_results_per_term
            )
            
            if results:
                all_results.extend(results)
                print(f"  ✓ Found {len(results)} documents")
            else:
                print(f"  ⚠ No results found")
            
            # Rate limiting
            time.sleep(1.5)
            
        except Exception as e:
            print(f"  ❌ Error processing '{term}': {e}")
            continue
    
    elapsed = datetime.now() - start_time
    print(f"\n=== Priority Collection Complete ===")
    print(f"Time elapsed: {elapsed.total_seconds():.1f} seconds")
    print(f"Total documents collected: {len(all_results)}")
    
    if all_results:
        # Convert to DataFrame
        df = pd.DataFrame(all_results)
        
        # Remove duplicates based on URN
        if 'urn' in df.columns:
            initial_count = len(df)
            df = df.drop_duplicates(subset=['urn'], keep='first')
            final_count = len(df)
            print(f"Removed {initial_count - final_count} duplicates")
            print(f"Final unique documents: {final_count}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f'lexml_priority_results_{timestamp}.csv'
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"✓ Results saved to: {output_file}")
        
        # Generate summary statistics
        print("\n--- Priority Collection Summary ---")
        
        if 'urn_type' in df.columns:
            print("Document types:")
            type_counts = df['urn_type'].value_counts()
            for doc_type, count in type_counts.items():
                print(f"  {doc_type}: {count}")
        
        if 'search_term' in df.columns:
            print(f"\nResults by term:")
            term_counts = df['search_term'].value_counts()
            for term, count in term_counts.items():
                print(f"  {term}: {count}")
        
        return output_file, len(df)
    else:
        print("❌ No results collected")
        return None, 0

if __name__ == "__main__":
    output_file, document_count = run_priority_collection()
    
    if output_file:
        print(f"\n🎉 Priority collection successful!")
        print(f"📄 File: {output_file}")  
        print(f"📊 Documents: {document_count}")
    else:
        print(f"\n❌ Priority collection failed")