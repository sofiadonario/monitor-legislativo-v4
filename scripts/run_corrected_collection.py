#!/usr/bin/env python3
"""
Run LexML collection with corrected strategy to fix identified problems
"""

import sys
import os
import time
import pandas as pd
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_strategy_corrected import LexMLStrategyCorrected

def load_priority_search_terms():
    """Load the same priority terms we tested before for comparison"""
    priority_terms = [
        "veículos pesados", "gás natural veicular", "eficiência energética", 
        "caminhão", "biodiesel", "diesel", "biometano", 
        "transporte rodoviário de carga", "decreto", "medida provisória"
    ]
    return priority_terms

def run_corrected_priority_collection():
    """
    Run corrected collection on priority terms to validate fixes
    """
    print("=== Running Corrected LexML Collection ===")
    print("🎯 Target: Fix date extraction and URN classification")
    print("📊 Testing priority terms for comparison")
    print()
    
    # Initialize corrected strategy
    strategy = LexMLStrategyCorrected()
    
    # Load priority terms
    priority_terms = load_priority_search_terms()
    print(f"Processing {len(priority_terms)} priority terms...")
    
    # Collection parameters
    max_results_per_term = 20  # Smaller sample for testing
    all_results = []
    
    # Progress tracking
    start_time = datetime.now()
    processed_count = 0
    errors = []
    
    for i, term in enumerate(priority_terms):
        term_num = i + 1
        
        try:
            print(f"  [{term_num:2d}/{len(priority_terms)}] '{term[:40]}{'...' if len(term) > 40 else ''}' ", end='')
            
            # Search for documents using corrected strategy
            results = strategy.search_documents(
                search_term=term,
                max_results=max_results_per_term
            )
            
            if results:
                all_results.extend(results)
                print(f"→ {len(results):2d} docs")
            else:
                print(f"→ 0 docs")
            
            processed_count += 1
            
            # Rate limiting
            time.sleep(2.0)
            
        except Exception as e:
            error_msg = f"Error processing '{term}': {e}"
            errors.append(error_msg)
            print(f"→ ERROR: {e}")
            continue
    
    total_time = datetime.now() - start_time
    print(f"\n=== Corrected Collection Complete ===")
    print(f"⏱️  Total time: {total_time.total_seconds()/60:.1f} minutes")
    print(f"✓ Terms processed: {processed_count}/{len(priority_terms)}")
    print(f"📄 Total documents: {len(all_results)}")
    print(f"⚠️  Errors encountered: {len(errors)}")
    
    if errors:
        print("\nErrors encountered:")
        for error in errors:
            print(f"  - {error}")
    
    if all_results:
        # Convert to DataFrame
        df = pd.DataFrame(all_results)
        
        # Remove duplicates based on URN
        if 'urn' in df.columns:
            initial_count = len(df)
            df = df.drop_duplicates(subset=['urn'], keep='first')
            final_count = len(df)
            duplicates_removed = initial_count - final_count
            print(f"🔄 Removed {duplicates_removed} duplicates")
            print(f"📊 Final unique documents: {final_count}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f'lexml_corrected_priority_{timestamp}.csv'
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"💾 Results saved to: {output_file}")
        
        # Generate validation summary
        print(f"\n📈 Correction Validation")
        
        # Check date extraction improvement
        if 'enacting_date' in df.columns:
            dates_extracted = df[df['enacting_date'].astype(str).str.len() > 0]
            date_rate = len(dates_extracted) / len(df) * 100
            print(f"📅 Date extraction rate: {date_rate:.1f}% ({len(dates_extracted)}/{len(df)})")
            
            if date_rate >= 90:
                print("  ✅ MAJOR IMPROVEMENT: Date extraction now working!")
            else:
                print("  ⚠️  Date extraction still needs work")
        
        # Check URN classification
        if 'urn_type' in df.columns:
            print(f"\n📋 Document type distribution:")
            type_counts = df['urn_type'].value_counts()
            for doc_type, count in type_counts.items():
                percentage = (count / len(df)) * 100
                print(f"  {doc_type}: {count} ({percentage:.1f}%)")
            
            # Check for proper legislation classification
            legislation_count = type_counts.get('legislation', 0)
            doctrine_count = type_counts.get('doctrine', 0)
            
            if legislation_count > 0:
                print("  ✅ MAJOR IMPROVEMENT: Legislation now properly classified!")
            
            if doctrine_count < legislation_count:
                print("  ✅ CLASSIFICATION FIXED: More legislation than doctrine (correct)")
            elif doctrine_count > legislation_count * 3:
                print("  ⚠️  Still too much content classified as doctrine")
        
        # Check date range
        if 'enacting_date' in df.columns:
            date_range = strategy.get_date_range_from_results(df)
            if date_range['total_with_dates'] > 0:
                print(f"\n📊 Document date range: {date_range['year_range']}")
                print(f"  Documents with dates: {date_range['total_with_dates']}")
                print("  ✅ IMPROVEMENT: Using document dates instead of search dates")
        
        # Compare with original results
        print(f"\n🔍 Comparison with Original Collection:")
        original_stats = {
            'date_extraction_rate': 10.6,  # From original analysis
            'doctrine_percentage': 83.6,
            'legislation_percentage': 5.9
        }
        
        current_legislation_pct = (type_counts.get('legislation', 0) / len(df) * 100) if len(df) > 0 else 0
        current_doctrine_pct = (type_counts.get('doctrine', 0) / len(df) * 100) if len(df) > 0 else 0
        
        print(f"  Date extraction: {original_stats['date_extraction_rate']:.1f}% → {date_rate:.1f}% (+{date_rate - original_stats['date_extraction_rate']:.1f}%)")
        print(f"  Legislation classification: {original_stats['legislation_percentage']:.1f}% → {current_legislation_pct:.1f}% (+{current_legislation_pct - original_stats['legislation_percentage']:.1f}%)")
        print(f"  Doctrine classification: {original_stats['doctrine_percentage']:.1f}% → {current_doctrine_pct:.1f}% ({current_doctrine_pct - original_stats['doctrine_percentage']:+.1f}%)")
        
        return output_file, len(df)
    else:
        print("❌ No results collected")
        return None, 0

def compare_strategies():
    """Compare original vs corrected strategy results"""
    print("\n🔄 Strategy Comparison Analysis")
    
    # Load original results
    original_files = [f for f in os.listdir('.') if f.startswith('lexml_priority_results_')]
    corrected_files = [f for f in os.listdir('.') if f.startswith('lexml_corrected_priority_')]
    
    if original_files and corrected_files:
        original_file = sorted(original_files)[-1]
        corrected_file = sorted(corrected_files)[-1]
        
        print(f"Original: {original_file}")
        print(f"Corrected: {corrected_file}")
        
        original_df = pd.read_csv(original_file)
        corrected_df = pd.read_csv(corrected_file)
        
        print(f"\n📊 Comparison Results:")
        print(f"Document count: {len(original_df)} → {len(corrected_df)} ({len(corrected_df) - len(original_df):+d})")
        
        # Date extraction comparison
        orig_dates = len(original_df[original_df['enacting_date'].astype(str).str.len() > 0])
        corr_dates = len(corrected_df[corrected_df['enacting_date'].astype(str).str.len() > 0])
        print(f"Documents with dates: {orig_dates} → {corr_dates} ({corr_dates - orig_dates:+d})")
        
        # Type classification comparison
        print(f"\nType Distribution:")
        orig_types = original_df['urn_type'].value_counts()
        corr_types = corrected_df['urn_type'].value_counts()
        
        for doc_type in set(list(orig_types.index) + list(corr_types.index)):
            orig_count = orig_types.get(doc_type, 0)
            corr_count = corr_types.get(doc_type, 0)
            print(f"  {doc_type}: {orig_count} → {corr_count} ({corr_count - orig_count:+d})")
        
    else:
        print("Missing comparison files")

def main():
    """Main execution function"""
    print("🚀 LexML Corrected Collection Starting...")
    print("This will test the fixes and validate improvements\n")
    
    try:
        output_file, document_count = run_corrected_priority_collection()
        
        if output_file:
            print(f"\n🎉 Corrected collection successful!")
            print(f"📁 File: {output_file}")  
            print(f"📊 Documents: {document_count}")
            
            # Run comparison if original results exist
            compare_strategies()
            
        else:
            print(f"\n❌ Corrected collection failed")
            
    except KeyboardInterrupt:
        print(f"\n⚠️ Collection interrupted by user")
    except Exception as e:
        print(f"\n❌ Collection failed with error: {e}")

if __name__ == "__main__":
    main()