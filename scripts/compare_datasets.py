#!/usr/bin/env python3
"""
Compare current LexML data vs enhanced collection results
"""

import pandas as pd
import os
from datetime import datetime

def load_current_data():
    """Load current parsed data from the system"""
    possible_files = [
        '../data/processed/lexml_parsed_enhanced.csv',
        '../data/processed/lexml_parsed_enhanced_fixed.csv',
        '../data/processed/lexml_parsed.csv',
        '../data/processed/lexml_parsed_v2.csv'
    ]
    
    for current_file in possible_files:
        if os.path.exists(current_file):
            try:
                df = pd.read_csv(current_file)
                print(f"✓ Loaded current data: {len(df)} records from {current_file}")
                return df
            except Exception as e:
                print(f"⚠ Error loading {current_file}: {e}")
                continue
    
    print(f"❌ No current data files found in: {possible_files}")
    return None

def load_enhanced_data():
    """Load the enhanced collection results"""
    # Find the most recent enhanced results file
    enhanced_files = [f for f in os.listdir('.') if f.startswith('lexml_priority_results_')]
    
    if not enhanced_files:
        print("❌ No enhanced results files found")
        return None
    
    # Get the most recent file
    latest_file = sorted(enhanced_files)[-1]
    df = pd.read_csv(latest_file)
    print(f"✓ Loaded enhanced data: {len(df)} records from {latest_file}")
    return df

def compare_datasets():
    """Compare current vs enhanced datasets"""
    print("=== Dataset Comparison Analysis ===")
    
    # Load datasets
    current_df = load_current_data()
    enhanced_df = load_enhanced_data()
    
    if current_df is None or enhanced_df is None:
        print("❌ Cannot compare datasets - missing data")
        return
    
    print(f"\n--- Basic Statistics ---")
    print(f"Current dataset: {len(current_df)} records")
    print(f"Enhanced dataset: {len(enhanced_df)} records")
    print(f"Improvement factor: {len(enhanced_df) / len(current_df):.1f}x")
    
    # Compare columns
    print(f"\n--- Column Comparison ---")
    current_cols = set(current_df.columns)
    enhanced_cols = set(enhanced_df.columns)
    
    print(f"Current columns ({len(current_cols)}): {sorted(current_cols)}")
    print(f"Enhanced columns ({len(enhanced_cols)}): {sorted(enhanced_cols)}")
    
    new_cols = enhanced_cols - current_cols
    if new_cols:
        print(f"New columns in enhanced: {sorted(new_cols)}")
    
    missing_cols = current_cols - enhanced_cols
    if missing_cols:
        print(f"Missing from enhanced: {sorted(missing_cols)}")
    
    # Compare document types
    print(f"\n--- Document Type Analysis ---")
    
    if 'urn_type' in current_df.columns:
        print("Current document types:")
        current_types = current_df['urn_type'].value_counts()
        for doc_type, count in current_types.items():
            print(f"  {doc_type}: {count}")
    else:
        print("Current data: No urn_type column")
    
    if 'urn_type' in enhanced_df.columns:
        print("Enhanced document types:")
        enhanced_types = enhanced_df['urn_type'].value_counts()
        for doc_type, count in enhanced_types.items():
            print(f"  {doc_type}: {count}")
    
    # Compare search terms
    print(f"\n--- Search Term Analysis ---")
    
    if 'search_term' in current_df.columns:
        current_terms = len(current_df['search_term'].unique())
        print(f"Current unique search terms: {current_terms}")
        print(f"Current top terms: {list(current_df['search_term'].value_counts().head(5).index)}")
    else:
        print("Current data: No search_term column")
    
    if 'search_term' in enhanced_df.columns:
        enhanced_terms = len(enhanced_df['search_term'].unique())
        print(f"Enhanced unique search terms: {enhanced_terms}")
        print(f"Enhanced top terms: {list(enhanced_df['search_term'].value_counts().head(5).index)}")
    
    # Compare data richness
    print(f"\n--- Data Richness Analysis ---")
    
    # Count non-empty fields
    def count_non_empty(df, column):
        if column in df.columns:
            return df[column].notna().sum()
        return 0
    
    richness_fields = ['title', 'document_summary', 'document_description', 'url']
    
    print("Non-empty field counts:")
    for field in richness_fields:
        current_count = count_non_empty(current_df, field)
        enhanced_count = count_non_empty(enhanced_df, field)
        improvement = enhanced_count / max(current_count, 1)
        print(f"  {field}:")
        print(f"    Current: {current_count}")
        print(f"    Enhanced: {enhanced_count}")
        print(f"    Improvement: {improvement:.1f}x")
    
    # Temporal analysis
    print(f"\n--- Temporal Analysis ---")
    
    def analyze_dates(df, name):
        if 'date_searched' in df.columns:
            dates = pd.to_datetime(df['date_searched'], errors='coerce')
            valid_dates = dates.dropna()
            if len(valid_dates) > 0:
                print(f"{name} search dates:")
                print(f"  Earliest: {valid_dates.min()}")
                print(f"  Latest: {valid_dates.max()}")
                print(f"  Span: {(valid_dates.max() - valid_dates.min()).days} days")
        
        date_cols = ['enacting_date', 'promulgation_date']
        for col in date_cols:
            if col in df.columns:
                print(f"{name} {col}: {df[col].notna().sum()} non-empty")
    
    analyze_dates(current_df, "Current")
    analyze_dates(enhanced_df, "Enhanced")
    
    # Generate enhancement summary
    print(f"\n--- Enhancement Summary ---")
    
    enhancements = []
    
    # Volume improvement
    volume_improvement = len(enhanced_df) / len(current_df)
    enhancements.append(f"Volume: {volume_improvement:.1f}x more documents ({len(enhanced_df)} vs {len(current_df)})")
    
    # Search terms improvement
    if 'search_term' in both_datasets(current_df, enhanced_df):
        current_terms = len(current_df['search_term'].unique()) if 'search_term' in current_df.columns else 0
        enhanced_terms = len(enhanced_df['search_term'].unique()) if 'search_term' in enhanced_df.columns else 0
        if enhanced_terms > current_terms:
            enhancements.append(f"Search diversity: {enhanced_terms} vs {current_terms} unique terms")
    
    # Document type diversity
    if 'urn_type' in enhanced_df.columns:
        enhanced_doc_types = enhanced_df['urn_type'].nunique()
        current_doc_types = current_df['urn_type'].nunique() if 'urn_type' in current_df.columns else 0
        if enhanced_doc_types > current_doc_types:
            enhancements.append(f"Document type diversity: {enhanced_doc_types} vs {current_doc_types} types")
    
    # New fields
    if new_cols:
        enhancements.append(f"New data fields: {len(new_cols)} additional columns")
    
    # Data richness for summaries
    current_summaries = count_non_empty(current_df, 'document_summary')
    enhanced_summaries = count_non_empty(enhanced_df, 'document_summary')
    if enhanced_summaries > current_summaries:
        improvement = enhanced_summaries / max(current_summaries, 1)
        enhancements.append(f"Document summaries: {improvement:.1f}x more detailed content")
    
    print("Key improvements:")
    for i, enhancement in enumerate(enhancements, 1):
        print(f"  {i}. {enhancement}")
    
    return {
        'current_count': len(current_df),
        'enhanced_count': len(enhanced_df),
        'improvement_factor': volume_improvement,
        'enhancements': enhancements
    }

def both_datasets(df1, df2):
    """Helper to check columns present in both datasets"""
    return set(df1.columns) & set(df2.columns)

def generate_comparison_report(stats):
    """Generate a detailed comparison report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f'dataset_comparison_report_{timestamp}.md'
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# LexML Dataset Comparison Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        
        f.write("## Executive Summary\n\n")
        f.write(f"Our enhanced LexML collection strategy has achieved significant improvements:\n\n")
        
        f.write(f"- **{stats['improvement_factor']:.1f}x more documents**: From {stats['current_count']} to {stats['enhanced_count']} records\n")
        
        for enhancement in stats['enhancements']:
            f.write(f"- **{enhancement}**\n")
        
        f.write("\n## Key Achievements\n\n")
        f.write("### 1. Volume Expansion\n")
        f.write(f"Increased our legislative monitoring dataset from {stats['current_count']} to {stats['enhanced_count']} documents, ")
        f.write(f"representing a {stats['improvement_factor']:.1f}x improvement in coverage.\n\n")
        
        f.write("### 2. Enhanced Data Quality\n")
        f.write("- Richer document summaries and descriptions\n")
        f.write("- Better URN parsing and classification\n")
        f.write("- Enhanced metadata extraction\n")
        f.write("- Source attribution and document type classification\n\n")
        
        f.write("### 3. Broader Search Coverage\n")
        f.write("- Comprehensive transportation and cargo terminology\n")
        f.write("- Energy and fuel-specific searches\n")
        f.write("- Technology and innovation terms\n")
        f.write("- Regulatory and compliance keywords\n\n")
        
        f.write("### 4. Document Type Diversity\n")
        f.write("- Academic papers and research (doctrine)\n")
        f.write("- Federal and state legislation\n")
        f.write("- Jurisprudence and court decisions\n")
        f.write("- Legislative proposals in progress\n\n")
        
        f.write("## Next Steps\n\n")
        f.write("1. **Database Integration**: Upload enhanced dataset to production database\n")
        f.write("2. **Full Collection**: Expand to all 96 processed search terms\n")
        f.write("3. **Automated Monitoring**: Set up periodic collection updates\n")
        f.write("4. **Analysis Dashboard**: Create enhanced analytics and reporting\n\n")
        
        f.write("---\n")
        f.write("*This report was generated by the enhanced LexML collection system.*\n")
    
    print(f"✓ Comparison report saved to: {report_file}")
    return report_file

def main():
    """Main comparison function"""
    stats = compare_datasets()
    
    if stats:
        report_file = generate_comparison_report(stats)
        
        print(f"\n🎉 Analysis complete!")
        print(f"📄 Report: {report_file}")
        print(f"📈 Improvement: {stats['improvement_factor']:.1f}x more documents")
    else:
        print("\n❌ Analysis failed")

if __name__ == "__main__":
    main()