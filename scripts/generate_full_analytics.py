#!/usr/bin/env python3
"""
Generate comprehensive analytics for the full LexML collection
"""

import pandas as pd
import os
from datetime import datetime
from collections import Counter
import re

def load_full_collection():
    """Load the full collection results"""
    files = [f for f in os.listdir('.') if f.startswith('lexml_full_collection_')]
    if not files:
        return None
    
    latest_file = sorted(files)[-1]
    df = pd.read_csv(latest_file)
    print(f"✓ Loaded full collection: {len(df)} records from {latest_file}")
    return df, latest_file

def analyze_document_types(df):
    """Analyze distribution of document types"""
    if 'urn_type' not in df.columns:
        return {}
    
    type_counts = df['urn_type'].value_counts()
    type_percentages = (type_counts / len(df) * 100).round(1)
    
    analysis = {
        'total_types': len(type_counts),
        'distribution': {},
        'dominant_type': type_counts.index[0] if len(type_counts) > 0 else None
    }
    
    for doc_type in type_counts.index:
        analysis['distribution'][doc_type] = {
            'count': int(type_counts[doc_type]),
            'percentage': float(type_percentages[doc_type])
        }
    
    return analysis

def analyze_search_performance(df):
    """Analyze search term performance"""
    if 'search_term' not in df.columns:
        return {}
    
    term_counts = df['search_term'].value_counts()
    
    # Calculate performance tiers
    high_performers = term_counts[term_counts >= 30]
    medium_performers = term_counts[(term_counts >= 15) & (term_counts < 30)]
    low_performers = term_counts[term_counts < 15]
    
    return {
        'total_terms': len(term_counts),
        'high_performers': {
            'count': len(high_performers),
            'terms': dict(high_performers.head(10))
        },
        'medium_performers': {
            'count': len(medium_performers),
            'avg_results': medium_performers.mean() if len(medium_performers) > 0 else 0
        },
        'low_performers': {
            'count': len(low_performers),
            'avg_results': low_performers.mean() if len(low_performers) > 0 else 0
        },
        'avg_results_per_term': term_counts.mean(),
        'max_results': term_counts.max(),
        'min_results': term_counts.min()
    }

def analyze_content_quality(df):
    """Analyze content quality metrics"""
    quality_metrics = {}
    
    # Summary completeness
    if 'document_summary' in df.columns:
        summaries = df['document_summary'].dropna()
        quality_metrics['summaries'] = {
            'count': len(summaries),
            'percentage': (len(summaries) / len(df) * 100),
            'avg_length': summaries.str.len().mean() if len(summaries) > 0 else 0,
            'min_length': summaries.str.len().min() if len(summaries) > 0 else 0,
            'max_length': summaries.str.len().max() if len(summaries) > 0 else 0
        }
    
    # Description completeness
    if 'document_description' in df.columns:
        descriptions = df['document_description'].dropna()
        quality_metrics['descriptions'] = {
            'count': len(descriptions),
            'percentage': (len(descriptions) / len(df) * 100),
            'avg_length': descriptions.str.len().mean() if len(descriptions) > 0 else 0
        }
    
    # Source attribution
    if 'source_type' in df.columns:
        sources = df['source_type'].dropna()
        quality_metrics['source_attribution'] = {
            'count': len(sources),
            'percentage': (len(sources) / len(df) * 100),
            'unique_sources': df['source_type'].nunique()
        }
    
    # URN quality
    if 'urn' in df.columns:
        valid_urns = df['urn'].str.startswith('urn:lex:', na=False).sum()
        quality_metrics['urn_quality'] = {
            'valid_urns': int(valid_urns),
            'validity_percentage': (valid_urns / len(df) * 100),
            'unique_urns': df['urn'].nunique()
        }
    
    return quality_metrics

def analyze_temporal_distribution(df):
    """Analyze temporal distribution of documents"""
    temporal = {}
    
    if 'enacting_date' in df.columns:
        # Extract years from various date formats
        years = []
        for date_str in df['enacting_date'].dropna():
            if pd.isna(date_str):
                continue
            
            # Look for 4-digit years
            year_match = re.search(r'(\d{4})', str(date_str))
            if year_match:
                year = int(year_match.group(1))
                if 1900 <= year <= 2030:  # Reasonable year range
                    years.append(year)
        
        if years:
            year_counts = Counter(years)
            temporal['enacting_dates'] = {
                'total_with_dates': len(years),
                'year_range': f"{min(years)}-{max(years)}",
                'most_common_year': year_counts.most_common(1)[0] if year_counts else None,
                'decade_distribution': {}
            }
            
            # Decade analysis
            decades = {}
            for year in years:
                decade = (year // 10) * 10
                decades[decade] = decades.get(decade, 0) + 1
            
            temporal['enacting_dates']['decade_distribution'] = dict(sorted(decades.items()))
    
    return temporal

def analyze_geographic_distribution(df):
    """Analyze geographic distribution"""
    geographic = {}
    
    # Country distribution
    if 'country' in df.columns:
        countries = df['country'].value_counts()
        geographic['countries'] = dict(countries)
    
    # State distribution
    if 'state' in df.columns:
        states = df['state'].dropna().value_counts()
        geographic['states'] = {
            'total_with_state': len(df['state'].dropna()),
            'unique_states': df['state'].nunique(),
            'top_states': dict(states.head(10)) if len(states) > 0 else {}
        }
    
    # Justice/Court distribution
    if 'justice' in df.columns:
        justice_types = df['justice'].dropna().value_counts()
        geographic['justice_types'] = dict(justice_types) if len(justice_types) > 0 else {}
    
    return geographic

def generate_comparison_with_existing():
    """Generate comparison with existing data"""
    # Try to load existing data for comparison
    possible_files = [
        '../data/processed/lexml_parsed_enhanced_fixed.csv',
        '../data/processed/lexml_parsed_enhanced.csv',
        '../data/processed/lexml_parsed.csv'
    ]
    
    for file_path in possible_files:
        if os.path.exists(file_path):
            existing_df = pd.read_csv(file_path)
            return {
                'existing_file': file_path,
                'existing_count': len(existing_df),
                'existing_columns': len(existing_df.columns)
            }
    
    return {'existing_file': None, 'note': 'No existing data found for comparison'}

def generate_analytics_report(df, source_file):
    """Generate comprehensive analytics report"""
    print("📊 Generating comprehensive analytics...")
    
    analytics = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'source_file': source_file,
            'total_records': len(df),
            'total_columns': len(df.columns)
        },
        'document_types': analyze_document_types(df),
        'search_performance': analyze_search_performance(df),
        'content_quality': analyze_content_quality(df),
        'temporal_distribution': analyze_temporal_distribution(df),
        'geographic_distribution': analyze_geographic_distribution(df),
        'comparison': generate_comparison_with_existing()
    }
    
    return analytics

def save_analytics_report(analytics):
    """Save analytics as both JSON and markdown"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save detailed markdown report
    md_file = f'full_collection_analytics_{timestamp}.md'
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write("# LexML Full Collection - Comprehensive Analytics\n\n")
        f.write(f"**Generated:** {analytics['metadata']['generated_at']}\n")
        f.write(f"**Source:** {analytics['metadata']['source_file']}\n")
        f.write(f"**Total Records:** {analytics['metadata']['total_records']:,}\n\n")
        
        # Document Types Analysis
        f.write("## 📋 Document Types Distribution\n\n")
        doc_types = analytics['document_types']
        if 'distribution' in doc_types:
            for doc_type, data in doc_types['distribution'].items():
                f.write(f"- **{doc_type}**: {data['count']:,} documents ({data['percentage']:.1f}%)\n")
        f.write(f"\n**Dominant Type:** {doc_types.get('dominant_type', 'N/A')}\n\n")
        
        # Search Performance Analysis
        f.write("## 🔍 Search Performance Analysis\n\n")
        search = analytics['search_performance']
        if search:
            f.write(f"- **Total Search Terms:** {search.get('total_terms', 0)}\n")
            f.write(f"- **Average Results per Term:** {search.get('avg_results_per_term', 0):.1f}\n")
            f.write(f"- **High Performers (≥30 results):** {search.get('high_performers', {}).get('count', 0)}\n")
            f.write(f"- **Medium Performers (15-29 results):** {search.get('medium_performers', {}).get('count', 0)}\n")
            f.write(f"- **Low Performers (<15 results):** {search.get('low_performers', {}).get('count', 0)}\n\n")
            
            # Top performing terms
            if 'high_performers' in search and 'terms' in search['high_performers']:
                f.write("### Top Performing Search Terms\n\n")
                for term, count in search['high_performers']['terms'].items():
                    f.write(f"- `{term}`: {count} documents\n")
                f.write("\n")
        
        # Content Quality Analysis
        f.write("## 📈 Content Quality Metrics\n\n")
        quality = analytics['content_quality']
        
        if 'summaries' in quality:
            s = quality['summaries']
            f.write(f"### Document Summaries\n")
            f.write(f"- **Coverage:** {s['count']:,} documents ({s['percentage']:.1f}%)\n")
            f.write(f"- **Average Length:** {s['avg_length']:.0f} characters\n")
            f.write(f"- **Length Range:** {s['min_length']:.0f} - {s['max_length']:.0f} characters\n\n")
        
        if 'source_attribution' in quality:
            s = quality['source_attribution']
            f.write(f"### Source Attribution\n")
            f.write(f"- **Coverage:** {s['count']:,} documents ({s['percentage']:.1f}%)\n")
            f.write(f"- **Unique Sources:** {s['unique_sources']}\n\n")
        
        if 'urn_quality' in quality:
            u = quality['urn_quality']
            f.write(f"### URN Quality\n")
            f.write(f"- **Valid URNs:** {u['valid_urns']:,} ({u['validity_percentage']:.1f}%)\n")
            f.write(f"- **Unique URNs:** {u['unique_urns']:,}\n\n")
        
        # Temporal Analysis
        f.write("## 📅 Temporal Distribution\n\n")
        temporal = analytics['temporal_distribution']
        if 'enacting_dates' in temporal:
            e = temporal['enacting_dates']
            f.write(f"- **Documents with Dates:** {e['total_with_dates']:,}\n")
            f.write(f"- **Year Range:** {e['year_range']}\n")
            if e['most_common_year']:
                f.write(f"- **Most Common Year:** {e['most_common_year'][0]} ({e['most_common_year'][1]} documents)\n")
            
            if e['decade_distribution']:
                f.write(f"\n### Distribution by Decade\n")
                for decade, count in e['decade_distribution'].items():
                    f.write(f"- **{decade}s:** {count} documents\n")
        f.write("\n")
        
        # Geographic Analysis
        f.write("## 🌍 Geographic Distribution\n\n")
        geo = analytics['geographic_distribution']
        
        if 'countries' in geo:
            f.write(f"### Countries\n")
            for country, count in geo['countries'].items():
                f.write(f"- **{country}**: {count:,} documents\n")
            f.write("\n")
        
        if 'states' in geo and geo['states']['top_states']:
            f.write(f"### Top States/Regions\n")
            for state, count in geo['states']['top_states'].items():
                f.write(f"- **{state}**: {count} documents\n")
            f.write("\n")
        
        # Comparison Section
        f.write("## 📊 Comparison with Existing Data\n\n")
        comp = analytics['comparison']
        if comp.get('existing_file'):
            improvement = analytics['metadata']['total_records'] - comp['existing_count']
            f.write(f"- **Previous Dataset:** {comp['existing_count']:,} records\n")
            f.write(f"- **Enhanced Dataset:** {analytics['metadata']['total_records']:,} records\n")
            f.write(f"- **Net Improvement:** +{improvement:,} documents ({improvement/comp['existing_count']*100:.1f}% increase)\n")
        else:
            f.write("- No existing dataset found for comparison\n")
        f.write("\n")
        
        # Performance Summary
        f.write("## ⚡ Collection Performance Summary\n\n")
        f.write(f"- **Total Documents Collected:** {analytics['metadata']['total_records']:,}\n")
        f.write(f"- **Document Types Captured:** {analytics['document_types'].get('total_types', 0)}\n")
        f.write(f"- **Search Terms Processed:** {analytics['search_performance'].get('total_terms', 0)}\n")
        f.write(f"- **Data Quality Score:** {quality.get('urn_quality', {}).get('validity_percentage', 0):.1f}% valid URNs\n")
        f.write(f"- **Content Richness:** {quality.get('summaries', {}).get('percentage', 0):.1f}% with summaries\n\n")
        
        f.write("---\n")
        f.write("**Status:** ✅ Analytics Complete - Ready for Database Integration\n")
    
    print(f"📄 Analytics report saved: {md_file}")
    return md_file

def main():
    """Main analytics generation function"""
    print("=== LexML Full Collection Analytics ===")
    
    # Load data
    df, source_file = load_full_collection()
    if df is None:
        print("❌ No collection data found")
        return
    
    # Generate analytics
    analytics = generate_analytics_report(df, source_file)
    
    # Save report
    report_file = save_analytics_report(analytics)
    
    # Print summary
    print(f"\n🎉 Analytics generation complete!")
    print(f"📄 Report: {report_file}")
    print(f"📊 {analytics['metadata']['total_records']:,} documents analyzed")
    print(f"📋 {analytics['document_types'].get('total_types', 0)} document types")
    print(f"🔍 {analytics['search_performance'].get('total_terms', 0)} search terms")
    print(f"✨ {analytics['content_quality'].get('summaries', {}).get('percentage', 0):.1f}% with summaries")

if __name__ == "__main__":
    main()