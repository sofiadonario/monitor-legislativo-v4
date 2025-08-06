#!/usr/bin/env python3
"""
CSV-BASED MUNICIPALITY PATTERN ANALYSIS
=======================================

This script analyzes CSV files to find hidden municipality patterns when database 
connection is not available. It searches through existing CSV files for combined
municipality-state formats.
"""

import os
import re
import pandas as pd
import glob
from collections import defaultdict, Counter
import json

# Brazilian state abbreviations
BRAZILIAN_STATES = {
    'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS',
    'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC',
    'SP', 'SE', 'TO'
}

def find_csv_files():
    """Find all relevant CSV files in the project"""
    csv_patterns = [
        'legacy/data/**/*.csv',
        'data_current/**/*.csv',
        'scripts/*.csv',
        'lexml_overview/**/*.csv',
        '*.csv'
    ]
    
    csv_files = []
    for pattern in csv_patterns:
        csv_files.extend(glob.glob(pattern, recursive=True))
    
    # Filter for relevant files and exclude test files
    relevant_files = []
    for file in csv_files:
        filename = os.path.basename(file).lower()
        if any(keyword in filename for keyword in [
            'lexml', 'municipal', 'legisla', 'juridic', 'doutrin', 
            'proposic', 'outros', 'geral', 'aereo', 'rodoviario', 'maritimo'
        ]):
            relevant_files.append(file)
    
    return relevant_files

def load_and_analyze_csv(csv_file):
    """Load CSV file and analyze for municipality patterns"""
    try:
        print(f"📁 Analyzing {os.path.basename(csv_file)}...")
        
        # Try different encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                df = pd.read_csv(csv_file, encoding=encoding, low_memory=False)
                break
            except UnicodeDecodeError:
                continue
        else:
            print(f"⚠️ Could not read {csv_file} - encoding issues")
            return {}
        
        if df.empty:
            return {}
        
        print(f"   📊 {len(df):,} rows, {len(df.columns)} columns")
        
        # Identify relevant columns
        relevant_columns = []
        for col in df.columns:
            col_lower = str(col).lower()
            if any(keyword in col_lower for keyword in [
                'municipal', 'localidade', 'cidade', 'autoridade', 'jurisdic',
                'titulo', 'local', 'authority', 'municipality', 'locality'
            ]):
                relevant_columns.append(col)
        
        if not relevant_columns:
            print(f"   ⚠️ No relevant columns found")
            return {}
        
        print(f"   🎯 Analyzing columns: {', '.join(relevant_columns)}")
        
        results = defaultdict(list)
        
        # Analyze each relevant column
        for col in relevant_columns:
            if col in df.columns:
                column_results = analyze_column_patterns(df[col].dropna(), col)
                for pattern_type, findings in column_results.items():
                    results[pattern_type].extend(findings)
        
        return results
        
    except Exception as e:
        print(f"❌ Error analyzing {csv_file}: {e}")
        return {}

def analyze_column_patterns(series, column_name):
    """Analyze a pandas Series for municipality patterns"""
    results = defaultdict(list)
    
    for idx, value in series.items():
        if not isinstance(value, str) or len(value) < 5:
            continue
        
        # Search for dash patterns (City - SP)
        dash_match = re.search(r'^(.+?)\s*-\s*([A-Z]{2})$', value.strip())
        if dash_match:
            city = dash_match.group(1).strip()
            state = dash_match.group(2)
            if state in BRAZILIAN_STATES and len(city) > 2 and is_likely_city_name(city):
                results['dash_patterns'].append({
                    'original': value,
                    'city': city,
                    'state': state,
                    'column': column_name,
                    'row': idx
                })
        
        # Search for parentheses patterns (City (SP))
        paren_match = re.search(r'^(.+?)\s*\(([A-Z]{2})\)$', value.strip())
        if paren_match:
            city = paren_match.group(1).strip()
            state = paren_match.group(2)
            if state in BRAZILIAN_STATES and len(city) > 2 and is_likely_city_name(city):
                results['parentheses_patterns'].append({
                    'original': value,
                    'city': city,
                    'state': state,
                    'column': column_name,
                    'row': idx
                })
        
        # Search for comma patterns (City, SP)
        comma_match = re.search(r'^(.+?),\s*([A-Z]{2})$', value.strip())
        if comma_match:
            city = comma_match.group(1).strip()
            state = comma_match.group(2)
            if state in BRAZILIAN_STATES and len(city) > 2 and is_likely_city_name(city):
                results['comma_patterns'].append({
                    'original': value,
                    'city': city,
                    'state': state,
                    'column': column_name,
                    'row': idx
                })
        
        # Search for authority patterns (Prefeitura de City)
        authority_patterns = [
            r'Prefeitura\s+(Municipal\s+)?de\s+(.+?)(?:\s*[-,(]|$)',
            r'Câmara\s+Municipal\s+de\s+(.+?)(?:\s*[-,(]|$)',
            r'Prefeitura\s+da\s+Cidade\s+de\s+(.+?)(?:\s*[-,(]|$)'
        ]
        
        for pattern in authority_patterns:
            auth_match = re.search(pattern, value, re.IGNORECASE)
            if auth_match:
                city = auth_match.group(-1).strip()  # Last group
                if len(city) > 2 and is_likely_city_name(city):
                    results['authority_patterns'].append({
                        'original': value,
                        'city': city,
                        'state': 'Unknown',
                        'column': column_name,
                        'row': idx
                    })
        
        # Search for slash patterns (City/SP)
        slash_match = re.search(r'^(.+?)/([A-Z]{2})$', value.strip())
        if slash_match:
            city = slash_match.group(1).strip()
            state = slash_match.group(2)
            if state in BRAZILIAN_STATES and len(city) > 2 and is_likely_city_name(city):
                results['slash_patterns'].append({
                    'original': value,
                    'city': city,
                    'state': state,
                    'column': column_name,
                    'row': idx
                })
    
    return results

def is_likely_city_name(text):
    """Check if text is likely a city name"""
    if not text or len(text) < 2:
        return False
    
    # Exclude obvious non-city words
    exclude_words = {
        'lei', 'decreto', 'portaria', 'resolução', 'instrução', 'medida',
        'federal', 'nacional', 'brasil', 'república', 'união', 'art',
        'artigo', 'inciso', 'parágrafo', 'caput', 'alínea', 'anexo',
        'regulamento', 'norma', 'código', 'consolidada', 'estatuto'
    }
    
    if any(word in text.lower() for word in exclude_words):
        return False
    
    # Must start with capital letter
    if not text[0].isupper():
        return False
    
    # Should not contain numbers at the start
    if text[0].isdigit():
        return False
    
    # Should not be mostly uppercase (likely an acronym)
    if text.isupper() and len(text) > 3:
        return False
    
    return True

def consolidate_results(all_results):
    """Consolidate results from all CSV files"""
    consolidated = defaultdict(list)
    
    for file_results in all_results:
        for pattern_type, findings in file_results.items():
            consolidated[pattern_type].extend(findings)
    
    # Remove duplicates based on city + state combination
    for pattern_type in consolidated:
        seen = set()
        unique_findings = []
        for finding in consolidated[pattern_type]:
            key = (finding['city'].lower(), finding['state'])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        consolidated[pattern_type] = unique_findings
    
    return consolidated

def generate_summary_report(consolidated_results):
    """Generate a comprehensive summary report"""
    # Count unique municipalities
    all_municipalities = set()
    pattern_counts = {}
    
    for pattern_type, findings in consolidated_results.items():
        pattern_counts[pattern_type] = len(findings)
        for finding in findings:
            city_state = (finding['city'], finding['state'])
            all_municipalities.add(city_state)
    
    # Count by state
    state_counts = Counter()
    for city, state in all_municipalities:
        if state != 'Unknown':
            state_counts[state] += 1
    
    # Top municipalities
    city_counts = Counter()
    for pattern_type, findings in consolidated_results.items():
        for finding in findings:
            city_counts[finding['city']] += 1
    
    report = {
        'summary': {
            'total_unique_municipalities': len(all_municipalities),
            'total_patterns_found': sum(pattern_counts.values()),
            'states_with_municipalities': len(state_counts),
            'pattern_type_counts': pattern_counts
        },
        'top_states': dict(state_counts.most_common(10)),
        'top_municipalities': dict(city_counts.most_common(20)),
        'examples_by_pattern': {}
    }
    
    # Add examples for each pattern type
    for pattern_type, findings in consolidated_results.items():
        if findings:
            report['examples_by_pattern'][pattern_type] = findings[:5]  # Top 5 examples
    
    return report

def save_results(consolidated_results, report):
    """Save results to files"""
    # Save detailed results
    with open('csv_municipality_search_results.json', 'w', encoding='utf-8') as f:
        json.dump(consolidated_results, f, indent=2, ensure_ascii=False, default=str)
    
    # Save summary report
    with open('csv_municipality_analysis_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # Create CSV with all found municipalities
    all_municipalities = []
    for pattern_type, findings in consolidated_results.items():
        for finding in findings:
            all_municipalities.append({
                'municipality': finding['city'],
                'state': finding['state'],
                'pattern_type': pattern_type,
                'original_text': finding['original'],
                'source_column': finding['column'],
                'validation_status': 'needs_validation'
            })
    
    if all_municipalities:
        df = pd.DataFrame(all_municipalities)
        df.to_csv('csv_based_municipalities_found.csv', index=False, encoding='utf-8')
        print(f"💾 Saved {len(all_municipalities)} municipality records to csv_based_municipalities_found.csv")

def print_summary(report):
    """Print analysis summary"""
    print("\n" + "="*80)
    print("CSV MUNICIPALITY PATTERN ANALYSIS SUMMARY")
    print("="*80)
    
    summary = report['summary']
    print(f"📊 OVERALL RESULTS:")
    print(f"   • Total unique municipalities found: {summary['total_unique_municipalities']:,}")
    print(f"   • Total patterns found: {summary['total_patterns_found']:,}")
    print(f"   • States with municipalities: {summary['states_with_municipalities']}")
    
    print(f"\n🔍 PATTERNS BY TYPE:")
    for pattern_type, count in summary['pattern_type_counts'].items():
        print(f"   • {pattern_type.replace('_', ' ').title()}: {count:,}")
    
    print(f"\n🏛️  TOP STATES:")
    for state, count in list(report['top_states'].items())[:5]:
        print(f"   • {state}: {count:,} municipalities")
    
    print(f"\n🏙️  TOP MUNICIPALITIES:")
    for city, count in list(report['top_municipalities'].items())[:10]:
        print(f"   • {city}: {count:,} occurrences")
    
    print(f"\n📝 EXAMPLES BY PATTERN TYPE:")
    for pattern_type, examples in report['examples_by_pattern'].items():
        if examples:
            print(f"\n   {pattern_type.replace('_', ' ').title()}:")
            for example in examples[:3]:
                print(f"     - '{example['original']}' → {example['city']} ({example['state']})")

def main():
    """Main analysis function"""
    print("🚀 CSV-BASED MUNICIPALITY PATTERN ANALYSIS STARTING...")
    print("=" * 60)
    
    # Find CSV files
    csv_files = find_csv_files()
    print(f"📁 Found {len(csv_files)} CSV files to analyze")
    
    if not csv_files:
        print("❌ No CSV files found!")
        return
    
    # Analyze each CSV file
    all_results = []
    for csv_file in csv_files[:10]:  # Limit to first 10 files for testing
        result = load_and_analyze_csv(csv_file)
        if result:
            all_results.append(result)
    
    if not all_results:
        print("❌ No municipality patterns found in any CSV files!")
        return
    
    # Consolidate results
    print("\n📊 Consolidating results from all files...")
    consolidated = consolidate_results(all_results)
    
    # Generate report
    print("📈 Generating analysis report...")
    report = generate_summary_report(consolidated)
    
    # Save results
    print("💾 Saving results...")
    save_results(consolidated, report)
    
    # Print summary
    print_summary(report)
    
    print("\n✅ CSV ANALYSIS COMPLETED!")
    print("Files created:")
    print("  • csv_municipality_search_results.json")
    print("  • csv_municipality_analysis_report.json")
    print("  • csv_based_municipalities_found.csv")

if __name__ == "__main__":
    main()