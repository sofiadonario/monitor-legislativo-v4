#!/usr/bin/env python3
"""
MUNICIPALITY PATTERN ANALYSIS
============================

This script systematically searches for hidden municipality patterns in the database
that might be in combined formats like "City - State", "City (State)", etc.

Focus on key fields:
- municipality (mapped from localidade)
- locality (original localidade field)  
- authority (mapped from autoridade)
- estado (mapped from jurisdicao)
- titulo (document titles)
"""

import re
import os
import sys
import pandas as pd
import psycopg2
from urllib.parse import urlparse
from collections import defaultdict, Counter
import json

# Brazilian state abbreviations and full names
BRAZILIAN_STATES = {
    'AC': 'Acre', 'AL': 'Alagoas', 'AP': 'Amapá', 'AM': 'Amazonas',
    'BA': 'Bahia', 'CE': 'Ceará', 'DF': 'Distrito Federal', 'ES': 'Espírito Santo',
    'GO': 'Goiás', 'MA': 'Maranhão', 'MT': 'Mato Grosso', 'MS': 'Mato Grosso do Sul',
    'MG': 'Minas Gerais', 'PA': 'Pará', 'PB': 'Paraíba', 'PR': 'Paraná',
    'PE': 'Pernambuco', 'PI': 'Piauí', 'RJ': 'Rio de Janeiro', 'RN': 'Rio Grande do Norte',
    'RS': 'Rio Grande do Sul', 'RO': 'Rondônia', 'RR': 'Roraima', 'SC': 'Santa Catarina',
    'SP': 'São Paulo', 'SE': 'Sergipe', 'TO': 'Tocantins'
}

def get_database_connection():
    """Get database connection using Railway configuration"""
    # Try to load from environment or config
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        # Fallback configuration - adjust as needed
        database_url = "postgresql://user:password@host:port/database"
        print("⚠️ Using fallback database configuration")
    
    try:
        conn = psycopg2.connect(database_url)
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return None

def create_search_patterns():
    """Create comprehensive search patterns for Brazilian municipalities"""
    patterns = {
        # State abbreviation patterns
        'dash_state_abbr': [],      # "City - SP", "City - RJ"
        'paren_state_abbr': [],     # "City (SP)", "City (RJ)"
        'comma_state_abbr': [],     # "City, SP", "City, RJ"
        'slash_state_abbr': [],     # "City/SP", "City/RJ"
        
        # Full state name patterns  
        'dash_state_full': [],      # "City - São Paulo"
        'paren_state_full': [],     # "City (São Paulo)"
        'comma_state_full': [],     # "City, São Paulo"
        'slash_state_full': [],     # "City/São Paulo"
        
        # Authority patterns
        'prefeitura_patterns': [],  # "Prefeitura de City - State"
        'camara_patterns': [],      # "Câmara Municipal de City"
        'municipal_patterns': [],   # "Poder Municipal de City"
    }
    
    # Create patterns for each state
    for abbr, full_name in BRAZILIAN_STATES.items():
        # State abbreviation patterns
        patterns['dash_state_abbr'].append(f" - {abbr}")
        patterns['paren_state_abbr'].append(f" \\({abbr}\\)")
        patterns['comma_state_abbr'].append(f", {abbr}")
        patterns['slash_state_abbr'].append(f"/{abbr}")
        
        # Full state name patterns
        patterns['dash_state_full'].append(f" - {full_name}")
        patterns['paren_state_full'].append(f" \\({full_name}\\)")
        patterns['comma_state_full'].append(f", {full_name}")
        patterns['slash_state_full'].append(f"/{full_name}")
    
    # Authority specific patterns
    patterns['prefeitura_patterns'] = [
        r'Prefeitura de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})',
        r'Prefeitura Municipal de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})',
        r'Prefeitura da Cidade de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})'
    ]
    
    patterns['camara_patterns'] = [
        r'Câmara Municipal de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})',
        r'Câmara de Vereadores de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})'
    ]
    
    patterns['municipal_patterns'] = [
        r'Poder Municipal de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})',
        r'Municipal de ([^-,(]+)\s*[-,(]?\s*([A-Z]{2})'
    ]
    
    return patterns

def search_municipality_patterns(conn):
    """Search for municipality patterns in database fields"""
    if not conn:
        print("❌ No database connection available")
        return {}
    
    patterns = create_search_patterns()
    results = {
        'municipality_field': defaultdict(list),
        'locality_field': defaultdict(list),
        'authority_field': defaultdict(list),
        'title_field': defaultdict(list),
        'estado_field': defaultdict(list)
    }
    
    print("🔍 Searching for municipality patterns in database...")
    
    try:
        cursor = conn.cursor()
        
        # Sample query to get data for analysis
        query = """
        SELECT DISTINCT 
            municipality,
            locality,
            authority,
            titulo as title,
            estado
        FROM documents 
        WHERE municipality IS NOT NULL 
           OR locality IS NOT NULL 
           OR authority IS NOT NULL
           OR titulo IS NOT NULL
        LIMIT 10000;
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        print(f"📊 Analyzing {len(rows)} records...")
        
        for row in rows:
            municipality, locality, authority, title, estado = row
            
            # Search in municipality field
            if municipality:
                results['municipality_field'].update(
                    search_field_for_patterns(municipality, patterns, 'municipality')
                )
            
            # Search in locality field
            if locality:
                results['locality_field'].update(
                    search_field_for_patterns(locality, patterns, 'locality')
                )
            
            # Search in authority field
            if authority:
                results['authority_field'].update(
                    search_field_for_patterns(authority, patterns, 'authority')
                )
            
            # Search in title field
            if title:
                results['title_field'].update(
                    search_field_for_patterns(title, patterns, 'title')
                )
            
            # Search in estado field
            if estado:
                results['estado_field'].update(
                    search_field_for_patterns(estado, patterns, 'estado')
                )
        
        cursor.close()
        return results
        
    except Exception as e:
        print(f"❌ Error searching patterns: {e}")
        return {}

def search_field_for_patterns(field_value, patterns, field_name):
    """Search a single field for municipality patterns"""
    found_patterns = defaultdict(list)
    
    if not field_value or not isinstance(field_value, str):
        return found_patterns
    
    # Search for dash patterns with state abbreviations
    for pattern in patterns['dash_state_abbr']:
        if pattern in field_value:
            city = field_value.split(pattern)[0].strip()
            state = pattern.replace(' - ', '').strip()
            if city and len(city) > 2:  # Valid city name
                found_patterns['dash_state_abbr'].append({
                    'original': field_value,
                    'city': city,
                    'state': state,
                    'field': field_name
                })
    
    # Search for parentheses patterns
    paren_match = re.search(r'([^(]+)\s*\(([A-Z]{2})\)', field_value)
    if paren_match:
        city = paren_match.group(1).strip()
        state = paren_match.group(2)
        if state in BRAZILIAN_STATES and len(city) > 2:
            found_patterns['paren_state_abbr'].append({
                'original': field_value,
                'city': city,
                'state': state,
                'field': field_name
            })
    
    # Search for comma patterns
    comma_match = re.search(r'([^,]+),\s*([A-Z]{2})', field_value)
    if comma_match:
        city = comma_match.group(1).strip()
        state = comma_match.group(2)
        if state in BRAZILIAN_STATES and len(city) > 2:
            found_patterns['comma_state_abbr'].append({
                'original': field_value,
                'city': city,
                'state': state,
                'field': field_name
            })
    
    # Search for authority patterns (Prefeitura, Câmara, etc.)
    for pattern in patterns['prefeitura_patterns']:
        match = re.search(pattern, field_value, re.IGNORECASE)
        if match:
            city = match.group(1).strip()
            state = match.group(2) if len(match.groups()) > 1 else 'Unknown'
            if len(city) > 2:
                found_patterns['prefeitura_patterns'].append({
                    'original': field_value,
                    'city': city,
                    'state': state,
                    'field': field_name
                })
    
    return found_patterns

def validate_municipalities(found_municipalities):
    """Validate found municipality names against known Brazilian municipalities"""
    # Load known Brazilian municipalities if available
    known_municipalities = load_known_municipalities()
    
    validated = {
        'valid_municipalities': [],
        'questionable_municipalities': [],
        'invalid_entries': []
    }
    
    for pattern_type, municipalities in found_municipalities.items():
        for muni_data in municipalities:
            city = muni_data.get('city', '').strip()
            
            # Basic validation
            if len(city) < 2:
                validated['invalid_entries'].append(muni_data)
                continue
                
            # Check if it contains obvious non-city words
            non_city_words = ['lei', 'decreto', 'portaria', 'resolução', 'instrução', 
                             'federal', 'nacional', 'brasil', 'república', 'união']
            
            if any(word in city.lower() for word in non_city_words):
                validated['invalid_entries'].append(muni_data)
                continue
            
            # If we have known municipalities, check against them
            if known_municipalities and city in known_municipalities:
                validated['valid_municipalities'].append(muni_data)
            else:
                # If it looks like a proper noun (capitalized), consider it questionable
                if city[0].isupper() and not any(char.isdigit() for char in city):
                    validated['questionable_municipalities'].append(muni_data)
                else:
                    validated['invalid_entries'].append(muni_data)
    
    return validated

def load_known_municipalities():
    """Load known Brazilian municipalities from available sources"""
    known_municipalities = set()
    
    # Try to load from existing CSV files
    csv_files = [
        'existing_municipalities.csv',
        'all_municipalities_found.csv',
        'found_municipalities.csv'
    ]
    
    for csv_file in csv_files:
        if os.path.exists(csv_file):
            try:
                df = pd.read_csv(csv_file)
                if 'municipality' in df.columns:
                    municipalities = df['municipality'].dropna().unique()
                    known_municipalities.update(municipalities)
                    print(f"✅ Loaded {len(municipalities)} municipalities from {csv_file}")
            except Exception as e:
                print(f"⚠️ Could not load {csv_file}: {e}")
    
    return known_municipalities

def generate_analysis_report(search_results, validated_results):
    """Generate comprehensive analysis report"""
    report = {
        'summary': {
            'total_patterns_found': 0,
            'valid_municipalities': len(validated_results['valid_municipalities']),
            'questionable_municipalities': len(validated_results['questionable_municipalities']),
            'invalid_entries': len(validated_results['invalid_entries'])
        },
        'patterns_by_field': {},
        'patterns_by_type': {},
        'top_municipalities': {},
        'examples': {}
    }
    
    # Count patterns by field
    for field, patterns in search_results.items():
        field_count = sum(len(pattern_list) for pattern_list in patterns.values())
        report['patterns_by_field'][field] = field_count
        report['summary']['total_patterns_found'] += field_count
    
    # Count patterns by type
    all_patterns = defaultdict(int)
    for field_patterns in search_results.values():
        for pattern_type, pattern_list in field_patterns.items():
            all_patterns[pattern_type] += len(pattern_list)
    
    report['patterns_by_type'] = dict(all_patterns)
    
    # Top municipalities found
    municipality_counts = Counter()
    for muni_data in (validated_results['valid_municipalities'] + 
                     validated_results['questionable_municipalities']):
        municipality_counts[muni_data['city']] += 1
    
    report['top_municipalities'] = dict(municipality_counts.most_common(20))
    
    # Examples for each pattern type
    for field, patterns in search_results.items():
        if field not in report['examples']:
            report['examples'][field] = {}
        
        for pattern_type, pattern_list in patterns.items():
            if pattern_list:
                # Get first 3 examples
                report['examples'][field][pattern_type] = pattern_list[:3]
    
    return report

def save_results(search_results, validated_results, report):
    """Save analysis results to files"""
    
    # Save detailed search results
    with open('municipality_pattern_search_results.json', 'w', encoding='utf-8') as f:
        json.dump(search_results, f, indent=2, ensure_ascii=False, default=str)
    
    # Save validated results
    with open('municipality_validation_results.json', 'w', encoding='utf-8') as f:
        json.dump(validated_results, f, indent=2, ensure_ascii=False)
    
    # Save comprehensive report
    with open('municipality_analysis_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # Create CSV with found municipalities
    all_found_municipalities = []
    
    for muni_data in (validated_results['valid_municipalities'] + 
                     validated_results['questionable_municipalities']):
        all_found_municipalities.append({
            'municipality': muni_data['city'],
            'state': muni_data['state'],
            'original_text': muni_data['original'],
            'source_field': muni_data['field'],
            'validation_status': ('valid' if muni_data in validated_results['valid_municipalities'] 
                                 else 'questionable')
        })
    
    if all_found_municipalities:
        df = pd.DataFrame(all_found_municipalities)
        df.to_csv('refined_municipalities_found.csv', index=False, encoding='utf-8')
        print(f"💾 Saved {len(all_found_municipalities)} municipalities to refined_municipalities_found.csv")

def print_analysis_summary(report):
    """Print comprehensive analysis summary"""
    print("\n" + "="*80)
    print("MUNICIPALITY PATTERN ANALYSIS SUMMARY")
    print("="*80)
    
    print(f"📊 OVERALL RESULTS:")
    print(f"   • Total patterns found: {report['summary']['total_patterns_found']:,}")
    print(f"   • Valid municipalities: {report['summary']['valid_municipalities']:,}")
    print(f"   • Questionable municipalities: {report['summary']['questionable_municipalities']:,}")
    print(f"   • Invalid entries: {report['summary']['invalid_entries']:,}")
    
    print(f"\n📋 PATTERNS BY DATABASE FIELD:")
    for field, count in report['patterns_by_field'].items():
        print(f"   • {field}: {count:,} patterns")
    
    print(f"\n🔍 PATTERNS BY TYPE:")
    for pattern_type, count in report['patterns_by_type'].items():
        print(f"   • {pattern_type}: {count:,} occurrences")
    
    print(f"\n🏙️  TOP MUNICIPALITIES FOUND:")
    for municipality, count in list(report['top_municipalities'].items())[:10]:
        print(f"   • {municipality}: {count:,} occurrences")
    
    print(f"\n📝 EXAMPLES BY FIELD AND PATTERN:")
    for field, patterns in report['examples'].items():
        if patterns:
            print(f"\n   {field.upper()}:")
            for pattern_type, examples in patterns.items():
                if examples:
                    print(f"     {pattern_type}:")
                    for example in examples[:2]:  # Show 2 examples
                        print(f"       - '{example['original']}' → '{example['city']}' ({example['state']})")

def main():
    """Main analysis function"""
    print("🚀 MUNICIPALITY PATTERN ANALYSIS STARTING...")
    print("=" * 60)
    
    # Get database connection
    conn = get_database_connection()
    
    # Search for patterns
    print("\n1️⃣ SEARCHING FOR MUNICIPALITY PATTERNS...")
    search_results = search_municipality_patterns(conn)
    
    # Flatten all found municipalities for validation
    all_found_municipalities = []
    for field_patterns in search_results.values():
        for pattern_list in field_patterns.values():
            all_found_municipalities.extend(pattern_list)
    
    # Validate municipalities
    print("\n2️⃣ VALIDATING FOUND MUNICIPALITIES...")
    validated_results = validate_municipalities({'all': all_found_municipalities})
    
    # Generate report
    print("\n3️⃣ GENERATING ANALYSIS REPORT...")
    report = generate_analysis_report(search_results, validated_results)
    
    # Save results
    print("\n4️⃣ SAVING RESULTS...")
    save_results(search_results, validated_results, report)
    
    # Print summary
    print_analysis_summary(report)
    
    print("\n✅ ANALYSIS COMPLETED!")
    print("Files saved:")
    print("  • municipality_pattern_search_results.json")
    print("  • municipality_validation_results.json") 
    print("  • municipality_analysis_report.json")
    print("  • refined_municipalities_found.csv")
    
    # Close database connection
    if conn:
        conn.close()

if __name__ == "__main__":
    main()