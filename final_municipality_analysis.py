#!/usr/bin/env python3
"""
Final Comprehensive Municipality Analysis - Brazilian Legislative Database
Complete investigation with proper null handling and statistical insights
"""

import psycopg2
import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter, defaultdict
import warnings
warnings.filterwarnings('ignore')

# Set up matplotlib for better visualization
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

# Database connection parameters
db_config = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def get_comprehensive_patterns():
    """Create comprehensive but precise municipality detection patterns"""
    
    # Brazilian state abbreviations
    states = ['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
              'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
              'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO']
    
    patterns = {
        # High precision patterns
        'autoriza_municipio': r'Autoriza\s+o\s+Munic[ií]pio\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s*\(({"|".join(states)})\)|\s+a\s|\s*,|\s*\.|\s*;|$)',
        
        'municipio_parentheses': rf'Munic[ií]pio\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)\s*\(\s*({"|".join(states)})\s*\)',
        
        'prefeitura_municipal': r'Prefeitura\s+Municipal\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s*\(({"|".join(states)})\)|\s+a\s|\s*,|\s*\.|\s*;|$)',
        
        'camara_municipal': r'C[âa]mara\s+Municipal\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s*\(({"|".join(states)})\)|\s+a\s|\s*,|\s*\.|\s*;|$)',
        
        'tribunal_comarca': r'Comarca\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s*\(({"|".join(states)})\)|\s+a\s|\s*,|\s*\.|\s*;|$)',
        
        # State-municipality combinations
        'city_state_hyphen': rf'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{{3,25}})\s*-\s*({"|".join(states)})\b',
        
        'city_state_slash': rf'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{{3,25}})\s*/\s*({"|".join(states)})\b',
    }
    
    return patterns, states

def is_likely_municipality(name):
    """Enhanced validation for municipality names"""
    if not name:
        return False
        
    name = name.strip()
    
    if len(name) < 3 or len(name) > 50:
        return False
    
    # Exclude obvious non-municipality patterns
    exclude_patterns = [
        r'^\d+$',  # Just numbers
        r'^[A-Z]{1,3}$',  # Short abbreviations
        r'Art\.|Lei|Decreto|Dec\.',  # Legal references
        r'^\d+[\-/]\d+',  # Date-like patterns
        r'[0-9]{5,}',  # Contains long numbers
        r'^(E|OU|DE|DO|DA|EM|COM|PARA|POR|SOBRE|ENTRE|QUE|SE|NA|NO|AS|OS|UM|UMA)$',
        r'ADMITE.SE|TRATANDO.SE|ESTABELECER.SE|TRANSMITE.SE',
        r'^(ADVOGADO|TRIBUNAL|CONSELHO|COMISSÃO|DEPARTAMENTO)$',
    ]
    
    for pattern in exclude_patterns:
        if re.search(pattern, name, re.IGNORECASE):
            return False
    
    # Must contain letters
    if not re.search(r'[a-zA-ZáàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]', name):
        return False
    
    # Should have reasonable word structure
    words = name.split()
    if len(words) > 6:  # Too many words
        return False
    
    return True

def analyze_existing_municipality_field(conn):
    """Analyze what's already in the municipio field"""
    print("\n" + "="*50)
    print("EXISTING MUNICIPALITY FIELD ANALYSIS")
    print("="*50)
    
    cur = conn.cursor()
    
    # Get all unique values in municipio field
    cur.execute("""
        SELECT municipio, COUNT(*) as document_count 
        FROM documents 
        WHERE municipio IS NOT NULL 
        GROUP BY municipio 
        ORDER BY document_count DESC
    """)
    
    municipio_data = cur.fetchall()
    
    print(f"Found {len(municipio_data)} unique municipalities in municipio field")
    print(f"Top municipalities by document count:")
    
    for muni, count in municipio_data[:20]:
        print(f"  {muni}: {count:,} documents")
    
    if len(municipio_data) > 20:
        print(f"  ... and {len(municipio_data) - 20} more municipalities")
    
    cur.close()
    return municipio_data

def deep_text_mining(conn, patterns):
    """Perform deep text mining across multiple fields"""
    print("\n" + "="*50)
    print("DEEP TEXT MINING ANALYSIS")
    print("="*50)
    
    cur = conn.cursor()
    
    # Fields to analyze
    fields_to_analyze = ['titulo', 'ementa', 'autoridade', 'origem']
    
    all_municipalities = set()
    pattern_stats = Counter()
    field_stats = {}
    
    for field in fields_to_analyze:
        print(f"\n--- Analyzing field: {field} ---")
        
        # Get sample of non-null values
        cur.execute(f"""
            SELECT {field}
            FROM documents 
            WHERE {field} IS NOT NULL 
            AND LENGTH({field}) > 10
            ORDER BY RANDOM()
            LIMIT 15000
        """)
        
        texts = [row[0] for row in cur.fetchall() if row[0]]
        print(f"Analyzing {len(texts)} text samples")
        
        field_municipalities = set()
        
        for pattern_name, pattern in patterns.items():
            matches_found = 0
            for text in texts:
                try:
                    matches = re.finditer(pattern, str(text), re.IGNORECASE)
                    for match in matches:
                        if len(match.groups()) >= 1:
                            municipality = match.group(1)
                            if municipality and is_likely_municipality(municipality):
                                municipality_clean = municipality.strip()
                                if len(municipality_clean) > 2:
                                    field_municipalities.add(municipality_clean)
                                    all_municipalities.add(municipality_clean)
                                    matches_found += 1
                except Exception as e:
                    continue
            
            if matches_found > 0:
                pattern_stats[pattern_name] += matches_found
                print(f"  {pattern_name}: {matches_found} valid matches")
        
        field_stats[field] = len(field_municipalities)
        print(f"  Total unique municipalities found in {field}: {len(field_municipalities)}")
        
        # Show some examples
        if field_municipalities:
            examples = sorted(list(field_municipalities))[:10]
            print(f"  Examples: {', '.join(examples)}")
    
    cur.close()
    return all_municipalities, pattern_stats, field_stats

def analyze_authority_field(conn):
    """Special analysis of the autoridade field for municipal authorities"""
    print("\n" + "="*50)
    print("AUTHORITY FIELD ANALYSIS")
    print("="*50)
    
    cur = conn.cursor()
    
    # Look for municipal authorities
    municipal_authority_patterns = [
        "Prefeitura",
        "Câmara Municipal", 
        "Prefeito",
        "Vereador",
        "Municipal",
        "Comarca"
    ]
    
    municipal_authorities = []
    
    for pattern in municipal_authority_patterns:
        cur.execute(f"""
            SELECT autoridade, COUNT(*) as count
            FROM documents 
            WHERE autoridade IS NOT NULL 
            AND LOWER(autoridade) LIKE LOWER('%{pattern}%')
            GROUP BY autoridade 
            ORDER BY count DESC
            LIMIT 10
        """)
        
        results = cur.fetchall()
        if results:
            print(f"\nAuthorities containing '{pattern}':")
            for auth, count in results:
                print(f"  {auth}: {count} documents")
                municipal_authorities.append((auth, count))
    
    cur.close()
    return municipal_authorities

def create_visualizations(municipio_data, text_mining_results, field_stats):
    """Create visualizations of the findings"""
    print("\n" + "="*50)
    print("CREATING VISUALIZATIONS")
    print("="*50)
    
    # Figure 1: Existing municipality field distribution
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    
    # Top municipalities from existing field
    if municipio_data:
        top_10 = municipio_data[:10]
        munis = [m[0] for m in top_10]
        counts = [m[1] for m in top_10]
        
        axes[0,0].barh(range(len(munis)), counts)
        axes[0,0].set_yticks(range(len(munis)))
        axes[0,0].set_yticklabels(munis)
        axes[0,0].set_xlabel('Number of Documents')
        axes[0,0].set_title('Top 10 Municipalities (Existing Field)')
    
    # Field statistics
    if field_stats:
        fields = list(field_stats.keys())
        values = list(field_stats.values())
        
        axes[0,1].bar(fields, values)
        axes[0,1].set_ylabel('Unique Municipalities Found')
        axes[0,1].set_title('Municipalities Found by Text Mining (by Field)')
        axes[0,1].tick_params(axis='x', rotation=45)
    
    # Pattern effectiveness (if we have pattern stats)
    total_existing = len(municipio_data) if municipio_data else 0
    total_text_mining = len(text_mining_results) if text_mining_results else 0
    
    coverage_data = ['Existing Field', 'Text Mining']
    coverage_values = [total_existing, total_text_mining]
    
    axes[1,0].pie(coverage_values, labels=coverage_data, autopct='%1.1f%%')
    axes[1,0].set_title('Municipality Data Sources')
    
    # Combined statistics
    stats_labels = ['Total Documents', 'Documents with Municipality Field', 'Estimated Additional Municipalities']
    stats_values = [134014, 2994, total_text_mining]  # Based on our findings
    
    axes[1,1].bar(range(len(stats_labels)), stats_values)
    axes[1,1].set_xticks(range(len(stats_labels)))
    axes[1,1].set_xticklabels(stats_labels, rotation=45, ha='right')
    axes[1,1].set_ylabel('Count')
    axes[1,1].set_title('Database Coverage Statistics')
    
    plt.tight_layout()
    plt.savefig('municipality_analysis_results.png', dpi=300, bbox_inches='tight')
    print("Visualization saved as 'municipality_analysis_results.png'")

def main():
    """Main comprehensive analysis"""
    print("="*70)
    print("FINAL COMPREHENSIVE MUNICIPALITY INVESTIGATION")
    print("Brazilian Legislative Database - Complete Analysis")
    print("="*70)
    
    # Connect to database
    conn = psycopg2.connect(**db_config)
    print("✓ Connected to database")
    
    # 1. Analyze existing municipality field
    municipio_data = analyze_existing_municipality_field(conn)
    
    # 2. Create patterns for text mining
    patterns, states = get_comprehensive_patterns()
    print(f"\n✓ Created {len(patterns)} refined detection patterns")
    
    # 3. Perform deep text mining
    text_mining_municipalities, pattern_stats, field_stats = deep_text_mining(conn, patterns)
    
    # 4. Analyze authority field
    municipal_authorities = analyze_authority_field(conn)
    
    # 5. Generate comprehensive report
    print("\n" + "="*60)
    print("COMPREHENSIVE FINDINGS REPORT")
    print("="*60)
    
    print(f"\n📊 DATABASE COVERAGE:")
    print(f"  • Total documents: 134,014")
    print(f"  • Documents with municipality field: 2,994")
    print(f"  • Unique municipalities in existing field: {len(municipio_data)}")
    print(f"  • Additional municipalities found via text mining: {len(text_mining_municipalities)}")
    
    total_potential = 2994 + len(text_mining_municipalities)
    coverage_percentage = (total_potential / 134014) * 100
    
    print(f"\n🎯 ESTIMATED TOTAL MUNICIPALITY COVERAGE:")
    print(f"  • Total documents with municipality data: ~{total_potential:,}")
    print(f"  • Coverage percentage: ~{coverage_percentage:.2f}%")
    
    print(f"\n🔍 TEXT MINING EFFECTIVENESS:")
    for pattern, count in pattern_stats.most_common():
        print(f"  • {pattern}: {count} matches")
    
    print(f"\n📍 FIELD ANALYSIS RESULTS:")
    for field, count in field_stats.items():
        print(f"  • {field}: {count} unique municipalities")
    
    if text_mining_municipalities:
        print(f"\n🏙️ SAMPLE MUNICIPALITIES DISCOVERED:")
        sample_municipalities = sorted(list(text_mining_municipalities))[:20]
        for i, muni in enumerate(sample_municipalities, 1):
            print(f"  {i:2d}. {muni}")
        
        if len(text_mining_municipalities) > 20:
            print(f"     ... and {len(text_mining_municipalities) - 20} more")
    
    if municipal_authorities:
        print(f"\n🏛️ MUNICIPAL AUTHORITIES FOUND:")
        for auth, count in municipal_authorities[:10]:
            print(f"  • {auth}: {count} documents")
    
    # 6. Save results
    # Existing municipalities
    existing_df = pd.DataFrame(municipio_data, columns=['municipality', 'document_count'])
    existing_df['source'] = 'existing_field'
    existing_df.to_csv('existing_municipalities.csv', index=False)
    
    # Text mining results  
    if text_mining_municipalities:
        text_mining_df = pd.DataFrame([
            {'municipality': muni, 'source': 'text_mining', 'document_count': 1} 
            for muni in text_mining_municipalities
        ])
        text_mining_df.to_csv('text_mining_municipalities.csv', index=False)
    
    # Combined results
    all_results = []
    for muni, count in municipio_data:
        all_results.append({'municipality': muni, 'document_count': count, 'source': 'existing_field'})
    
    for muni in text_mining_municipalities:
        all_results.append({'municipality': muni, 'document_count': 1, 'source': 'text_mining'})
    
    combined_df = pd.DataFrame(all_results)
    combined_df.to_csv('all_municipalities_found.csv', index=False)
    
    print(f"\n💾 RESULTS SAVED:")
    print(f"  • existing_municipalities.csv - {len(municipio_data)} municipalities from existing field")
    if text_mining_municipalities:
        print(f"  • text_mining_municipalities.csv - {len(text_mining_municipalities)} from text mining")
    print(f"  • all_municipalities_found.csv - Combined results")
    
    # 7. Create visualizations
    create_visualizations(municipio_data, text_mining_municipalities, field_stats)
    
    # 8. Final recommendations
    print(f"\n" + "="*60)
    print("RECOMMENDATIONS")
    print("="*60)
    
    print(f"1. 📈 POTENTIAL FOR IMPROVEMENT:")
    print(f"   Currently only {2994:,} documents have municipality data explicitly.")
    print(f"   Text mining could potentially identify municipality information")
    print(f"   in an additional ~{len(text_mining_municipalities)} documents.")
    
    print(f"\n2. 🔧 DATA ENHANCEMENT OPPORTUNITIES:")
    print(f"   - Parse autoridade field for municipal authorities")
    print(f"   - Extract locations from document titles using refined patterns")
    print(f"   - Implement geo-coding for locality field")
    
    print(f"\n3. ⚠️  CURRENT LIMITATIONS:")
    print(f"   - Most documents ({134014-2994:,}) lack explicit municipality data")
    print(f"   - Text mining has precision challenges with legal text")
    print(f"   - Federal-level documents naturally lack municipality specificity")
    
    conn.close()
    print(f"\n✅ Analysis completed successfully!")

if __name__ == "__main__":
    main()